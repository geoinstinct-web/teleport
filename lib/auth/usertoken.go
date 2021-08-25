/*
Copyright 2017-2020 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"bytes"
	"context"
	"fmt"
	"image/png"
	"net/url"
	"time"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/auth/u2f"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/gravitational/trace"
)

const (
	// UserTokenTypeResetPasswordInvite is a token type used for the UI invite flow that
	// allows users to change their password and set second factor (if enabled).
	UserTokenTypeResetPasswordInvite = "invite"
	// UserTokenTypeResetPassword is a token type used for the UI flow where user
	// re-sets their password and second factor (if enabled).
	UserTokenTypeResetPassword = "password"
	// UserTokenTypePrivilege describes a token type that grants access to a privileged action
	// that requires users to re-authenticate with their second factor while looged in. This
	// token is issued to users who has successfully re-authenticated.
	UserTokenTypePrivilege = "privilege"
	// UserTokenTypePrivilegeException describes a token type that allowed a user to bypass
	// second factor re-authentication which in other cases would be required eg:
	// allowing user to add a mfa device if they don't have any registered.
	UserTokenTypePrivilegeException = "privilege_exception"
)

// CreateUserTokenRequest is a request to create a new user token.
type CreateUserTokenRequest struct {
	// Name is the user name for token.
	Name string `json:"name"`
	// TTL specifies how long the generated token is valid for.
	TTL time.Duration `json:"ttl"`
	// Type is the token type.
	Type string `json:"type"`
}

// CheckAndSetDefaults checks and sets the defaults.
func (r *CreateUserTokenRequest) CheckAndSetDefaults() error {
	if r.Name == "" {
		return trace.BadParameter("user name can't be empty")
	}

	if r.TTL < 0 {
		return trace.BadParameter("TTL can't be negative")
	}

	if r.Type == "" {
		r.Type = UserTokenTypeResetPassword
	}

	switch r.Type {
	case UserTokenTypeResetPasswordInvite:
		if r.TTL == 0 {
			r.TTL = defaults.SignupTokenTTL
		}

		if r.TTL > defaults.MaxSignupTokenTTL {
			return trace.BadParameter(
				"failed to create user token for reset password invite: maximum token TTL is %v hours",
				defaults.MaxSignupTokenTTL)
		}

	case UserTokenTypeResetPassword:
		if r.TTL == 0 {
			r.TTL = defaults.ChangePasswordTokenTTL
		}

		if r.TTL > defaults.MaxChangePasswordTokenTTL {
			return trace.BadParameter(
				"failed to create user token for reset password: maximum token TTL is %v hours",
				defaults.MaxChangePasswordTokenTTL)
		}

	case UserTokenTypePrivilege, UserTokenTypePrivilegeException:
		r.TTL = defaults.PrivilegeTokenTTL

	default:
		return trace.BadParameter("unknown user token request type(%v)", r.Type)
	}

	return nil
}

// CreateResetPasswordToken creates a reset password token
func (s *Server) CreateResetPasswordToken(ctx context.Context, req CreateUserTokenRequest) (types.UserToken, error) {
	err := req.CheckAndSetDefaults()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if req.Type != UserTokenTypeResetPassword && req.Type != UserTokenTypeResetPasswordInvite {
		return nil, trace.BadParameter("invalid reset password token request type")
	}

	_, err = s.GetUser(req.Name, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	_, err = s.ResetPassword(req.Name)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := s.resetMFA(ctx, req.Name); err != nil {
		return nil, trace.Wrap(err)
	}

	token, err := s.newUserToken(req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// remove any other existing tokens for this user
	err = s.deleteUserTokens(ctx, req.Name)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	_, err = s.Identity.CreateUserToken(ctx, token)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := s.emitter.EmitAuditEvent(ctx, &apievents.UserTokenCreate{
		Metadata: apievents.Metadata{
			Type: events.ResetPasswordTokenCreateEvent,
			Code: events.ResetPasswordTokenCreateCode,
		},
		UserMetadata: apievents.UserMetadata{
			User:         ClientUsername(ctx),
			Impersonator: ClientImpersonator(ctx),
		},
		ResourceMetadata: apievents.ResourceMetadata{
			Name:    req.Name,
			TTL:     req.TTL.String(),
			Expires: s.GetClock().Now().UTC().Add(req.TTL),
		},
	}); err != nil {
		log.WithError(err).Warn("Failed to emit create reset password token event.")
	}

	return s.GetUserToken(ctx, token.GetName())
}

func (s *Server) resetMFA(ctx context.Context, user string) error {
	devs, err := s.Identity.GetMFADevices(ctx, user, false)
	if err != nil {
		return trace.Wrap(err)
	}
	var errs []error
	for _, d := range devs {
		errs = append(errs, s.DeleteMFADevice(ctx, user, d.Id))
	}
	return trace.NewAggregate(errs...)
}

// proxyDomainGetter is a reduced subset of the Auth API for formatAccountName.
type proxyDomainGetter interface {
	GetProxies() ([]types.Server, error)
	GetDomainName() (string, error)
}

// formatAccountName builds the account name to display in OTP applications.
// Format for accountName is user@address. User is passed in, this function
// tries to find the best available address.
func formatAccountName(s proxyDomainGetter, username string, authHostname string) (string, error) {
	var err error
	var proxyHost string

	// Get a list of proxies.
	proxies, err := s.GetProxies()
	if err != nil {
		return "", trace.Wrap(err)
	}

	// If no proxies were found, try and set address to the name of the cluster.
	// If even the cluster name is not found (an unlikely) event, fallback to
	// hostname of the auth server.
	//
	// If a proxy was found, and any of the proxies has a public address set,
	// use that. If none of the proxies have a public address set, use the
	// hostname of the first proxy found.
	if len(proxies) == 0 {
		proxyHost, err = s.GetDomainName()
		if err != nil {
			log.Errorf("Failed to retrieve cluster name, falling back to hostname: %v.", err)
			proxyHost = authHostname
		}
	} else {
		proxyHost, _, err = services.GuessProxyHostAndVersion(proxies)
		if err != nil {
			return "", trace.Wrap(err)
		}
	}

	return fmt.Sprintf("%v@%v", username, proxyHost), nil
}

// RotateUserTokenSecrets rotates secrets for a given tokenID.
// It gets called every time a user fetches 2nd-factor secrets during registration attempt.
// This ensures that an attacker that gains the user token link can not view it,
// extract the OTP key from the QR code, then allow the user to signup with
// the same OTP token.
func (s *Server) RotateUserTokenSecrets(ctx context.Context, tokenID string) (types.UserTokenSecrets, error) {
	token, err := s.GetUserToken(ctx, tokenID)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	key, _, err := s.newTOTPKey(token.GetUser())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Create QR code.
	var otpQRBuf bytes.Buffer
	otpImage, err := key.Image(456, 456)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := png.Encode(&otpQRBuf, otpImage); err != nil {
		return nil, trace.Wrap(err)
	}

	secrets, err := types.NewUserTokenSecrets(tokenID)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	secrets.SetOTPKey(key.Secret())
	secrets.SetQRCode(otpQRBuf.Bytes())
	secrets.SetExpiry(token.Expiry())
	err = s.UpsertUserTokenSecrets(ctx, secrets)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return secrets, nil
}

func (s *Server) newTOTPKey(user string) (*otp.Key, *totp.GenerateOpts, error) {
	// Fetch account name to display in OTP apps.
	accountName, err := formatAccountName(s, user, s.AuthServiceName)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	clusterName, err := s.GetClusterName()
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	opts := totp.GenerateOpts{
		Issuer:      clusterName.GetClusterName(),
		AccountName: accountName,
		Period:      30, // seconds
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	}
	key, err := totp.Generate(opts)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	return key, &opts, nil
}

func (s *Server) newUserToken(req CreateUserTokenRequest) (types.UserToken, error) {
	var err error
	var proxyHost string

	tokenID, err := utils.CryptoRandomHex(TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Get the list of proxies and try and guess the address of the proxy. If
	// failed to guess public address, use "<proxyhost>:3080" as a fallback.
	proxies, err := s.GetProxies()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if len(proxies) == 0 {
		proxyHost = fmt.Sprintf("<proxyhost>:%v", defaults.HTTPListenPort)
	} else {
		proxyHost, _, err = services.GuessProxyHostAndVersion(proxies)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	url, err := formatUserTokenURL(proxyHost, tokenID, req.Type)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	token, err := types.NewUserToken(tokenID)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	token.SetSubKind(req.Type)
	token.SetExpiry(s.clock.Now().UTC().Add(req.TTL))
	token.SetUser(req.Name)
	token.SetCreated(s.clock.Now().UTC())
	token.SetURL(url)
	return token, nil
}

func formatUserTokenURL(proxyHost string, tokenID string, reqType string) (string, error) {
	u := &url.URL{
		Scheme: "https",
		Host:   proxyHost,
	}

	// Defines different UI flows that process user tokens.
	switch reqType {
	case UserTokenTypeResetPasswordInvite:
		u.Path = fmt.Sprintf("/web/invite/%v", tokenID)
	case UserTokenTypeResetPassword:
		u.Path = fmt.Sprintf("/web/reset/%v", tokenID)
	}

	return u.String(), nil
}

// deleteUserTokens deletes all user tokens for the specified user.
func (s *Server) deleteUserTokens(ctx context.Context, username string) error {
	tokens, err := s.GetUserTokens(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	for _, token := range tokens {
		if token.GetUser() != username {
			continue
		}

		err = s.DeleteUserToken(ctx, token.GetName())
		if err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// getResetPasswordToken returns user token with subkind set to reset or invite, both
// types which allows users to change their password and set new second factors (if enabled).
func (s *Server) getResetPasswordToken(ctx context.Context, tokenID string) (types.UserToken, error) {
	token, err := s.GetUserToken(ctx, tokenID)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// DELETE IN 9.0.0: remove checking for empty string.
	if token.GetSubKind() != "" && token.GetSubKind() != UserTokenTypeResetPassword && token.GetSubKind() != UserTokenTypeResetPasswordInvite {
		return nil, trace.BadParameter("invalid token")
	}

	return token, nil
}

// CreatePrivilegeToken implements AuthService.CreatePrivilegeToken.
func (s *Server) CreatePrivilegeToken(ctx context.Context, req *proto.CreatePrivilegeTokenRequest, username string) (types.UserToken, error) {
	if username == "" {
		return nil, trace.BadParameter("missing parameter username")
	}

	authPref, err := s.GetAuthPreference(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if !authPref.GetAllowLocalAuth() {
		return nil, trace.AccessDenied("local auth needs to be enabled")
	}

	secondFactor := authPref.GetSecondFactor()
	if secondFactor == constants.SecondFactorOff {
		return nil, trace.AccessDenied("second factor must be enabled")
	}

	tokenKind := UserTokenTypePrivilege

	// Begin authenticating second factor.
	switch req.GetExistingMFAResponse().GetResponse().(type) {
	case *proto.MFAAuthenticateResponse_TOTP:
		if secondFactor == constants.SecondFactorU2F {
			return nil, trace.BadParameter("unexpected u2f credential")
		}

		err := s.WithUserLock(username, func() error {
			_, err := s.checkOTP(username, req.GetExistingMFAResponse().GetTOTP().GetCode())
			return err
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}

	case *proto.MFAAuthenticateResponse_U2F:
		if secondFactor == constants.SecondFactorOTP {
			return nil, trace.BadParameter("unexpected otp credential")
		}

		err := s.WithUserLock(username, func() error {
			_, err := s.CheckU2FSignResponse(ctx, username, &u2f.AuthenticateChallengeResponse{
				KeyHandle:     req.GetExistingMFAResponse().GetU2F().GetKeyHandle(),
				SignatureData: req.GetExistingMFAResponse().GetU2F().GetSignature(),
				ClientData:    req.GetExistingMFAResponse().GetU2F().GetClientData(),
			})
			return trace.Wrap(err)
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}

	default:
		// Allows users with no devices to bypass second factor re-auth.
		devices, err := s.Identity.GetMFADevices(ctx, username, false)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		if len(devices) > 0 {
			return nil, trace.BadParameter("second factor authentication required")
		}

		tokenKind = UserTokenTypePrivilegeException
	}

	// Delete any existing user tokens for user before creating.
	if err := s.deleteUserTokens(ctx, username); err != nil {
		return nil, trace.Wrap(err)
	}

	token, err := s.createPrivilegeToken(ctx, username, tokenKind)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return token, nil
}

func (s *Server) createPrivilegeToken(ctx context.Context, username string, tokenKind string) (types.UserToken, error) {
	if tokenKind != UserTokenTypePrivilege && tokenKind != UserTokenTypePrivilegeException {
		return nil, trace.BadParameter("invalid privilege token type")
	}

	req := CreateUserTokenRequest{
		Name: username,
		Type: tokenKind,
	}

	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	newToken, err := s.newUserToken(req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	token, err := s.Identity.CreateUserToken(ctx, newToken)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := s.emitter.EmitAuditEvent(ctx, &apievents.UserTokenCreate{
		Metadata: apievents.Metadata{
			Type: events.PrivilegeTokenCreateEvent,
			Code: events.PrivilegeTokenCreateCode,
		},
		UserMetadata: apievents.UserMetadata{
			User: username,
		},
		ResourceMetadata: apievents.ResourceMetadata{
			Name:    req.Name,
			TTL:     req.TTL.String(),
			Expires: s.GetClock().Now().UTC().Add(req.TTL),
		},
	}); err != nil {
		log.WithError(err).Warn("Failed to emit create privilege token event.")
	}

	return token, nil
}
