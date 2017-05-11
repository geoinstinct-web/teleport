/*
Copyright 2015 Gravitational, Inc.

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

// Package auth implements certificate signing authority and access control server
// Authority server is composed of several parts:
//
// * Authority server itself that implements signing and acl logic
// * HTTP server wrapper for authority server
// * HTTP client wrapper
//
package auth

import (
	"bytes"
	"image/png"

	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"github.com/pquerna/otp/totp"

	"github.com/tstranex/u2f"
)

// CreateSignupToken creates one time token for creating account for the user
// For each token it creates username and otp generator
func (s *AuthServer) CreateSignupToken(userv1 services.UserV1) (string, error) {
	user := userv1.V2()
	if err := user.Check(); err != nil {
		return "", trace.Wrap(err)
	}

	// make sure that connectors actually exist
	for _, id := range user.GetIdentities() {
		if err := id.Check(); err != nil {
			return "", trace.Wrap(err)
		}
		if _, err := s.GetOIDCConnector(id.ConnectorID, false); err != nil {
			if _, err := s.GetSAMLConnector(id.ConnectorID, false); err != nil {
				return "", trace.Wrap(err)
			}
		}
	}

	// TODO(rjones): TOCTOU, instead try to create signup token for user and fail
	// when unable to.
	_, err := s.GetPasswordHash(user.GetName())
	if err == nil {
		return "", trace.BadParameter("user %q already exists", user)
	}

	token, err := utils.CryptoRandomHex(TokenLenBytes)
	if err != nil {
		return "", trace.Wrap(err)
	}

	accountName := user.GetName() + "@" + s.AuthServiceName
	otpKey, otpQRCode, err := s.initializeTOTP(accountName)
	if err != nil {
		return "", trace.Wrap(err)
	}

	// create and upsert signup token
	tokenData := services.SignupToken{
		Token:     token,
		User:      userv1,
		OTPKey:    otpKey,
		OTPQRCode: otpQRCode,
	}

	err = s.UpsertSignupToken(token, tokenData, defaults.MaxSignupTokenTTL)
	if err != nil {
		return "", trace.Wrap(err)
	}

	log.Infof("[AUTH API] created the signup token for %q", user)
	return token, nil
}

// initializeTOTP creates TOTP algorithm and returns the key and QR code.
func (s *AuthServer) initializeTOTP(accountName string) (key string, qr []byte, err error) {
	// create totp key
	otpKey, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Teleport",
		AccountName: accountName,
	})
	if err != nil {
		return "", nil, trace.Wrap(err)
	}

	// create QR code
	var otpQRBuf bytes.Buffer
	otpImage, err := otpKey.Image(456, 456)
	if err != nil {
		return "", nil, trace.Wrap(err)
	}
	png.Encode(&otpQRBuf, otpImage)

	return otpKey.Secret(), otpQRBuf.Bytes(), nil
}

// GetSignupTokenData returns token data for a valid token
func (s *AuthServer) GetSignupTokenData(token string) (user string, qrCode []byte, err error) {
	tokenData, err := s.GetSignupToken(token)
	if err != nil {
		return "", nil, trace.Wrap(err)
	}

	// TODO(rjones): Remove this check and use compare and swap in the Create* functions below.
	// It's a TOCTOU bug in the making: https://en.wikipedia.org/wiki/Time_of_check_to_time_of_use
	_, err = s.GetPasswordHash(tokenData.User.Name)
	if err == nil {
		return "", nil, trace.Errorf("can't add user %v: user already exists", tokenData.User)
	}

	return tokenData.User.Name, tokenData.OTPQRCode, nil
}

func (s *AuthServer) CreateSignupU2FRegisterRequest(token string) (u2fRegisterRequest *u2f.RegisterRequest, e error) {
	universalSecondFactor, err := s.GetUniversalSecondFactor()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	tokenData, err := s.GetSignupToken(token)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	_, err = s.GetPasswordHash(tokenData.User.Name)
	if err == nil {
		return nil, trace.AlreadyExists("can't add user %q, user already exists", tokenData.User)
	}

	c, err := u2f.NewChallenge(universalSecondFactor.GetAppID(), universalSecondFactor.GetFacets())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	request := c.RegisterRequest()

	err = s.UpsertU2FRegisterChallenge(token, c)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return request, nil
}

// CreateUserWithOTP creates account with provided token and password.
// Account username and hotp generator are taken from token data.
// Deletes token after account creation.
func (s *AuthServer) CreateUserWithOTP(token string, password string, otpToken string) (services.WebSession, error) {
	tokenData, err := s.GetSignupToken(token)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = s.UpsertTOTP(tokenData.User.Name, tokenData.OTPKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = s.CheckOTP(tokenData.User.Name, otpToken)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = s.UpsertPassword(tokenData.User.Name, []byte(password))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// apply user allowed logins
	role := services.RoleForUser(tokenData.User.V2())
	role.SetLogins(tokenData.User.AllowedLogins)
	if err := s.UpsertRole(role, backend.Forever); err != nil {
		return nil, trace.Wrap(err)
	}

	// Allowed logins are not going to be used anymore
	tokenData.User.AllowedLogins = nil
	tokenData.User.Roles = append(tokenData.User.Roles, role.GetName())
	user := tokenData.User.V2()
	if err = s.UpsertUser(user); err != nil {
		return nil, trace.Wrap(err)
	}

	log.Infof("[AUTH] created new user: %v", &tokenData.User)

	if err = s.DeleteSignupToken(token); err != nil {
		return nil, trace.Wrap(err)
	}

	sess, err := s.NewWebSession(user.GetName())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = s.UpsertWebSession(user.GetName(), sess)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return sess.WithoutSecrets(), nil
}

// CreateUserWithoutOTP creates an account with the provided password and deletes the token afterwards.
func (s *AuthServer) CreateUserWithoutOTP(token string, password string) (services.WebSession, error) {
	tokenData, err := s.GetSignupToken(token)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = s.UpsertPassword(tokenData.User.Name, []byte(password))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// apply user allowed logins
	role := services.RoleForUser(tokenData.User.V2())
	role.SetLogins(tokenData.User.AllowedLogins)
	if err := s.UpsertRole(role, backend.Forever); err != nil {
		return nil, trace.Wrap(err)
	}

	// allowed logins are not going to be used anymore
	tokenData.User.AllowedLogins = nil
	tokenData.User.Roles = append(tokenData.User.Roles, role.GetName())
	user := tokenData.User.V2()
	if err = s.UpsertUser(user); err != nil {
		return nil, trace.Wrap(err)
	}

	log.Infof("[AUTH] Created new user: %v", &tokenData.User)

	if err = s.DeleteSignupToken(token); err != nil {
		return nil, trace.Wrap(err)
	}

	sess, err := s.NewWebSession(user.GetName())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = s.UpsertWebSession(user.GetName(), sess)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return sess.WithoutSecrets(), nil
}

func (s *AuthServer) CreateUserWithU2FToken(token string, password string, response u2f.RegisterResponse) (services.WebSession, error) {
	// before trying to create a user, see U2F is actually setup on the backend
	_, err := s.GetUniversalSecondFactor()
	if err != nil {
		return nil, err
	}

	tokenData, err := s.GetSignupToken(token)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	challenge, err := s.GetU2FRegisterChallenge(token)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	reg, err := u2f.Register(response, *challenge, &u2f.Config{SkipAttestationVerify: true})
	if err != nil {
		log.Error(trace.DebugReport(err))
		return nil, trace.Wrap(err)
	}

	err = s.UpsertU2FRegistration(tokenData.User.Name, reg)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	err = s.UpsertU2FRegistrationCounter(tokenData.User.Name, 0)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = s.UpsertPassword(tokenData.User.Name, []byte(password))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	role := services.RoleForUser(tokenData.User.V2())
	role.SetLogins(tokenData.User.AllowedLogins)
	if err := s.UpsertRole(role, backend.Forever); err != nil {
		return nil, trace.Wrap(err)
	}

	// Allowed logins are not going to be used anymore
	tokenData.User.AllowedLogins = nil
	tokenData.User.Roles = append(tokenData.User.Roles, role.GetName())
	user := tokenData.User.V2()
	if err = s.UpsertUser(user); err != nil {
		return nil, trace.Wrap(err)
	}

	log.Infof("[AUTH] created new user: %v", &tokenData.User)

	if err = s.DeleteSignupToken(token); err != nil {
		return nil, trace.Wrap(err)
	}

	sess, err := s.NewWebSession(user.GetName())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = s.UpsertWebSession(user.GetName(), sess)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return sess.WithoutSecrets(), nil
}

func (a *AuthServer) DeleteUser(user string) error {
	role, err := a.Access.GetRole(services.RoleNameForUser(user))
	if err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	} else {
		if err := a.Access.DeleteRole(role.GetName()); err != nil {
			if !trace.IsNotFound(err) {
				return trace.Wrap(err)
			}
		}
	}
	return a.Identity.DeleteUser(user)
}
