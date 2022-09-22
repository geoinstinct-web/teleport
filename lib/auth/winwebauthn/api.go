// Copyright 2022 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package winwebauthn is wrapper around Windows webauthn API.
// It loads system webauthn.dll and uses it's method.
// It supports API versions 1-4.
// API definition: https://github.com/microsoft/webauthn/blob/master/webauthn.h
// As Windows Webauthn device can be used both Windows Hello and FIDO devices.
package winwebauthn

import (
	"context"
	"io"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/gravitational/teleport/api/client/proto"
	wanlib "github.com/gravitational/teleport/lib/auth/webauthn"
	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
)

// LoginOpts groups non-mandatory options for Login.
type LoginOpts struct {
	// AuthenticatorAttachment specifies the desired authenticator attachment.
	AuthenticatorAttachment AuthenticatorAttachment
}

type AuthenticatorAttachment int

const (
	AttachmentAuto AuthenticatorAttachment = iota
	AttachmentCrossPlatform
	AttachmentPlatform
)

// nativeWebauthn represents the native windows webauthn interface.
// Implementors must provide a global variable called `native`.
type nativeWebauthn interface {
	CheckSupport() CheckSupportResult
	GetAssertion(origin string, in protocol.PublicKeyCredentialRequestOptions, loginOpts *LoginOpts) (*wanlib.CredentialAssertionResponse, error)
	MakeCredential(origin string, in protocol.PublicKeyCredentialCreationOptions) (*wanlib.CredentialCreationResponse, error)
}

// Login implements Login for Windows Webauthn API.
// It returns an MFAAuthenticateResponse.
// Most callers should call Login directly, as it is correctly guarded by
// IsAvailable.
func Login(ctx context.Context, origin string, assertion *wanlib.CredentialAssertion, opts *LoginOpts) (*proto.MFAAuthenticateResponse, string, error) {
	switch {
	case origin == "":
		return nil, "", trace.BadParameter("origin required")
	case assertion == nil:
		return nil, "", trace.BadParameter("assertion required")
	case len(assertion.Response.Challenge) == 0:
		return nil, "", trace.BadParameter("assertion challenge required")
	case assertion.Response.RelyingPartyID == "":
		return nil, "", trace.BadParameter("assertion relying party ID required")
	}
	resp, err := native.GetAssertion(origin, assertion.Response, opts)
	if err != nil {
		// TODO(tobiaszheller): proper error
		return nil, "", err
	}

	return &proto.MFAAuthenticateResponse{
		Response: &proto.MFAAuthenticateResponse_Webauthn{
			Webauthn: wanlib.CredentialAssertionResponseToProto(resp),
		},
	}, "", nil
}

// Register implements Register for Windows Webauthn API.
// Most callers should call Register directly, as it is correctly guarded by
// IsAvailable.
func Register(
	ctx context.Context,
	origin string, cc *wanlib.CredentialCreation,
) (*proto.MFARegisterResponse, error) {
	switch {
	case origin == "":
		return nil, trace.BadParameter("origin required")
	case cc == nil:
		return nil, trace.BadParameter("credential creation required")
	case len(cc.Response.Challenge) == 0:
		return nil, trace.BadParameter("credential creation challenge required")
	case cc.Response.RelyingParty.ID == "":
		return nil, trace.BadParameter("credential creation relying party ID required")
	}

	rrk := cc.Response.AuthenticatorSelection.RequireResidentKey != nil && *cc.Response.AuthenticatorSelection.RequireResidentKey
	log.Debugf("WINWEBAUTHN: registration: resident key=%v", rrk)
	if rrk {
		// Be more pedantic with resident keys, some of this info gets recorded with
		// the credential.
		switch {
		case len(cc.Response.RelyingParty.Name) == 0:
			return nil, trace.BadParameter("relying party name required for resident credential")
		case len(cc.Response.User.Name) == 0:
			return nil, trace.BadParameter("user name required for resident credential")
		case len(cc.Response.User.DisplayName) == 0:
			return nil, trace.BadParameter("user display name required for resident credential")
		case len(cc.Response.User.ID) == 0:
			return nil, trace.BadParameter("user ID required for resident credential")
		}
	}

	resp, err := native.MakeCredential(origin, cc.Response)
	if err != nil {
		// TODO(tobiaszheller): proper error
		return nil, err
	}

	return &proto.MFARegisterResponse{
		Response: &proto.MFARegisterResponse_Webauthn{
			Webauthn: wanlib.CredentialCreationResponseToProto(resp),
		},
	}, nil
}

// CheckSupport is the result from a Windows webauthn support check.
type CheckSupportResult struct {
	HasCompileSupport bool
	IsAvailable       bool
	HasPlatformUV     bool
	APIVersion        int
}

// IsAvailable returns true if Windows webauthn library is available in the
// system. Typically, a series of checks is performed in an attempt to avoid
// false positives.
// See CheckSupport.
func IsAvailable() bool {
	return CheckSupport().IsAvailable
}

// CheckSupport return information whether Windows Webauthn is supported and
// information about API version.
func CheckSupport() CheckSupportResult {
	return native.CheckSupport()
}

type RunDiagnosticsResult struct {
	Available                           bool
	RegisterSuccessful, LoginSuccessful bool
}

// RunDiagnostics runs a few diagnostic commands and returns the result.
// User interaction is required.
func RunDiagnostics(ctx context.Context, promptOut io.Writer) (*RunDiagnosticsResult, error) {
	res := &RunDiagnosticsResult{}
	if !IsAvailable() {
		return res, nil
	}
	res.Available = true

	// Attempt registration.
	const origin = "localhost"
	cc := &wanlib.CredentialCreation{
		Response: protocol.PublicKeyCredentialCreationOptions{
			Challenge: make([]byte, 32),
			RelyingParty: protocol.RelyingPartyEntity{
				ID: "localhost",
				CredentialEntity: protocol.CredentialEntity{
					Name: "test RP",
				},
			},
			User: protocol.UserEntity{
				CredentialEntity: protocol.CredentialEntity{
					Name: "test",
				},
				ID:          []byte("test"),
				DisplayName: "test",
			},
			Parameters: []protocol.CredentialParameter{
				{
					Type:      protocol.PublicKeyCredentialType,
					Algorithm: webauthncose.AlgRS256,
				},
			},
			Attestation: protocol.PreferNoAttestation,
		},
	}
	ccr, err := Register(ctx, origin, cc)
	if err != nil {
		return res, trace.Wrap(err)
	}
	res.RegisterSuccessful = true

	// Attempt login.
	assertion := &wanlib.CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{
			Challenge:      make([]byte, 32),
			RelyingPartyID: cc.Response.RelyingParty.ID,
			AllowedCredentials: []protocol.CredentialDescriptor{
				{
					Type:         protocol.PublicKeyCredentialType,
					CredentialID: ccr.GetWebauthn().GetRawId(),
				},
			},
			UserVerification: protocol.VerificationDiscouraged,
		},
	}
	if _, _, err := Login(ctx, origin, assertion, &LoginOpts{}); err != nil {
		return res, trace.Wrap(err)
	}
	res.LoginSuccessful = true

	return res, nil
}
