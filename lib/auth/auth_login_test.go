// Copyright 2021 Gravitational, Inc
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

package auth

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/mocku2f"
	"github.com/gravitational/trace"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"github.com/tstranex/u2f"
)

func TestServer_GetMFAAuthenticateChallenge_authPreference(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	svr := newTestTLSServer(t)
	authServer := svr.Auth()
	mfa := configureForMFA(t, svr)
	username := mfa.User
	password := mfa.Password

	tests := []struct {
		name            string
		spec            *types.AuthPreferenceSpecV2
		assertChallenge func(*MFAAuthenticateChallenge)
	}{
		{
			name: "OK second_factor:off",
			spec: &types.AuthPreferenceSpecV2{
				Type:         constants.Local,
				SecondFactor: constants.SecondFactorOff,
			},
			assertChallenge: func(challenge *MFAAuthenticateChallenge) {
				require.False(t, challenge.TOTPChallenge)
				require.Empty(t, challenge.U2FChallenges)
				require.Empty(t, challenge.WebauthnChallenge)
			},
		},
		{
			name: "OK second_factor:otp",
			spec: &types.AuthPreferenceSpecV2{
				Type:         constants.Local,
				SecondFactor: constants.SecondFactorOTP,
			},
			assertChallenge: func(challenge *MFAAuthenticateChallenge) {
				require.True(t, challenge.TOTPChallenge)
				require.Empty(t, challenge.U2FChallenges)
				require.Empty(t, challenge.WebauthnChallenge)
			},
		},
		{
			name: "OK second_factor:u2f",
			spec: &types.AuthPreferenceSpecV2{
				Type:         constants.Local,
				SecondFactor: constants.SecondFactorU2F,
				U2F: &types.U2F{
					AppID:  "https://localhost",
					Facets: []string{"https://localhost"},
				},
			},
			assertChallenge: func(challenge *MFAAuthenticateChallenge) {
				require.False(t, challenge.TOTPChallenge)
				require.NotEmpty(t, challenge.U2FChallenges)
				require.Empty(t, challenge.WebauthnChallenge)
			},
		},
		{
			name: "OK second_factor:webauthn (derived from U2F)",
			spec: &types.AuthPreferenceSpecV2{
				Type:         constants.Local,
				SecondFactor: constants.SecondFactorWebauthn,
				U2F: &types.U2F{
					AppID:  "https://localhost",
					Facets: []string{"https://localhost"},
				},
			},
			assertChallenge: func(challenge *MFAAuthenticateChallenge) {
				require.False(t, challenge.TOTPChallenge)
				require.Empty(t, challenge.U2FChallenges)
				require.NotEmpty(t, challenge.WebauthnChallenge)
			},
		},
		{
			name: "OK second_factor:webauthn (standalone)",
			spec: &types.AuthPreferenceSpecV2{
				Type:         constants.Local,
				SecondFactor: constants.SecondFactorWebauthn,
				Webauthn: &types.Webauthn{
					RPID: "localhost",
				},
			},
			assertChallenge: func(challenge *MFAAuthenticateChallenge) {
				require.False(t, challenge.TOTPChallenge)
				require.Empty(t, challenge.U2FChallenges)
				require.NotEmpty(t, challenge.WebauthnChallenge)
			},
		},
		{
			name: "OK second_factor:webauthn uses explicit RPID",
			spec: &types.AuthPreferenceSpecV2{
				Type:         constants.Local,
				SecondFactor: constants.SecondFactorWebauthn,
				U2F: &types.U2F{
					AppID: "https://myoldappid.com",
					Facets: []string{
						"https://myoldappid.com",
						"https://localhost",
					},
				},
				Webauthn: &types.Webauthn{
					RPID: "myexplicitid",
				},
			},
			assertChallenge: func(challenge *MFAAuthenticateChallenge) {
				require.False(t, challenge.TOTPChallenge)
				require.Empty(t, challenge.U2FChallenges)
				require.NotEmpty(t, challenge.WebauthnChallenge)
				require.Equal(t, "myexplicitid", challenge.WebauthnChallenge.Response.RelyingPartyID)
			},
		},
		{
			name: "OK second_factor:webauthn (derived from U2F)",
			spec: &types.AuthPreferenceSpecV2{
				Type:         constants.Local,
				SecondFactor: constants.SecondFactorWebauthn,
				U2F: &types.U2F{
					AppID:  "https://localhost",
					Facets: []string{"https://localhost"},
				},
			},
			assertChallenge: func(challenge *MFAAuthenticateChallenge) {
				require.False(t, challenge.TOTPChallenge)
				require.Empty(t, challenge.U2FChallenges)
				require.NotEmpty(t, challenge.WebauthnChallenge)
			},
		},
		{
			name: "OK second_factor:optional",
			spec: &types.AuthPreferenceSpecV2{
				Type:         constants.Local,
				SecondFactor: constants.SecondFactorOptional,
				U2F: &types.U2F{
					AppID:  "https://localhost",
					Facets: []string{"https://localhost"},
				},
			},
			assertChallenge: func(challenge *MFAAuthenticateChallenge) {
				require.True(t, challenge.TOTPChallenge)
				require.NotEmpty(t, challenge.U2FChallenges)
				require.NotEmpty(t, challenge.WebauthnChallenge)
			},
		},
		{
			name: "OK second_factor:on",
			spec: &types.AuthPreferenceSpecV2{
				Type:         constants.Local,
				SecondFactor: constants.SecondFactorOn,
				U2F: &types.U2F{
					AppID:  "https://localhost",
					Facets: []string{"https://localhost"},
				},
			},
			assertChallenge: func(challenge *MFAAuthenticateChallenge) {
				require.True(t, challenge.TOTPChallenge)
				require.NotEmpty(t, challenge.U2FChallenges)
				require.NotEmpty(t, challenge.WebauthnChallenge)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authPreference, err := types.NewAuthPreference(*test.spec)
			require.NoError(t, err)
			require.NoError(t, authServer.SetAuthPreference(ctx, authPreference))

			challenge, err := authServer.GetMFAAuthenticateChallenge(username, []byte(password))
			require.NoError(t, err)
			test.assertChallenge(challenge)
		})
	}
}

func TestServer_AuthenticateUser_WebauthnWithU2F(t *testing.T) {
	t.Parallel()

	svr := newTestTLSServer(t)
	authServer := svr.Auth()
	mfa := configureForMFA(t, svr)
	username := mfa.User
	password := mfa.Password
	dev := mfa.Device1

	// 1st step: acquire challenge
	challenge, err := authServer.GetMFAAuthenticateChallenge(username, []byte(password))
	require.NoError(t, err)
	require.NotEmpty(t, challenge.WebauthnChallenge)

	// Sign challenge (client-side)
	const origin = "https://localhost"
	assertionResp, err := dev.SignAssertion(origin, challenge.WebauthnChallenge)
	require.NoError(t, err)

	// 2nd step: finish login
	require.NoError(t, authServer.AuthenticateUser(AuthenticateUserRequest{
		Username: username,
		Webauthn: assertionResp,
	}))
}

type configureMFAResp struct {
	User, Password   string
	OTPKey           string
	Device1, Device2 *mocku2f.Key
}

func configureForMFA(t *testing.T, svr *TestTLSServer) *configureMFAResp {
	t.Helper()
	ctx := context.Background()

	authServer := svr.Auth()

	// Enable second factor, configure U2F.
	authPreference, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{
		Type:         constants.Local,
		SecondFactor: constants.SecondFactorOn,
		U2F: &types.U2F{
			AppID:  "https://localhost",
			Facets: []string{"https://localhost"},
		},
		// Use default Webauthn config.
	})
	require.NoError(t, err)
	require.NoError(t, authServer.SetAuthPreference(ctx, authPreference))

	// Create user with a default password.
	const username = "bob"
	_, _, err = CreateUserAndRole(authServer, username, []string{"bob", "root"})
	require.NoError(t, err)
	require.NoError(t, authServer.UpsertPassword(username, []byte("changeme")))

	// Register initial U2F device.
	token, err := authServer.CreateResetPasswordToken(ctx, CreateUserTokenRequest{
		Name: username,
	})
	require.NoError(t, err)
	registerReq, err := authServer.CreateSignupU2FRegisterRequest(token.GetName())
	require.NoError(t, err)
	dev1, err := mocku2f.Create()
	require.NoError(t, err)
	registerResp, err := dev1.RegisterResponse(registerReq)
	require.NoError(t, err)
	const password = "supersecurepassword1"
	_, err = authServer.ChangeUserAuthentication(ctx, &proto.ChangeUserAuthenticationRequest{
		TokenID:     token.GetName(),
		NewPassword: []byte(password),
		NewMFARegisterResponse: &proto.MFARegisterResponse{
			Response: &proto.MFARegisterResponse_U2F{
				U2F: &proto.U2FRegisterResponse{
					RegistrationData: registerResp.RegistrationData,
					ClientData:       registerResp.ClientData,
				},
			},
		},
	})
	require.NoError(t, err)

	// Prepare to add additional devices.
	client, err := svr.NewClient(TestUser(username))
	require.NoError(t, err)
	authenticateFn := func(challenge *proto.MFAAuthenticateChallenge) (*proto.MFAAuthenticateResponse, error) {
		kh := base64.RawURLEncoding.EncodeToString(dev1.KeyHandle)
		var devChallenge *proto.U2FChallenge
		for _, c := range challenge.U2F {
			if c.KeyHandle == kh {
				devChallenge = c
				break
			}
		}
		if devChallenge == nil {
			return nil, trace.BadParameter("missing challenge for dev1")
		}
		resp, err := dev1.SignResponse(&u2f.SignRequest{
			Version:   devChallenge.Version,
			Challenge: devChallenge.Challenge,
			KeyHandle: devChallenge.KeyHandle,
			AppID:     devChallenge.AppID,
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return &proto.MFAAuthenticateResponse{
			Response: &proto.MFAAuthenticateResponse_U2F{
				U2F: &proto.U2FResponse{
					KeyHandle:  resp.KeyHandle,
					ClientData: resp.ClientData,
					Signature:  resp.SignatureData,
				},
			},
		}, nil
	}

	// Register an additional U2F device.
	dev2, err := mocku2f.Create()
	require.NoError(t, err)
	require.NoError(t, runAddMFADevice(ctx, client, proto.AddMFADeviceRequestInit_U2F, "u2f#2", authenticateFn,
		func(challenge *proto.MFARegisterChallenge) (*proto.MFARegisterResponse, error) {
			resp, err := dev2.RegisterResponse(&u2f.RegisterRequest{
				Version:   challenge.GetU2F().Version,
				Challenge: challenge.GetU2F().Challenge,
				AppID:     challenge.GetU2F().AppID,
			})
			if err != nil {
				return nil, trace.Wrap(err)
			}
			return &proto.MFARegisterResponse{
				Response: &proto.MFARegisterResponse_U2F{
					U2F: &proto.U2FRegisterResponse{
						RegistrationData: resp.RegistrationData,
						ClientData:       resp.ClientData,
					},
				},
			}, nil
		}))

	// Register a TOTP device.
	var otpKey string
	require.NoError(t, runAddMFADevice(ctx, client, proto.AddMFADeviceRequestInit_TOTP, "totp#1", authenticateFn,
		func(challenge *proto.MFARegisterChallenge) (*proto.MFARegisterResponse, error) {
			otpKey = challenge.GetTOTP().Secret
			code, err := totp.GenerateCode(otpKey, svr.Clock().Now())
			if err != nil {
				return nil, trace.Wrap(err)
			}
			return &proto.MFARegisterResponse{
				Response: &proto.MFARegisterResponse_TOTP{
					TOTP: &proto.TOTPRegisterResponse{
						Code: code,
					},
				},
			}, nil
		}))

	return &configureMFAResp{
		User:     username,
		Password: password,
		OTPKey:   otpKey,
		Device1:  dev1,
		Device2:  dev2,
	}
}

func runAddMFADevice(
	ctx context.Context, client *Client, devType proto.AddMFADeviceRequestInit_DeviceType, devName string,
	authenticate func(challenge *proto.MFAAuthenticateChallenge) (*proto.MFAAuthenticateResponse, error),
	register func(challenge *proto.MFARegisterChallenge) (*proto.MFARegisterResponse, error)) error {
	stream, err := client.AddMFADevice(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	// Step 1: initialize and get challenge.
	if err := stream.Send(&proto.AddMFADeviceRequest{
		Request: &proto.AddMFADeviceRequest_Init{
			Init: &proto.AddMFADeviceRequestInit{
				DeviceName: devName,
				Type:       devType,
			},
		},
	}); err != nil {
		return trace.Wrap(err)
	}
	resp, err := stream.Recv()
	if err != nil {
		return trace.Wrap(err)
	}

	// Step 2: authenticate.
	authResp, err := authenticate(resp.GetExistingMFAChallenge())
	if err != nil {
		return trace.Wrap(err)
	}
	if err := stream.Send(&proto.AddMFADeviceRequest{
		Request: &proto.AddMFADeviceRequest_ExistingMFAResponse{
			ExistingMFAResponse: authResp,
		},
	}); err != nil {
		return trace.Wrap(err)
	}
	resp, err = stream.Recv()
	if err != nil {
		return trace.Wrap(err)
	}

	// Step 3: register.
	registerResp, err := register(resp.GetNewMFARegisterChallenge())
	if err != nil {
		return trace.Wrap(err)
	}
	if err := stream.Send(&proto.AddMFADeviceRequest{
		Request: &proto.AddMFADeviceRequest_NewMFARegisterResponse{
			NewMFARegisterResponse: registerResp,
		},
	}); err != nil {
		return trace.Wrap(err)
	}
	_, err = stream.Recv()
	if err != nil {
		return trace.Wrap(err)
	}
	// OK, last response is an Ack.
	return nil
}
