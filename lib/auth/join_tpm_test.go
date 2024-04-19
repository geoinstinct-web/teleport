/*
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package auth

import (
	"bytes"
	"context"
	"crypto/x509"
	"log/slog"
	"testing"
	"time"

	"github.com/google/go-attestation/attest"
	gocmp "github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/gravitational/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/client/proto"
	apifixtures "github.com/gravitational/teleport/api/fixtures"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/tpm"
)

type mockTPMValidator struct {
	lastCalledParams   tpm.ValidateParams
	returnErr          error
	returnValidatedTPM *tpm.ValidatedTPM
}

func (m *mockTPMValidator) setup(returns *tpm.ValidatedTPM, err error) {
	m.lastCalledParams = tpm.ValidateParams{}
	m.returnErr = err
	m.returnValidatedTPM = returns
}

func (m *mockTPMValidator) validate(
	_ context.Context, _ *slog.Logger, params tpm.ValidateParams,
) (*tpm.ValidatedTPM, error) {
	m.lastCalledParams = params

	solution, err := params.Solve(&attest.EncryptedCredential{
		Secret:     []byte("mock-secret"),
		Credential: []byte("mock-credential"),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if !bytes.Equal(solution, []byte("mock-solution")) {
		return nil, trace.AccessDenied("invalid solution")
	}

	return m.returnValidatedTPM, m.returnErr
}

func TestServer_RegisterUsingTPMMethod(t *testing.T) {
	ctx := context.Background()
	mockValidator := &mockTPMValidator{}
	p, err := newTestPack(ctx, t.TempDir(), func(server *Server) error {
		server.tpmValidator = mockValidator.validate
		return nil
	})
	require.NoError(t, err)
	auth := p.a

	sshPrivateKey, sshPublicKey, err := testauthority.New().GenerateKeyPair()
	require.NoError(t, err)
	tlsPublicKey, err := PrivateKeyToPublicKeyTLS(sshPrivateKey)
	require.NoError(t, err)

	attParams := &proto.TPMAttestationParameters{
		Public: []byte("mock-public"),
	}

	tokenSpec := func(mutate func(v2 *types.ProvisionTokenSpecV2)) types.ProvisionTokenSpecV2 {
		spec := types.ProvisionTokenSpecV2{
			JoinMethod: types.JoinMethodTPM,
			Roles:      []types.SystemRole{types.RoleNode},
			TPM: &types.ProvisionTokenSpecV2TPM{
				Allow: []*types.ProvisionTokenSpecV2TPM_Rule{
					{
						Description:  "ekpub only",
						EKPublicHash: "mock-ekpub-hashed",
					},
					{
						Description:         "ekcert only",
						EKCertificateSerial: "mock-ekcert-serial",
					},
					{
						Description:         "both",
						EKPublicHash:        "mock-ekpub-hashed-1",
						EKCertificateSerial: "mock-ekcert-serial-1",
					},
				},
			},
		}
		if mutate != nil {
			mutate(&spec)
		}
		return spec
	}
	joinRequest := func() *types.RegisterUsingTokenRequest {
		return &types.RegisterUsingTokenRequest{
			HostID:       "host-id",
			Role:         types.RoleNode,
			PublicTLSKey: tlsPublicKey,
			PublicSSHKey: sshPublicKey,
		}
	}

	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM([]byte(apifixtures.TLSCACertPEM)))

	allowRulesNotMatched := require.ErrorAssertionFunc(func(t require.TestingT, err error, i ...interface{}) {
		require.ErrorContains(t, err, "validated tpm attributes did not match any allow rules")
		require.True(t, trace.IsAccessDenied(err))
	})
	tests := []struct {
		name          string
		setEnterprise bool

		tokenSpec types.ProvisionTokenSpecV2

		validateReturnTPM *tpm.ValidatedTPM
		validateReturnErr error

		initReq    *proto.RegisterUsingTPMMethodInitialRequest
		wantParams tpm.ValidateParams

		assertError require.ErrorAssertionFunc
	}{
		{
			name:          "success, ekpub",
			setEnterprise: true,
			assertError:   require.NoError,

			initReq: &proto.RegisterUsingTPMMethodInitialRequest{
				JoinRequest: joinRequest(),
				Ek: &proto.RegisterUsingTPMMethodInitialRequest_EkKey{
					EkKey: []byte("mock-ekpub"),
				},
				AttestationParams: attParams,
			},
			tokenSpec: tokenSpec(nil),
			wantParams: tpm.ValidateParams{
				EKKey:        []byte("mock-ekpub"),
				AttestParams: tpm.AttestationParametersFromProto(attParams),
			},
			validateReturnTPM: &tpm.ValidatedTPM{
				EKPubHash: "mock-ekpub-hashed",
			},
		},
		{
			name:          "success, ekcert",
			setEnterprise: true,
			assertError:   require.NoError,

			initReq: &proto.RegisterUsingTPMMethodInitialRequest{
				JoinRequest: joinRequest(),
				Ek: &proto.RegisterUsingTPMMethodInitialRequest_EkCert{
					EkCert: []byte("mock-ekcert"),
				},
				AttestationParams: attParams,
			},
			tokenSpec: tokenSpec(func(v2 *types.ProvisionTokenSpecV2) {
				v2.TPM.EKCertAllowedCAs = []string{apifixtures.TLSCACertPEM}
			}),
			wantParams: tpm.ValidateParams{
				EKCert:       []byte("mock-ekcert"),
				AttestParams: tpm.AttestationParametersFromProto(attParams),
				AllowedCAs:   caPool,
			},
			validateReturnTPM: &tpm.ValidatedTPM{
				EKCertSerial:   "mock-ekcert-serial",
				EKCertVerified: true,
			},
		},
		{
			name:          "success, both ek cert serial and ek pub hash match",
			setEnterprise: true,
			assertError:   require.NoError,

			initReq: &proto.RegisterUsingTPMMethodInitialRequest{
				JoinRequest: joinRequest(),
				Ek: &proto.RegisterUsingTPMMethodInitialRequest_EkCert{
					EkCert: []byte("mock-ekcert"),
				},
				AttestationParams: attParams,
			},
			tokenSpec: tokenSpec(nil),
			wantParams: tpm.ValidateParams{
				EKCert:       []byte("mock-ekcert"),
				AttestParams: tpm.AttestationParametersFromProto(attParams),
			},
			validateReturnTPM: &tpm.ValidatedTPM{
				EKCertSerial:   "mock-ekcert-serial-1",
				EKPubHash:      "mock-ekpub-hashed-1",
				EKCertVerified: true,
			},
		},
		{
			name:          "failure, mismatched ekpub",
			setEnterprise: true,
			assertError:   allowRulesNotMatched,

			initReq: &proto.RegisterUsingTPMMethodInitialRequest{
				JoinRequest: joinRequest(),
				Ek: &proto.RegisterUsingTPMMethodInitialRequest_EkKey{
					EkKey: []byte("mock-ekpub"),
				},
				AttestationParams: attParams,
			},
			tokenSpec: tokenSpec(nil),
			wantParams: tpm.ValidateParams{
				EKKey:        []byte("mock-ekpub"),
				AttestParams: tpm.AttestationParametersFromProto(attParams),
			},
			validateReturnTPM: &tpm.ValidatedTPM{
				EKPubHash: "mock-ekpub-hashed-mismatched!",
			},
		},
		{
			name:          "failure, mismatched ekcert",
			setEnterprise: true,
			assertError:   allowRulesNotMatched,

			initReq: &proto.RegisterUsingTPMMethodInitialRequest{
				JoinRequest: joinRequest(),
				Ek: &proto.RegisterUsingTPMMethodInitialRequest_EkCert{
					EkCert: []byte("mock-ekcert"),
				},
				AttestationParams: attParams,
			},
			tokenSpec: tokenSpec(nil),
			wantParams: tpm.ValidateParams{
				EKCert:       []byte("mock-ekcert"),
				AttestParams: tpm.AttestationParametersFromProto(attParams),
			},
			validateReturnTPM: &tpm.ValidatedTPM{
				EKCertSerial: "mock-ekcert-serial-mismatched!",
			},
		},
		{
			name:          "failure, verification",
			setEnterprise: true,
			assertError: func(t require.TestingT, err error, i ...interface{}) {
				assert.ErrorContains(t, err, "capacitor overcharged")
			},

			initReq: &proto.RegisterUsingTPMMethodInitialRequest{
				JoinRequest: joinRequest(),
				Ek: &proto.RegisterUsingTPMMethodInitialRequest_EkCert{
					EkCert: []byte("mock-ekcert"),
				},
				AttestationParams: attParams,
			},
			tokenSpec: tokenSpec(nil),
			wantParams: tpm.ValidateParams{
				EKCert:       []byte("mock-ekcert"),
				AttestParams: tpm.AttestationParametersFromProto(attParams),
			},
			validateReturnTPM: &tpm.ValidatedTPM{
				EKCertSerial: "mock-ekcert-serial",
			},
			validateReturnErr: trace.AccessDenied("capacitor overcharged"),
		},
		{
			name: "failure, no enterprise",
			assertError: func(t require.TestingT, err error, i ...interface{}) {
				assert.ErrorContains(t, err, "tpm joining requires Teleport Enterprise")
			},
			initReq: &proto.RegisterUsingTPMMethodInitialRequest{
				JoinRequest: joinRequest(),
				Ek: &proto.RegisterUsingTPMMethodInitialRequest_EkCert{
					EkCert: []byte("mock-ekcert"),
				},
				AttestationParams: attParams,
			},
			tokenSpec: tokenSpec(nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockValidator.setup(tt.validateReturnTPM, tt.validateReturnErr)
			if tt.setEnterprise {
				modules.SetTestModules(
					t,
					&modules.TestModules{TestBuildType: modules.BuildEnterprise},
				)
			}

			token, err := types.NewProvisionTokenFromSpec(
				tt.name, time.Now().Add(time.Minute), tt.tokenSpec,
			)
			require.NoError(t, err)
			require.NoError(t, auth.CreateToken(ctx, token))
			tt.initReq.JoinRequest.Token = tt.name

			solver := func(ec *proto.TPMEncryptedCredential) (
				*proto.RegisterUsingTPMMethodChallengeResponse, error,
			) {
				assert.Equal(t, []byte("mock-secret"), ec.Secret)
				assert.Equal(t, []byte("mock-credential"), ec.CredentialBlob)
				return &proto.RegisterUsingTPMMethodChallengeResponse{
					Solution: []byte("mock-solution"),
				}, nil
			}

			_, err = auth.registerUsingTPMMethod(
				ctx,
				tt.initReq,
				solver)
			tt.assertError(t, err)

			assert.Empty(t,
				gocmp.Diff(
					tt.wantParams,
					mockValidator.lastCalledParams,
					cmpopts.IgnoreFields(tpm.ValidateParams{}, "Solve"),
				),
			)
		})
	}
}
