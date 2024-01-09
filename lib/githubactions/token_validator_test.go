/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
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

package githubactions

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
)

type fakeIDP struct {
	t             *testing.T
	signer        jose.Signer
	privateKey    *rsa.PrivateKey
	server        *httptest.Server
	entepriseSlug string
	ghesMode      bool
}

func newFakeIDP(t *testing.T, ghesMode bool, enterpriseSlug string) *fakeIDP {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)

	f := &fakeIDP{
		signer:        signer,
		ghesMode:      ghesMode,
		privateKey:    privateKey,
		t:             t,
		entepriseSlug: enterpriseSlug,
	}

	providerMux := http.NewServeMux()
	providerMux.HandleFunc(
		f.pathPostfix()+"/.well-known/openid-configuration",
		f.handleOpenIDConfig,
	)
	providerMux.HandleFunc(
		f.pathPostfix()+"/.well-known/jwks",
		f.handleJWKSEndpoint,
	)

	srv := httptest.NewServer(providerMux)
	t.Cleanup(srv.Close)
	f.server = srv
	return f
}

func (f *fakeIDP) pathPostfix() string {
	if f.ghesMode {
		// GHES instances serve the token related content on a prefix of the
		// instance hostname.
		return "/_services/token"
	}
	if f.entepriseSlug != "" {
		return "/" + f.entepriseSlug
	}
	return ""
}

func (f *fakeIDP) issuer() string {
	return f.server.URL + f.pathPostfix()
}

func (f *fakeIDP) handleOpenIDConfig(w http.ResponseWriter, r *http.Request) {
	// mimic https://token.actions.githubusercontent.com/.well-known/openid-configuration
	response := map[string]interface{}{
		"claims_supported": []string{
			"sub",
			"aud",
			"exp",
			"iat",
			"iss",
			"jti",
			"nbf",
			"ref",
			"repository",
			"repository_id",
			"repository_owner",
			"repository_owner_id",
			"run_id",
			"run_number",
			"run_attempt",
			"actor",
			"actor_id",
			"workflow",
			"head_ref",
			"base_ref",
			"event_name",
			"ref_type",
			"environment",
			"job_workflow_ref",
			"repository_visibility",
		},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"issuer":                                f.issuer(),
		"jwks_uri":                              f.issuer() + "/.well-known/jwks",
		"response_types_supported":              []string{"id_token"},
		"scopes_supported":                      []string{"openid"},
		"subject_types_supported":               []string{"public", "pairwise"},
	}
	responseBytes, err := json.Marshal(response)
	require.NoError(f.t, err)
	_, err = w.Write(responseBytes)
	require.NoError(f.t, err)
}

func (f *fakeIDP) handleJWKSEndpoint(w http.ResponseWriter, r *http.Request) {
	// mimic https://token.actions.githubusercontent.com/.well-known/jwks
	// but with our own keys
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key: &f.privateKey.PublicKey,
			},
		},
	}
	responseBytes, err := json.Marshal(jwks)
	require.NoError(f.t, err)
	_, err = w.Write(responseBytes)
	require.NoError(f.t, err)
}

func (f *fakeIDP) issueToken(
	t *testing.T,
	issuer,
	audience,
	actor,
	sub string,
	issuedAt time.Time,
	expiry time.Time,
) string {
	stdClaims := jwt.Claims{
		Issuer:    issuer,
		Subject:   sub,
		Audience:  jwt.Audience{audience},
		IssuedAt:  jwt.NewNumericDate(issuedAt),
		NotBefore: jwt.NewNumericDate(issuedAt),
		Expiry:    jwt.NewNumericDate(expiry),
	}
	customClaims := map[string]interface{}{
		"actor": actor,
	}
	token, err := jwt.Signed(f.signer).
		Claims(stdClaims).
		Claims(customClaims).
		CompactSerialize()
	require.NoError(t, err)

	return token
}

func TestIDTokenValidator_Validate(t *testing.T) {
	t.Parallel()
	idp := newFakeIDP(t, false, "")
	ghesIdp := newFakeIDP(t, true, "")
	enterpriseSlugIDP := newFakeIDP(t, false, "slug")

	tests := []struct {
		name           string
		assertError    require.ErrorAssertionFunc
		want           *IDTokenClaims
		token          string
		ghesHost       string
		defaultIDPHost string
		enterpriseSlug string
	}{
		{
			name:           "success",
			assertError:    require.NoError,
			defaultIDPHost: idp.server.Listener.Addr().String(),
			token: idp.issueToken(
				t,
				idp.issuer(),
				"teleport.cluster.local",
				"octocat",
				"repo:octo-org/octo-repo:environment:prod",
				time.Now().Add(-5*time.Minute),
				time.Now().Add(5*time.Minute),
			),
			want: &IDTokenClaims{
				Actor: "octocat",
				Sub:   "repo:octo-org/octo-repo:environment:prod",
			},
		},
		{
			name:        "success with ghes",
			assertError: require.NoError,
			// This is intentionally the plain IDP as the GHES Host should
			// override it.
			defaultIDPHost: idp.server.Listener.Addr().String(),
			token: ghesIdp.issueToken(
				t,
				ghesIdp.issuer(),
				"teleport.cluster.local",
				"octocat",
				"repo:octo-org/octo-repo:environment:prod",
				time.Now().Add(-5*time.Minute),
				time.Now().Add(5*time.Minute),
			),
			want: &IDTokenClaims{
				Actor: "octocat",
				Sub:   "repo:octo-org/octo-repo:environment:prod",
			},
			ghesHost: ghesIdp.server.Listener.Addr().String(),
		},
		{
			name:           "success with slug",
			assertError:    require.NoError,
			defaultIDPHost: enterpriseSlugIDP.server.Listener.Addr().String(),
			token: enterpriseSlugIDP.issueToken(
				t,
				enterpriseSlugIDP.issuer(),
				"teleport.cluster.local",
				"octocat",
				"repo:octo-org/octo-repo:environment:prod",
				time.Now().Add(-5*time.Minute),
				time.Now().Add(5*time.Minute),
			),
			enterpriseSlug: "slug",
			want: &IDTokenClaims{
				Actor: "octocat",
				Sub:   "repo:octo-org/octo-repo:environment:prod",
			},
		},
		{
			name:           "fails if slugged jwt is used with non-slug idp",
			assertError:    require.Error,
			defaultIDPHost: idp.server.Listener.Addr().String(),
			token: enterpriseSlugIDP.issueToken(
				t,
				enterpriseSlugIDP.issuer(),
				"teleport.cluster.local",
				"octocat",
				"repo:octo-org/octo-repo:environment:prod",
				time.Now().Add(-5*time.Minute),
				time.Now().Add(5*time.Minute),
			),
		},
		{
			name:           "fails if non-slugged jwt is used with idp",
			assertError:    require.Error,
			defaultIDPHost: enterpriseSlugIDP.server.Listener.Addr().String(),
			token: idp.issueToken(
				t,
				idp.issuer(),
				"teleport.cluster.local",
				"octocat",
				"repo:octo-org/octo-repo:environment:prod",
				time.Now().Add(-5*time.Minute),
				time.Now().Add(5*time.Minute),
			),
			enterpriseSlug: "slug",
		},
		{
			name:           "expired",
			assertError:    require.Error,
			defaultIDPHost: idp.server.Listener.Addr().String(),
			token: idp.issueToken(
				t,
				idp.issuer(),
				"teleport.cluster.local",
				"octocat",
				"repo:octo-org/octo-repo:environment:prod",
				time.Now().Add(-15*time.Minute),
				time.Now().Add(-5*time.Minute),
			),
		},
		{
			name:           "future",
			assertError:    require.Error,
			defaultIDPHost: idp.server.Listener.Addr().String(),
			token: idp.issueToken(
				t,
				idp.issuer(),
				"teleport.cluster.local",
				"octocat",
				"repo:octo-org/octo-repo:environment:prod",
				time.Now().Add(10*time.Minute), time.Now().Add(20*time.Minute)),
		},
		{
			name:           "invalid audience",
			assertError:    require.Error,
			defaultIDPHost: idp.server.Listener.Addr().String(),
			token: idp.issueToken(
				t,
				idp.issuer(),
				"incorrect.audience",
				"octocat",
				"repo:octo-org/octo-repo:environment:prod",
				time.Now().Add(-5*time.Minute), time.Now().Add(5*time.Minute)),
		},
		{
			name:           "invalid issuer",
			assertError:    require.Error,
			defaultIDPHost: idp.server.Listener.Addr().String(),
			token: idp.issueToken(
				t,
				"https://the.wrong.issuer",
				"teleport.cluster.local",
				"octocat",
				"repo:octo-org/octo-repo:environment:prod",
				time.Now().Add(-5*time.Minute), time.Now().Add(5*time.Minute)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			v := NewIDTokenValidator(IDTokenValidatorConfig{
				Clock:            clockwork.NewRealClock(),
				GitHubIssuerHost: tt.defaultIDPHost,
				insecure:         true,
			})

			claims, err := v.Validate(
				ctx, tt.ghesHost, tt.enterpriseSlug, tt.token,
			)
			tt.assertError(t, err)
			require.Equal(t, tt.want, claims)
		})
	}
}
