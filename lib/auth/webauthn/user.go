/*
Copyright 2021 Gravitational, Inc.

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

package webauthn

import (
	"context"

	"github.com/google/uuid"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"

	wan "github.com/duo-labs/webauthn/webauthn"
)

// userIDStorage is used to keep getOrCreateUserWebauthnID as focused as
// possible, since it's used both by login and registration.
type userIDStorage interface {
	UpsertWebauthnLocalAuth(ctx context.Context, user string, wla *types.WebauthnLocalAuth) error
	GetWebauthnLocalAuth(ctx context.Context, user string) (*types.WebauthnLocalAuth, error)
}

func getOrCreateUserWebauthnID(ctx context.Context, user string, identity userIDStorage) ([]byte, error) {
	wla, err := identity.GetWebauthnLocalAuth(ctx, user)
	switch {
	case trace.IsNotFound(err): // first-time user, create a new ID
		webID := uuid.New()
		err := identity.UpsertWebauthnLocalAuth(ctx, user, &types.WebauthnLocalAuth{
			UserID: webID[:],
		})
		return webID[:], trace.Wrap(err)
	case err != nil:
		return nil, trace.Wrap(err)
	default:
		return wla.UserID, nil
	}
}

// webUser implements a WebAuthn protocol user.
// It is used to provide user information to WebAuthn APIs, but has no direct
// counterpart in storage nor in other packages.
type webUser struct {
	credentials []wan.Credential
	name        string
	webID       []byte
}

func newWebUser(name string, webID []byte, credentialIDOnly bool, devices []*types.MFADevice) *webUser {
	var credentials []wan.Credential
	for _, dev := range devices {
		c, ok := deviceToCredential(dev, credentialIDOnly)
		if ok {
			credentials = append(credentials, c)
		}
	}
	return &webUser{
		credentials: credentials,
		name:        name,
		webID:       webID,
	}
}

func (w *webUser) WebAuthnID() []byte {
	return w.webID
}

func (w *webUser) WebAuthnName() string {
	return w.name
}

func (w *webUser) WebAuthnDisplayName() string {
	return w.name
}

func (w *webUser) WebAuthnIcon() string {
	return ""
}

func (w *webUser) WebAuthnCredentials() []wan.Credential {
	return w.credentials
}
