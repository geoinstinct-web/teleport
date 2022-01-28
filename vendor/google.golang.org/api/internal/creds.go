// Copyright 2017 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"

	"golang.org/x/oauth2"
	"google.golang.org/api/internal/impersonate"

	"golang.org/x/oauth2/google"
)

// Creds returns credential information obtained from DialSettings, or if none, then
// it returns default credential information.
func Creds(ctx context.Context, ds *DialSettings) (*google.Credentials, error) {
	creds, err := baseCreds(ctx, ds)
	if err != nil {
		return nil, err
	}
	if ds.ImpersonationConfig != nil {
		return impersonateCredentials(ctx, creds, ds)
	}
	return creds, nil
}

func baseCreds(ctx context.Context, ds *DialSettings) (*google.Credentials, error) {
	if ds.InternalCredentials != nil {
		return ds.InternalCredentials, nil
	}
	if ds.Credentials != nil {
		return ds.Credentials, nil
	}
	if ds.CredentialsJSON != nil {
		return credentialsFromJSON(ctx, ds.CredentialsJSON, ds)
	}
	if ds.CredentialsFile != "" {
		data, err := ioutil.ReadFile(ds.CredentialsFile)
		if err != nil {
			return nil, fmt.Errorf("cannot read credentials file: %v", err)
		}
		return credentialsFromJSON(ctx, data, ds)
	}
	if ds.TokenSource != nil {
		return &google.Credentials{TokenSource: ds.TokenSource}, nil
	}
	cred, err := google.FindDefaultCredentials(ctx, ds.GetScopes()...)
	if err != nil {
		return nil, err
	}
	if len(cred.JSON) > 0 {
		return credentialsFromJSON(ctx, cred.JSON, ds)
	}
	// For GAE and GCE, the JSON is empty so return the default credentials directly.
	return cred, nil
}

// JSON key file type.
const (
	serviceAccountKey = "service_account"
)

// credentialsFromJSON returns a google.Credentials from the JSON data
//
// - A self-signed JWT flow will be executed if the following conditions are
// met:
//   (1) At least one of the following is true:
//       (a) No scope is provided
//       (b) Scope for self-signed JWT flow is enabled
//       (c) Audiences are explicitly provided by users
//   (2) No service account impersontation
//
// - Otherwise, executes standard OAuth 2.0 flow
// More details: google.aip.dev/auth/4111
func credentialsFromJSON(ctx context.Context, data []byte, ds *DialSettings) (*google.Credentials, error) {
	// By default, a standard OAuth 2.0 token source is created
	cred, err := google.CredentialsFromJSON(ctx, data, ds.GetScopes()...)
	if err != nil {
		return nil, err
	}

	// Override the token source to use self-signed JWT if conditions are met
	isJWTFlow, err := isSelfSignedJWTFlow(data, ds)
	if err != nil {
		return nil, err
	}
	if isJWTFlow {
		ts, err := selfSignedJWTTokenSource(data, ds)
		if err != nil {
			return nil, err
		}
		cred.TokenSource = ts
	}

	return cred, err
}

func isSelfSignedJWTFlow(data []byte, ds *DialSettings) (bool, error) {
	if (ds.EnableJwtWithScope || ds.HasCustomAudience()) &&
		ds.ImpersonationConfig == nil {
		// Check if JSON is a service account and if so create a self-signed JWT.
		var f struct {
			Type string `json:"type"`
			// The rest JSON fields are omitted because they are not used.
		}
		if err := json.Unmarshal(data, &f); err != nil {
			return false, err
		}
		return f.Type == serviceAccountKey, nil
	}
	return false, nil
}

func selfSignedJWTTokenSource(data []byte, ds *DialSettings) (oauth2.TokenSource, error) {
	if len(ds.GetScopes()) > 0 && !ds.HasCustomAudience() {
		// Scopes are preferred in self-signed JWT unless the scope is not available
		// or a custom audience is used.
		return google.JWTAccessTokenSourceWithScope(data, ds.GetScopes()...)
	} else if ds.GetAudience() != "" {
		// Fallback to audience if scope is not provided
		return google.JWTAccessTokenSourceFromJSON(data, ds.GetAudience())
	} else {
		return nil, errors.New("neither scopes or audience are available for the self-signed JWT")
	}
}

// QuotaProjectFromCreds returns the quota project from the JSON blob in the provided credentials.
//
// NOTE(cbro): consider promoting this to a field on google.Credentials.
func QuotaProjectFromCreds(cred *google.Credentials) string {
	var v struct {
		QuotaProject string `json:"quota_project_id"`
	}
	if err := json.Unmarshal(cred.JSON, &v); err != nil {
		return ""
	}
	return v.QuotaProject
}

func impersonateCredentials(ctx context.Context, creds *google.Credentials, ds *DialSettings) (*google.Credentials, error) {
	if len(ds.ImpersonationConfig.Scopes) == 0 {
		ds.ImpersonationConfig.Scopes = ds.GetScopes()
	}
	ts, err := impersonate.TokenSource(ctx, creds.TokenSource, ds.ImpersonationConfig)
	if err != nil {
		return nil, err
	}
	return &google.Credentials{
		TokenSource: ts,
		ProjectID:   creds.ProjectID,
	}, nil
}
