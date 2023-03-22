/*
Copyright 2023 Gravitational, Inc.

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

package types

import (
	"time"

	"github.com/gravitational/trace"
)

// NewHeadlessAuthenticationStub creates a new headless authentication stub, which is
// a headless authentication resource with limited data. This stub is used to initiate
// headless login.
func NewHeadlessAuthenticationStub(name string, expires time.Time) (*HeadlessAuthentication, error) {
	ha := &HeadlessAuthentication{
		ResourceHeader: ResourceHeader{
			Metadata: Metadata{
				Name:    name,
				Expires: &expires,
			},
		},
	}
	return ha, ha.CheckAndSetDefaults()
}

// CheckAndSetDefaults does basic validation and default setting.
func (h *HeadlessAuthentication) CheckAndSetDefaults() error {
	h.setStaticFields()
	if err := h.Metadata.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	if h.Metadata.Expires == nil || h.Metadata.Expires.IsZero() {
		return trace.BadParameter("headless authentication resource must have non-zero header.metadata.expires")
	}

	if h.Version == "" {
		h.Version = V1
	}
	if h.State == HeadlessAuthenticationState_HEADLESS_AUTHENTICATION_STATE_UNSPECIFIED {
		h.State = HeadlessAuthenticationState_HEADLESS_AUTHENTICATION_STATE_PENDING
	}

	return nil
}

// setStaticFields sets static resource header and metadata fields.
func (h *HeadlessAuthentication) setStaticFields() {
	h.Kind = KindHeadlessAuthentication
}

// Stringify returns the readable string for a headless authentication state.
func (h HeadlessAuthenticationState) Stringify() string {
	switch h {
	case HeadlessAuthenticationState_HEADLESS_AUTHENTICATION_STATE_PENDING:
		return "pending"
	case HeadlessAuthenticationState_HEADLESS_AUTHENTICATION_STATE_DENIED:
		return "denied"
	case HeadlessAuthenticationState_HEADLESS_AUTHENTICATION_STATE_APPROVED:
		return "approved"
	default:
		return "unknown"
	}
}
