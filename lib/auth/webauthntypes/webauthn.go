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

package webauthntypes

import (
	"encoding/base64"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/gravitational/trace"
)

// CredentialAssertion is the payload sent to authenticators to initiate login.
type CredentialAssertion struct {
	Response PublicKeyCredentialRequestOptions `json:"publicKey"`
}

// PublicKeyCredentialRequestOptions is a clone of
// [protocol.PublicKeyCredentialRequestOptions], materialized here to keep a
// stable JSON marshal/unmarshal representation.
type PublicKeyCredentialRequestOptions struct {
	Challenge          Challenge                            `json:"challenge"`
	Timeout            int                                  `json:"timeout,omitempty"`
	RelyingPartyID     string                               `json:"rpId,omitempty"`
	AllowedCredentials []CredentialDescriptor               `json:"allowCredentials,omitempty"`
	UserVerification   protocol.UserVerificationRequirement `json:"userVerification,omitempty"` // Default is "preferred"
	Extensions         AuthenticationExtensions             `json:"extensions,omitempty"`
}

func (a *PublicKeyCredentialRequestOptions) GetAllowedCredentialIDs() [][]byte {
	var allowedCredentialIDs = make([][]byte, len(a.AllowedCredentials))
	for i, credential := range a.AllowedCredentials {
		allowedCredentialIDs[i] = credential.CredentialID
	}
	return allowedCredentialIDs
}

// Validate performs client-side validation of CredentialAssertion.
// It makes sure that data are valid and can be sent to authenticator.
// This is general purpose validation and authenticator should add its own
// on top of it, if necessary.
func (ca *CredentialAssertion) Validate() error {
	switch {
	case ca == nil:
		return trace.BadParameter("credential assertion required")
	case len(ca.Response.Challenge) == 0:
		return trace.BadParameter("credential assertion challenge required")
	case ca.Response.RelyingPartyID == "":
		return trace.BadParameter("credential assertion relying party ID required")
	}
	return nil
}

// CredentialAssertionFromProtocol converts a [protocol.CredentialAssertion] to
// a [CredentialAssertion].
func CredentialAssertionFromProtocol(a *protocol.CredentialAssertion) *CredentialAssertion {
	if a == nil {
		return nil
	}

	return &CredentialAssertion{
		Response: PublicKeyCredentialRequestOptions{
			Challenge:          Challenge(a.Response.Challenge),
			Timeout:            a.Response.Timeout,
			RelyingPartyID:     a.Response.RelyingPartyID,
			AllowedCredentials: credentialDescriptorsFromProtocol(a.Response.AllowedCredentials),
			UserVerification:   a.Response.UserVerification,
			Extensions:         a.Response.Extensions,
		},
	}
}

func credentialDescriptorsFromProtocol(cs []protocol.CredentialDescriptor) []CredentialDescriptor {
	if len(cs) == 0 {
		return nil
	}

	res := make([]CredentialDescriptor, len(cs))
	for i, c := range cs {
		res[i] = CredentialDescriptor{
			Type:            c.Type,
			CredentialID:    c.CredentialID,
			Transport:       c.Transport,
			AttestationType: c.AttestationType,
		}
	}
	return res
}

// CredentialAssertionResponse is the reply from authenticators to complete
// login.
type CredentialAssertionResponse struct {
	// CredentialAssertionResponse is redefined because, unlike
	// CredentialAssertion, it is likely to be manually created by package users.
	// Redefining allows us to 1) make sure it can be properly JSON-marshaled
	// (protocol.CredentialAssertionResponse.Extensions can't) and 2) we avoid
	// leaking the duo-labs/webauthn dependency.
	// The nesting of types is identical to protocol.CredentialAssertionResponse.

	PublicKeyCredential
	AssertionResponse AuthenticatorAssertionResponse `json:"response"`
}

// AuthenticatorAssertionResponse is a clone of
// [protocol.AuthenticatorAssertionResponse], materialized here to keep a
// stable JSON marshal/unmarshal representation.
type AuthenticatorAssertionResponse struct {
	AuthenticatorResponse
	AuthenticatorData protocol.URLEncodedBase64 `json:"authenticatorData"`
	Signature         protocol.URLEncodedBase64 `json:"signature"`
	UserHandle        protocol.URLEncodedBase64 `json:"userHandle,omitempty"`
}

// AuthenticatorResponse is a clone of [protocol.AuthenticatorResponse],
// materialized here to keep a stable JSON marshal/unmarshal representation.
type AuthenticatorResponse protocol.AuthenticatorResponse

// CredentialCreation is the payload sent to authenticators to initiate
// registration.
type CredentialCreation struct {
	Response PublicKeyCredentialCreationOptions `json:"publicKey"`
}

// PublicKeyCredentialCreationOptions is a clone of
// [protocol.PublicKeyCredentialCreationOptions], materialized here to keep a
// stable JSON marshal/unmarshal representation.
type PublicKeyCredentialCreationOptions struct {
	Challenge              Challenge                     `json:"challenge"`
	RelyingParty           RelyingPartyEntity            `json:"rp"`
	User                   UserEntity                    `json:"user"`
	Parameters             []CredentialParameter         `json:"pubKeyCredParams,omitempty"`
	AuthenticatorSelection AuthenticatorSelection        `json:"authenticatorSelection,omitempty"`
	Timeout                int                           `json:"timeout,omitempty"`
	CredentialExcludeList  []CredentialDescriptor        `json:"excludeCredentials,omitempty"`
	Extensions             AuthenticationExtensions      `json:"extensions,omitempty"`
	Attestation            protocol.ConveyancePreference `json:"attestation,omitempty"`
}

// RelyingPartyEntity is a clone of [protocol.RelyingPartyEntity], materialized
// here to keep a stable JSON marshal/unmarshal representation.
type RelyingPartyEntity struct {
	CredentialEntity
	ID string `json:"id"`
}

// UserEntity is a clone of [protocol.UserEntity], materialized here to keep a
// stable JSON marshal/unmarshal representation.
type UserEntity struct {
	CredentialEntity
	DisplayName string `json:"displayName,omitempty"`
	ID          []byte `json:"id"`
}

// CredentialEntity is a clone of [protocol.CredentialEntity], materialized here
// to keep a stable JSON marshal/unmarshal representation.
type CredentialEntity = protocol.CredentialEntity

// CredentialParameter is a clone of
// [protocol.CredentialParameter], materialized here to keep a stable JSON
// marshal/unmarshal representation.
type CredentialParameter struct {
	Type      protocol.CredentialType              `json:"type"`
	Algorithm webauthncose.COSEAlgorithmIdentifier `json:"alg"`
}

// AuthenticatorSelection is a clone of
// [protocol.AuthenticatorSelection], materialized here to keep a stable JSON
// marshal/unmarshal representation.
type AuthenticatorSelection struct {
	AuthenticatorAttachment protocol.AuthenticatorAttachment     `json:"authenticatorAttachment,omitempty"`
	RequireResidentKey      *bool                                `json:"requireResidentKey,omitempty"`
	ResidentKey             protocol.ResidentKeyRequirement      `json:"residentKey,omitempty"`
	UserVerification        protocol.UserVerificationRequirement `json:"userVerification,omitempty"`
}

// AuthenticationExtensions is a clone of [protocol.AuthenticationExtensions],
// materialized here to keep a stable JSON marshal/unmarshal representation.
type AuthenticationExtensions = protocol.AuthenticationExtensions

// RequireResidentKey returns information whether resident key is required or
// not. It checks ResidentKey and fallbacks to RequireResidentKey.
func (cc *CredentialCreation) RequireResidentKey() (bool, error) {
	as := cc.Response.AuthenticatorSelection
	switch as.ResidentKey {
	case protocol.ResidentKeyRequirementRequired:
		if as.RequireResidentKey != nil && !*as.RequireResidentKey {
			return false, trace.BadParameter("invalid combination of ResidentKey: %v and RequireResidentKey: %v", as.ResidentKey, *as.RequireResidentKey)
		}
		return true, nil
	case protocol.ResidentKeyRequirementDiscouraged:
		if as.RequireResidentKey != nil && *as.RequireResidentKey {
			return false, trace.BadParameter("invalid combination of ResidentKey: %v and RequireResidentKey: %v", as.ResidentKey, *as.RequireResidentKey)
		}
		return false, nil
	case protocol.ResidentKeyRequirementPreferred:
		return false, nil
	}
	// If ResidentKey is not set, then fallback to the legacy RequireResidentKey
	// field.
	return as.RequireResidentKey != nil && *as.RequireResidentKey, nil
}

// Validate performs client-side validation of CredentialCreation.
// It makes sure that data are valid and can be sent to authenticator.
// This is general purpose validation and authenticator should add its own
// on top of it, if necessary.
func (cc *CredentialCreation) Validate() error {
	switch {
	case cc == nil:
		return trace.BadParameter("credential creation required")
	case len(cc.Response.Challenge) == 0:
		return trace.BadParameter("credential creation challenge required")
	case cc.Response.RelyingParty.ID == "":
		return trace.BadParameter("credential creation relying party ID required")
	case len(cc.Response.RelyingParty.Name) == 0:
		return trace.BadParameter("relying party name required")
	case len(cc.Response.User.Name) == 0:
		return trace.BadParameter("user name required")
	case len(cc.Response.User.DisplayName) == 0:
		return trace.BadParameter("user display name required")
	case len(cc.Response.User.ID) == 0:
		return trace.BadParameter("user ID required")
	default:
		return nil
	}
}

// CredentialCreationFromProtocol converts a [protocol.CredentialCreation] to a
// [CredentialCreation].
func CredentialCreationFromProtocol(cc *protocol.CredentialCreation) *CredentialCreation {
	if cc == nil {
		return nil
	}

	return &CredentialCreation{
		Response: PublicKeyCredentialCreationOptions{
			Challenge: Challenge(cc.Response.Challenge),
			RelyingParty: RelyingPartyEntity{
				CredentialEntity: cc.Response.RelyingParty.CredentialEntity,
				ID:               cc.Response.RelyingParty.ID,
			},
			User: UserEntity{
				CredentialEntity: cc.Response.User.CredentialEntity,
				DisplayName:      cc.Response.User.Name,
				ID:               cc.Response.User.ID,
			},
			Parameters: credentialParametersFromProtocol(cc.Response.Parameters),
			AuthenticatorSelection: AuthenticatorSelection{
				AuthenticatorAttachment: cc.Response.AuthenticatorSelection.AuthenticatorAttachment,
				RequireResidentKey:      cc.Response.AuthenticatorSelection.RequireResidentKey,
				ResidentKey:             cc.Response.AuthenticatorSelection.ResidentKey,
				UserVerification:        cc.Response.AuthenticatorSelection.UserVerification,
			},
			Timeout:               cc.Response.Timeout,
			CredentialExcludeList: credentialDescriptorsFromProtocol(cc.Response.CredentialExcludeList),
			Extensions:            cc.Response.Extensions,
			Attestation:           cc.Response.Attestation,
		},
	}
}

func credentialParametersFromProtocol(ps []protocol.CredentialParameter) []CredentialParameter {
	if len(ps) == 0 {
		return nil
	}

	res := make([]CredentialParameter, len(ps))
	for i, p := range ps {
		res[i] = CredentialParameter{
			Type:      p.Type,
			Algorithm: p.Algorithm,
		}
	}
	return res
}

// CredentialCreationResponse is the reply from authenticators to complete
// registration.
type CredentialCreationResponse struct {
	// CredentialCreationResponse is manually redefined, instead of directly based
	// in protocol.CredentialCreationResponse, for the same reasoning that
	// CredentialAssertionResponse is - in short, we want a clean package.
	// The nesting of types is identical to protocol.CredentialCreationResponse.

	PublicKeyCredential
	AttestationResponse AuthenticatorAttestationResponse `json:"response"`
}

// AuthenticatorAttestationResponse is a clone of
// [protocol.AuthenticatorAttestationResponse], materialized here to keep a
// stable JSON marshal/unmarshal representation.
type AuthenticatorAttestationResponse struct {
	AuthenticatorResponse
	AttestationObject protocol.URLEncodedBase64 `json:"attestationObject"`

	// Added by go-webauthn/webauthn v0.7.2.
	// Transports []string `json:"transports,omitempty"`
}

// Challenge represents a WebAuthn challenge.
// It is used instead of [protocol.URLEncodedBase64] so its JSON
// marshal/unmarshal representation won't change in relation to older Teleport
// versions.
type Challenge []byte

func CreateChallenge() (Challenge, error) {
	chal, err := protocol.CreateChallenge()
	if err != nil {
		return nil, err
	}
	return Challenge(chal), nil
}

func (c Challenge) String() string {
	return base64.RawURLEncoding.EncodeToString(c)
}

// CredentialDescriptor is a clone of [protocol.CredentialDescriptor],
// materialized here to keep a stable JSON marshal/unmarshal representation.
type CredentialDescriptor struct {
	Type            protocol.CredentialType           `json:"type"`
	CredentialID    []byte                            `json:"id"`
	Transport       []protocol.AuthenticatorTransport `json:"transports,omitempty"`
	AttestationType string                            `json:"-"`
}

// PublicKeyCredential is a clone of [protocol.PublicKeyCredential],
// materialized here to keep a stable JSON marshal/unmarshal representation.
type PublicKeyCredential struct {
	Credential
	RawID      protocol.URLEncodedBase64              `json:"rawId"`
	Extensions *AuthenticationExtensionsClientOutputs `json:"extensions,omitempty"`

	// Added by go-webauthn/webauthn v0.7.2.
	// AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
}

// Credential is a clone of [protocol.Credential], materialized here to keep a
// stable JSON marshal/unmarshal representation.
type Credential protocol.Credential

// AuthenticationExtensionsClientOutputs is a clone of
// [protocol.AuthenticationExtensionsClientOutputs], materialized here to keep a
// stable JSON marshal/unmarshal representation.
type AuthenticationExtensionsClientOutputs struct {
	AppID bool `json:"appid,omitempty"`
}
