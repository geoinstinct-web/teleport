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
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNewSAMLIdPServiceProvider ensures a valid SAML IdP service provider.
func TestNewSAMLIdPServiceProvider(t *testing.T) {
	tests := []struct {
		name             string
		entityDescriptor string
		entityID         string
		acsURL           string
		errAssertion     require.ErrorAssertionFunc
		expectedEntityID string
		attributeMapping []*SAMLAttributeMapping
	}{
		{
			name:             "valid entity descriptor",
			entityDescriptor: testEntityDescriptor,
			entityID:         "IAMShowcase",
			errAssertion:     require.NoError,
			expectedEntityID: "IAMShowcase",
		},
		{
			// This validates that parse is not called when the entity ID is set.
			name:             "invalid entity descriptor with valid entity ID",
			entityDescriptor: "invalid XML",
			entityID:         "IAMShowcase",
			errAssertion:     require.NoError,
			expectedEntityID: "IAMShowcase",
		},
		{
			name:             "empty entity descriptor, entity ID and ACS URL",
			entityDescriptor: "",
			errAssertion:     require.Error,
		},
		{
			name:             "empty entity ID",
			entityDescriptor: testEntityDescriptor,
			errAssertion:     require.NoError,
			expectedEntityID: "IAMShowcase",
		},
		{
			name:             "empty entity descriptor and entity ID",
			entityDescriptor: "",
			acsURL:           "https:/test.com/acs",
			errAssertion: func(t require.TestingT, err error, i ...interface{}) {
				require.ErrorIs(t, err, ErrEmptyEntityDescriptorAndEntityID)
			},
		},
		{
			name:             "empty entity descriptor and ACS URL",
			entityDescriptor: "",
			entityID:         "IAMShowcase",
			errAssertion: func(t require.TestingT, err error, i ...interface{}) {
				require.ErrorIs(t, err, ErrEmptyEntityDescriptorAndACSURL)
			},
		},
		{
			name:             "empty entity descriptor with entity ID and ACS URL",
			entityDescriptor: "",
			entityID:         "IAMShowcase",
			acsURL:           "https:/test.com/acs",
			errAssertion:     require.NoError,
			expectedEntityID: "IAMShowcase",
		},
		{
			name:             "duplicate attribute mapping",
			entityDescriptor: testEntityDescriptor,
			attributeMapping: []*SAMLAttributeMapping{
				{
					Name:  "username",
					Value: "user.tratis.name",
				},
				{
					Name:  "user1",
					Value: "user.tratis.firstname",
				},
				{
					Name:  "username",
					Value: "user.tratis.givenname",
				},
			},
			errAssertion: func(t require.TestingT, err error, i ...interface{}) {
				require.ErrorIs(t, err, ErrDuplicateAttributeName)
			},
		},
		{
			name:             "valid attribute mapping",
			entityDescriptor: testEntityDescriptor,
			entityID:         "IAMShowcase",
			expectedEntityID: "IAMShowcase",
			attributeMapping: []*SAMLAttributeMapping{
				{
					Name:  "username",
					Value: "user.tratis.name",
				},
				{
					Name:  "user1",
					Value: "user.tratis.givenname",
				},
			},
			errAssertion: require.NoError,
		},
		{
			name:             "invalid attribute mapping name format",
			entityDescriptor: testEntityDescriptor,
			entityID:         "IAMShowcase",
			expectedEntityID: "IAMShowcase",
			attributeMapping: []*SAMLAttributeMapping{
				{
					Name:       "username",
					Value:      "user.tratis.name",
					NameFormat: "emailAddress",
				},
				{
					Name:  "user1",
					Value: "user.tratis.givenname",
				},
			},
			errAssertion: func(t require.TestingT, err error, i ...interface{}) {
				require.ErrorContains(t, err, "invalid name format")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sp, err := NewSAMLIdPServiceProvider(Metadata{
				Name: "test",
			}, SAMLIdPServiceProviderSpecV1{
				EntityDescriptor: test.entityDescriptor,
				EntityID:         test.entityID,
				ACSURL:           test.acsURL,
				AttributeMapping: test.attributeMapping,
			})

			test.errAssertion(t, err)
			if sp != nil {
				require.Equal(t, test.expectedEntityID, sp.GetEntityID())
				if len(sp.GetAttributeMapping()) > 0 {
					require.Equal(t, test.attributeMapping, sp.GetAttributeMapping())
				}
			}
		})
	}
}

// A test entity descriptor from https://sptest.iamshowcase.com/testsp_metadata.xml.
const testEntityDescriptor = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="IAMShowcase" validUntil="2025-12-09T09:13:31.006Z">
   <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
      <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
      <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sptest.iamshowcase.com/acs" index="0" isDefault="true"/>
   </md:SPSSODescriptor>
</md:EntityDescriptor>
`
