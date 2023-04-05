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
	"encoding/json"
	"fmt"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/utils"
)

const (
	// IntegrationSubKindAWSOIDC is an integration with AWS that uses OpenID Connect as an Identity Provider.
	IntegrationSubKindAWSOIDC = "aws-oidc"
)

// Integration specifies is a connection configuration between Teleport and a 3rd party system.
type Integration interface {
	ResourceWithLabels

	// GetAWSOIDCIntegrationSpec returns the `aws-oidc` spec fields.
	GetAWSOIDCIntegrationSpec() *AWSOIDCIntegrationSpecV1
	// SetAWSOIDCIntegrationSpec sets the `aws-oidc` spec fields.
	SetAWSOIDCIntegrationSpec(*AWSOIDCIntegrationSpecV1)
}

var _ ResourceWithLabels = (*IntegrationV1)(nil)

// NewIntegrationAWSOIDC returns a new `aws-oidc` subkind Integration
func NewIntegrationAWSOIDC(md Metadata, spec *AWSOIDCIntegrationSpecV1) (*IntegrationV1, error) {
	ig := &IntegrationV1{
		ResourceHeader: ResourceHeader{
			Metadata: md,
			Kind:     KindIntegration,
			Version:  V1,
			SubKind:  IntegrationSubKindAWSOIDC,
		},
		Spec: IntegrationSpecV1{
			SubKindSpec: &IntegrationSpecV1_AWSOIDC{
				AWSOIDC: spec,
			},
		},
	}
	if err := ig.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return ig, nil
}

// String returns the integration string representation.
func (ig *IntegrationV1) String() string {
	return fmt.Sprintf("IntegrationV1(Name=%v, SubKind=%s, Labels=%v)",
		ig.GetName(), ig.GetSubKind(), ig.GetAllLabels())
}

// MatchSearch goes through select field values and tries to
// match against the list of search values.
func (ig *IntegrationV1) MatchSearch(values []string) bool {
	fieldVals := append(utils.MapToStrings(ig.GetAllLabels()), ig.GetName(), ig.GetSubKind())
	return MatchSearch(fieldVals, values, nil)
}

// setStaticFields sets static resource header and metadata fields.
func (ig *IntegrationV1) setStaticFields() {
	ig.Kind = KindIntegration
	ig.Version = V1
}

// CheckAndSetDefaults checks and sets default values
func (ig *IntegrationV1) CheckAndSetDefaults() error {
	ig.setStaticFields()
	if err := ig.ResourceHeader.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	return trace.Wrap(ig.Spec.CheckAndSetDefaults())
}

// CheckAndSetDefaults validates and sets default values for a integration.
func (s *IntegrationSpecV1) CheckAndSetDefaults() error {
	if s.SubKindSpec == nil {
		return trace.BadParameter("missing required subkind spec")
	}

	switch integrationSubKind := s.SubKindSpec.(type) {
	case *IntegrationSpecV1_AWSOIDC:
		err := integrationSubKind.CheckAndSetDefaults()
		if err != nil {
			return trace.Wrap(err)
		}
	default:
		return trace.BadParameter("unknown integration subkind: %T", integrationSubKind)
	}

	return nil
}

// CheckAndSetDefaults validates an agent mesh integration.
func (s *IntegrationSpecV1_AWSOIDC) CheckAndSetDefaults() error {
	if s == nil || s.AWSOIDC == nil {
		return trace.BadParameter("aws_oidc is required for %q subkind", IntegrationSubKindAWSOIDC)
	}

	if s.AWSOIDC.RoleARN == "" {
		return trace.BadParameter("role_arn is required for %q subkind", IntegrationSubKindAWSOIDC)
	}

	return nil
}

// GetAWSOIDCIntegrationSpec returns the specific spec fields for `aws-oidc` subkind integrations.
func (ig *IntegrationV1) GetAWSOIDCIntegrationSpec() *AWSOIDCIntegrationSpecV1 {
	return ig.Spec.GetAWSOIDC()
}

// SetAWSOIDCIntegrationSpec sets the specific fields for the `aws-oidc` subkind integration.
func (ig *IntegrationV1) SetAWSOIDCIntegrationSpec(awsOIDCSpec *AWSOIDCIntegrationSpecV1) {
	ig.Spec.SubKindSpec = &IntegrationSpecV1_AWSOIDC{
		AWSOIDC: awsOIDCSpec,
	}
}

// Integrations is a list of Integration resources.
type Integrations []Integration

// AsResources returns these groups as resources with labels.
func (igs Integrations) AsResources() []ResourceWithLabels {
	resources := make([]ResourceWithLabels, len(igs))
	for i, ig := range igs {
		resources[i] = ig
	}
	return resources
}

// Len returns the slice length.
func (igs Integrations) Len() int { return len(igs) }

// Less compares integrations by name.
func (igs Integrations) Less(i, j int) bool { return igs[i].GetName() < igs[j].GetName() }

// Swap swaps two integrations.
func (igs Integrations) Swap(i, j int) { igs[i], igs[j] = igs[j], igs[i] }

// UnmarshalJSON is a custom unmarshaller for JSON format.
// It is required because the Spec.SubKindSpec proto field is a oneof.
// This translates into two issues when generating golang code:
// - the Spec.SubKindSpec field in Go is an interface
// - there's no way to provide json tags for oneof fields, so instead of snake_case, we get CamelCase for the Spec.SubKindSpec field
//
// Spec.SubKindSpec is an interface because it can have one of multiple values,
// even though there's only one type for now: aws_oidc.
// When trying to unmarshal this field, we must provide a concrete type.
// To do so, we unmarshal just the root fields (ResourceHeader: Name, Kind, SubKind, Version, Metadata)
// and then use its SubKind to provide a concrete type for the Spec.SubKindSpec field.
// Unmarshalling the remaining fields uses the standard json.Unmarshal over the Spec field.
//
// Spec.SubKindSpec is expecting the `SubKindSpec` json tag, however we are using snake_case everywhere.
// So, we create a local type that has the expected json tag (`sub_kind_spec`) and use it to unmarshal and then copy
// to the proper type.
func (ig *IntegrationV1) UnmarshalJSON(data []byte) error {
	var integration IntegrationV1

	d := struct {
		ResourceHeader `json:""`
		Spec           struct {
			RawSubKindSpec json.RawMessage `json:"subkind_spec"`
		} `json:"spec"`
	}{}

	err := json.Unmarshal(data, &d)
	if err != nil {
		return trace.Wrap(err)
	}

	integration.ResourceHeader = d.ResourceHeader

	var subkindSpec isIntegrationSpecV1_SubKindSpec
	switch integration.SubKind {
	case IntegrationSubKindAWSOIDC:
		subkindSpec = &IntegrationSpecV1_AWSOIDC{}
	default:
		return trace.BadParameter("invalid subkind %q", integration.ResourceHeader.SubKind)
	}

	if err := json.Unmarshal(d.Spec.RawSubKindSpec, subkindSpec); err != nil {
		return trace.Wrap(err)
	}

	integration.Spec.SubKindSpec = subkindSpec

	if err := integration.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	*ig = integration
	return nil
}

// MarshalJSON is a custom marshaller for JSON format.
// gogoproto doesn't allow for oneof json tags [https://github.com/gogo/protobuf/issues/623]
// So, this is required to correctly use snake_case for every field.
// Please see [IntegrationV1.UnmarshalJSON] for more information.
func (ig *IntegrationV1) MarshalJSON() ([]byte, error) {
	d := struct {
		ResourceHeader `json:""`
		Spec           struct {
			SubKindSpec isIntegrationSpecV1_SubKindSpec `json:"subkind_spec"`
		} `json:"spec"`
	}{}

	d.ResourceHeader = ig.ResourceHeader
	d.Spec.SubKindSpec = ig.Spec.SubKindSpec

	out, err := json.Marshal(d)
	return out, trace.Wrap(err)
}
