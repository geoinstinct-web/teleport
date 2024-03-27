/*
Copyright 2024 Gravitational, Inc.

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

package v1

import (
	"github.com/gravitational/trace"

	accessmonitoringrulev1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/accessmonitoringrules/v1"
	"github.com/gravitational/teleport/api/types/accessmonitoringrule"
	headerv1 "github.com/gravitational/teleport/api/types/header/convert/v1"
)

// FromProto converts a v1 access monitoring rule into an internal access monitoring rule object.
func FromProto(amr *accessmonitoringrulev1.AccessMonitoringRule) (*accessmonitoringrule.AccessMonitoringRule, error) {
	if amr == nil {
		return nil, trace.BadParameter("access monitoring rule is nil")
	}
	if amr.Spec == nil {
		return nil, trace.BadParameter("access monitoring rule spec is nil")
	}
	subjects := make([]string, 0, len(amr.Spec.Subjects))
	subjects = append(subjects, amr.Spec.Subjects...)
	states := make([]string, 0, len(amr.Spec.States))
	states = append(states, amr.Spec.States...)
	var notification *accessmonitoringrule.Notification
	if amr.Spec.Notification != nil {
		recipients := make([]string, 0, len(amr.Spec.Notification.Recipients))
		recipients = append(recipients, amr.Spec.Notification.Recipients...)
		notification = &accessmonitoringrule.Notification{
			Name:       amr.Spec.Notification.Name,
			Recipients: recipients,
		}
	}
	spec := accessmonitoringrule.Spec{
		Subjects:  subjects,
		States:    states,
		Condition: amr.Spec.Condition,
	}
	if notification != nil {
		spec.Notification = *notification
	}
	return &accessmonitoringrule.AccessMonitoringRule{
		Metadata: headerv1.FromMetadataProto(amr.Metadata),
		Kind:     amr.Kind,
		SubKind:  amr.SubKind,
		Version:  amr.Version,
		Spec:     spec,
	}, nil
}

// ToProto converts an internal access monitoring rule into a v1 access monitoring rule object.
func ToProto(amr *accessmonitoringrule.AccessMonitoringRule) *accessmonitoringrulev1.AccessMonitoringRule {
	subjects := make([]string, 0, len(amr.Spec.Subjects))
	subjects = append(subjects, amr.Spec.Subjects...)
	states := make([]string, 0, len(amr.Spec.States))
	states = append(states, amr.Spec.States...)
	recipients := make([]string, 0, len(amr.Spec.Notification.Recipients))
	recipients = append(recipients, amr.Spec.Notification.Recipients...)
	return &accessmonitoringrulev1.AccessMonitoringRule{
		Metadata: headerv1.ToMetadataProto(amr.Metadata),
		Kind:     amr.Kind,
		SubKind:  amr.SubKind,
		Version:  amr.Version,
		Spec: &accessmonitoringrulev1.AccessMonitoringRuleSpec{
			Subjects:  subjects,
			States:    states,
			Condition: amr.Spec.Condition,
			Notification: &accessmonitoringrulev1.Notification{
				Name:       amr.Spec.Notification.Name,
				Recipients: recipients,
			},
		},
	}
}
