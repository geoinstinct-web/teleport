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
	"fmt"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/utils"
)

// OktaImportRule specifies a rule for importing and labeling Okta applications and groups.
type OktaImportRule interface {
	ResourceWithLabels

	// GetPriority will return the priority of the Okta import rule.
	GetPriority() int32

	// GetMappings will return the list of mappings for the Okta import rule.
	GetMappings() []OktaImportRuleMapping
}

// NewOktaImportRule returns a new OktaImportRule.
func NewOktaImportRule(metadata Metadata, spec OktaImportRuleSpecV1) (OktaImportRule, error) {
	o := &OktaImportRuleV1{
		ResourceHeader: ResourceHeader{
			Metadata: metadata,
		},
		Spec: spec,
	}
	if err := o.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return o, nil
}

// GetPriority will return the priority of the Okta import rule.
func (o *OktaImportRuleV1) GetPriority() int32 {
	return o.Spec.Priority
}

// GetMappings will return the list of mappings for the Okta import rule.
func (o *OktaImportRuleV1) GetMappings() []OktaImportRuleMapping {
	matches := make([]OktaImportRuleMapping, len(o.Spec.Mappings))

	for i, match := range o.Spec.Mappings {
		matches[i] = match
	}

	return matches
}

// String returns the Okta import rule string representation.
func (o *OktaImportRuleV1) String() string {
	return fmt.Sprintf("OktaImportRuleV1(Name=%v, Labels=%v)",
		o.GetName(), o.GetAllLabels())
}

// MatchSearch goes through select field values and tries to
// match against the list of search values.
func (o *OktaImportRuleV1) MatchSearch(values []string) bool {
	fieldVals := append(utils.MapToStrings(o.GetAllLabels()), o.GetName())
	return MatchSearch(fieldVals, values, nil)
}

// setStaticFields sets static resource header and metadata fields.
func (o *OktaImportRuleV1) setStaticFields() {
	o.Kind = KindOktaImportRule
	o.Version = V1
}

// CheckAndSetDefaults checks and sets default values
func (o *OktaImportRuleV1) CheckAndSetDefaults() error {
	o.setStaticFields()
	if err := o.Metadata.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	if o.Spec.Priority < 0 {
		return trace.BadParameter("priority must be a positive number")
	}

	if len(o.Spec.Mappings) == 0 {
		return trace.BadParameter("mappings is empty")
	}

	for _, mapping := range o.Spec.Mappings {
		if err := mapping.CheckAndSetDefaults(); err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// OktaImportRuleMapping is a list of matches that map match rules to labels.
type OktaImportRuleMapping interface {
	// GetMatches returns all matches for a mapping.
	GetMatches() []OktaImportRuleMatch
	// GetAddLabels returns the labels that will be added for a mapping.
	GetAddLabels() map[string]string
}

// GetMatches returns all matches for a mapping.
func (o *OktaImportRuleMappingV1) GetMatches() []OktaImportRuleMatch {
	matches := make([]OktaImportRuleMatch, len(o.Match))

	for i, match := range o.Match {
		matches[i] = match
	}

	return matches
}

// GetAddLabels returns the labels that will be added for a mapping.
func (o *OktaImportRuleMappingV1) GetAddLabels() map[string]string {
	return o.AddLabels
}

// CheckAndSetDefaults checks and sets default values
func (o *OktaImportRuleMappingV1) CheckAndSetDefaults() error {
	for _, match := range o.Match {
		if err := match.CheckAndSetDefaults(); err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// OktaImportRuleMatch creates a new Okta import rule match.
type OktaImportRuleMatch interface {
	// GetAppIDs returns whether or not this match contains an App ID match and, if so, the list of app IDs.
	GetAppIDs() (bool, []string)
	// GetGroupIDs returns whether or not this match contains a Group ID match and, if so, the list of app IDs.
	GetGroupIDs() (bool, []string)
}

// GetAppIDs returns whether or not this match contains an App ID match and, if so, the list of app IDs.
func (o *OktaImportRuleMatchV1) GetAppIDs() (bool, []string) {
	return len(o.AppIDs) > 0, o.AppIDs
}

// GetGroupIDs returns whether or not this match contains a Group ID match and, if so, the list of app IDs.
func (o *OktaImportRuleMatchV1) GetGroupIDs() (bool, []string) {
	return len(o.GroupIDs) > 0, o.GroupIDs
}

// CheckAndSetDefaults checks and sets default values
func (o *OktaImportRuleMatchV1) CheckAndSetDefaults() error {
	if len(o.AppIDs) > 0 && len(o.GroupIDs) > 0 {
		return trace.BadParameter("only one of App IDs or Group IDs can be set")
	}

	return nil
}

// OktaAssignment is a representation of an action or set of actions taken by Teleport to assign Okta users to applications or groups.
type OktaAssignment interface {
	ResourceWithLabels

	// GetUser will return the user that the Okta assignment actions applies to.
	GetUser() string
	// GetActions will return the list of actions that will be performed as part of this assignment.
	GetActions() []OktaAssignmentAction
	// GetCleanupTime will return the optional time that the assignment should be cleaned up.
	GetCleanupTime() *time.Time
	// Copy returns a copy of this Okta assignment resource.
	Copy() OktaAssignment
}

// NewOktaAssignment creates a new Okta assignment object.
func NewOktaAssignment(metadata Metadata, spec OktaAssignmentSpecV1) (OktaAssignment, error) {
	o := &OktaAssignmentV1{
		ResourceHeader: ResourceHeader{
			Metadata: metadata,
		},
		Spec: spec,
	}
	if err := o.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return o, nil
}

// GetUser returns the user that the actions will be applied to.
func (o *OktaAssignmentV1) GetUser() string {
	return o.Spec.User
}

// GetActions returns the actions associated with the Okta assignment.
func (o *OktaAssignmentV1) GetActions() []OktaAssignmentAction {
	actions := make([]OktaAssignmentAction, len(o.Spec.Actions))

	for i, action := range o.Spec.Actions {
		actions[i] = action
	}

	return actions
}

// GetCleanupTime will return the optional time that the assignment should be cleaned up.
func (o *OktaAssignmentV1) GetCleanupTime() *time.Time {
	return o.Spec.CleanupTime
}

// Copy returns a copy of this Okta assignment resource.
func (o *OktaAssignmentV1) Copy() OktaAssignment {
	return proto.Clone(o).(*OktaAssignmentV1)
}

// String returns the Okta assignment rule string representation.
func (o *OktaAssignmentV1) String() string {
	return fmt.Sprintf("OktaAssignmentV1(Name=%v, Labels=%v)",
		o.GetName(), o.GetAllLabels())
}

// MatchSearch goes through select field values and tries to
// match against the list of search values.
func (o *OktaAssignmentV1) MatchSearch(values []string) bool {
	fieldVals := append(utils.MapToStrings(o.GetAllLabels()), o.GetName())
	return MatchSearch(fieldVals, values, nil)
}

// setStaticFields sets static resource header and metadata fields.
func (o *OktaAssignmentV1) setStaticFields() {
	o.Kind = KindOktaAssignment
	o.Version = V1
}

// CheckAndSetDefaults checks and sets default values
func (o *OktaAssignmentV1) CheckAndSetDefaults() error {
	o.setStaticFields()
	if err := o.Metadata.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	if o.Spec.User == "" {
		return trace.BadParameter("user must not be empty")
	}

	if len(o.Spec.Actions) == 0 {
		return trace.BadParameter("actions is empty")
	}

	if o.Spec.CleanupTime != nil {
		utcTime := o.Spec.CleanupTime.UTC()
		o.Spec.CleanupTime = &utcTime
	}

	for _, action := range o.Spec.Actions {
		action.LastTransition = action.LastTransition.UTC()
	}

	return nil
}

// OktaAssignmentAction is an individual action to apply to an Okta assignment.
type OktaAssignmentAction interface {
	// GetStatus returns the current status of the action.
	GetStatus() string
	// SetStatus sets the status of the action. Only allows valid transitions.
	//
	// Valid transitions are:
	// * PENDING -> (PROCESSING, CLEANUP_PENDING)
	// * PROCESSING -> (SUCCESSFUL, FAILED, CLEANUP_PENDING)
	// * SUCCESSFUL -> (CLEANUP_PENDING, CLEANUP_PROCESSING)
	// * FAILED -> (PROCESSING, CLEANUP_PENDING, CLEANUP_PROCESSING)
	// * CLEANUP_PENDING -> CLEANUP_PROCESSING
	// * CLEANUP_PROCESSING -> (CLEANUP_FAILED, CLEANED_UP)
	SetStatus(string) error
	// GetTargetType returns the target type of the action.
	GetTargetType() string
	// GetID returns the ID of the action target.
	GetID() string
	// SetLastTransition sets the last transition time.
	SetLastTransition(time time.Time)
	// GetLastTransition returns the optional time that the action last transitioned.
	GetLastTransition() time.Time
}

// GetStatus returns the current status of the action.
func (o *OktaAssignmentActionV1) GetStatus() string {
	switch o.Status {
	case OktaAssignmentActionV1_PENDING:
		return constants.OktaAssignmentActionStatusPending
	case OktaAssignmentActionV1_PROCESSING:
		return constants.OktaAssignmentActionStatusProcessing
	case OktaAssignmentActionV1_SUCCESSFUL:
		return constants.OktaAssignmentActionStatusSuccessful
	case OktaAssignmentActionV1_FAILED:
		return constants.OktaAssignmentActionStatusFailed
	case OktaAssignmentActionV1_CLEANUP_PENDING:
		return constants.OktaAssignmentActionStatusCleanupPending
	case OktaAssignmentActionV1_CLEANUP_PROCESSING:
		return constants.OktaAssignmentActionStatusCleanupProcessing
	case OktaAssignmentActionV1_CLEANED_UP:
		return constants.OktaAssignmentActionStatusCleanedUp
	case OktaAssignmentActionV1_CLEANUP_FAILED:
		return constants.OktaAssignmentActionStatusCleanupFailed
	default:
		return constants.OktaAssignmentActionStatusUnknown
	}
}

// SetStatus sets the status of the action. Only allows valid transitions.
//
// Valid transitions are:
// * PENDING -> (PROCESSING, CLEANUP_PENDING)
// * PROCESSING -> (SUCCESSFUL, FAILED, CLEANUP_PENDING)
// * SUCCESSFUL -> (CLEANUP_PENDING, CLEANUP_PROCESSING)
// * FAILED -> (PROCESSING, CLEANUP_PENDING, CLEANUP_PROCESSING)
// * CLEANUP_PENDING -> CLEANUP_PROCESSING
// * CLEANUP_PROCESSING -> (CLEANUP_FAILED, CLEANED_UP)
func (o *OktaAssignmentActionV1) SetStatus(status string) error {
	invalidTransition := false
	switch o.Status {
	case OktaAssignmentActionV1_PENDING:
		switch status {
		case constants.OktaAssignmentActionStatusProcessing:
		case constants.OktaAssignmentActionStatusCleanupPending:
		default:
			invalidTransition = true
		}
	case OktaAssignmentActionV1_PROCESSING:
		switch status {
		case constants.OktaAssignmentActionStatusSuccessful:
		case constants.OktaAssignmentActionStatusFailed:
		case constants.OktaAssignmentActionStatusCleanupPending:
		default:
			invalidTransition = true
		}
	case OktaAssignmentActionV1_SUCCESSFUL:
		switch status {
		case constants.OktaAssignmentActionStatusCleanupPending:
		default:
			invalidTransition = true
		}
	case OktaAssignmentActionV1_FAILED:
		switch status {
		case constants.OktaAssignmentActionStatusProcessing:
		case constants.OktaAssignmentActionStatusCleanupPending:
		default:
			invalidTransition = true
		}
	case OktaAssignmentActionV1_CLEANUP_PENDING:
		switch status {
		case constants.OktaAssignmentActionStatusCleanupProcessing:
		default:
			invalidTransition = true
		}
	case OktaAssignmentActionV1_CLEANUP_PROCESSING:
		switch status {
		case constants.OktaAssignmentActionStatusCleanedUp:
		case constants.OktaAssignmentActionStatusCleanupFailed:
		default:
			invalidTransition = true
		}
	case OktaAssignmentActionV1_CLEANED_UP:
		invalidTransition = true
	case OktaAssignmentActionV1_CLEANUP_FAILED:
		invalidTransition = true
	}

	if invalidTransition {
		return trace.BadParameter("invalid transition: %s -> %s", o.GetStatus(), status)
	}

	o.Status = OktaAssignmentActionStatusToProto(status)

	return nil
}

// OktaAssignmentActionStatusToProto will convert the internal notion of an Okta status into the Okta status
// message understood by protobuf.
func OktaAssignmentActionStatusToProto(status string) OktaAssignmentActionV1_OktaAssignmentActionStatus {
	switch status {
	case constants.OktaAssignmentActionStatusPending:
		return OktaAssignmentActionV1_PENDING
	case constants.OktaAssignmentActionStatusProcessing:
		return OktaAssignmentActionV1_PROCESSING
	case constants.OktaAssignmentActionStatusSuccessful:
		return OktaAssignmentActionV1_SUCCESSFUL
	case constants.OktaAssignmentActionStatusFailed:
		return OktaAssignmentActionV1_FAILED
	case constants.OktaAssignmentActionStatusCleanupPending:
		return OktaAssignmentActionV1_CLEANUP_PENDING
	case constants.OktaAssignmentActionStatusCleanupProcessing:
		return OktaAssignmentActionV1_CLEANUP_PROCESSING
	case constants.OktaAssignmentActionStatusCleanedUp:
		return OktaAssignmentActionV1_CLEANED_UP
	case constants.OktaAssignmentActionStatusCleanupFailed:
		return OktaAssignmentActionV1_CLEANUP_FAILED
	default:
		return OktaAssignmentActionV1_UNKNOWN
	}
}

// GetTargetType returns the target type of the action.
func (o *OktaAssignmentActionV1) GetTargetType() string {
	switch o.Target.Type {
	case OktaAssignmentActionTargetV1_APPLICATION:
		return constants.OktaAssignmentActionTargetApplication
	case OktaAssignmentActionTargetV1_GROUP:
		return constants.OktaAssignmentActionTargetGroup
	default:
		return constants.OktaAssignmentActionTargetUnknown
	}
}

// GetID returns the ID of the action target.
func (o *OktaAssignmentActionV1) GetID() string {
	return o.Target.Id
}

// SetLastTransition sets the last transition time.
func (o *OktaAssignmentActionV1) SetLastTransition(time time.Time) {
	o.LastTransition = time.UTC()
}

// GetLastTransition returns the optional time that the action last transitioned.
func (o *OktaAssignmentActionV1) GetLastTransition() time.Time {
	return o.LastTransition
}

// OktaAssignments is a list of OktaAssignment resources.
type OktaAssignments []OktaAssignment

// ToMap returns these Okta assignments as a map keyed by Okta assignment name.
func (o OktaAssignments) ToMap() map[string]OktaAssignment {
	m := make(map[string]OktaAssignment, len(o))
	for _, oktaAssignment := range o {
		m[oktaAssignment.GetName()] = oktaAssignment
	}
	return m
}

// AsResources returns these Okta assignments as resources with labels.
func (o OktaAssignments) AsResources() ResourcesWithLabels {
	resources := make(ResourcesWithLabels, 0, len(o))
	for _, oktaAssignment := range o {
		resources = append(resources, oktaAssignment)
	}
	return resources
}

// Len returns the slice length.
func (o OktaAssignments) Len() int { return len(o) }

// Less compares Okta assignments by name.
func (o OktaAssignments) Less(i, j int) bool { return o[i].GetName() < o[j].GetName() }

// Swap swaps two Okta assignments.
func (o OktaAssignments) Swap(i, j int) { o[i], o[j] = o[j], o[i] }
