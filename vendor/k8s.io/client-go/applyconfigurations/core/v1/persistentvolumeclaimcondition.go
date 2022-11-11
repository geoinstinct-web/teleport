/*
Copyright The Kubernetes Authors.

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

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PersistentVolumeClaimConditionApplyConfiguration represents an declarative configuration of the PersistentVolumeClaimCondition type for use
// with apply.
type PersistentVolumeClaimConditionApplyConfiguration struct {
	Type               *v1.PersistentVolumeClaimConditionType `json:"type,omitempty"`
	Status             *v1.ConditionStatus                    `json:"status,omitempty"`
	LastProbeTime      *metav1.Time                           `json:"lastProbeTime,omitempty"`
	LastTransitionTime *metav1.Time                           `json:"lastTransitionTime,omitempty"`
	Reason             *string                                `json:"reason,omitempty"`
	Message            *string                                `json:"message,omitempty"`
}

// PersistentVolumeClaimConditionApplyConfiguration constructs an declarative configuration of the PersistentVolumeClaimCondition type for use with
// apply.
func PersistentVolumeClaimCondition() *PersistentVolumeClaimConditionApplyConfiguration {
	return &PersistentVolumeClaimConditionApplyConfiguration{}
}

// WithType sets the Type field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Type field is set to the value of the last call.
func (b *PersistentVolumeClaimConditionApplyConfiguration) WithType(value v1.PersistentVolumeClaimConditionType) *PersistentVolumeClaimConditionApplyConfiguration {
	b.Type = &value
	return b
}

// WithStatus sets the Status field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Status field is set to the value of the last call.
func (b *PersistentVolumeClaimConditionApplyConfiguration) WithStatus(value v1.ConditionStatus) *PersistentVolumeClaimConditionApplyConfiguration {
	b.Status = &value
	return b
}

// WithLastProbeTime sets the LastProbeTime field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the LastProbeTime field is set to the value of the last call.
func (b *PersistentVolumeClaimConditionApplyConfiguration) WithLastProbeTime(value metav1.Time) *PersistentVolumeClaimConditionApplyConfiguration {
	b.LastProbeTime = &value
	return b
}

// WithLastTransitionTime sets the LastTransitionTime field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the LastTransitionTime field is set to the value of the last call.
func (b *PersistentVolumeClaimConditionApplyConfiguration) WithLastTransitionTime(value metav1.Time) *PersistentVolumeClaimConditionApplyConfiguration {
	b.LastTransitionTime = &value
	return b
}

// WithReason sets the Reason field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Reason field is set to the value of the last call.
func (b *PersistentVolumeClaimConditionApplyConfiguration) WithReason(value string) *PersistentVolumeClaimConditionApplyConfiguration {
	b.Reason = &value
	return b
}

// WithMessage sets the Message field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Message field is set to the value of the last call.
func (b *PersistentVolumeClaimConditionApplyConfiguration) WithMessage(value string) *PersistentVolumeClaimConditionApplyConfiguration {
	b.Message = &value
	return b
}
