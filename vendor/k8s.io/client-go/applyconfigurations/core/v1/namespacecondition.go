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

// NamespaceConditionApplyConfiguration represents an declarative configuration of the NamespaceCondition type for use
// with apply.
type NamespaceConditionApplyConfiguration struct {
	Type               *v1.NamespaceConditionType `json:"type,omitempty"`
	Status             *v1.ConditionStatus        `json:"status,omitempty"`
	LastTransitionTime *metav1.Time               `json:"lastTransitionTime,omitempty"`
	Reason             *string                    `json:"reason,omitempty"`
	Message            *string                    `json:"message,omitempty"`
}

// NamespaceConditionApplyConfiguration constructs an declarative configuration of the NamespaceCondition type for use with
// apply.
func NamespaceCondition() *NamespaceConditionApplyConfiguration {
	return &NamespaceConditionApplyConfiguration{}
}

// WithType sets the Type field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Type field is set to the value of the last call.
func (b *NamespaceConditionApplyConfiguration) WithType(value v1.NamespaceConditionType) *NamespaceConditionApplyConfiguration {
	b.Type = &value
	return b
}

// WithStatus sets the Status field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Status field is set to the value of the last call.
func (b *NamespaceConditionApplyConfiguration) WithStatus(value v1.ConditionStatus) *NamespaceConditionApplyConfiguration {
	b.Status = &value
	return b
}

// WithLastTransitionTime sets the LastTransitionTime field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the LastTransitionTime field is set to the value of the last call.
func (b *NamespaceConditionApplyConfiguration) WithLastTransitionTime(value metav1.Time) *NamespaceConditionApplyConfiguration {
	b.LastTransitionTime = &value
	return b
}

// WithReason sets the Reason field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Reason field is set to the value of the last call.
func (b *NamespaceConditionApplyConfiguration) WithReason(value string) *NamespaceConditionApplyConfiguration {
	b.Reason = &value
	return b
}

// WithMessage sets the Message field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Message field is set to the value of the last call.
func (b *NamespaceConditionApplyConfiguration) WithMessage(value string) *NamespaceConditionApplyConfiguration {
	b.Message = &value
	return b
}
