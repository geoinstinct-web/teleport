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

package v1beta1

// HostPortRangeApplyConfiguration represents an declarative configuration of the HostPortRange type for use
// with apply.
type HostPortRangeApplyConfiguration struct {
	Min *int32 `json:"min,omitempty"`
	Max *int32 `json:"max,omitempty"`
}

// HostPortRangeApplyConfiguration constructs an declarative configuration of the HostPortRange type for use with
// apply.
func HostPortRange() *HostPortRangeApplyConfiguration {
	return &HostPortRangeApplyConfiguration{}
}

// WithMin sets the Min field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Min field is set to the value of the last call.
func (b *HostPortRangeApplyConfiguration) WithMin(value int32) *HostPortRangeApplyConfiguration {
	b.Min = &value
	return b
}

// WithMax sets the Max field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Max field is set to the value of the last call.
func (b *HostPortRangeApplyConfiguration) WithMax(value int32) *HostPortRangeApplyConfiguration {
	b.Max = &value
	return b
}
