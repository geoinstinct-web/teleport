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
	apinodev1 "k8s.io/api/node/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	managedfields "k8s.io/apimachinery/pkg/util/managedfields"
	internal "k8s.io/client-go/applyconfigurations/internal"
	v1 "k8s.io/client-go/applyconfigurations/meta/v1"
)

// RuntimeClassApplyConfiguration represents an declarative configuration of the RuntimeClass type for use
// with apply.
type RuntimeClassApplyConfiguration struct {
	v1.TypeMetaApplyConfiguration    `json:",inline"`
	*v1.ObjectMetaApplyConfiguration `json:"metadata,omitempty"`
	Handler                          *string                       `json:"handler,omitempty"`
	Overhead                         *OverheadApplyConfiguration   `json:"overhead,omitempty"`
	Scheduling                       *SchedulingApplyConfiguration `json:"scheduling,omitempty"`
}

// RuntimeClass constructs an declarative configuration of the RuntimeClass type for use with
// apply.
func RuntimeClass(name string) *RuntimeClassApplyConfiguration {
	b := &RuntimeClassApplyConfiguration{}
	b.WithName(name)
	b.WithKind("RuntimeClass")
	b.WithAPIVersion("node.k8s.io/v1")
	return b
}

// ExtractRuntimeClass extracts the applied configuration owned by fieldManager from
// runtimeClass. If no managedFields are found in runtimeClass for fieldManager, a
// RuntimeClassApplyConfiguration is returned with only the Name, Namespace (if applicable),
// APIVersion and Kind populated. It is possible that no managed fields were found for because other
// field managers have taken ownership of all the fields previously owned by fieldManager, or because
// the fieldManager never owned fields any fields.
// runtimeClass must be a unmodified RuntimeClass API object that was retrieved from the Kubernetes API.
// ExtractRuntimeClass provides a way to perform a extract/modify-in-place/apply workflow.
// Note that an extracted apply configuration will contain fewer fields than what the fieldManager previously
// applied if another fieldManager has updated or force applied any of the previously applied fields.
// Experimental!
func ExtractRuntimeClass(runtimeClass *apinodev1.RuntimeClass, fieldManager string) (*RuntimeClassApplyConfiguration, error) {
	return extractRuntimeClass(runtimeClass, fieldManager, "")
}

// ExtractRuntimeClassStatus is the same as ExtractRuntimeClass except
// that it extracts the status subresource applied configuration.
// Experimental!
func ExtractRuntimeClassStatus(runtimeClass *apinodev1.RuntimeClass, fieldManager string) (*RuntimeClassApplyConfiguration, error) {
	return extractRuntimeClass(runtimeClass, fieldManager, "status")
}

func extractRuntimeClass(runtimeClass *apinodev1.RuntimeClass, fieldManager string, subresource string) (*RuntimeClassApplyConfiguration, error) {
	b := &RuntimeClassApplyConfiguration{}
	err := managedfields.ExtractInto(runtimeClass, internal.Parser().Type("io.k8s.api.node.v1.RuntimeClass"), fieldManager, b, subresource)
	if err != nil {
		return nil, err
	}
	b.WithName(runtimeClass.Name)

	b.WithKind("RuntimeClass")
	b.WithAPIVersion("node.k8s.io/v1")
	return b, nil
}

// WithKind sets the Kind field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Kind field is set to the value of the last call.
func (b *RuntimeClassApplyConfiguration) WithKind(value string) *RuntimeClassApplyConfiguration {
	b.Kind = &value
	return b
}

// WithAPIVersion sets the APIVersion field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the APIVersion field is set to the value of the last call.
func (b *RuntimeClassApplyConfiguration) WithAPIVersion(value string) *RuntimeClassApplyConfiguration {
	b.APIVersion = &value
	return b
}

// WithName sets the Name field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Name field is set to the value of the last call.
func (b *RuntimeClassApplyConfiguration) WithName(value string) *RuntimeClassApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.Name = &value
	return b
}

// WithGenerateName sets the GenerateName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the GenerateName field is set to the value of the last call.
func (b *RuntimeClassApplyConfiguration) WithGenerateName(value string) *RuntimeClassApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.GenerateName = &value
	return b
}

// WithNamespace sets the Namespace field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Namespace field is set to the value of the last call.
func (b *RuntimeClassApplyConfiguration) WithNamespace(value string) *RuntimeClassApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.Namespace = &value
	return b
}

// WithSelfLink sets the SelfLink field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SelfLink field is set to the value of the last call.
func (b *RuntimeClassApplyConfiguration) WithSelfLink(value string) *RuntimeClassApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.SelfLink = &value
	return b
}

// WithUID sets the UID field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the UID field is set to the value of the last call.
func (b *RuntimeClassApplyConfiguration) WithUID(value types.UID) *RuntimeClassApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.UID = &value
	return b
}

// WithResourceVersion sets the ResourceVersion field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ResourceVersion field is set to the value of the last call.
func (b *RuntimeClassApplyConfiguration) WithResourceVersion(value string) *RuntimeClassApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.ResourceVersion = &value
	return b
}

// WithGeneration sets the Generation field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Generation field is set to the value of the last call.
func (b *RuntimeClassApplyConfiguration) WithGeneration(value int64) *RuntimeClassApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.Generation = &value
	return b
}

// WithCreationTimestamp sets the CreationTimestamp field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the CreationTimestamp field is set to the value of the last call.
func (b *RuntimeClassApplyConfiguration) WithCreationTimestamp(value metav1.Time) *RuntimeClassApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.CreationTimestamp = &value
	return b
}

// WithDeletionTimestamp sets the DeletionTimestamp field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the DeletionTimestamp field is set to the value of the last call.
func (b *RuntimeClassApplyConfiguration) WithDeletionTimestamp(value metav1.Time) *RuntimeClassApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.DeletionTimestamp = &value
	return b
}

// WithDeletionGracePeriodSeconds sets the DeletionGracePeriodSeconds field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the DeletionGracePeriodSeconds field is set to the value of the last call.
func (b *RuntimeClassApplyConfiguration) WithDeletionGracePeriodSeconds(value int64) *RuntimeClassApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.DeletionGracePeriodSeconds = &value
	return b
}

// WithLabels puts the entries into the Labels field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the Labels field,
// overwriting an existing map entries in Labels field with the same key.
func (b *RuntimeClassApplyConfiguration) WithLabels(entries map[string]string) *RuntimeClassApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	if b.Labels == nil && len(entries) > 0 {
		b.Labels = make(map[string]string, len(entries))
	}
	for k, v := range entries {
		b.Labels[k] = v
	}
	return b
}

// WithAnnotations puts the entries into the Annotations field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the Annotations field,
// overwriting an existing map entries in Annotations field with the same key.
func (b *RuntimeClassApplyConfiguration) WithAnnotations(entries map[string]string) *RuntimeClassApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	if b.Annotations == nil && len(entries) > 0 {
		b.Annotations = make(map[string]string, len(entries))
	}
	for k, v := range entries {
		b.Annotations[k] = v
	}
	return b
}

// WithOwnerReferences adds the given value to the OwnerReferences field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the OwnerReferences field.
func (b *RuntimeClassApplyConfiguration) WithOwnerReferences(values ...*v1.OwnerReferenceApplyConfiguration) *RuntimeClassApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithOwnerReferences")
		}
		b.OwnerReferences = append(b.OwnerReferences, *values[i])
	}
	return b
}

// WithFinalizers adds the given value to the Finalizers field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Finalizers field.
func (b *RuntimeClassApplyConfiguration) WithFinalizers(values ...string) *RuntimeClassApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	for i := range values {
		b.Finalizers = append(b.Finalizers, values[i])
	}
	return b
}

// WithClusterName sets the ClusterName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ClusterName field is set to the value of the last call.
func (b *RuntimeClassApplyConfiguration) WithClusterName(value string) *RuntimeClassApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.ClusterName = &value
	return b
}

func (b *RuntimeClassApplyConfiguration) ensureObjectMetaApplyConfigurationExists() {
	if b.ObjectMetaApplyConfiguration == nil {
		b.ObjectMetaApplyConfiguration = &v1.ObjectMetaApplyConfiguration{}
	}
}

// WithHandler sets the Handler field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Handler field is set to the value of the last call.
func (b *RuntimeClassApplyConfiguration) WithHandler(value string) *RuntimeClassApplyConfiguration {
	b.Handler = &value
	return b
}

// WithOverhead sets the Overhead field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Overhead field is set to the value of the last call.
func (b *RuntimeClassApplyConfiguration) WithOverhead(value *OverheadApplyConfiguration) *RuntimeClassApplyConfiguration {
	b.Overhead = value
	return b
}

// WithScheduling sets the Scheduling field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Scheduling field is set to the value of the last call.
func (b *RuntimeClassApplyConfiguration) WithScheduling(value *SchedulingApplyConfiguration) *RuntimeClassApplyConfiguration {
	b.Scheduling = value
	return b
}
