// Copyright 2023 Gravitational, Inc
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

package device

import (
	"github.com/gravitational/trace"

	devicepb "github.com/gravitational/teleport/api/gen/proto/go/teleport/devicetrust/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/utils"
)

// Resource is a wrapper around devicepb.Device that implements types.Resource.
type Resource struct {
	// ResourceHeader is embedded to implement types.Resource
	types.ResourceHeader
	// Spec is the device specification
	Spec *devicepb.Device `json:"spec"`
}

// checkAndSetDefaults sanity checks Resource fields to catch simple errors, and
// sets default values for all fields with defaults.
func (r *Resource) checkAndSetDefaults() error {
	if err := r.Metadata.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if r.Kind == "" {
		r.Kind = types.KindDevice
		// Sanity check.
	} else if r.Kind != types.KindDevice {
		return trace.BadParameter("unexpected resource kind %q, must be %q", r.Kind, types.KindDevice)
	}
	if r.Spec == nil {
		return trace.BadParameter("device must have a spec")
	}
	switch {
	case r.Version != types.V1:
		return trace.BadParameter("unsupported resource version %q, %q is currently the only supported version", r.Version, types.V1)
	case r.Spec.ApiVersion == "":
		r.Spec.ApiVersion = r.Version
	case r.Spec.ApiVersion != types.V1:
		return trace.BadParameter("mismatched resource version %q and spec api version %q", r.Version, r.Spec.ApiVersion)
	}
	switch {
	case r.Metadata.Name == "":
		return trace.BadParameter("device must have a name")
	case r.Spec.Id == "":
		r.Spec.Id = r.Metadata.Name
	case r.Spec.Id != r.Metadata.Name:
		return trace.BadParameter("mismatched resource name %q and spec id %q", r.Metadata.Name, r.Spec.Id)
	}

	return nil
}

// UnmarshalDevice parses a device in the Resource format which matches
// the expected YAML format for Teleport resources, sets default values, and
// converts to *devicepb.Device.
func UnmarshalDevice(raw []byte) (*devicepb.Device, error) {
	var resource Resource
	if err := utils.FastUnmarshal(raw, &resource); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := resource.checkAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return resourceToProto(&resource), nil
}

// ProtoToResource converts a *devicepb.Device into a *Resource which
// implements types.Resource and can be marshaled to YAML or JSON in a
// human-friendly format.
func ProtoToResource(device *devicepb.Device) *Resource {
	r := &Resource{
		ResourceHeader: types.ResourceHeader{
			Kind:    types.KindDevice,
			Version: device.ApiVersion,
			Metadata: types.Metadata{
				Name: device.AssetTag,
			},
		},
		Spec: device,
	}

	return r
}

func resourceToProto(r *Resource) *devicepb.Device {
	return r.Spec
}
