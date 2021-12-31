// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.14.0
// source: envoy/api/v2/endpoint/endpoint_components.proto

package envoy_api_v2_endpoint

import (
	_ "github.com/cncf/xds/go/udpa/annotations"
	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	proto "github.com/golang/protobuf/proto"
	wrappers "github.com/golang/protobuf/ptypes/wrappers"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

// Upstream host identifier.
type Endpoint struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The upstream host address.
	//
	// .. attention::
	//
	//   The form of host address depends on the given cluster type. For STATIC or EDS,
	//   it is expected to be a direct IP address (or something resolvable by the
	//   specified :ref:`resolver <envoy_api_field_core.SocketAddress.resolver_name>`
	//   in the Address). For LOGICAL or STRICT DNS, it is expected to be hostname,
	//   and will be resolved via DNS.
	Address *core.Address `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	// The optional health check configuration is used as configuration for the
	// health checker to contact the health checked host.
	//
	// .. attention::
	//
	//   This takes into effect only for upstream clusters with
	//   :ref:`active health checking <arch_overview_health_checking>` enabled.
	HealthCheckConfig *Endpoint_HealthCheckConfig `protobuf:"bytes,2,opt,name=health_check_config,json=healthCheckConfig,proto3" json:"health_check_config,omitempty"`
	// The hostname associated with this endpoint. This hostname is not used for routing or address
	// resolution. If provided, it will be associated with the endpoint, and can be used for features
	// that require a hostname, like
	// :ref:`auto_host_rewrite <envoy_api_field_route.RouteAction.auto_host_rewrite>`.
	Hostname string `protobuf:"bytes,3,opt,name=hostname,proto3" json:"hostname,omitempty"`
}

func (x *Endpoint) Reset() {
	*x = Endpoint{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_api_v2_endpoint_endpoint_components_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Endpoint) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Endpoint) ProtoMessage() {}

func (x *Endpoint) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_api_v2_endpoint_endpoint_components_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Endpoint.ProtoReflect.Descriptor instead.
func (*Endpoint) Descriptor() ([]byte, []int) {
	return file_envoy_api_v2_endpoint_endpoint_components_proto_rawDescGZIP(), []int{0}
}

func (x *Endpoint) GetAddress() *core.Address {
	if x != nil {
		return x.Address
	}
	return nil
}

func (x *Endpoint) GetHealthCheckConfig() *Endpoint_HealthCheckConfig {
	if x != nil {
		return x.HealthCheckConfig
	}
	return nil
}

func (x *Endpoint) GetHostname() string {
	if x != nil {
		return x.Hostname
	}
	return ""
}

// An Endpoint that Envoy can route traffic to.
// [#next-free-field: 6]
type LbEndpoint struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Upstream host identifier or a named reference.
	//
	// Types that are assignable to HostIdentifier:
	//	*LbEndpoint_Endpoint
	//	*LbEndpoint_EndpointName
	HostIdentifier isLbEndpoint_HostIdentifier `protobuf_oneof:"host_identifier"`
	// Optional health status when known and supplied by EDS server.
	HealthStatus core.HealthStatus `protobuf:"varint,2,opt,name=health_status,json=healthStatus,proto3,enum=envoy.api.v2.core.HealthStatus" json:"health_status,omitempty"`
	// The endpoint metadata specifies values that may be used by the load
	// balancer to select endpoints in a cluster for a given request. The filter
	// name should be specified as *envoy.lb*. An example boolean key-value pair
	// is *canary*, providing the optional canary status of the upstream host.
	// This may be matched against in a route's
	// :ref:`RouteAction <envoy_api_msg_route.RouteAction>` metadata_match field
	// to subset the endpoints considered in cluster load balancing.
	Metadata *core.Metadata `protobuf:"bytes,3,opt,name=metadata,proto3" json:"metadata,omitempty"`
	// The optional load balancing weight of the upstream host; at least 1.
	// Envoy uses the load balancing weight in some of the built in load
	// balancers. The load balancing weight for an endpoint is divided by the sum
	// of the weights of all endpoints in the endpoint's locality to produce a
	// percentage of traffic for the endpoint. This percentage is then further
	// weighted by the endpoint's locality's load balancing weight from
	// LocalityLbEndpoints. If unspecified, each host is presumed to have equal
	// weight in a locality. The sum of the weights of all endpoints in the
	// endpoint's locality must not exceed uint32_t maximal value (4294967295).
	LoadBalancingWeight *wrappers.UInt32Value `protobuf:"bytes,4,opt,name=load_balancing_weight,json=loadBalancingWeight,proto3" json:"load_balancing_weight,omitempty"`
}

func (x *LbEndpoint) Reset() {
	*x = LbEndpoint{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_api_v2_endpoint_endpoint_components_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LbEndpoint) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LbEndpoint) ProtoMessage() {}

func (x *LbEndpoint) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_api_v2_endpoint_endpoint_components_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LbEndpoint.ProtoReflect.Descriptor instead.
func (*LbEndpoint) Descriptor() ([]byte, []int) {
	return file_envoy_api_v2_endpoint_endpoint_components_proto_rawDescGZIP(), []int{1}
}

func (m *LbEndpoint) GetHostIdentifier() isLbEndpoint_HostIdentifier {
	if m != nil {
		return m.HostIdentifier
	}
	return nil
}

func (x *LbEndpoint) GetEndpoint() *Endpoint {
	if x, ok := x.GetHostIdentifier().(*LbEndpoint_Endpoint); ok {
		return x.Endpoint
	}
	return nil
}

func (x *LbEndpoint) GetEndpointName() string {
	if x, ok := x.GetHostIdentifier().(*LbEndpoint_EndpointName); ok {
		return x.EndpointName
	}
	return ""
}

func (x *LbEndpoint) GetHealthStatus() core.HealthStatus {
	if x != nil {
		return x.HealthStatus
	}
	return core.HealthStatus_UNKNOWN
}

func (x *LbEndpoint) GetMetadata() *core.Metadata {
	if x != nil {
		return x.Metadata
	}
	return nil
}

func (x *LbEndpoint) GetLoadBalancingWeight() *wrappers.UInt32Value {
	if x != nil {
		return x.LoadBalancingWeight
	}
	return nil
}

type isLbEndpoint_HostIdentifier interface {
	isLbEndpoint_HostIdentifier()
}

type LbEndpoint_Endpoint struct {
	Endpoint *Endpoint `protobuf:"bytes,1,opt,name=endpoint,proto3,oneof"`
}

type LbEndpoint_EndpointName struct {
	// [#not-implemented-hide:]
	EndpointName string `protobuf:"bytes,5,opt,name=endpoint_name,json=endpointName,proto3,oneof"`
}

func (*LbEndpoint_Endpoint) isLbEndpoint_HostIdentifier() {}

func (*LbEndpoint_EndpointName) isLbEndpoint_HostIdentifier() {}

// A group of endpoints belonging to a Locality.
// One can have multiple LocalityLbEndpoints for a locality, but this is
// generally only done if the different groups need to have different load
// balancing weights or different priorities.
// [#next-free-field: 7]
type LocalityLbEndpoints struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Identifies location of where the upstream hosts run.
	Locality *core.Locality `protobuf:"bytes,1,opt,name=locality,proto3" json:"locality,omitempty"`
	// The group of endpoints belonging to the locality specified.
	LbEndpoints []*LbEndpoint `protobuf:"bytes,2,rep,name=lb_endpoints,json=lbEndpoints,proto3" json:"lb_endpoints,omitempty"`
	// Optional: Per priority/region/zone/sub_zone weight; at least 1. The load
	// balancing weight for a locality is divided by the sum of the weights of all
	// localities  at the same priority level to produce the effective percentage
	// of traffic for the locality. The sum of the weights of all localities at
	// the same priority level must not exceed uint32_t maximal value (4294967295).
	//
	// Locality weights are only considered when :ref:`locality weighted load
	// balancing <arch_overview_load_balancing_locality_weighted_lb>` is
	// configured. These weights are ignored otherwise. If no weights are
	// specified when locality weighted load balancing is enabled, the locality is
	// assigned no load.
	LoadBalancingWeight *wrappers.UInt32Value `protobuf:"bytes,3,opt,name=load_balancing_weight,json=loadBalancingWeight,proto3" json:"load_balancing_weight,omitempty"`
	// Optional: the priority for this LocalityLbEndpoints. If unspecified this will
	// default to the highest priority (0).
	//
	// Under usual circumstances, Envoy will only select endpoints for the highest
	// priority (0). In the event all endpoints for a particular priority are
	// unavailable/unhealthy, Envoy will fail over to selecting endpoints for the
	// next highest priority group.
	//
	// Priorities should range from 0 (highest) to N (lowest) without skipping.
	Priority uint32 `protobuf:"varint,5,opt,name=priority,proto3" json:"priority,omitempty"`
	// Optional: Per locality proximity value which indicates how close this
	// locality is from the source locality. This value only provides ordering
	// information (lower the value, closer it is to the source locality).
	// This will be consumed by load balancing schemes that need proximity order
	// to determine where to route the requests.
	// [#not-implemented-hide:]
	Proximity *wrappers.UInt32Value `protobuf:"bytes,6,opt,name=proximity,proto3" json:"proximity,omitempty"`
}

func (x *LocalityLbEndpoints) Reset() {
	*x = LocalityLbEndpoints{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_api_v2_endpoint_endpoint_components_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LocalityLbEndpoints) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LocalityLbEndpoints) ProtoMessage() {}

func (x *LocalityLbEndpoints) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_api_v2_endpoint_endpoint_components_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LocalityLbEndpoints.ProtoReflect.Descriptor instead.
func (*LocalityLbEndpoints) Descriptor() ([]byte, []int) {
	return file_envoy_api_v2_endpoint_endpoint_components_proto_rawDescGZIP(), []int{2}
}

func (x *LocalityLbEndpoints) GetLocality() *core.Locality {
	if x != nil {
		return x.Locality
	}
	return nil
}

func (x *LocalityLbEndpoints) GetLbEndpoints() []*LbEndpoint {
	if x != nil {
		return x.LbEndpoints
	}
	return nil
}

func (x *LocalityLbEndpoints) GetLoadBalancingWeight() *wrappers.UInt32Value {
	if x != nil {
		return x.LoadBalancingWeight
	}
	return nil
}

func (x *LocalityLbEndpoints) GetPriority() uint32 {
	if x != nil {
		return x.Priority
	}
	return 0
}

func (x *LocalityLbEndpoints) GetProximity() *wrappers.UInt32Value {
	if x != nil {
		return x.Proximity
	}
	return nil
}

// The optional health check configuration.
type Endpoint_HealthCheckConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Optional alternative health check port value.
	//
	// By default the health check address port of an upstream host is the same
	// as the host's serving address port. This provides an alternative health
	// check port. Setting this with a non-zero value allows an upstream host
	// to have different health check address port.
	PortValue uint32 `protobuf:"varint,1,opt,name=port_value,json=portValue,proto3" json:"port_value,omitempty"`
	// By default, the host header for L7 health checks is controlled by cluster level configuration
	// (see: :ref:`host <envoy_api_field_core.HealthCheck.HttpHealthCheck.host>` and
	// :ref:`authority <envoy_api_field_core.HealthCheck.GrpcHealthCheck.authority>`). Setting this
	// to a non-empty value allows overriding the cluster level configuration for a specific
	// endpoint.
	Hostname string `protobuf:"bytes,2,opt,name=hostname,proto3" json:"hostname,omitempty"`
}

func (x *Endpoint_HealthCheckConfig) Reset() {
	*x = Endpoint_HealthCheckConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_api_v2_endpoint_endpoint_components_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Endpoint_HealthCheckConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Endpoint_HealthCheckConfig) ProtoMessage() {}

func (x *Endpoint_HealthCheckConfig) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_api_v2_endpoint_endpoint_components_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Endpoint_HealthCheckConfig.ProtoReflect.Descriptor instead.
func (*Endpoint_HealthCheckConfig) Descriptor() ([]byte, []int) {
	return file_envoy_api_v2_endpoint_endpoint_components_proto_rawDescGZIP(), []int{0, 0}
}

func (x *Endpoint_HealthCheckConfig) GetPortValue() uint32 {
	if x != nil {
		return x.PortValue
	}
	return 0
}

func (x *Endpoint_HealthCheckConfig) GetHostname() string {
	if x != nil {
		return x.Hostname
	}
	return ""
}

var File_envoy_api_v2_endpoint_endpoint_components_proto protoreflect.FileDescriptor

var file_envoy_api_v2_endpoint_endpoint_components_proto_rawDesc = []byte{
	0x0a, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x32, 0x2f, 0x65,
	0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x2f, 0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74,
	0x5f, 0x63, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x15, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x32, 0x2e,
	0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x1a, 0x1f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f,
	0x61, 0x70, 0x69, 0x2f, 0x76, 0x32, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x61, 0x64, 0x64, 0x72,
	0x65, 0x73, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x65, 0x6e, 0x76, 0x6f, 0x79,
	0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x32, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x62, 0x61, 0x73,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x24, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x61,
	0x70, 0x69, 0x2f, 0x76, 0x32, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x68, 0x65, 0x61, 0x6c, 0x74,
	0x68, 0x5f, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x77,
	0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x75,
	0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f,
	0x6d, 0x69, 0x67, 0x72, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x75,
	0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f,
	0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x76, 0x61,
	0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x9a, 0x02, 0x0a, 0x08, 0x45, 0x6e, 0x64, 0x70, 0x6f, 0x69,
	0x6e, 0x74, 0x12, 0x34, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x61, 0x70, 0x69, 0x2e,
	0x76, 0x32, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x52,
	0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x61, 0x0a, 0x13, 0x68, 0x65, 0x61, 0x6c,
	0x74, 0x68, 0x5f, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x31, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x61, 0x70,
	0x69, 0x2e, 0x76, 0x32, 0x2e, 0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x2e, 0x45, 0x6e,
	0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x2e, 0x48, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x43, 0x68, 0x65,
	0x63, 0x6b, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x11, 0x68, 0x65, 0x61, 0x6c, 0x74, 0x68,
	0x43, 0x68, 0x65, 0x63, 0x6b, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x1a, 0x0a, 0x08, 0x68,
	0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x68,
	0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x1a, 0x59, 0x0a, 0x11, 0x48, 0x65, 0x61, 0x6c, 0x74,
	0x68, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x28, 0x0a, 0x0a,
	0x70, 0x6f, 0x72, 0x74, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d,
	0x42, 0x09, 0xfa, 0x42, 0x06, 0x2a, 0x04, 0x18, 0xff, 0xff, 0x03, 0x52, 0x09, 0x70, 0x6f, 0x72,
	0x74, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61,
	0x6d, 0x65, 0x22, 0xdf, 0x02, 0x0a, 0x0a, 0x4c, 0x62, 0x45, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e,
	0x74, 0x12, 0x3d, 0x0a, 0x08, 0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x61, 0x70, 0x69, 0x2e,
	0x76, 0x32, 0x2e, 0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x2e, 0x45, 0x6e, 0x64, 0x70,
	0x6f, 0x69, 0x6e, 0x74, 0x48, 0x00, 0x52, 0x08, 0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74,
	0x12, 0x25, 0x0a, 0x0d, 0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x5f, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x0c, 0x65, 0x6e, 0x64, 0x70, 0x6f,
	0x69, 0x6e, 0x74, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x44, 0x0a, 0x0d, 0x68, 0x65, 0x61, 0x6c, 0x74,
	0x68, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x1f,
	0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x32, 0x2e, 0x63, 0x6f,
	0x72, 0x65, 0x2e, 0x48, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52,
	0x0c, 0x68, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x37, 0x0a,
	0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1b, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x32, 0x2e, 0x63,
	0x6f, 0x72, 0x65, 0x2e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x08, 0x6d, 0x65,
	0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x59, 0x0a, 0x15, 0x6c, 0x6f, 0x61, 0x64, 0x5f, 0x62,
	0x61, 0x6c, 0x61, 0x6e, 0x63, 0x69, 0x6e, 0x67, 0x5f, 0x77, 0x65, 0x69, 0x67, 0x68, 0x74, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x55, 0x49, 0x6e, 0x74, 0x33, 0x32, 0x56, 0x61,
	0x6c, 0x75, 0x65, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x2a, 0x02, 0x28, 0x01, 0x52, 0x13, 0x6c, 0x6f,
	0x61, 0x64, 0x42, 0x61, 0x6c, 0x61, 0x6e, 0x63, 0x69, 0x6e, 0x67, 0x57, 0x65, 0x69, 0x67, 0x68,
	0x74, 0x42, 0x11, 0x0a, 0x0f, 0x68, 0x6f, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69,
	0x66, 0x69, 0x65, 0x72, 0x22, 0xd1, 0x02, 0x0a, 0x13, 0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x69, 0x74,
	0x79, 0x4c, 0x62, 0x45, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x73, 0x12, 0x37, 0x0a, 0x08,
	0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x69, 0x74, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b,
	0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x32, 0x2e, 0x63, 0x6f,
	0x72, 0x65, 0x2e, 0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x69, 0x74, 0x79, 0x52, 0x08, 0x6c, 0x6f, 0x63,
	0x61, 0x6c, 0x69, 0x74, 0x79, 0x12, 0x44, 0x0a, 0x0c, 0x6c, 0x62, 0x5f, 0x65, 0x6e, 0x64, 0x70,
	0x6f, 0x69, 0x6e, 0x74, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x65, 0x6e,
	0x76, 0x6f, 0x79, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x32, 0x2e, 0x65, 0x6e, 0x64, 0x70, 0x6f,
	0x69, 0x6e, 0x74, 0x2e, 0x4c, 0x62, 0x45, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x52, 0x0b,
	0x6c, 0x62, 0x45, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x73, 0x12, 0x59, 0x0a, 0x15, 0x6c,
	0x6f, 0x61, 0x64, 0x5f, 0x62, 0x61, 0x6c, 0x61, 0x6e, 0x63, 0x69, 0x6e, 0x67, 0x5f, 0x77, 0x65,
	0x69, 0x67, 0x68, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x55, 0x49, 0x6e,
	0x74, 0x33, 0x32, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x2a, 0x02, 0x28,
	0x01, 0x52, 0x13, 0x6c, 0x6f, 0x61, 0x64, 0x42, 0x61, 0x6c, 0x61, 0x6e, 0x63, 0x69, 0x6e, 0x67,
	0x57, 0x65, 0x69, 0x67, 0x68, 0x74, 0x12, 0x24, 0x0a, 0x08, 0x70, 0x72, 0x69, 0x6f, 0x72, 0x69,
	0x74, 0x79, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x2a, 0x03, 0x18,
	0x80, 0x01, 0x52, 0x08, 0x70, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x12, 0x3a, 0x0a, 0x09,
	0x70, 0x72, 0x6f, 0x78, 0x69, 0x6d, 0x69, 0x74, 0x79, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x55, 0x49, 0x6e, 0x74, 0x33, 0x32, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x09, 0x70,
	0x72, 0x6f, 0x78, 0x69, 0x6d, 0x69, 0x74, 0x79, 0x42, 0x68, 0x0a, 0x23, 0x69, 0x6f, 0x2e, 0x65,
	0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e,
	0x61, 0x70, 0x69, 0x2e, 0x76, 0x32, 0x2e, 0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x42,
	0x17, 0x45, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x43, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65,
	0x6e, 0x74, 0x73, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0xf2, 0x98, 0xfe, 0x8f, 0x05, 0x1a,
	0x12, 0x18, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x65,
	0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x2e, 0x76, 0x33, 0xba, 0x80, 0xc8, 0xd1, 0x06, 0x02,
	0x10, 0x01, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_api_v2_endpoint_endpoint_components_proto_rawDescOnce sync.Once
	file_envoy_api_v2_endpoint_endpoint_components_proto_rawDescData = file_envoy_api_v2_endpoint_endpoint_components_proto_rawDesc
)

func file_envoy_api_v2_endpoint_endpoint_components_proto_rawDescGZIP() []byte {
	file_envoy_api_v2_endpoint_endpoint_components_proto_rawDescOnce.Do(func() {
		file_envoy_api_v2_endpoint_endpoint_components_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_api_v2_endpoint_endpoint_components_proto_rawDescData)
	})
	return file_envoy_api_v2_endpoint_endpoint_components_proto_rawDescData
}

var file_envoy_api_v2_endpoint_endpoint_components_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_envoy_api_v2_endpoint_endpoint_components_proto_goTypes = []interface{}{
	(*Endpoint)(nil),                   // 0: envoy.api.v2.endpoint.Endpoint
	(*LbEndpoint)(nil),                 // 1: envoy.api.v2.endpoint.LbEndpoint
	(*LocalityLbEndpoints)(nil),        // 2: envoy.api.v2.endpoint.LocalityLbEndpoints
	(*Endpoint_HealthCheckConfig)(nil), // 3: envoy.api.v2.endpoint.Endpoint.HealthCheckConfig
	(*core.Address)(nil),               // 4: envoy.api.v2.core.Address
	(core.HealthStatus)(0),             // 5: envoy.api.v2.core.HealthStatus
	(*core.Metadata)(nil),              // 6: envoy.api.v2.core.Metadata
	(*wrappers.UInt32Value)(nil),       // 7: google.protobuf.UInt32Value
	(*core.Locality)(nil),              // 8: envoy.api.v2.core.Locality
}
var file_envoy_api_v2_endpoint_endpoint_components_proto_depIdxs = []int32{
	4,  // 0: envoy.api.v2.endpoint.Endpoint.address:type_name -> envoy.api.v2.core.Address
	3,  // 1: envoy.api.v2.endpoint.Endpoint.health_check_config:type_name -> envoy.api.v2.endpoint.Endpoint.HealthCheckConfig
	0,  // 2: envoy.api.v2.endpoint.LbEndpoint.endpoint:type_name -> envoy.api.v2.endpoint.Endpoint
	5,  // 3: envoy.api.v2.endpoint.LbEndpoint.health_status:type_name -> envoy.api.v2.core.HealthStatus
	6,  // 4: envoy.api.v2.endpoint.LbEndpoint.metadata:type_name -> envoy.api.v2.core.Metadata
	7,  // 5: envoy.api.v2.endpoint.LbEndpoint.load_balancing_weight:type_name -> google.protobuf.UInt32Value
	8,  // 6: envoy.api.v2.endpoint.LocalityLbEndpoints.locality:type_name -> envoy.api.v2.core.Locality
	1,  // 7: envoy.api.v2.endpoint.LocalityLbEndpoints.lb_endpoints:type_name -> envoy.api.v2.endpoint.LbEndpoint
	7,  // 8: envoy.api.v2.endpoint.LocalityLbEndpoints.load_balancing_weight:type_name -> google.protobuf.UInt32Value
	7,  // 9: envoy.api.v2.endpoint.LocalityLbEndpoints.proximity:type_name -> google.protobuf.UInt32Value
	10, // [10:10] is the sub-list for method output_type
	10, // [10:10] is the sub-list for method input_type
	10, // [10:10] is the sub-list for extension type_name
	10, // [10:10] is the sub-list for extension extendee
	0,  // [0:10] is the sub-list for field type_name
}

func init() { file_envoy_api_v2_endpoint_endpoint_components_proto_init() }
func file_envoy_api_v2_endpoint_endpoint_components_proto_init() {
	if File_envoy_api_v2_endpoint_endpoint_components_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_api_v2_endpoint_endpoint_components_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Endpoint); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_envoy_api_v2_endpoint_endpoint_components_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LbEndpoint); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_envoy_api_v2_endpoint_endpoint_components_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LocalityLbEndpoints); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_envoy_api_v2_endpoint_endpoint_components_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Endpoint_HealthCheckConfig); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_envoy_api_v2_endpoint_endpoint_components_proto_msgTypes[1].OneofWrappers = []interface{}{
		(*LbEndpoint_Endpoint)(nil),
		(*LbEndpoint_EndpointName)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_envoy_api_v2_endpoint_endpoint_components_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_api_v2_endpoint_endpoint_components_proto_goTypes,
		DependencyIndexes: file_envoy_api_v2_endpoint_endpoint_components_proto_depIdxs,
		MessageInfos:      file_envoy_api_v2_endpoint_endpoint_components_proto_msgTypes,
	}.Build()
	File_envoy_api_v2_endpoint_endpoint_components_proto = out.File
	file_envoy_api_v2_endpoint_endpoint_components_proto_rawDesc = nil
	file_envoy_api_v2_endpoint_endpoint_components_proto_goTypes = nil
	file_envoy_api_v2_endpoint_endpoint_components_proto_depIdxs = nil
}
