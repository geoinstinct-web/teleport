package local

import (
	"context"
	"log/slog"
	"net"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/gen/proto/go/teleport/vnet/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local/generic"
	"github.com/gravitational/trace"
)

const (
	vnetConfigPrefix        = "vnet_config"
	vnetConfigSingletonName = "vnet-config"
)

type VnetConfigService struct {
	slog *slog.Logger
	svc  *generic.ServiceWrapper[*vnet.VnetConfig]
}

func NewVnetConfigService(backend backend.Backend) (*VnetConfigService, error) {
	svc, err := generic.NewServiceWrapper(
		backend,
		types.KindVnetConfig,
		vnetConfigPrefix,
		services.MarshalProtoResource[*vnet.VnetConfig],
		services.UnmarshalProtoResource[*vnet.VnetConfig],
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &VnetConfigService{
		svc:  svc,
		slog: slog.With(teleport.ComponentKey, "VnetConfig.local"),
	}, nil
}

func (s *VnetConfigService) GetVnetConfig(ctx context.Context) (*vnet.VnetConfig, error) {
	return s.svc.GetResource(ctx, vnetConfigSingletonName)
}

func (s *VnetConfigService) CreateVnetConfig(ctx context.Context, vnetConfig *vnet.VnetConfig) (*vnet.VnetConfig, error) {
	if err := validateVnetConfig(vnetConfig); err != nil {
		return nil, trace.Wrap(err)
	}
	return s.svc.CreateResource(ctx, vnetConfig)
}

func (s *VnetConfigService) UpdateVnetConfig(ctx context.Context, vnetConfig *vnet.VnetConfig) (*vnet.VnetConfig, error) {
	if err := validateVnetConfig(vnetConfig); err != nil {
		return nil, trace.Wrap(err)
	}
	return s.svc.ConditionalUpdateResource(ctx, vnetConfig)
}

func (s *VnetConfigService) UpsertVnetConfig(ctx context.Context, vnetConfig *vnet.VnetConfig) (*vnet.VnetConfig, error) {
	if err := validateVnetConfig(vnetConfig); err != nil {
		return nil, trace.Wrap(err)
	}
	return s.svc.UpsertResource(ctx, vnetConfig)
}

func (s *VnetConfigService) DeleteVnetConfig(ctx context.Context) error {
	return s.svc.DeleteResource(ctx, vnetConfigSingletonName)
}

func validateVnetConfig(vnetConfig *vnet.VnetConfig) error {
	if vnetConfig.GetKind() != types.KindVnetConfig {
		return trace.BadParameter("kind must be %q", types.KindVnetConfig)
	}
	if vnetConfig.GetVersion() != types.V1 {
		return trace.BadParameter("version must be %q", types.V1)
	}
	if vnetConfig.GetMetadata().GetName() != vnetConfigSingletonName {
		return trace.BadParameter("name must be %q", vnetConfigSingletonName)
	}
	if cidrRange := vnetConfig.GetSpec().GetCidrRange(); cidrRange != "" {
		ip, _, err := net.ParseCIDR(cidrRange)
		if err != nil {
			return trace.Wrap(err, "parsing cidr_range")
		}
		if ip4 := ip.To4(); ip4 == nil {
			return trace.BadParameter("cidr_range must be IPv4")
		}
	}
	return nil
}
