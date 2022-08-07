//TODO(gavin)

package azure

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysql"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/trace"
)

// mySQLClient implements ServersClient
var _ ServersClient = (*mySQLClient)(nil)

// mySQLClient wraps armmysql.ServersClient so we can implement the ServersClient interface.
type mySQLClient struct {
	client       *armmysql.ServersClient
	kind         string
	subscription string
}

// TODO(gavin)
func NewMySQLClient(subscription string, cred azcore.TokenCredential) (ServersClient, error) {
	// TODO(gavin): if/when we support AzureChina/AzureGovernment, we will need to specify the cloud in these options
	options := &arm.ClientOptions{}
	client, err := armmysql.NewServersClient(subscription, cred, options)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &mySQLClient{
		client:       client,
		kind:         "mysql",
		subscription: subscription,
	}, nil
}

// ListServers lists all database servers within an Azure subscription.
func (c *mySQLClient) ListServers(ctx context.Context, group string, maxPages int) ([]Server, error) {
	var servers []*armmysql.Server
	var err error
	if group == types.Wildcard {
		servers, err = c.listAll(ctx, maxPages)
	} else {
		servers, err = c.listByGroup(ctx, group, maxPages)
	}
	if err != nil {
		// TODO(gavin) convert at call site?
		return nil, trace.Wrap(err)
	}

	result := make([]Server, 0, len(servers))
	for _, s := range servers {
		server, err := ServerFromMySQLServer(s)
		if err != nil {
			continue
		}
		result = append(result, server)
	}
	return result, nil
}

// TODO(gavin)
func (c *mySQLClient) Kind() string {
	return c.kind
}

// TODO(gavin)
func (c *mySQLClient) Subscription() string {
	return c.subscription
}

func (c *mySQLClient) Get(ctx context.Context, group, name string) (Server, error) {
	res, err := c.client.Get(ctx, group, name, nil)
	if err != nil {
		// TODO(gavin) convert at call site?
		return nil, trace.Wrap(err)
	}
	server, err := ServerFromMySQLServer(&res.Server)
	return server, trace.Wrap(err)
}

// TODO(gavin)
func (c *mySQLClient) listAll(ctx context.Context, maxPages int) ([]*armmysql.Server, error) {
	var servers []*armmysql.Server
	options := &armmysql.ServersClientListOptions{}
	pager := c.client.NewListPager(options)
	for pageNum := 0; pageNum < maxPages && pager.More(); pageNum++ {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		servers = append(servers, page.Value...)
	}
	return servers, nil
}

// TODO(gavin)
func (c *mySQLClient) listByGroup(ctx context.Context, group string, maxPages int) ([]*armmysql.Server, error) {
	var servers []*armmysql.Server
	options := &armmysql.ServersClientListByResourceGroupOptions{}
	pager := c.client.NewListByResourceGroupPager(group, options)
	for pageNum := 0; pageNum < maxPages && pager.More(); pageNum++ {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		servers = append(servers, page.Value...)
	}
	return servers, nil
}

var _ Server = (*mySQLServer)(nil)

type mySQLServer struct {
	server *armmysql.Server
	tags   map[string]string
	id     types.AzureResourceID
}

// TODO(gavin)
func ServerFromMySQLServer(server *armmysql.Server) (Server, error) {
	if server == nil {
		return nil, trace.BadParameter("nil server")
	}
	id, err := parseID(server.ID)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &mySQLServer{
		server: server,
		tags:   convertTags(server.Tags),
		id:     *id,
	}, nil
}

// IsVersionSupported returns true if database supports AAD authentication.
// Only available for 5.7 and newer.
func (s *mySQLServer) IsVersionSupported() bool {
	switch armmysql.ServerVersion(s.Version()) {
	case armmysql.ServerVersionEight0, armmysql.ServerVersionFive7:
		return true
	case armmysql.ServerVersionFive6:
		return false
	default:
		return false
	}
}

// TODO(gavin)
func (s *mySQLServer) IsAvailable() bool {
	switch armmysql.ServerState(s.State()) {
	case armmysql.ServerStateReady:
		return true
	case armmysql.ServerStateInaccessible,
		armmysql.ServerStateDropping,
		armmysql.ServerStateDisabled:
		return false
	default:
		return false
	}
}

// TODO(gavin)
func (s *mySQLServer) Region() string {
	return stringVal(s.server.Location)
}

// TODO(gavin)
func (s *mySQLServer) Version() string {
	if s.server.Properties != nil && s.server.Properties.Version != nil {
		return string(*s.server.Properties.Version)
	}
	return ""
}

// TODO(gavin)
func (s *mySQLServer) Name() string {
	return stringVal(s.server.Name)
}

// TODO(gavin)
func (s *mySQLServer) Endpoint() string {
	if s.server.Properties != nil && s.server.Properties.FullyQualifiedDomainName != nil {
		return *s.server.Properties.FullyQualifiedDomainName + ":" + MySQLPort
	}
	return ""
}

// TODO(gavin)
func (s *mySQLServer) ID() types.AzureResourceID {
	return s.id
}

// TODO(gavin)
func (s *mySQLServer) Protocol() string {
	return defaults.ProtocolMySQL
}

// TODO(gavin)
func (s *mySQLServer) State() string {
	if s.server.Properties != nil && s.server.Properties.UserVisibleState != nil {
		return string(*s.server.Properties.UserVisibleState)
	}
	return ""
}

// TODO(gavin)
func (s *mySQLServer) Tags() map[string]string {
	return s.tags
}

// TODO(gavin)
func parseID(id *string) (*types.AzureResourceID, error) {
	if id == nil {
		return nil, trace.BadParameter("nil server ID")
	}
	rid, err := arm.ParseResourceID(*id)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &types.AzureResourceID{
		SubscriptionID:    rid.SubscriptionID,
		ResourceGroup:     rid.ResourceGroupName,
		ProviderNamespace: rid.ResourceType.Namespace,
		ResourceType:      rid.ResourceType.Type,
		ResourceName:      rid.Name,
	}, nil
}

func stringVal(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

func convertTags(azureTags map[string]*string) map[string]string {
	tags := make(map[string]string, len(azureTags))
	for k, v := range azureTags {
		if v != nil {
			tags[k] = *v
		}
	}
	return tags
}
