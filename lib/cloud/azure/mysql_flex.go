/*
Copyright 2022 Gravitational, Inc.

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

package azure

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
)

type armMySQLFlexServersClient interface {
	NewListPager(*armmysqlflexibleservers.ServersClientListOptions) *runtime.Pager[armmysqlflexibleservers.ServersClientListResponse]
	NewListByResourceGroupPager(string, *armmysqlflexibleservers.ServersClientListByResourceGroupOptions) *runtime.Pager[armmysqlflexibleservers.ServersClientListByResourceGroupResponse]
}

// TODO(gavin): godoc
type mySQLFlexServersClient struct {
	api armMySQLFlexServersClient
}

var _ MySQLFlexServersClient = (*mySQLFlexServersClient)(nil)

// TODO(gavin): godoc
func NewMySQLFlexServersClient(subID string, cred azcore.TokenCredential, opts *arm.ClientOptions) (MySQLFlexServersClient, error) {
	logrus.Debug("Initializing Azure MySQL Flexible servers client.")
	api, err := armmysqlflexibleservers.NewServersClient(subID, cred, opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return NewMySQLFlexServersClientByAPI(api), nil
}

// TODO(gavin): godoc
func NewMySQLFlexServersClientByAPI(api armMySQLFlexServersClient) MySQLFlexServersClient {
	return &mySQLFlexServersClient{
		api: api,
	}
}

// TODO(gavin): godoc
func (c *mySQLFlexServersClient) ListAll(ctx context.Context) ([]*armmysqlflexibleservers.Server, error) {
	var servers []*armmysqlflexibleservers.Server
	opts := &armmysqlflexibleservers.ServersClientListOptions{}
	pager := c.api.NewListPager(opts)
	for pageNum := 0; pager.More(); pageNum++ {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, trace.Wrap(ConvertResponseError(err))
		}
		servers = append(servers, page.Value...)
	}
	return servers, nil
}

// TODO(gavin): godoc
func (c *mySQLFlexServersClient) ListWithinGroup(ctx context.Context, group string) ([]*armmysqlflexibleservers.Server, error) {
	var servers []*armmysqlflexibleservers.Server
	opts := &armmysqlflexibleservers.ServersClientListByResourceGroupOptions{}
	pager := c.api.NewListByResourceGroupPager(group, opts)
	for pageNum := 0; pager.More(); pageNum++ {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, trace.Wrap(ConvertResponseError(err))
		}
		servers = append(servers, page.Value...)
	}
	return servers, nil
}
