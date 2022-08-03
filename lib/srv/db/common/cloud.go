/*
Copyright 2021 Gravitational, Inc.

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

package common

import (
	"context"
	"io"
	"sync"

	gcpcredentials "cloud.google.com/go/iam/credentials/apiv1"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresql"
	"github.com/aws/aws-sdk-go/aws"
	awssession "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/elasticache"
	"github.com/aws/aws-sdk-go/service/elasticache/elasticacheiface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/aws/aws-sdk-go/service/memorydb"
	"github.com/aws/aws-sdk-go/service/memorydb/memorydbiface"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/rds/rdsiface"
	"github.com/aws/aws-sdk-go/service/redshift"
	"github.com/aws/aws-sdk-go/service/redshift/redshiftiface"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
)

// CloudClients provides interface for obtaining cloud provider clients.
type CloudClients interface {
	// GetAWSSession returns AWS session for the specified region.
	GetAWSSession(region string) (*awssession.Session, error)
	// GetAWSRDSClient returns AWS RDS client for the specified region.
	GetAWSRDSClient(region string) (rdsiface.RDSAPI, error)
	// GetAWSRedshiftClient returns AWS Redshift client for the specified region.
	GetAWSRedshiftClient(region string) (redshiftiface.RedshiftAPI, error)
	// GetAWSElastiCacheClient returns AWS ElastiCache client for the specified region.
	GetAWSElastiCacheClient(region string) (elasticacheiface.ElastiCacheAPI, error)
	// GetAWSMemoryDBClient returns AWS MemoryDB client for the specified region.
	GetAWSMemoryDBClient(region string) (memorydbiface.MemoryDBAPI, error)
	// GetAWSSecretsManagerClient returns AWS Secrets Manager client for the specified region.
	GetAWSSecretsManagerClient(region string) (secretsmanageriface.SecretsManagerAPI, error)
	// GetAWSIAMClient returns AWS IAM client for the specified region.
	GetAWSIAMClient(region string) (iamiface.IAMAPI, error)
	// GetAWSSTSClient returns AWS STS client for the specified region.
	GetAWSSTSClient(region string) (stsiface.STSAPI, error)
	// GetGCPIAMClient returns GCP IAM client.
	GetGCPIAMClient(context.Context) (*gcpcredentials.IamCredentialsClient, error)
	// GetGCPSQLAdminClient returns GCP Cloud SQL Admin client.
	GetGCPSQLAdminClient(context.Context) (GCPSQLAdminClient, error)
	// GetAzureCredential returns Azure default token credential chain.
	GetAzureCredential() (azcore.TokenCredential, error)
	// GetAzureMySQLClient returns Azure MySQL client for the specified subscription.
	GetAzureMySQLClient(subscription string, cred azcore.TokenCredential) (AzureMySQLClient, error)
	// GetAzurePostgresClient returns Azure Postgres client for the specified subscription.
	GetAzurePostgresClient(subscription string, cred azcore.TokenCredential) (AzurePostgresClient, error)
	// Closer closes all initialized clients.
	io.Closer
}

// NewCloudClients returns a new instance of cloud clients retriever.
func NewCloudClients() CloudClients {
	return &cloudClients{
		awsSessions:       make(map[string]*awssession.Session),
		azureMySQLClients: make(map[string]AzureMySQLClient),
	}
}

// cloudClients implements CloudClients
var _ CloudClients = (*cloudClients)(nil)

type cloudClients struct {
	// awsSessions is a map of cached AWS sessions per region.
	awsSessions map[string]*awssession.Session
	// gcpIAM is the cached GCP IAM client.
	gcpIAM *gcpcredentials.IamCredentialsClient
	// gcpSQLAdmin is the cached GCP Cloud SQL Admin client.
	gcpSQLAdmin GCPSQLAdminClient
	// azureCredential is the cached Azure credential.
	azureCredential azcore.TokenCredential
	// azureMySQLClients is the cached Azure MySQL Server clients.
	azureMySQLClients map[string]AzureMySQLClient
	// azurePostgresClients is the cached Azure Postgres Server clients.
	azurePostgresClients map[string]AzurePostgresClient
	// mtx is used for locking.
	mtx sync.RWMutex
}

// AzureMySQLClient provides an interface for getting MySQL servers.
type AzureMySQLClient interface {
	// ListServers lists all Azure MySQL servers within an Azure subscription.
	ListServers(ctx context.Context) ([]*armmysql.Server, error)
}

// ARMMySQLServersClient implements AzureMySQLClient.
var _ AzureMySQLClient = (*azureMySQLClientWrapper)(nil)

// azureMySQLClientWrapper wraps armmysql.ServersClient so we can implement the AzureMySQLClient interface.
type azureMySQLClientWrapper struct {
	client *armmysql.ServersClient
}

// ListServers lists all Azure MySQL servers within an Azure subscription, using a configured armmysql client.
func (wrapper *azureMySQLClientWrapper) ListServers(ctx context.Context) ([]*armmysql.Server, error) {
	var servers []*armmysql.Server
	options := &armmysql.ServersClientListOptions{}
	pager := wrapper.client.NewListPager(options)
	for pageNum := 0; pageNum <= MaxPages && pager.More(); pageNum++ {
		page, err := pager.NextPage(ctx)
		if err != nil {
			// TODO(gavin): convert from azure error to trace error
			return nil, trace.Wrap(err)
		}
		for _, server := range page.Value {
			if server != nil {
				servers = append(servers, server)
			}
		}
	}
	return servers, nil
}

// AzurePostgresClient provides an interface for getting Postgres servers.
type AzurePostgresClient interface {
	// ListServers lists all Azure Postgres servers within an Azure subscription.
	ListServers(ctx context.Context) ([]*armpostgresql.Server, error)
}

// azurePostgresClientWrapper implements AzurePostgresClient.
var _ AzurePostgresClient = (*azurePostgresClientWrapper)(nil)

// azurePostgresClientWrapper wraps armpostgresql.ServersClient so we can implement the AzurePostgresClient interface.
type azurePostgresClientWrapper struct {
	client *armpostgresql.ServersClient
}

// ListServers lists all Azure Postgres servers within an Azure subscription, using a configured armpostgresql client.
func (wrapper *azurePostgresClientWrapper) ListServers(ctx context.Context) ([]*armpostgresql.Server, error) {
	var servers []*armpostgresql.Server
	options := &armpostgresql.ServersClientListOptions{}
	pager := wrapper.client.NewListPager(options)
	for pageNum := 0; pageNum <= MaxPages && pager.More(); pageNum++ {
		page, err := pager.NextPage(ctx)
		if err != nil {
			// TODO(gavin): convert from azure error to trace error
			return nil, trace.Wrap(err)
		}
		for _, server := range page.Value {
			if server != nil {
				servers = append(servers, server)
			}
		}
	}
	return servers, nil
}

// GetAWSSession returns AWS session for the specified region.
func (c *cloudClients) GetAWSSession(region string) (*awssession.Session, error) {
	c.mtx.RLock()
	if session, ok := c.awsSessions[region]; ok {
		c.mtx.RUnlock()
		return session, nil
	}
	c.mtx.RUnlock()
	return c.initAWSSession(region)
}

// GetAWSRDSClient returns AWS RDS client for the specified region.
func (c *cloudClients) GetAWSRDSClient(region string) (rdsiface.RDSAPI, error) {
	session, err := c.GetAWSSession(region)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return rds.New(session), nil
}

// GetAWSRedshiftClient returns AWS Redshift client for the specified region.
func (c *cloudClients) GetAWSRedshiftClient(region string) (redshiftiface.RedshiftAPI, error) {
	session, err := c.GetAWSSession(region)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return redshift.New(session), nil
}

// GetAWSElastiCacheClient returns AWS ElastiCache client for the specified region.
func (c *cloudClients) GetAWSElastiCacheClient(region string) (elasticacheiface.ElastiCacheAPI, error) {
	session, err := c.GetAWSSession(region)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return elasticache.New(session), nil
}

// GetAWSMemoryDBClient returns AWS MemoryDB client for the specified region.
func (c *cloudClients) GetAWSMemoryDBClient(region string) (memorydbiface.MemoryDBAPI, error) {
	session, err := c.GetAWSSession(region)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return memorydb.New(session), nil
}

// GetAWSSecretsManagerClient returns AWS Secrets Manager client for the specified region.
func (c *cloudClients) GetAWSSecretsManagerClient(region string) (secretsmanageriface.SecretsManagerAPI, error) {
	session, err := c.GetAWSSession(region)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return secretsmanager.New(session), nil
}

// GetAWSIAMClient returns AWS IAM client for the specified region.
func (c *cloudClients) GetAWSIAMClient(region string) (iamiface.IAMAPI, error) {
	session, err := c.GetAWSSession(region)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return iam.New(session), nil
}

// GetAWSSTSClient returns AWS STS client for the specified region.
func (c *cloudClients) GetAWSSTSClient(region string) (stsiface.STSAPI, error) {
	session, err := c.GetAWSSession(region)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return sts.New(session), nil
}

// GetGCPIAMClient returns GCP IAM client.
func (c *cloudClients) GetGCPIAMClient(ctx context.Context) (*gcpcredentials.IamCredentialsClient, error) {
	c.mtx.RLock()
	if c.gcpIAM != nil {
		defer c.mtx.RUnlock()
		return c.gcpIAM, nil
	}
	c.mtx.RUnlock()
	return c.initGCPIAMClient(ctx)
}

// GetGCPSQLAdminClient returns GCP Cloud SQL Admin client.
func (c *cloudClients) GetGCPSQLAdminClient(ctx context.Context) (GCPSQLAdminClient, error) {
	c.mtx.RLock()
	if c.gcpSQLAdmin != nil {
		defer c.mtx.RUnlock()
		return c.gcpSQLAdmin, nil
	}
	c.mtx.RUnlock()
	return c.initGCPSQLAdminClient(ctx)
}

// GetAzureCredential returns default Azure token credential chain.
func (c *cloudClients) GetAzureCredential() (azcore.TokenCredential, error) {
	c.mtx.RLock()
	if c.azureCredential != nil {
		defer c.mtx.RUnlock()
		return c.azureCredential, nil
	}
	c.mtx.RUnlock()
	return c.initAzureCredential()
}

// GetAzureMySQLClient returns an AzureMySQLClient for the given subscription.
func (c *cloudClients) GetAzureMySQLClient(subscription string, cred azcore.TokenCredential) (AzureMySQLClient, error) {
	c.mtx.RLock()
	if client, ok := c.azureMySQLClients[subscription]; ok {
		c.mtx.RUnlock()
		return client, nil
	}
	c.mtx.RUnlock()
	return c.initAzureMySQLClient(subscription, cred)
}

// GetAzurePostgresClient returns an AzurePostgresClient for the given subscription.
func (c *cloudClients) GetAzurePostgresClient(subscription string, cred azcore.TokenCredential) (AzurePostgresClient, error) {
	c.mtx.RLock()
	if client, ok := c.azurePostgresClients[subscription]; ok {
		c.mtx.RUnlock()
		return client, nil
	}
	c.mtx.RUnlock()
	return c.initAzurePostgresClient(subscription, cred)
}

// Close closes all initialized clients.
func (c *cloudClients) Close() (err error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.gcpIAM != nil {
		err = c.gcpIAM.Close()
		c.gcpIAM = nil
	}
	return trace.Wrap(err)
}

func (c *cloudClients) initAWSSession(region string) (*awssession.Session, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if session, ok := c.awsSessions[region]; ok { // If some other thead already got here first.
		return session, nil
	}
	logrus.Debugf("Initializing AWS session for region %v.", region)
	session, err := awssession.NewSessionWithOptions(awssession.Options{
		SharedConfigState: awssession.SharedConfigEnable,
		Config: aws.Config{
			Region: aws.String(region),
		},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	c.awsSessions[region] = session
	return session, nil
}

func (c *cloudClients) initGCPIAMClient(ctx context.Context) (*gcpcredentials.IamCredentialsClient, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.gcpIAM != nil { // If some other thread already got here first.
		return c.gcpIAM, nil
	}
	logrus.Debug("Initializing GCP IAM client.")
	gcpIAM, err := gcpcredentials.NewIamCredentialsClient(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	c.gcpIAM = gcpIAM
	return gcpIAM, nil
}

func (c *cloudClients) initGCPSQLAdminClient(ctx context.Context) (GCPSQLAdminClient, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.gcpSQLAdmin != nil { // If some other thread already got here first.
		return c.gcpSQLAdmin, nil
	}
	logrus.Debug("Initializing GCP Cloud SQL Admin client.")
	gcpSQLAdmin, err := NewGCPSQLAdminClient(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	c.gcpSQLAdmin = gcpSQLAdmin
	return gcpSQLAdmin, nil
}

func (c *cloudClients) initAzureCredential() (azcore.TokenCredential, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.azureCredential != nil { // If some other thread already got here first.
		return c.azureCredential, nil
	}
	logrus.Debug("Initializing Azure default credential chain.")
	// TODO(gavin): if/when we support AzureChina/AzureGovernment, we will need to specify the cloud in these options
	options := &azidentity.DefaultAzureCredentialOptions{}
	cred, err := azidentity.NewDefaultAzureCredential(options)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	c.azureCredential = cred
	return cred, nil
}

func (c *cloudClients) initAzureMySQLClient(subscription string, cred azcore.TokenCredential) (AzureMySQLClient, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if client, ok := c.azureMySQLClients[subscription]; ok { // If some other thread already got here first.
		return client, nil
	}
	logrus.Debug("Initializing Azure MySQL servers client.")
	// TODO(gavin): if/when we support AzureChina/AzureGovernment, we will need to specify the cloud in these options
	options := &arm.ClientOptions{}
	client, err := armmysql.NewServersClient(subscription, cred, options)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	wrappedClient := &azureMySQLClientWrapper{client: client}
	c.azureMySQLClients[subscription] = wrappedClient
	return wrappedClient, nil
}

func (c *cloudClients) initAzurePostgresClient(subscription string, cred azcore.TokenCredential) (AzurePostgresClient, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if client, ok := c.azurePostgresClients[subscription]; ok { // If some other thread already got here first.
		return client, nil
	}
	logrus.Debug("Initializing Azure Postgres servers client.")
	// TODO(gavin): if/when we support AzureChina/AzureGovernment, we will need to specify the cloud in these options
	options := &arm.ClientOptions{}
	client, err := armpostgresql.NewServersClient(subscription, cred, options)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	wrappedClient := &azurePostgresClientWrapper{client: client}
	c.azurePostgresClients[subscription] = wrappedClient
	return wrappedClient, nil
}

// TestCloudClients implements CloudClients
var _ CloudClients = (*TestCloudClients)(nil)

// TestCloudClients are used in tests.
type TestCloudClients struct {
	RDS                 rdsiface.RDSAPI
	RDSPerRegion        map[string]rdsiface.RDSAPI
	Redshift            redshiftiface.RedshiftAPI
	ElastiCache         elasticacheiface.ElastiCacheAPI
	MemoryDB            memorydbiface.MemoryDBAPI
	SecretsManager      secretsmanageriface.SecretsManagerAPI
	IAM                 iamiface.IAMAPI
	STS                 stsiface.STSAPI
	GCPSQL              GCPSQLAdminClient
	AzureMySQL          AzureMySQLClient
	AzureMySQLPerSub    map[string]AzureMySQLClient
	AzurePostgres       AzurePostgresClient
	AzurePostgresPerSub map[string]AzurePostgresClient
}

// GetAWSSession returns AWS session for the specified region.
func (c *TestCloudClients) GetAWSSession(region string) (*awssession.Session, error) {
	return nil, trace.NotImplemented("not implemented")
}

// GetAWSRDSClient returns AWS RDS client for the specified region.
func (c *TestCloudClients) GetAWSRDSClient(region string) (rdsiface.RDSAPI, error) {
	if len(c.RDSPerRegion) != 0 {
		return c.RDSPerRegion[region], nil
	}
	return c.RDS, nil
}

// GetAWSRedshiftClient returns AWS Redshift client for the specified region.
func (c *TestCloudClients) GetAWSRedshiftClient(region string) (redshiftiface.RedshiftAPI, error) {
	return c.Redshift, nil
}

// GetAWSElastiCacheClient returns AWS ElastiCache client for the specified region.
func (c *TestCloudClients) GetAWSElastiCacheClient(region string) (elasticacheiface.ElastiCacheAPI, error) {
	return c.ElastiCache, nil
}

// GetAWSMemoryDBClient returns AWS MemoryDB client for the specified region.
func (c *TestCloudClients) GetAWSMemoryDBClient(region string) (memorydbiface.MemoryDBAPI, error) {
	return c.MemoryDB, nil
}

// GetAWSSecretsManagerClient returns AWS Secrets Manager client for the specified region.
func (c *TestCloudClients) GetAWSSecretsManagerClient(region string) (secretsmanageriface.SecretsManagerAPI, error) {
	return c.SecretsManager, nil
}

// GetAWSIAMClient returns AWS IAM client for the specified region.
func (c *TestCloudClients) GetAWSIAMClient(region string) (iamiface.IAMAPI, error) {
	return c.IAM, nil
}

// GetAWSSTSClient returns AWS STS client for the specified region.
func (c *TestCloudClients) GetAWSSTSClient(region string) (stsiface.STSAPI, error) {
	return c.STS, nil
}

// GetGCPIAMClient returns GCP IAM client.
func (c *TestCloudClients) GetGCPIAMClient(ctx context.Context) (*gcpcredentials.IamCredentialsClient, error) {
	return gcpcredentials.NewIamCredentialsClient(ctx,
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())), // Insecure must be set for unauth client.
		option.WithoutAuthentication())
}

// GetGCPSQLAdminClient returns GCP Cloud SQL Admin client.
func (c *TestCloudClients) GetGCPSQLAdminClient(ctx context.Context) (GCPSQLAdminClient, error) {
	return c.GCPSQL, nil
}

// GetAzureCredential returns default Azure token credential chain.
func (c *TestCloudClients) GetAzureCredential() (azcore.TokenCredential, error) {
	return &azidentity.ChainedTokenCredential{}, nil
}

// GetAzureMySQLClient returns an AzureMySQLClient for the specified subscription
func (c *TestCloudClients) GetAzureMySQLClient(subscription string, cred azcore.TokenCredential) (AzureMySQLClient, error) {
	if len(c.AzureMySQLPerSub) != 0 {
		return c.AzureMySQLPerSub[subscription], nil
	}
	return c.AzureMySQL, nil
}

// GetAzurePostgresClient returns an AzurePostgresClient for the specified subscription
func (c *TestCloudClients) GetAzurePostgresClient(subscription string, cred azcore.TokenCredential) (AzurePostgresClient, error) {
	if len(c.AzurePostgresPerSub) != 0 {
		return c.AzurePostgresPerSub[subscription], nil
	}
	return c.AzurePostgres, nil
}

// Close closes all initialized clients.
func (c *TestCloudClients) Close() error {
	return nil
}

// FilterDatabasesByLabels filters input databases with provided labels.
func FilterDatabasesByLabels(databases types.Databases, labels types.Labels, log logrus.FieldLogger) types.Databases {
	var matchedDatabases types.Databases
	for _, database := range databases {
		match, _, err := services.MatchLabels(labels, database.GetAllLabels())
		if err != nil {
			log.Warnf("Failed to match %v against selector: %v.", database, err)
		} else if match {
			matchedDatabases = append(matchedDatabases, database)
		} else {
			log.Debugf("%v doesn't match selector.", database)
		}
	}
	return matchedDatabases
}
