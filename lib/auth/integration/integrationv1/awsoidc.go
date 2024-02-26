/*
Copyright 2023 Gravitational, Inc.

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

package integrationv1

import (
	"context"
	"time"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"

	integrationpb "github.com/gravitational/teleport/api/gen/proto/go/teleport/integration/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/integrations/awsoidc"
	"github.com/gravitational/teleport/lib/jwt"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils/oidc"
)

// GenerateAWSOIDCToken generates a token to be used when executing an AWS OIDC Integration action.
func (s *Service) GenerateAWSOIDCToken(ctx context.Context, _ *integrationpb.GenerateAWSOIDCTokenRequest) (*integrationpb.GenerateAWSOIDCTokenResponse, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := authCtx.CheckAccessToKind(types.KindIntegration, types.VerbUse); err != nil {
		return nil, trace.Wrap(err)
	}
	return s.generateAWSOIDCTokenWithoutAuthZ(ctx)
}

// generateAWSOIDCTokenWithoutAuthZ generates a token to be used when executing an AWS OIDC Integration action.
// Bypasses authz and should only be used by other methods that validate AuthZ.
func (s *Service) generateAWSOIDCTokenWithoutAuthZ(ctx context.Context) (*integrationpb.GenerateAWSOIDCTokenResponse, error) {
	username, err := authz.GetClientUsername(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	clusterName, err := s.cache.GetClusterName()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	ca, err := s.cache.GetCertAuthority(ctx, types.CertAuthID{
		Type:       types.OIDCIdPCA,
		DomainName: clusterName.GetClusterName(),
	}, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Extract the JWT signing key and sign the claims.
	signer, err := s.keyStoreManager.GetJWTSigner(ctx, ca)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	privateKey, err := services.GetJWTSigner(signer, ca.GetClusterName(), s.clock)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	issuer, err := oidc.IssuerForCluster(ctx, s.cache)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	token, err := privateKey.SignAWSOIDC(jwt.SignParams{
		Username: username,
		Audience: types.IntegrationAWSOIDCAudience,
		Subject:  types.IntegrationAWSOIDCSubject,
		Issuer:   issuer,
		// Token expiration is not controlled by the Expires property.
		// It is defined by assumed IAM Role's "Maximum session duration" (usually 1h).
		Expires: s.clock.Now().Add(time.Minute),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &integrationpb.GenerateAWSOIDCTokenResponse{
		Token: token,
	}, nil
}

// AWSOIDCServiceConfig holds configuration options for the AWSOIDC Integration gRPC service.
type AWSOIDCServiceConfig struct {
	IntegrationService *Service
	Authorizer         authz.Authorizer
	Cache              CacheAWSOIDC
	Logger             *logrus.Entry
}

// CheckAndSetDefaults checks the AWSOIDCServiceConfig fields and returns an error if a required param is not provided.
// Authorizer and IntegrationService are required params.
func (s *AWSOIDCServiceConfig) CheckAndSetDefaults() error {
	if s.Authorizer == nil {
		return trace.BadParameter("authorizer is required")
	}

	if s.IntegrationService == nil {
		return trace.BadParameter("integration service is required")
	}

	if s.Cache == nil {
		return trace.BadParameter("cache is required")
	}

	if s.Logger == nil {
		s.Logger = logrus.WithField(trace.Component, "integrations.awsoidc.service")
	}

	return nil
}

// AWSOIDCService implements the teleport.integration.v1.AWSOIDCService RPC service.
type AWSOIDCService struct {
	integrationpb.UnimplementedAWSOIDCServiceServer

	integrationService *Service
	authorizer         authz.Authorizer
	logger             *logrus.Entry
	cache              CacheAWSOIDC
}

// CacheAWSOIDC is the subset of the cached resources that the Service queries.
type CacheAWSOIDC interface {
	// GetToken returns a provision token by name.
	GetToken(ctx context.Context, name string) (types.ProvisionToken, error)

	// UpsertToken creates or updates a provision token.
	UpsertToken(ctx context.Context, token types.ProvisionToken) error

	// GetClusterName returns the current cluster name.
	GetClusterName(...services.MarshalOption) (types.ClusterName, error)
}

// NewAWSOIDCService returns a new AWSOIDCService.
func NewAWSOIDCService(cfg *AWSOIDCServiceConfig) (*AWSOIDCService, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	return &AWSOIDCService{
		integrationService: cfg.IntegrationService,
		logger:             cfg.Logger,
		authorizer:         cfg.Authorizer,
		cache:              cfg.Cache,
	}, nil
}

var _ integrationpb.AWSOIDCServiceServer = (*AWSOIDCService)(nil)

func (s *AWSOIDCService) awsClientReq(ctx context.Context, integrationName, region string) (*awsoidc.AWSClientRequest, error) {
	integration, err := s.integrationService.GetIntegration(ctx, &integrationpb.GetIntegrationRequest{
		Name: integrationName,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if integration.GetSubKind() != types.IntegrationSubKindAWSOIDC {
		return nil, trace.BadParameter("integration subkind (%s) mismatch", integration.GetSubKind())
	}

	awsoidcSpec := integration.GetAWSOIDCIntegrationSpec()
	if awsoidcSpec == nil {
		return nil, trace.BadParameter("missing spec fields for %q (%q) integration", integration.GetName(), integration.GetSubKind())
	}

	token, err := s.integrationService.generateAWSOIDCTokenWithoutAuthZ(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &awsoidc.AWSClientRequest{
		IntegrationName: integrationName,
		Token:           token.Token,
		RoleARN:         integration.GetAWSOIDCIntegrationSpec().RoleARN,
		Region:          region,
	}, nil
}

// ListDatabases returns a paginated list of Databases.
func (s *AWSOIDCService) ListDatabases(ctx context.Context, req *integrationpb.ListDatabasesRequest) (*integrationpb.ListDatabasesResponse, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := authCtx.CheckAccessToKind(types.KindIntegration, types.VerbUse); err != nil {
		return nil, trace.Wrap(err)
	}

	awsClientReq, err := s.awsClientReq(ctx, req.Integration, req.Region)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	listDBsClient, err := awsoidc.NewListDatabasesClient(ctx, awsClientReq)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	listDBsResp, err := awsoidc.ListDatabases(ctx, listDBsClient, awsoidc.ListDatabasesRequest{
		Region:    req.Region,
		RDSType:   req.RdsType,
		Engines:   req.Engines,
		NextToken: req.NextToken,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	dbList := make([]*types.DatabaseV3, 0, len(listDBsResp.Databases))
	for _, db := range listDBsResp.Databases {
		dbV3, ok := db.(*types.DatabaseV3)
		if !ok {
			s.logger.Warnf("Skipping %s because conversion (%T) to DatabaseV3 failed: %v", db.GetName(), db, err)
			continue
		}
		dbList = append(dbList, dbV3)
	}

	return &integrationpb.ListDatabasesResponse{
		Databases: dbList,
		NextToken: listDBsResp.NextToken,
	}, nil
}

// DeployDatabaseService deploys Database Services into Amazon ECS.
func (s *AWSOIDCService) DeployDatabaseService(ctx context.Context, req *integrationpb.DeployDatabaseServiceRequest) (*integrationpb.DeployDatabaseServiceResponse, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := authCtx.CheckAccessToKind(types.KindIntegration, types.VerbUse); err != nil {
		return nil, trace.Wrap(err)
	}

	clusterName, err := s.cache.GetClusterName()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	awsClientReq, err := s.awsClientReq(ctx, req.Integration, req.Region)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	deployServiceClient, err := awsoidc.NewDeployServiceClient(ctx, awsClientReq, s.cache)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	deployments := make([]awsoidc.DeployDatabaseServiceRequestDeployment, 0, len(req.Deployments))
	for _, d := range req.Deployments {
		deployments = append(deployments, awsoidc.DeployDatabaseServiceRequestDeployment{
			VPCID:               d.VpcId,
			SubnetIDs:           d.SubnetIds,
			SecurityGroupIDs:    d.SecurityGroups,
			DeployServiceConfig: d.TeleportConfigString,
		})
	}

	deployDBResp, err := awsoidc.DeployDatabaseService(ctx, deployServiceClient, awsoidc.DeployDatabaseServiceRequest{
		Region:                  req.Region,
		TaskRoleARN:             req.TaskRoleArn,
		TeleportVersionTag:      req.TeleportVersion,
		DeploymentJoinTokenName: req.DeploymentJoinTokenName,
		Deployments:             deployments,
		TeleportClusterName:     clusterName.GetClusterName(),
		IntegrationName:         req.Integration,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &integrationpb.DeployDatabaseServiceResponse{
		ClusterArn:          deployDBResp.ClusterARN,
		ClusterDashboardUrl: deployDBResp.ClusterDashboardURL,
	}, nil
}
