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

package service

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/utils/retryutils"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/automaticupgrades"
	awslib "github.com/gravitational/teleport/lib/cloud/aws"
	"github.com/gravitational/teleport/lib/integrations/awsoidc"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/utils/interval"
)

const (
	// updateDeployAgentsInterval specifies how frequently to check for available updates.
	updateDeployAgentsInterval = time.Minute * 30

	// maxConcurrentUpdates specifies the maximum number of concurrent updates
	maxConcurrentUpdates = 3
)

func (process *TeleportProcess) initDeployServiceUpdater() error {
	// start process only after teleport process has started
	if _, err := process.WaitForEvent(process.GracefulExitContext(), TeleportReadyEvent); err != nil {
		return trace.Wrap(err)
	}

	resp, err := process.getInstanceClient().Ping(process.GracefulExitContext())
	if err != nil {
		return trace.Wrap(err)
	}

	if !resp.ServerFeatures.AutomaticUpgrades {
		return nil
	}

	// If criticalEndpoint or versionEndpoint are empty, the default stable/cloud endpoint will be used
	var criticalEndpoint string
	var versionEndpoint string
	if automaticupgrades.GetChannel() != "" {
		criticalEndpoint, err = url.JoinPath(automaticupgrades.GetChannel(), "critical")
		if err != nil {
			return trace.Wrap(err)
		}
		versionEndpoint, err = url.JoinPath(automaticupgrades.GetChannel(), "version")
		if err != nil {
			return trace.Wrap(err)
		}
	}

	issuer, err := awsoidc.IssuerFromPublicAddress(process.proxyPublicAddr().Addr)
	if err != nil {
		return trace.Wrap(err)
	}

	clusterNameConfig, err := process.getInstanceClient().GetClusterName()
	if err != nil {
		return trace.Wrap(err)
	}

	updater, err := NewDeployServiceUpdater(DeployServiceUpdaterConfig{
		Log:                    process.log.WithField(trace.Component, teleport.Component(teleport.ComponentProxy, "aws_oidc_deploy_service_updater")),
		AuthClient:             process.getInstanceClient(),
		Clock:                  process.Clock,
		TeleportClusterName:    clusterNameConfig.GetClusterName(),
		TeleportClusterVersion: resp.GetServerVersion(),
		AWSOIDCProviderAddr:    issuer,
		CriticalEndpoint:       criticalEndpoint,
		VersionEndpoint:        versionEndpoint,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	process.log.Infof("The new service has started successfully. Checking for deploy service updates every %v.", updateDeployAgentsInterval)
	return trace.Wrap(updater.Run(process.GracefulExitContext()))
}

// DeployServiceUpdaterConfig specifies updater configs
type DeployServiceUpdaterConfig struct {
	// Log is the logger
	Log *logrus.Entry
	// AuthClient is the auth api client
	AuthClient *auth.Client
	// Clock is the local clock
	Clock clockwork.Clock
	// TeleportClusterName specifies the teleport cluster name
	TeleportClusterName string
	// TeleportClusterVersion specifies the teleport cluster version
	TeleportClusterVersion string
	// AWSOIDCProvderAddr specifies the aws oidc provider address used to generate AWS OIDC tokens
	AWSOIDCProviderAddr string
	// CriticalEndpoint specifies the endpoint to check for critical updates
	CriticalEndpoint string
	// VersionEndpoint specifies the endpoint to check for current teleport version
	VersionEndpoint string
}

// CheckAndSetDefaults checks and sets default config values.
func (cfg *DeployServiceUpdaterConfig) CheckAndSetDefaults() error {
	if cfg.AuthClient == nil {
		return trace.BadParameter("auth client required")
	}

	if cfg.TeleportClusterName == "" {
		return trace.BadParameter("teleport cluster name required")
	}

	if cfg.TeleportClusterVersion == "" {
		return trace.BadParameter("teleport cluster version required")
	}

	if cfg.AWSOIDCProviderAddr == "" {
		return trace.BadParameter("aws oidc provider address required")
	}

	if cfg.Log == nil {
		cfg.Log = logrus.WithField(trace.Component, teleport.Component(teleport.ComponentProxy, "aws_oidc_deploy_service_updater"))
	}

	if cfg.Clock == nil {
		cfg.Clock = clockwork.NewRealClock()
	}

	return nil
}

// DeployServiceUpdater periodically updates deploy service agents
type DeployServiceUpdater struct {
	DeployServiceUpdaterConfig
}

// NewDeployServiceUpdater returns a new DeployServiceUpdater
func NewDeployServiceUpdater(config DeployServiceUpdaterConfig) (*DeployServiceUpdater, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	return &DeployServiceUpdater{
		DeployServiceUpdaterConfig: config,
	}, nil
}

// Run periodically updates the deploy service agents
func (updater *DeployServiceUpdater) Run(ctx context.Context) error {
	periodic := interval.New(interval.Config{
		Duration: updateDeployAgentsInterval,
		Jitter:   retryutils.NewSeventhJitter(),
	})
	defer periodic.Stop()

	for {
		if err := updater.updateDeployServiceAgents(ctx); err != nil {
			updater.Log.WithError(err).Warningf("Update failed. Retrying in ~%v.", updateDeployAgentsInterval)
		}

		select {
		case <-periodic.Next():
		case <-ctx.Done():
			return nil
		}
	}
}

func (updater *DeployServiceUpdater) updateDeployServiceAgents(ctx context.Context) error {
	cmc, err := updater.AuthClient.GetClusterMaintenanceConfig(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	critical, err := automaticupgrades.Critical(ctx, updater.CriticalEndpoint)
	if err != nil {
		return trace.Wrap(err)
	}

	// Upgrade should only be attempted if the current time is within the configured
	// upgrade window, or if a critical upgrade is available
	if !cmc.WithinUpgradeWindow(updater.Clock.Now()) && !critical {
		return nil
	}

	stableVersion, err := automaticupgrades.Version(ctx, updater.VersionEndpoint)
	if err != nil {
		return trace.Wrap(err)
	}
	// stableVersion has vX.Y.Z format, however the container image tag does not include the `v`.
	stableVersion = strings.TrimPrefix(stableVersion, "v")

	// minServerVersion specifies the minimum version of the cluster required for
	// updated agents to remain compatible with the cluster.
	minServerVersion, err := utils.MajorSemver(stableVersion)
	if err != nil {
		return trace.Wrap(err)
	}

	if !utils.MeetsVersion(updater.TeleportClusterVersion, minServerVersion) {
		updater.Log.Debugf("Skipping update. %v agents will not be compatible with a %v cluster.", stableVersion, updater.TeleportClusterVersion)
		return nil
	}

	databases, err := updater.AuthClient.GetDatabases(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	// The updater needs to iterate over all integrations and aws regions to check
	// for deploy service agents to update. In order to reduce the number of api
	// calls, the aws regions are first reduced to only the regions containing
	// an RDS database.
	awsRegions := make(map[string]interface{})
	for _, database := range databases {
		if database.IsAWSHosted() && database.IsRDS() {
			awsRegions[database.GetAWS().Region] = nil
		}
	}

	integrations, err := updater.AuthClient.ListAllIntegrations(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	// Perform updates in parallel across regions.
	sem := semaphore.NewWeighted(maxConcurrentUpdates)
	for _, ig := range integrations {
		for region := range awsRegions {
			if err := sem.Acquire(ctx, 1); err != nil {
				return trace.Wrap(err)
			}
			go func(ig types.Integration, region string) {
				defer sem.Release(1)
				if err := updater.updateDeployServiceAgent(ctx, ig, region, stableVersion); err != nil {
					updater.Log.WithError(err).Warningf("Failed to update deploy service agent for integration %s in region %s.", ig.GetName(), region)
				}
			}(ig, region)
		}
	}

	// Wait for all updates to finish.
	return trace.Wrap(sem.Acquire(ctx, maxConcurrentUpdates))
}

func (updater *DeployServiceUpdater) updateDeployServiceAgent(ctx context.Context, integration types.Integration, awsRegion, teleportVersion string) error {
	// Do not attempt update if integration is not an aws oidc integration.
	if integration.GetAWSOIDCIntegrationSpec() == nil {
		return nil
	}

	token, err := updater.AuthClient.GenerateAWSOIDCToken(ctx, types.GenerateAWSOIDCTokenRequest{
		Issuer: updater.AWSOIDCProviderAddr,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	req := &awsoidc.AWSClientRequest{
		IntegrationName: integration.GetName(),
		Token:           token,
		RoleARN:         integration.GetAWSOIDCIntegrationSpec().RoleARN,
		Region:          awsRegion,
	}

	// The deploy service client is initialized using AWS OIDC integration.
	deployServiceClient, err := awsoidc.NewDeployServiceClient(ctx, req, updater.AuthClient)
	if err != nil {
		return trace.Wrap(err)
	}

	// ownershipTags are used to identify if the ecs resources are managed by the
	// teleport integration.
	ownershipTags := map[string]string{
		types.ClusterLabel:     updater.TeleportClusterName,
		types.OriginLabel:      types.OriginIntegrationAWSOIDC,
		types.IntegrationLabel: integration.GetName(),
	}

	// Acquire a lease for the region + integration before attempting to update the deploy service agent.
	// If the lease cannot be acquired, the update is already being handled by another instance.
	semLock, err := updater.AuthClient.AcquireSemaphore(ctx, types.AcquireSemaphoreRequest{
		SemaphoreKind: types.SemaphoreKindConnection,
		SemaphoreName: fmt.Sprintf("update_deploy_service_agents_%s_%s", awsRegion, integration.GetName()),
		MaxLeases:     1,
		Expires:       updater.Clock.Now().Add(updateDeployAgentsInterval),
		Holder:        "update_deploy_service_agents",
	})
	if err != nil {
		if strings.Contains(err.Error(), teleport.MaxLeases) {
			updater.Log.WithError(err).Debug("Deploy service agent update is already being processed.")
			return nil
		}
		return trace.Wrap(err)
	}
	defer func() {
		if err := updater.AuthClient.CancelSemaphoreLease(ctx, *semLock); err != nil {
			updater.Log.WithError(err).Error("Failed to cancel semaphore lease.")
		}
	}()

	updater.Log.Debugf("Updating Deploy Service Agents for integration %s in AWS region: %s", integration.GetName(), awsRegion)
	if err := awsoidc.UpdateDeployServiceAgent(ctx, deployServiceClient, awsoidc.UpdateServiceRequest{
		TeleportClusterName: updater.TeleportClusterName,
		TeleportVersionTag:  teleportVersion,
		OwnershipTags:       ownershipTags,
	}); err != nil {

		switch {
		case trace.IsNotFound(err):
			// The updater checks each integration/region combination, so
			// there will be regions where there is no ECS cluster deployed
			// for the integration.
			updater.Log.Debugf("Integration %s does not manage any services within region %s.", integration.GetName(), awsRegion)
			return nil
		case trace.IsAccessDenied(awslib.ConvertIAMv2Error(trace.Unwrap(err))):
			// The aws oidc role may lack permissions due to changes in teleport.
			// In this situation users should be notified that they will need to
			// re-run the deploy service iam configuration script and update the
			// permissions.
			updater.Log.WithError(err).Warning("Update integration role and add missing permissions.")
		}
		return trace.Wrap(err)
	}
	return nil
}
