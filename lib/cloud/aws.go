/*
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package cloud

import (
	"context"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/utils"
)

// AWSIntegrationConfigV2Provider defines a function that creates an [awsconfig.Session] from a Region and an Integration.
// This is used to generate aws sessions for clients that must use an Integration instead of ambient credentials.
type AWSIntegrationConfigV2Provider func(ctx context.Context, region string, integration string) (*aws.Config, error)

// AWSV2Clients is an interface for providing AWS API clients.
type AWSClientsV2 interface {
	// GetAWSConfigV2 returns AWS session for the specified region, optionally
	// assuming AWS IAM Roles.
	GetAWSConfigV2(ctx context.Context, region string, opts ...AWSOptionsFn) (*aws.Config, error)
}

type awsClientsV2 struct {
	// awsSessionsCache is a cache of AWS sessions, where the cache key is
	// an instance of awsSessionCacheKey.
	awsSessionsCache *utils.FnCache
	// awsIntegrationConfigProviderFn is a AWS Session Generator that uses an Integration to generate an AWS Session.
	// TODO provide function to populate this. Currently it is always nil.
	// TODO support retry options.
	awsIntegrationConfigProviderFn AWSIntegrationConfigV2Provider
}

func newAWSClientsV2() (*awsClientsV2, error) {
	awsSessionsCache, err := utils.NewFnCache(utils.FnCacheConfig{
		TTL: 15 * time.Minute,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &awsClientsV2{
		awsSessionsCache: awsSessionsCache,
	}, nil
}

func (c *awsClientsV2) GetAWSConfigV2(ctx context.Context, region string, opts ...AWSOptionsFn) (*aws.Config, error) {
	var options awsOptions
	for _, opt := range opts {
		opt(&options)
	}
	var err error
	if options.baseConfigV2 == nil {
		options.baseConfigV2, err = c.getAWSConfigV2ForRegion(ctx, region, options)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	if options.assumeRoleARN == "" {
		return options.baseConfigV2, nil
	}
	return c.getAWSConfigV2ForRole(ctx, region, options)
}

// getAWSConfigV2ForRegion returns AWS config for the specified region.
func (c *awsClientsV2) getAWSConfigV2ForRegion(ctx context.Context, region string, opts awsOptions) (*aws.Config, error) {
	if err := opts.checkAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	cacheKey := awsSessionCacheKey{
		region:      region,
		integration: opts.integration,
	}

	config, err := utils.FnCacheGet(ctx, c.awsSessionsCache, cacheKey, func(ctx context.Context) (*aws.Config, error) {
		if opts.credentialsSource == credentialsSourceIntegration {
			if c.awsIntegrationConfigProviderFn == nil {
				return nil, trace.BadParameter("missing aws integration config provider")
			}

			slog.DebugContext(ctx, "Initializing AWS config for integration.", "region", region, "integration", opts.integration)
			config, err := c.awsIntegrationConfigProviderFn(ctx, region, opts.integration)
			return config, trace.Wrap(err)
		}

		slog.DebugContext(ctx, "Initializing AWS config using ambient credentials.", "region", region)
		config, err := awsAmbientConfigV2Provider(ctx, region, nil /*credProvider*/)
		return config, trace.Wrap(err)
	})
	return config, trace.Wrap(err)
}

// getAWSConfigV2ForRole returns AWS session for the specified region and role.
func (c *awsClientsV2) getAWSConfigV2ForRole(ctx context.Context, region string, options awsOptions) (*aws.Config, error) {
	if err := options.checkAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	if options.baseConfigV2 == nil {
		return nil, trace.BadParameter("missing base config")
	}

	cacheKey := awsSessionCacheKey{
		region:      region,
		integration: options.integration,
		roleARN:     options.assumeRoleARN,
		externalID:  options.assumeRoleExternalID,
	}
	return utils.FnCacheGet(ctx, c.awsSessionsCache, cacheKey, func(ctx context.Context) (*aws.Config, error) {
		stsClient := sts.NewFromConfig(*options.baseConfigV2)
		provider := stscreds.NewAssumeRoleProvider(stsClient, options.assumeRoleARN, func(o *stscreds.AssumeRoleOptions) {
			if options.assumeRoleExternalID != "" {
				o.ExternalID = aws.String(options.assumeRoleExternalID)
			}
		})

		if _, err := provider.Retrieve(ctx); err != nil {
			// TODO convert error.
			return nil, trace.Wrap(err)
		}

		config, err := awsAmbientConfigV2Provider(ctx, region, provider)
		return config, trace.Wrap(err)
	})
}

// awsAmbientConfigV2Provider loads a new session using the environment variables.
func awsAmbientConfigV2Provider(ctx context.Context, region string, credProvider aws.CredentialsProvider) (*aws.Config, error) {
	config, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(credProvider),
		awsConfigFipsOption(),
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &config, nil
}

func awsConfigFipsOption() awsconfig.LoadOptionsFunc {
	if modules.GetModules().IsBoringBinary() {
		return awsconfig.WithUseFIPSEndpoint(aws.FIPSEndpointStateEnabled)
	}
	return awsconfig.WithUseFIPSEndpoint(aws.FIPSEndpointStateUnset)
}
