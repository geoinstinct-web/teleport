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

package awsoidc

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecsTypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
)

func TestGenerateServiceWithTaskDefinition(t *testing.T) {
	service := &ecsTypes.Service{
		ServiceName:    aws.String("service"),
		ClusterArn:     aws.String("cluster"),
		TaskDefinition: aws.String("task-definition-v1"),
		NetworkConfiguration: &ecsTypes.NetworkConfiguration{
			AwsvpcConfiguration: &ecsTypes.AwsVpcConfiguration{
				AssignPublicIp: ecsTypes.AssignPublicIpEnabled,
				Subnets:        []string{"subnet"},
			},
		},
		PropagateTags: ecsTypes.PropagateTagsService,
	}

	expected := &ecs.UpdateServiceInput{
		Service:        aws.String("service"),
		Cluster:        aws.String("cluster"),
		TaskDefinition: aws.String("task-definition-v2"),
		NetworkConfiguration: &ecsTypes.NetworkConfiguration{
			AwsvpcConfiguration: &ecsTypes.AwsVpcConfiguration{
				AssignPublicIp: ecsTypes.AssignPublicIpEnabled,
				Subnets:        []string{"subnet"},
			},
		},
		PropagateTags: ecsTypes.PropagateTagsService,
	}

	require.Equal(t, expected, generateServiceWithTaskDefinition(service, "task-definition-v2"))
}

func TestGenerateTaskDefinitionWithImage(t *testing.T) {
	taskDefinition := &ecsTypes.TaskDefinition{
		Family: aws.String("example-task"),
		RequiresCompatibilities: []ecsTypes.Compatibility{
			ecsTypes.CompatibilityFargate,
		},
		Cpu:    aws.String(taskCPU),
		Memory: aws.String(taskMem),

		NetworkMode:      ecsTypes.NetworkModeAwsvpc,
		TaskRoleArn:      aws.String("task-role-arn"),
		ExecutionRoleArn: aws.String("task-role-arn"),
		ContainerDefinitions: []ecsTypes.ContainerDefinition{{
			Environment: []ecsTypes.KeyValuePair{{
				Name:  aws.String(types.InstallMethodAWSOIDCDeployServiceEnvVar),
				Value: aws.String("true"),
			}},
			Command: []string{
				"start",
				"--config-string",
				"config-bytes",
			},
			EntryPoint: []string{"teleport"},
			Image:      aws.String("image-v1"),
			Name:       aws.String(taskAgentContainerName),
			LogConfiguration: &ecsTypes.LogConfiguration{
				LogDriver: ecsTypes.LogDriverAwslogs,
				Options: map[string]string{
					"awslogs-group":         "ecs-cluster",
					"awslogs-region":        "us-west-2",
					"awslogs-create-group":  "true",
					"awslogs-stream-prefix": "service/example-task",
				},
			},
		}},
	}
	tags := []ecsTypes.Tag{
		{Key: aws.String("teleport.dev/origin"), Value: aws.String("integration_awsoidc")},
	}

	expected := &ecs.RegisterTaskDefinitionInput{
		Family: aws.String("example-task"),
		RequiresCompatibilities: []ecsTypes.Compatibility{
			ecsTypes.CompatibilityFargate,
		},
		Cpu:    aws.String(taskCPU),
		Memory: aws.String(taskMem),

		NetworkMode:      ecsTypes.NetworkModeAwsvpc,
		TaskRoleArn:      aws.String("task-role-arn"),
		ExecutionRoleArn: aws.String("task-role-arn"),
		ContainerDefinitions: []ecsTypes.ContainerDefinition{{
			Environment: []ecsTypes.KeyValuePair{{
				Name:  aws.String(types.InstallMethodAWSOIDCDeployServiceEnvVar),
				Value: aws.String("true"),
			}},
			Command: []string{
				"start",
				"--config-string",
				"config-bytes",
			},
			EntryPoint: []string{"teleport"},
			Image:      aws.String("image-v2"),
			Name:       aws.String(taskAgentContainerName),
			LogConfiguration: &ecsTypes.LogConfiguration{
				LogDriver: ecsTypes.LogDriverAwslogs,
				Options: map[string]string{
					"awslogs-group":         "ecs-cluster",
					"awslogs-region":        "us-west-2",
					"awslogs-create-group":  "true",
					"awslogs-stream-prefix": "service/example-task",
				},
			},
		}},
		Tags: tags,
	}

	input, err := generateTaskDefinitionWithImage(taskDefinition, "image-v2", tags)
	require.NoError(t, err)
	require.Equal(t, expected, input)
}

func TestUpdateDeployServices(t *testing.T) {
	ctx := context.Background()

	clusterName := "my-cluster"
	integrationName := "my-integration"
	ownershipTags := defaultResourceCreationTags(clusterName, integrationName)
	teleportVersion := teleport.Version
	log := logrus.WithField("test", t.Name())

	t.Run("only legacy service present", func(t *testing.T) {
		m := &mockDeployServiceClient{
			defaultTags: ownershipTags,
			services: map[string]*ecsTypes.Service{
				"my-cluster-teleport-database-service": {
					ServiceName:    aws.String("my-cluster-teleport-database-service"),
					ServiceArn:     aws.String("my-cluster-teleport-database-service"),
					TaskDefinition: aws.String("my-cluster-teleport-database-service"),
					ClusterArn:     aws.String("my-cluster-teleport"),
					LaunchType:     ecsTypes.LaunchTypeFargate,
					Tags:           ownershipTags.ToECSTags(),
					Status:         aws.String("ACTIVE"),
				},
			},
			taskDefinitions: map[string]*ecsTypes.TaskDefinition{
				"my-cluster-teleport-database-service": {
					Family: aws.String("my-cluster-teleport-database-service"),
					ContainerDefinitions: []ecsTypes.ContainerDefinition{{
						Image: aws.String("myteleport-image:1.2.3"),
					}},
				},
			},
		}

		err := UpdateDeployService(ctx, m, log, UpdateServiceRequest{
			TeleportClusterName: clusterName,
			TeleportVersionTag:  teleportVersion,
			OwnershipTags:       ownershipTags,
		})
		require.NoError(t, err)
		newTaskDefinitionImage := aws.ToString(m.taskDefinitions["my-cluster-teleport-database-service"].ContainerDefinitions[0].Image)
		require.Contains(t, newTaskDefinitionImage, teleportVersion)
		require.Contains(t, newTaskDefinitionImage, "public.ecr.aws/gravitational/teleport")
	})

	t.Run("only legacy service present, and lacks permission to ecs:ListServices", func(t *testing.T) {
		m := &mockDeployServiceClient{
			defaultTags: ownershipTags,
			services: map[string]*ecsTypes.Service{
				"my-cluster-teleport-database-service": {
					ServiceName:    aws.String("my-cluster-teleport-database-service"),
					ServiceArn:     aws.String("my-cluster-teleport-database-service"),
					TaskDefinition: aws.String("my-cluster-teleport-database-service"),
					ClusterArn:     aws.String("my-cluster-teleport"),
					LaunchType:     ecsTypes.LaunchTypeFargate,
					Tags:           ownershipTags.ToECSTags(),
					Status:         aws.String("ACTIVE"),
				},
			},
			taskDefinitions: map[string]*ecsTypes.TaskDefinition{
				"my-cluster-teleport-database-service": {
					Family: aws.String("my-cluster-teleport-database-service"),
					ContainerDefinitions: []ecsTypes.ContainerDefinition{{
						Image: aws.String("myteleport-image:1.2.3"),
					}},
				},
			},
			iamAccessDeniedListServices: true,
		}

		err := UpdateDeployService(ctx, m, log, UpdateServiceRequest{
			TeleportClusterName: clusterName,
			TeleportVersionTag:  teleportVersion,
			OwnershipTags:       ownershipTags,
		})
		require.NoError(t, err)
		newTaskDefinitionImage := aws.ToString(m.taskDefinitions["my-cluster-teleport-database-service"].ContainerDefinitions[0].Image)
		require.Contains(t, newTaskDefinitionImage, teleportVersion)
		require.Contains(t, newTaskDefinitionImage, "public.ecr.aws/gravitational/teleport")
	})

	t.Run("only new services present", func(t *testing.T) {
		ctx, cancelFn := context.WithCancel(ctx)
		defer cancelFn()
		m := &mockDeployServiceClient{
			defaultTags: ownershipTags,
			services: map[string]*ecsTypes.Service{
				"database-service-vpc-123": {
					ServiceName:    aws.String("database-service-vpc-123"),
					ServiceArn:     aws.String("database-service-vpc-123"),
					TaskDefinition: aws.String("my-cluster-teleport-database-service-vpc-123"),
					ClusterArn:     aws.String("my-cluster-teleport"),
					LaunchType:     ecsTypes.LaunchTypeFargate,
					Tags:           ownershipTags.ToECSTags(),
					Status:         aws.String("ACTIVE"),
					Deployments:    []ecsTypes.Deployment{{}},
					DesiredCount:   1,
					RunningCount:   1,
				},
				"database-service-vpc-345": {
					ServiceName:    aws.String("database-service-vpc-345"),
					ServiceArn:     aws.String("database-service-vpc-345"),
					TaskDefinition: aws.String("my-cluster-teleport-database-service-vpc-345"),
					ClusterArn:     aws.String("my-cluster-teleport"),
					LaunchType:     ecsTypes.LaunchTypeFargate,
					Tags:           ownershipTags.ToECSTags(),
					Status:         aws.String("ACTIVE"),
					Deployments:    []ecsTypes.Deployment{{}},
					DesiredCount:   1,
					RunningCount:   1,
				},
			},
			taskDefinitions: map[string]*ecsTypes.TaskDefinition{
				"my-cluster-teleport-database-service-vpc-123": {
					Family: aws.String("my-cluster-teleport-database-service-vpc-123"),
					ContainerDefinitions: []ecsTypes.ContainerDefinition{{
						Image: aws.String("myteleport-image:1.2.3"),
					}},
				},
				"my-cluster-teleport-database-service-vpc-345": {
					Family: aws.String("my-cluster-teleport-database-service-vpc-345"),
					ContainerDefinitions: []ecsTypes.ContainerDefinition{{
						Image: aws.String("myteleport-image:1.2.3"),
					}},
				},
			},
		}

		err := UpdateDeployService(ctx, m, log, UpdateServiceRequest{
			TeleportClusterName: clusterName,
			TeleportVersionTag:  teleportVersion,
			OwnershipTags:       ownershipTags,
		})
		require.NoError(t, err)

		newTaskDefinitionImage := aws.ToString(m.taskDefinitions["my-cluster-teleport-database-service-vpc-123"].ContainerDefinitions[0].Image)
		require.Contains(t, newTaskDefinitionImage, teleportVersion)
		require.Contains(t, newTaskDefinitionImage, "public.ecr.aws/gravitational/teleport")

		newTaskDefinitionImage = aws.ToString(m.taskDefinitions["my-cluster-teleport-database-service-vpc-345"].ContainerDefinitions[0].Image)
		require.Contains(t, newTaskDefinitionImage, teleportVersion)
		require.Contains(t, newTaskDefinitionImage, "public.ecr.aws/gravitational/teleport")
	})

	t.Run("new services and old service", func(t *testing.T) {
		m := &mockDeployServiceClient{
			defaultTags: ownershipTags,
			services: map[string]*ecsTypes.Service{
				"my-cluster-teleport-database-service": {
					ServiceName:    aws.String("my-cluster-teleport-database-service"),
					ServiceArn:     aws.String("my-cluster-teleport-database-service"),
					TaskDefinition: aws.String("my-cluster-teleport-database-service"),
					ClusterArn:     aws.String("my-cluster-teleport"),
					LaunchType:     ecsTypes.LaunchTypeFargate,
					Tags:           ownershipTags.ToECSTags(),
					Status:         aws.String("ACTIVE"),
				},
				"database-service-vpc-123": {
					ServiceName:    aws.String("database-service-vpc-123"),
					ServiceArn:     aws.String("database-service-vpc-123"),
					TaskDefinition: aws.String("my-cluster-teleport-database-service-vpc-123"),
					ClusterArn:     aws.String("my-cluster-teleport"),
					LaunchType:     ecsTypes.LaunchTypeFargate,
					Tags:           ownershipTags.ToECSTags(),
					Status:         aws.String("ACTIVE"),
				},
				"database-service-vpc-345": {
					ServiceName:    aws.String("database-service-vpc-345"),
					ServiceArn:     aws.String("database-service-vpc-345"),
					TaskDefinition: aws.String("my-cluster-teleport-database-service-vpc-345"),
					ClusterArn:     aws.String("my-cluster-teleport"),
					LaunchType:     ecsTypes.LaunchTypeFargate,
					Tags:           ownershipTags.ToECSTags(),
					Status:         aws.String("ACTIVE"),
				},
			},
			taskDefinitions: map[string]*ecsTypes.TaskDefinition{
				"my-cluster-teleport-database-service-vpc-123": {
					Family: aws.String("my-cluster-teleport-database-service-vpc-123"),
					ContainerDefinitions: []ecsTypes.ContainerDefinition{{
						Image: aws.String("myteleport-image:1.2.3"),
					}},
				},
				"my-cluster-teleport-database-service-vpc-345": {
					Family: aws.String("my-cluster-teleport-database-service-vpc-345"),
					ContainerDefinitions: []ecsTypes.ContainerDefinition{{
						Image: aws.String("myteleport-image:1.2.3"),
					}},
				},
				"my-cluster-teleport-database-service": {
					Family: aws.String("my-cluster-teleport-database-service"),
					ContainerDefinitions: []ecsTypes.ContainerDefinition{{
						Image: aws.String("myteleport-image:1.2.3"),
					}},
				},
			},
		}

		err := UpdateDeployService(ctx, m, log, UpdateServiceRequest{
			TeleportClusterName: clusterName,
			TeleportVersionTag:  teleportVersion,
			OwnershipTags:       ownershipTags,
		})
		require.NoError(t, err)

		newTaskDefinitionImage := aws.ToString(m.taskDefinitions["my-cluster-teleport-database-service"].ContainerDefinitions[0].Image)
		require.Contains(t, newTaskDefinitionImage, teleportVersion)
		require.Contains(t, newTaskDefinitionImage, "public.ecr.aws/gravitational/teleport")

		newTaskDefinitionImage = aws.ToString(m.taskDefinitions["my-cluster-teleport-database-service-vpc-123"].ContainerDefinitions[0].Image)
		require.Contains(t, newTaskDefinitionImage, teleportVersion)
		require.Contains(t, newTaskDefinitionImage, "public.ecr.aws/gravitational/teleport")

		newTaskDefinitionImage = aws.ToString(m.taskDefinitions["my-cluster-teleport-database-service-vpc-345"].ContainerDefinitions[0].Image)
		require.Contains(t, newTaskDefinitionImage, teleportVersion)
		require.Contains(t, newTaskDefinitionImage, "public.ecr.aws/gravitational/teleport")
	})

	t.Run("no services running", func(t *testing.T) {
		m := &mockDeployServiceClient{}

		err := UpdateDeployService(ctx, m, log, UpdateServiceRequest{
			TeleportClusterName: clusterName,
			TeleportVersionTag:  teleportVersion,
			OwnershipTags:       ownershipTags,
		})
		require.NoError(t, err)

		require.Empty(t, m.clusters)
		require.Empty(t, m.services)
		require.Empty(t, m.taskDefinitions)
	})
}
