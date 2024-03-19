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
	"fmt"
	"strings"

	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	ecsTypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/gravitational/teleport/api/types"
)

type AWSTags map[string]string

// String converts AWSTags into a ',' separated list of k:v
func (d AWSTags) String() string {
	tagsString := make([]string, 0, len(d))
	for k, v := range d {
		tagsString = append(tagsString, fmt.Sprintf("%s:%s", k, v))
	}

	return strings.Join(tagsString, ", ")
}

// defaultResourceCreationTags returns the default tags that should be applied when creating new AWS resources.
// The following tags are returned:
// - teleport.dev/cluster: <clusterName>
// - teleport.dev/origin: aws-oidc-integration
// - teleport.dev/integration: <integrationName>
func defaultResourceCreationTags(clusterName, integrationName string) AWSTags {
	return AWSTags{
		types.ClusterLabel:     clusterName,
		types.OriginLabel:      types.OriginIntegrationAWSOIDC,
		types.IntegrationLabel: integrationName,
	}
}

// ToECSTags returns the default tags using the expected type for ECS resources: [ecsTypes.Tag]
func (d AWSTags) ToECSTags() []ecsTypes.Tag {
	ecsTags := make([]ecsTypes.Tag, 0, len(d))
	for k, v := range d {
		k, v := k, v
		ecsTags = append(ecsTags, ecsTypes.Tag{
			Key:   &k,
			Value: &v,
		})
	}
	return ecsTags
}

// ToEC2Tags the default tags using the expected type for EC2 resources: [ec2Types.Tag]
func (d AWSTags) ToEC2Tags() []ec2Types.Tag {
	ec2Tags := make([]ec2Types.Tag, 0, len(d))
	for k, v := range d {
		k, v := k, v
		ec2Tags = append(ec2Tags, ec2Types.Tag{
			Key:   &k,
			Value: &v,
		})
	}
	return ec2Tags
}

// MatchesECSTags checks if the AWSTags are present and have the same value in resourceTags.
func (d AWSTags) MatchesECSTags(resourceTags []ecsTypes.Tag) bool {
	resourceTagsMap := make(map[string]string, len(resourceTags))
	for _, tag := range resourceTags {
		resourceTagsMap[*tag.Key] = *tag.Value
	}

	for awsTagKey, awsTagValue := range d {
		resourceTagValue, found := resourceTagsMap[awsTagKey]
		if !found || resourceTagValue != awsTagValue {
			return false
		}
	}

	return true
}

// MatchesIAMTags checks if the AWSTags are present and have the same value in resourceTags.
func (d AWSTags) MatchesIAMTags(resourceTags []iamTypes.Tag) bool {
	resourceTagsMap := make(map[string]string, len(resourceTags))
	for _, tag := range resourceTags {
		resourceTagsMap[*tag.Key] = *tag.Value
	}

	for awsTagKey, awsTagValue := range d {
		resourceTagValue, found := resourceTagsMap[awsTagKey]
		if !found || resourceTagValue != awsTagValue {
			return false
		}
	}

	return true
}

// ToIAMTags returns the default tags using the expected type for IAM resources: [iamTypes.Tag]
func (d AWSTags) ToIAMTags() []iamTypes.Tag {
	iamTags := make([]iamTypes.Tag, 0, len(d))
	for k, v := range d {
		k, v := k, v
		iamTags = append(iamTags, iamTypes.Tag{
			Key:   &k,
			Value: &v,
		})
	}
	return iamTags
}
