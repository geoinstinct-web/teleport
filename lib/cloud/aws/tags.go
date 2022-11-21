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

package aws

import (
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/elasticache"
	"github.com/aws/aws-sdk-go/service/memorydb"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/redshift"
	"github.com/aws/aws-sdk-go/service/redshiftserverless"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/gravitational/teleport/api/types"
)

const (
	// TagKeyTeleportCreated defines a tag key that indicates the the cloud
	// resource is created by Teleport.
	TagKeyTeleportCreated = "teleport.dev/created"

	// TagKeyTeleportManaged defines a tag key that indicates the the cloud
	// resource is being managed by Teleport.
	TagKeyTeleportManaged = "teleport.dev/managed"

	// TagValueTrue is the tag value "true" in string format.
	TagValueTrue = "true"
)

// IsTagValueTrue checks whether a tag value is true.
func IsTagValueTrue(value string) bool {
	// Here doing a lenient negative check. Any other value is assumed to be
	// true.
	switch strings.ToLower(value) {
	case "false", "no", "disable", "disabled":
		return false
	default:
		return true
	}
}

// settableTag is a generic interface that represents an AWS resource tag with
// SetKey and SetValue functions.
type settableTag[T any] interface {
	SetKey(key string) *T
	SetValue(Value string) *T
	*T
}

// LabelsToTags converts a label map to a list of AWS resource tags.
func LabelsToTags[T any, PT settableTag[T]](labels map[string]string) (tags []*T) {
	keys := maps.Keys(labels)
	slices.Sort(keys)

	for _, key := range keys {
		tag := PT(new(T))
		tag.SetKey(key)
		tag.SetValue(labels[key])

		tags = append(tags, (*T)(tag))
	}
	return
}

// resourceTag is a generic interface that represents an AWS resource tag.
type resourceTag interface {
	// TODO Go generic does not allow access common fields yet. List all types
	// here and use a type switch for now.
	rds.Tag | redshift.Tag | elasticache.Tag | memorydb.Tag | redshiftserverless.Tag
}

// TagsToLabels converts a list of AWS resource tags to a label map.
func TagsToLabels[Tag resourceTag](tags []*Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}

	labels := make(map[string]string)
	for _, tag := range tags {
		key, value := resourceTagToKeyValue(tag)

		if types.IsValidLabelKey(key) {
			labels[key] = value
		} else {
			logrus.Debugf("Skipping AWS resource tag %q, not a valid label key.", key)
		}
	}
	return labels
}

func resourceTagToKeyValue[Tag resourceTag](tag *Tag) (string, string) {
	switch v := any(tag).(type) {
	case *rds.Tag:
		return aws.StringValue(v.Key), aws.StringValue(v.Value)
	case *redshift.Tag:
		return aws.StringValue(v.Key), aws.StringValue(v.Value)
	case *elasticache.Tag:
		return aws.StringValue(v.Key), aws.StringValue(v.Value)
	case *memorydb.Tag:
		return aws.StringValue(v.Key), aws.StringValue(v.Value)
	case *redshiftserverless.Tag:
		return aws.StringValue(v.Key), aws.StringValue(v.Value)
	default:
		return "", ""
	}
}
