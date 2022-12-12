// Copyright 2022 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package configurators

import (
	"context"
)

// BootstrapFlags flags provided by users to configure and define how the
// configurators will work.
type BootstrapFlags struct {
	DiscoveryService bool
	// ConfigPath database agent configuration path.
	ConfigPath string
	// Manual boolean indicating if the configurator will perform the
	// instructions or if it will be the user.
	Manual bool
	// PolicyName name of the generated policy.
	PolicyName string
	// AttachToUser user that the generated policies will be attached to.
	AttachToUser string
	// AttachToRole role that the generated policies will be attached to.
	AttachToRole string
	// ForceRDSPermissions forces the presence of RDS permissions.
	ForceRDSPermissions bool
	// ForceRDSProxyPermissions forces the presence of RDS Proxy permissions.
	ForceRDSProxyPermissions bool
	// ForceRedshiftPermissions forces the presence of Redshift permissions.
	ForceRedshiftPermissions bool
	// ForceRedshiftServerlessPermissions forces the presence of Redshift Serverless permissions.
	ForceRedshiftServerlessPermissions bool
	// ForceElastiCachePermissions forces the presence of ElastiCache permissions.
	ForceElastiCachePermissions bool
	// ForceMemoryDBPermissions forces the presence of MemoryDB permissions.
	ForceMemoryDBPermissions bool
	// ForceEC2Permissions forces the presence of EC2 permissions.
	ForceEC2Permissions bool
}

// ConfiguratorActionContext context passed across configurator actions. It is
// used to share attributes between actions.
type ConfiguratorActionContext struct {
	// AWSPolicyArn AWS ARN of the created policy.
	AWSPolicyArn string
	// AWS ARN of the created policy boundary.
	AWSPolicyBoundaryArn string
}

// ConfiguratorAction is single configurator action, its details can be retrieved
// using `Description` and `Details`, and executed using `Execute` function.
type ConfiguratorAction interface {
	// Description returns human-readable description of what the action will
	// do.
	Description() string
	// Details if the action has some additional information, such as a JSON
	// payload, it will be returned in the `Details`.
	Details() string
	// Execute executes the action with the provided context. It might or not
	// modify the `ConfiguratorActionContext`.
	//
	// Actions can store and retrieve information from the
	// `ConfiguratorActionContext` that is passed to `Execute`. For example,
	// if an action requires information that was generated by a previous action.
	// It should retrieve this information from context.
	Execute(context.Context, *ConfiguratorActionContext) error
}

// Configurator responsible for generating a list of actions that needs to be
// performed in the database agent bootstrap process.
type Configurator interface {
	// Actions return the list of actions that needs to be performed by the
	// users (when in manual mode) or by the configurator itself.
	Actions() []ConfiguratorAction
	// Name returns the configurator name.
	Name() string
	// IsEmpty defines if the configurator will have to perform any action.
	IsEmpty() bool
}
