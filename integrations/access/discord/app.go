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

package discord

import (
	"github.com/gravitational/teleport/integrations/access/accessrequest"
	"github.com/gravitational/teleport/integrations/access/common"
)

const (
	// discordPluginName is used to tag Discord GenericPluginData and as a Delegator in Audit log.
	discordPluginName = "discord"
)

// NewApp initializes a new teleport-discord app and returns it.
func NewApp(conf *Config) *common.BaseApp[DiscordBot] {
	return common.NewApp(conf, discordPluginName).
		AddApp(accessrequest.NewApp[DiscordBot]())
}
