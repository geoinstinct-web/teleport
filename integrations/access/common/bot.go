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

package common

import (
	"context"
)

// MessagingBot is a generic interface with all methods required to send notifications through a messaging service.
// A messaging bot contains an API client to send/edit messages and is able to resolve a Recipient from a string.
// Implementing this interface allows to leverage BaseApp logic without customization.
type MessagingBot interface {
	// CheckHealth checks if the bot can connect to its messaging service
	CheckHealth(ctx context.Context) error
	// FetchRecipient fetches recipient data from the messaging service API. It can also be used to check and initialize
	// a communication channel (e.g. MsTeams needs to install the app for the user before being able to send
	// notifications)
	FetchRecipient(ctx context.Context, recipient string) (*Recipient, error)
	// SupportedApps are the apps supported by this bot.
	SupportedApps() []App
}
