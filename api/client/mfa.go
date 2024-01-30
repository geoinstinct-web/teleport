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

package client

import (
	"context"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/mfa"
)

// PerformMFACeremony retrieves an MFA challenge from the server with the given challenge extensions
// and prompts the user to answer the challenge with the given promptOpts, and ultimately returning
// an MFA challenge response for the user.
func (c *Client) PerformMFACeremony(ctx context.Context, challengeRequest *proto.CreateAuthenticateChallengeRequest, promptOpts ...mfa.PromptOpt) (*proto.MFAAuthenticateResponse, error) {
	// Don't attempt the MFA ceremony if we can't prompt for a response.
	if c.c.MFAPromptConstructor == nil {
		return nil, trace.Wrap(&mfa.ErrMFANotSupported, "missing MFAPromptConstructor field, client cannot perform MFA ceremony")
	}

	return mfa.PerformMFACeremony(ctx, c, challengeRequest, promptOpts...)
}

// PromptMFA prompts the user for MFA. Implements [mfa.MFACeremonyClient].
func (c *Client) PromptMFA(ctx context.Context, chal *proto.MFAAuthenticateChallenge, promptOpts ...mfa.PromptOpt) (*proto.MFAAuthenticateResponse, error) {
	if c.c.MFAPromptConstructor == nil {
		return nil, trace.Wrap(&mfa.ErrMFANotSupported, "missing MFAPromptConstructor field, client cannot prompt for MFA")
	}

	return c.c.MFAPromptConstructor(promptOpts...).Run(ctx, chal)
}
