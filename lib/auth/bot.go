/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
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

package auth

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/services"
)

// validateGenerationLabel validates and updates a generation label.
func (a *Server) validateGenerationLabel(ctx context.Context, username string, certReq *certRequest, currentIdentityGeneration uint64) error {
	// Fetch the user, bypassing the cache. We might otherwise fetch a stale
	// value in case of a rapid certificate renewal.
	user, err := a.Services.GetUser(ctx, username, false)
	if err != nil {
		return trace.Wrap(err)
	}

	var currentUserGeneration uint64
	label := user.BotGenerationLabel()
	if label != "" {
		currentUserGeneration, err = strconv.ParseUint(label, 10, 64)
		if err != nil {
			return trace.BadParameter("user has invalid value for label %q", types.BotGenerationLabel)
		}
	}

	// If there is no existing generation on any of the user, identity, or
	// cert request, we have nothing to do here.
	if currentUserGeneration == 0 && currentIdentityGeneration == 0 && certReq.generation == 0 {
		return nil
	}

	// By now, we know a generation counter is in play _somewhere_ and this is a
	// bot certs. Bot certs should include the host CA so that they can make
	// Teleport API calls.
	certReq.includeHostCA = true

	// If the certReq already has generation set, it was explicitly requested
	// (presumably this is the initial set of renewable certs). We'll want to
	// commit that value to the User object.
	if certReq.generation > 0 {
		// ...however, if the user already has a stored generation, bail.
		// (bots should be deleted and recreated if their certs expire)
		if currentUserGeneration > 0 {
			return trace.BadParameter(
				"user %q has already been issued a renewable certificate and cannot be issued another; consider deleting and recreating the bot",
				user.GetName(),
			)
		}

		// Sanity check that the requested generation is 1.
		if certReq.generation != 1 {
			return trace.BadParameter("explicitly requested generation %d is not equal to 1, this is a logic error", certReq.generation)
		}

		userV2, ok := user.(*types.UserV2)
		if !ok {
			return trace.BadParameter("unsupported version of user: %T", user)
		}
		newUser := apiutils.CloneProtoMsg(userV2)
		metadata := newUser.GetMetadata()
		generation := fmt.Sprint(certReq.generation)
		metadata.Labels[types.BotGenerationLabel] = generation
		newUser.SetMetadata(metadata)

		// Note: we bypass the RBAC check on purpose as bot users should not
		// have user update permissions.
		if err := a.CompareAndSwapUser(ctx, newUser, user); err != nil {
			// If this fails it's likely to be some miscellaneous competing
			// write. The request should be tried again - if it's malicious,
			// someone will get a generation mismatch and trigger a lock.
			return trace.CompareFailed("Database comparison failed, try the request again")
		}

		return nil
	}

	// The current generations must match to continue:
	if currentIdentityGeneration != currentUserGeneration {
		// Lock the bot user indefinitely.
		lock, err := types.NewLock(uuid.New().String(), types.LockSpecV2{
			Target: types.LockTarget{
				User: user.GetName(),
			},
			Message: fmt.Sprintf(
				"The bot user %q has been locked due to a certificate generation mismatch, possibly indicating a stolen certificate.",
				user.GetName(),
			),
		})
		if err != nil {
			return trace.Wrap(err)
		}
		if err := a.UpsertLock(ctx, lock); err != nil {
			return trace.Wrap(err)
		}

		// Emit an audit event.
		userMetadata := authz.ClientUserMetadata(ctx)
		if err := a.emitter.EmitAuditEvent(a.closeCtx, &apievents.RenewableCertificateGenerationMismatch{
			Metadata: apievents.Metadata{
				Type: events.RenewableCertificateGenerationMismatchEvent,
				Code: events.RenewableCertificateGenerationMismatchCode,
			},
			UserMetadata: userMetadata,
		}); err != nil {
			log.WithError(err).Warn("Failed to emit renewable cert generation mismatch event")
		}

		return trace.AccessDenied(
			"renewable cert generation mismatch: stored=%v, presented=%v",
			currentUserGeneration, currentIdentityGeneration,
		)
	}

	// Update the user with the new generation count.
	newGeneration := currentIdentityGeneration + 1

	// As above, commit some crimes to clone the User.
	newUser, err := a.Services.GetUser(ctx, user.GetName(), false)
	if err != nil {
		return trace.Wrap(err)
	}
	metadata := newUser.GetMetadata()
	metadata.Labels[types.BotGenerationLabel] = fmt.Sprint(newGeneration)
	newUser.SetMetadata(metadata)

	newUser.SetLastActive(time.Now())

	if err := a.CompareAndSwapUser(ctx, newUser, user); err != nil {
		// If this fails it's likely to be some miscellaneous competing
		// write. The request should be tried again - if it's malicious,
		// someone will get a generation mismatch and trigger a lock.
		return trace.CompareFailed("Database comparison failed, try the request again")
	}

	// And lastly, set the generation on the cert request.
	certReq.generation = newGeneration

	return nil
}

// generateInitialBotCerts is used to generate bot certs and overlaps
// significantly with `generateUserCerts()`. However, it omits a number of
// options (impersonation, access requests, role requests, actual cert renewal,
// and most UserCertsRequest options that don't relate to bots) and does not
// care if the current identity is Nop.  This function does not validate the
// current identity at all; the caller is expected to validate that the client
// is allowed to issue the (possibly renewable) certificates.
func (a *Server) generateInitialBotCerts(ctx context.Context, botName, username, loginIP string, pubKey []byte, expires time.Time, renewable bool) (*proto.Certs, error) {
	var err error

	// Extract the user and role set for whom the certificate will be generated.
	// This should be safe since this is typically done against a local user.
	//
	// This call bypasses RBAC check for users read on purpose.
	// Users who are allowed to impersonate other users might not have
	// permissions to read user data.
	userState, err := a.GetUserOrLoginState(ctx, username)
	if err != nil {
		log.WithError(err).Debugf("Could not impersonate user %v. The user could not be fetched from local store.", username)
		return nil, trace.AccessDenied("access denied")
	}

	// Do not allow SSO users to be impersonated.
	if userState.GetUserType() == types.UserTypeSSO {
		log.Warningf("Tried to issue a renewable cert for externally managed user %v, this is not supported.", username)
		return nil, trace.AccessDenied("access denied")
	}

	// Cap the cert TTL to the MaxRenewableCertTTL.
	if max := a.GetClock().Now().Add(defaults.MaxRenewableCertTTL); expires.After(max) {
		expires = max
	}

	// Inherit the user's roles and traits verbatim.
	accessInfo := services.AccessInfoFromUserState(userState)
	clusterName, err := a.GetClusterName()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	checker, err := services.NewAccessChecker(accessInfo, clusterName.GetClusterName(), a)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// renewable cert request must include a generation
	var generation uint64
	if renewable {
		generation = 1
	}

	// Generate certificate
	certReq := certRequest{
		user:          userState,
		ttl:           expires.Sub(a.GetClock().Now()),
		publicKey:     pubKey,
		checker:       checker,
		traits:        accessInfo.Traits,
		renewable:     renewable,
		includeHostCA: true,
		generation:    generation,
		loginIP:       loginIP,
		botName:       botName,
	}

	if err := a.validateGenerationLabel(ctx, userState.GetName(), &certReq, 0); err != nil {
		return nil, trace.Wrap(err)
	}

	certs, err := a.generateUserCert(ctx, certReq)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return certs, nil
}
