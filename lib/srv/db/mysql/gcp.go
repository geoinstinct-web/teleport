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

package mysql

import (
	"context"
	"fmt"
	"strings"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/lib/cloud/gcp"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/db/common"
)

func isDBUserFullGCPServerAccountID(dbUser string) bool {
	// Example: mysql-iam-user@my-project-id.iam.gserviceaccount.com
	return strings.Contains(dbUser, "@") &&
		strings.HasSuffix(dbUser, ".iam.gserviceaccount.com")
}

func isDBUserShortGCPServiceAccountID(dbUser string) bool {
	// Example: mysql-iam-user@my-project-id.iam
	return strings.Contains(dbUser, "@") &&
		strings.HasSuffix(dbUser, ".iam")
}

func gcpServiceAccountToDatabaseUser(serviceAccountName string) string {
	user, _, _ := strings.Cut(serviceAccountName, "@")
	return user
}

func databaseUserToGCPServiceAccount(sessionCtx *common.Session) string {
	return fmt.Sprintf("%s@%s.iam.gserviceaccount.com", sessionCtx.DatabaseUser, sessionCtx.Database.GetGCP().ProjectID)
}

func (e *Engine) getGCPUserAndPassword(ctx context.Context, sessionCtx *common.Session, gcpClient gcp.SQLAdminClient) (string, string, error) {
	// If `--db-user` is the full service account email ID, use IAM Auth.
	if isDBUserFullGCPServerAccountID(sessionCtx.DatabaseUser) {
		user := gcpServiceAccountToDatabaseUser(sessionCtx.DatabaseUser)
		password, err := e.getGCPIAMAuthToken(ctx, sessionCtx)
		if err != nil {
			return "", "", trace.Wrap(err)
		}
		return user, password, nil
	}

	// Note that GCP Postgres' format "user@my-project-id.iam" is not accepted
	// for GCP MySQL. For GCP Postgres, "user@my-project-id.iam" is the actual
	// mapped in-database username. However, the mapped in-database username
	// for GCP MySQL does not have the "@my-project-id.iam" part.
	if isDBUserShortGCPServiceAccountID(sessionCtx.DatabaseUser) {
		return "", "", trace.BadParameter("username %q is not accepted for GCP MySQL. Please use the in-database username or the full service account Email ID.", sessionCtx.DatabaseUser)
	}

	// Get user info to decide how to authenticate.
	user := sessionCtx.DatabaseUser
	dbUserInfo, err := gcpClient.GetUser(ctx, sessionCtx.Database, sessionCtx.DatabaseUser)
	switch {
	// GetUser permission is new for IAM auth. If no permission, assume legacy password user.
	case trace.IsAccessDenied(err):
		password, err := e.getGCPOneTimePassword(ctx, sessionCtx)
		if err != nil {
			return "", "", trace.Wrap(err)
		}
		return user, password, nil

	// Report any other error.
	case err != nil:
		return "", "", trace.Wrap(err)
	}

	// The user type constants are documented in their SDK. However, in
	// practice, type can also be empty for built-in user.
	switch dbUserInfo.Type {
	case "",
		gcpMySQLDBUserTypeBuiltIn:
		password, err := e.getGCPOneTimePassword(ctx, sessionCtx)
		if err != nil {
			return "", "", trace.Wrap(err)
		}
		return user, password, nil

	case gcpMySQLDBUserTypeServiceAccount,
		gcpMySQLDBUserTypeGroupServiceAccount:
		serviceAccountName := databaseUserToGCPServiceAccount(sessionCtx)
		password, err := e.getGCPIAMAuthToken(ctx, sessionCtx.WithUser(serviceAccountName))
		if err != nil {
			return "", "", trace.Wrap(err)
		}
		return user, password, nil

	case gcpMySQLDBUserTypeUser,
		gcpMySQLDBUserTypeGroupUser:
		return "", "", trace.BadParameter("GCP MySQL user type %q not supported", dbUserInfo.Type)

	default:
		return "", "", trace.BadParameter("unknown GCP MySQL user type %q", dbUserInfo.Type)
	}
}

func (e *Engine) getGCPIAMAuthToken(ctx context.Context, sessionCtx *common.Session) (string, error) {
	e.Log.WithField("session", sessionCtx).Debug("Authenticating GCP MySQL with IAM auth.")

	// Note that sessionCtx.DatabaseUser is the service account.
	password, err := e.Auth.GetCloudSQLAuthToken(ctx, sessionCtx)
	return password, trace.Wrap(err)
}

func (e *Engine) getGCPOneTimePassword(ctx context.Context, sessionCtx *common.Session) (string, error) {
	e.Log.WithField("session", sessionCtx).Debug("Authenticating GCP MySQL with password auth.")

	// For Cloud SQL MySQL legacy auth, we use one-time passwords by resetting
	// the database user password for each connection. Thus, acquire a lock to
	// make sure all connection attempts to the same database and user are
	// serialized.
	retryCtx, cancel := context.WithTimeout(ctx, defaults.DatabaseConnectTimeout)
	defer cancel()
	lease, err := services.AcquireSemaphoreWithRetry(retryCtx, e.makeAcquireSemaphoreConfig(sessionCtx))
	if err != nil {
		return "", trace.Wrap(err)
	}
	// Only release the semaphore after the connection has been established
	// below. If the semaphore fails to release for some reason, it will
	// expire in a minute on its own.
	defer func() {
		err := e.AuthClient.CancelSemaphoreLease(ctx, *lease)
		if err != nil {
			e.Log.WithError(err).Errorf("Failed to cancel lease: %v.", lease)
		}
	}()
	password, err := e.Auth.GetCloudSQLPassword(ctx, sessionCtx)
	if err != nil {
		return "", trace.Wrap(err)
	}
	return password, nil
}

const (
	// gcpMySQLDBUserTypeBuiltIn indicates the database's built-in user type.
	gcpMySQLDBUserTypeBuiltIn = "BUILT_IN"
	// gcpMySQLDBUserTypeServiceAccount indicates a Cloud IAM service account.
	gcpMySQLDBUserTypeServiceAccount = "CLOUD_IAM_SERVICE_ACCOUNT"
	//  gcpMySQLDBUserTypeGroupServiceAccount indicates a Cloud IAM group service account.
	gcpMySQLDBUserTypeGroupServiceAccount = "CLOUD_IAM_GROUP_SERVICE_ACCOUNT"
	// gcpMySQLDBUserTypeUser indicates a Cloud IAM user.
	gcpMySQLDBUserTypeUser = "CLOUD_IAM_USER"
	// gcpMySQLDBUserTypeGroupUser indicates a Cloud IAM group login user.
	gcpMySQLDBUserTypeGroupUser = "CLOUD_IAM_GROUP_USER"
)
