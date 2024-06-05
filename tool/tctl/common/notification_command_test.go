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

package common

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/integration/helpers"
	"github.com/gravitational/teleport/lib/config"
)

// TestNotificationCommandCRUD tests creating, listing, and deleting notifications via the `tctl notifications` commands.
func TestNotificationCommmandCRUD(t *testing.T) {
	dynAddr := helpers.NewDynamicServiceAddr(t)
	fileConfig := &config.FileConfig{
		Global: config.Global{
			DataDir: t.TempDir(),
		},
		Auth: config.Auth{
			Service: config.Service{
				EnabledFlag:   "true",
				ListenAddress: dynAddr.AuthAddr,
			},
		},
	}
	makeAndRunTestAuthServer(t, withFileConfig(fileConfig), withFileDescriptors(dynAddr.Descriptors))

	auditorUsername := "auditor-user"
	managerUsername := "manager-user"

	// Test creating a user-specific notification for auditor user.
	buf, err := runNotificationsCommand(t, fileConfig, []string{"create", "--user", auditorUsername, "--title", "auditor user specific test notification", "--content", "This is a test notification."})
	require.NoError(t, err)
	require.Contains(t, buf.String(), "for user auditor-user")
	auditorUserNotificationId := strings.Split(buf.String(), " ")[2]

	// Test creating a user-specific notification for manager user.
	buf, err = runNotificationsCommand(t, fileConfig, []string{"create", "--user", managerUsername, "--title", "manager user specific test notification", "--content", "This is a test notification."})
	require.NoError(t, err)
	require.Contains(t, buf.String(), "for user manager-user")

	// Test creating a global notification for users with the test-1 role.
	buf, err = runNotificationsCommand(t, fileConfig, []string{"create", "--roles", "test-1", "--title", "test-1 role test notification", "--content", "This is a test notification."})
	require.NoError(t, err)
	require.Contains(t, buf.String(), "for users with one or more of the following roles: test-1")
	globalNotificationId := strings.Split(buf.String(), " ")[2]

	// List notifications for auditor and verify output.
	buf, err = runNotificationsCommand(t, fileConfig, []string{"ls", "--user", auditorUsername})
	require.NoError(t, err)
	require.Contains(t, buf.String(), "auditor user specific test notification")
	require.NotContains(t, buf.String(), "manager user specific test notification")

	// List notifications for manager and verify output.
	buf, err = runNotificationsCommand(t, fileConfig, []string{"ls", "--user", managerUsername})
	require.NoError(t, err)
	require.Contains(t, buf.String(), "manager user specific test notification")
	require.NotContains(t, buf.String(), "auditor user specific test notification")

	// List global notifications and verify output.
	buf, err = runNotificationsCommand(t, fileConfig, []string{"ls"})
	require.NoError(t, err)
	require.Contains(t, buf.String(), "test-1 role test notification")
	require.NotContains(t, buf.String(), "auditor user specific test notification")
	require.NotContains(t, buf.String(), "manager user specific test notification")

	// Delete the auditor's user-specific notification.
	_, err = runNotificationsCommand(t, fileConfig, []string{"rm", auditorUserNotificationId, "--user", auditorUsername})
	require.NoError(t, err)
	// Verify that it's no longer listed when listing notifications for auditor.
	buf, err = runNotificationsCommand(t, fileConfig, []string{"ls", "--user", auditorUsername})
	require.NoError(t, err)
	require.NotContains(t, buf.String(), "auditor user specific test notification")

	// Delete the auditor's user-specific notification.
	_, err = runNotificationsCommand(t, fileConfig, []string{"rm", globalNotificationId})
	require.NoError(t, err)
	// Verify that it's no longer listed when listing global notifications.
	buf, err = runNotificationsCommand(t, fileConfig, []string{"ls"})
	require.NoError(t, err)
	require.NotContains(t, buf.String(), "test-1 role test notification")
}
