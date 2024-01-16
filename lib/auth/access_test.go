/*
Copyright 2021 Gravitational, Inc.

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

package auth

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/accesslist"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/api/types/header"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/events"
)

func TestUpsertDeleteRoleEventsEmitted(t *testing.T) {
	t.Parallel()
	clientAddr := &net.TCPAddr{IP: net.IPv4(10, 255, 0, 0)}
	ctx := authz.ContextWithClientSrcAddr(context.Background(), clientAddr)
	p, err := newTestPack(ctx, t.TempDir())
	require.NoError(t, err)

	// test create new role
	role, err := types.NewRole("test-role", types.RoleSpecV6{
		Options: types.RoleOptions{},
		Allow:   types.RoleConditions{},
	})
	require.NoError(t, err)

	// Creating a role should emit a RoleCreatedEvent.
	err = p.a.UpsertRole(ctx, role)
	require.NoError(t, err)
	require.Equal(t, events.RoleCreatedEvent, p.mockEmitter.LastEvent().GetType())
	createEvt := p.mockEmitter.LastEvent().(*apievents.RoleCreate)
	require.Equal(t, role.GetName(), createEvt.Name)
	require.Equal(t, clientAddr.String(), createEvt.ConnectionMetadata.RemoteAddr)
	p.mockEmitter.Reset()

	// Updating a role should emit a RoleCreatedEvent.
	err = p.a.UpsertRole(ctx, role)
	require.NoError(t, err)
	require.Equal(t, p.mockEmitter.LastEvent().GetType(), events.RoleCreatedEvent)
	require.Equal(t, p.mockEmitter.LastEvent().(*apievents.RoleCreate).Name, role.GetName())
	p.mockEmitter.Reset()

	// Deleting a role should emit a RoleDeletedEvent.
	err = p.a.DeleteRole(ctx, role.GetName())
	require.NoError(t, err)
	require.Equal(t, events.RoleDeletedEvent, p.mockEmitter.LastEvent().GetType())
	deleteEvt := p.mockEmitter.LastEvent().(*apievents.RoleDelete)
	require.Equal(t, role.GetName(), deleteEvt.Name)
	require.Equal(t, clientAddr.String(), deleteEvt.ConnectionMetadata.RemoteAddr)
	p.mockEmitter.Reset()

	// When deleting a nonexistent role, no event should be emitted.
	err = p.a.DeleteRole(ctx, role.GetName())
	require.True(t, trace.IsNotFound(err))
	require.Nil(t, p.mockEmitter.LastEvent())
}

func TestUpsertDeleteDependentRoles(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, err := newTestPack(ctx, t.TempDir())
	require.NoError(t, err)

	// test create new role
	role, err := types.NewRole("test-role", types.RoleSpecV6{
		Options: types.RoleOptions{},
		Allow:   types.RoleConditions{},
	})
	require.NoError(t, err)

	// Create a role and assign it to a user.
	err = p.a.UpsertRole(ctx, role)
	require.NoError(t, err)
	user, err := types.NewUser("test-user")
	require.NoError(t, err)
	user.AddRole(role.GetName())
	err = p.a.CreateUser(ctx, user)
	require.NoError(t, err)

	// Deletion should fail.
	require.ErrorIs(t, p.a.DeleteRole(ctx, role.GetName()), errDeleteRoleUser)
	require.NoError(t, p.a.DeleteUser(ctx, user.GetName()))

	clusterName, err := p.a.GetClusterName()
	require.NoError(t, err)

	// Update the user CA with the role.
	ca, err := p.a.GetCertAuthority(ctx, types.CertAuthID{Type: types.UserCA, DomainName: clusterName.GetClusterName()}, true)
	require.NoError(t, err)
	ca.AddRole(role.GetName())
	require.NoError(t, p.a.UpsertCertAuthority(ctx, ca))

	// Deletion should fail.
	require.ErrorIs(t, p.a.DeleteRole(ctx, role.GetName()), errDeleteRoleCA)

	// Clear out the roles for the CA.
	ca.SetRoles([]string{})
	require.NoError(t, p.a.UpsertCertAuthority(ctx, ca))

	// Create an access list that references the role.
	accessList, err := accesslist.NewAccessList(header.Metadata{
		Name: "test-access-list",
	}, accesslist.Spec{
		Title: "simple",
		Owners: []accesslist.Owner{
			{Name: "some-user"},
		},
		Grants: accesslist.Grants{
			Roles: []string{role.GetName()},
		},
		Audit: accesslist.Audit{
			NextAuditDate: time.Now(),
		},
		MembershipRequires: accesslist.Requires{
			Roles: []string{role.GetName()},
		},
		OwnershipRequires: accesslist.Requires{
			Roles: []string{role.GetName()},
		},
	})
	require.NoError(t, err)
	_, err = p.a.UpsertAccessList(ctx, accessList)
	require.NoError(t, err)

	// Deletion should fail due to the grant.
	require.ErrorIs(t, p.a.DeleteRole(ctx, role.GetName()), errDeleteRoleAccessList)

	accessList.Spec.Grants.Roles = []string{"non-existent-role"}
	_, err = p.a.UpsertAccessList(ctx, accessList)
	require.NoError(t, err)

	// Deletion should fail due to membership requires.
	require.ErrorIs(t, p.a.DeleteRole(ctx, role.GetName()), errDeleteRoleAccessList)

	accessList.Spec.MembershipRequires.Roles = []string{"non-existent-role"}
	_, err = p.a.UpsertAccessList(ctx, accessList)
	require.NoError(t, err)

	// Deletion should fail due to ownership requires.
	require.ErrorIs(t, p.a.DeleteRole(ctx, role.GetName()), errDeleteRoleAccessList)

	accessList.Spec.OwnershipRequires.Roles = []string{"non-existent-role"}
	_, err = p.a.UpsertAccessList(ctx, accessList)
	require.NoError(t, err)

	// Deletion should succeed
	require.NoError(t, p.a.DeleteRole(ctx, role.GetName()))
}

func TestUpsertDeleteLockEventsEmitted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, err := newTestPack(ctx, t.TempDir())
	require.NoError(t, err)

	lock, err := types.NewLock("test-lock", types.LockSpecV2{
		Target: types.LockTarget{MFADevice: "mfa-device-id"},
	})
	require.NoError(t, err)
	futureTime := time.Now().UTC().Add(12 * time.Hour)
	lock.SetLockExpiry(&futureTime)

	// Creating a lock should emit a LockCreatedEvent.
	err = p.a.UpsertLock(ctx, lock)
	require.NoError(t, err)
	require.Equal(t, events.LockCreatedEvent, p.mockEmitter.LastEvent().GetType())
	require.Equal(t, lock.GetName(), p.mockEmitter.LastEvent().(*apievents.LockCreate).Name)
	require.Equal(t, lock.Target(), p.mockEmitter.LastEvent().(*apievents.LockCreate).Target)
	require.Equal(t, lock.LockExpiry().UTC(), p.mockEmitter.LastEvent().(*apievents.LockCreate).Expires)
	p.mockEmitter.Reset()

	// When a lock update results in an error, no event should be emitted.
	lock.SetTarget(types.LockTarget{})
	err = p.a.UpsertLock(ctx, lock)
	require.Error(t, err)
	require.Nil(t, p.mockEmitter.LastEvent())

	// Updating a lock should emit a LockCreatedEvent.
	lock.SetTarget(types.LockTarget{Role: "test-role"})
	err = p.a.UpsertLock(ctx, lock)
	require.NoError(t, err)
	require.Equal(t, events.LockCreatedEvent, p.mockEmitter.LastEvent().GetType())
	require.Equal(t, lock.GetName(), p.mockEmitter.LastEvent().(*apievents.LockCreate).Name)
	require.Equal(t, lock.Target(), p.mockEmitter.LastEvent().(*apievents.LockCreate).Target)
	p.mockEmitter.Reset()

	// Deleting a lock should emit a LockDeletedEvent.
	err = p.a.DeleteLock(ctx, lock.GetName())
	require.NoError(t, err)
	require.Equal(t, events.LockDeletedEvent, p.mockEmitter.LastEvent().GetType())
	require.Equal(t, lock.GetName(), p.mockEmitter.LastEvent().(*apievents.LockDelete).Name)
	p.mockEmitter.Reset()

	// When deleting a nonexistent lock, no event should be emitted.
	err = p.a.DeleteLock(ctx, lock.GetName())
	require.True(t, trace.IsNotFound(err))
	require.Nil(t, p.mockEmitter.LastEvent())
}
