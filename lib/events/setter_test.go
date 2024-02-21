// Teleport
// Copyright (C) 2024 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package events

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	apidefaults "github.com/gravitational/teleport/api/defaults"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/session"
)

func TestPreparerIncrementalIndex(t *testing.T) {
	sessionID := session.NewID()
	preparer, err := NewPreparer(PreparerConfig{
		SessionID:   sessionID,
		ClusterName: "root",
	})
	require.NoError(t, err)

	for i := 0; i < 10; i++ {
		e, err := preparer.PrepareSessionEvent(generateEvent(t))
		require.NoError(t, err)
		require.Equal(t, int64(i), e.GetAuditEvent().GetIndex(), "unexpected event index")
	}
}

func TestPreparerTimeBasedIndex(t *testing.T) {
	clock := clockwork.NewRealClock()
	preparer, err := NewPreparer(PreparerConfig{
		SessionID:   session.NewID(),
		ServerID:    uuid.New().String(),
		ClusterName: "root",
		Clock:       clock,
		StartTime:   clock.Now(),
	})
	require.NoError(t, err)

	var lastIndex int64
	for i := 0; i < 9; i++ {
		e, err := preparer.PrepareSessionEvent(generateEvent(t))
		require.NoError(t, err)
		require.Greater(t, e.GetAuditEvent().GetIndex(), lastIndex, "expected a larger index")
		lastIndex = e.GetAuditEvent().GetIndex()
	}
}

func TestPreparerTimeBasedIndexCollisions(t *testing.T) {
	serverID := uuid.New().String()
	sessionID := session.NewID()
	clusterName := "root"
	clock := clockwork.NewRealClock()
	loginTime := clock.Now()

	preparerOne, err := NewPreparer(PreparerConfig{
		SessionID:   sessionID,
		ServerID:    serverID,
		ClusterName: clusterName,
		Clock:       clock,
		StartTime:   loginTime,
	})
	require.NoError(t, err)

	preparerTwo, err := NewPreparer(PreparerConfig{
		SessionID:   sessionID,
		ServerID:    serverID,
		ClusterName: clusterName,
		Clock:       clock,
		StartTime:   loginTime,
	})
	require.NoError(t, err)

	for i := 0; i < 9; i++ {
		evtOne, err := preparerOne.PrepareSessionEvent(generateEvent(t))
		require.NoError(t, err)
		idxOne := evtOne.GetAuditEvent().GetIndex()

		evtTwo, err := preparerTwo.PrepareSessionEvent(generateEvent(t))
		require.NoError(t, err)
		idxTwo := evtTwo.GetAuditEvent().GetIndex()

		require.NotEqual(t, idxOne, idxTwo)
		require.Greater(t, idxTwo, idxOne)
	}
}

func generateEvent(t *testing.T) apievents.AuditEvent {
	t.Helper()

	return &apievents.AppSessionChunk{
		Metadata: apievents.Metadata{
			Type:        AppSessionChunkEvent,
			Code:        AppSessionChunkCode,
			ClusterName: "root",
		},
		ServerMetadata: apievents.ServerMetadata{
			ServerID:        uuid.New().String(),
			ServerNamespace: apidefaults.Namespace,
		},
		AppMetadata: apievents.AppMetadata{
			AppURI:        "nginx",
			AppPublicAddr: "https://nginx",
			AppName:       "nginx",
		},
		SessionChunkID: uuid.New().String(),
	}
}
