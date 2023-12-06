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

package mattermost

import (
	"context"
	"sync/atomic"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/integrations/access/accessrequest"
)

type MattermostPostSlice []Post
type MattermostDataPostSet map[accessrequest.MessageData]struct{}

func (slice MattermostPostSlice) Len() int {
	return len(slice)
}

func (slice MattermostPostSlice) Less(i, j int) bool {
	if slice[i].ChannelID < slice[j].ChannelID {
		return true
	}
	return slice[i].ID < slice[j].ID
}

func (slice MattermostPostSlice) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (set MattermostDataPostSet) Add(msg accessrequest.MessageData) {
	set[msg] = struct{}{}
}

func (set MattermostDataPostSet) Contains(msg accessrequest.MessageData) bool {
	_, ok := set[msg]
	return ok
}

type fakeStatusSink struct {
	status atomic.Pointer[types.PluginStatus]
}

func (s *fakeStatusSink) Emit(_ context.Context, status types.PluginStatus) error {
	s.status.Store(&status)
	return nil
}

func (s *fakeStatusSink) Get() types.PluginStatus {
	status := s.status.Load()
	if status == nil {
		panic("expected status to be set, but it has not been")
	}
	return *status
}
