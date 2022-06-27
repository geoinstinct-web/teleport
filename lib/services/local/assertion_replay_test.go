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

package local

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/lite"
	"github.com/stretchr/testify/require"
)

func TestAssertionReplayService(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	delay := func(t time.Duration) time.Time { return time.Now().UTC().Add(t) }
	bk, err := lite.New(ctx, backend.Params{"path": t.TempDir()})
	require.NoError(t, err)

	service := NewAssertionReplayService(bk)
	id := make([]string, 2)
	for i := range id {
		id[i] = uuid.New().String()
	}

	require.NoError(t, service.Recognize(ctx, id[0], "foo", delay(time.Hour)))
	require.Error(t, service.Recognize(ctx, id[0], "foo", delay(time.Hour)))

	require.NoError(t, service.Recognize(ctx, id[1], "bar", delay(time.Millisecond)))
	time.Sleep(time.Second)
	require.NoError(t, service.Recognize(ctx, id[1], "bar", delay(time.Hour)))
	require.Error(t, service.Recognize(ctx, id[1], "bar", delay(time.Hour)))
}
