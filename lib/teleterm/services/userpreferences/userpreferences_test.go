// Copyright 2023 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package userpreferences

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	userpreferencesv1 "github.com/gravitational/teleport/api/gen/proto/go/userpreferences/v1"
	api "github.com/gravitational/teleport/gen/proto/go/teleport/lib/teleterm/v1"
)

var rootPreferencesMock = &userpreferencesv1.UserPreferences{
	Assist:  nil,
	Onboard: nil,
	Theme:   userpreferencesv1.Theme_THEME_LIGHT,
	ClusterPreferences: &userpreferencesv1.ClusterUserPreferences{
		PinnedResources: &userpreferencesv1.PinnedResourcesUserPreferences{
			ResourceIds: []string{"abc", "def"},
		},
	},
	UnifiedResourcePreferences: &userpreferencesv1.UnifiedResourcePreferences{
		DefaultTab:     userpreferencesv1.DefaultTab_DEFAULT_TAB_ALL,
		ViewMode:       userpreferencesv1.ViewMode_VIEW_MODE_CARD,
		LabelsViewMode: userpreferencesv1.LabelsViewMode_LABELS_VIEW_MODE_COLLAPSED,
	},
}

var leafPreferencesMock = &userpreferencesv1.UserPreferences{
	Assist:  nil,
	Onboard: nil,
	ClusterPreferences: &userpreferencesv1.ClusterUserPreferences{
		PinnedResources: &userpreferencesv1.PinnedResourcesUserPreferences{
			ResourceIds: []string{"ghi", "jkl"},
		},
	},
}

func TestUserPreferencesGet(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	mockedRootClient := &mockClient{preferences: rootPreferencesMock}
	mockedLeafClient := &mockClient{preferences: leafPreferencesMock}

	response, err := Get(ctx, mockedRootClient, mockedLeafClient)
	require.NoError(t, err)
	require.Equal(t, rootPreferencesMock.GetUnifiedResourcePreferences(), response.GetUnifiedResourcePreferences())
	require.Equal(t, leafPreferencesMock.GetClusterPreferences(), response.GetClusterPreferences())
}

func TestUserPreferencesUpdateForRoot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	mockedClient := &mockClient{preferences: rootPreferencesMock}

	newPreferences := &api.UserPreferences{
		ClusterPreferences: &userpreferencesv1.ClusterUserPreferences{
			PinnedResources: &userpreferencesv1.PinnedResourcesUserPreferences{
				ResourceIds: []string{"foo", "bar"},
			},
		},
		UnifiedResourcePreferences: nil,
	}

	updatedPreferences, err := Update(ctx, mockedClient, nil, newPreferences)
	require.NoError(t, err)
	// ClusterPreferences field has been updated with the new value.
	require.Equal(t, newPreferences.ClusterPreferences, mockedClient.upsertCalledWith.ClusterPreferences)
	require.Equal(t, newPreferences.ClusterPreferences, updatedPreferences.ClusterPreferences)
	// UnifiedResourcePreferences field has not changed because it was nil in the new value.
	require.Equal(t, rootPreferencesMock.UnifiedResourcePreferences, mockedClient.upsertCalledWith.UnifiedResourcePreferences)
	require.Equal(t, rootPreferencesMock.UnifiedResourcePreferences, updatedPreferences.UnifiedResourcePreferences)
	// Other user preferences have not been touched.
	require.Equal(t, rootPreferencesMock.Theme, mockedClient.upsertCalledWith.Theme)
}

func TestUserPreferencesUpdateForRootAndLeaf(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	mockedRootClient := &mockClient{preferences: rootPreferencesMock}
	mockedLeafClient := &mockClient{preferences: leafPreferencesMock}

	newPreferences := &api.UserPreferences{
		ClusterPreferences: &userpreferencesv1.ClusterUserPreferences{
			PinnedResources: &userpreferencesv1.PinnedResourcesUserPreferences{
				ResourceIds: []string{"foo", "bar"},
			},
		},
		UnifiedResourcePreferences: &userpreferencesv1.UnifiedResourcePreferences{
			DefaultTab:     userpreferencesv1.DefaultTab_DEFAULT_TAB_PINNED,
			ViewMode:       userpreferencesv1.ViewMode_VIEW_MODE_LIST,
			LabelsViewMode: userpreferencesv1.LabelsViewMode_LABELS_VIEW_MODE_EXPANDED,
		},
	}

	updatedPreferences, err := Update(ctx, mockedRootClient, mockedLeafClient, newPreferences)
	require.NoError(t, err)
	// ClusterPreferences field has been updated with the leaf cluster value.
	require.Equal(t, updatedPreferences.ClusterPreferences, mockedLeafClient.upsertCalledWith.ClusterPreferences)
	require.Equal(t, updatedPreferences.ClusterPreferences, updatedPreferences.ClusterPreferences)
	// ClusterPreferences field has been updated with the root cluster value.
	require.Equal(t, updatedPreferences.UnifiedResourcePreferences, mockedRootClient.upsertCalledWith.UnifiedResourcePreferences)
	require.Equal(t, updatedPreferences.UnifiedResourcePreferences, updatedPreferences.UnifiedResourcePreferences)
	// Other user preferences have not been touched.
	require.Equal(t, rootPreferencesMock.Theme, mockedRootClient.upsertCalledWith.Theme)
}

type mockClient struct {
	preferences      *userpreferencesv1.UserPreferences
	upsertCalledWith *userpreferencesv1.UserPreferences
}

func (m *mockClient) GetUserPreferences(ctx context.Context, req *userpreferencesv1.GetUserPreferencesRequest) (*userpreferencesv1.GetUserPreferencesResponse, error) {
	return &userpreferencesv1.GetUserPreferencesResponse{
		Preferences: m.preferences,
	}, nil
}

func (m *mockClient) UpsertUserPreferences(ctx context.Context, req *userpreferencesv1.UpsertUserPreferencesRequest) error {
	m.upsertCalledWith = req.Preferences
	return nil
}
