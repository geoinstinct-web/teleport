import { Theme } from 'gen-proto-ts/teleport/userpreferences/v1/theme_pb';
import { UserPreferences } from 'gen-proto-ts/teleport/userpreferences/v1/userpreferences_pb';

import {
  BackendUserPreferences,
  convertBackendUserPreferences,
  convertUserPreferences,
  isBackendUserPreferences,
} from 'teleport/services/userPreferences/userPreferences';

test('should convert the old cluster user preferences format to the new one', () => {
  // this is how the backend currently returns cluster preferences - as an array of strings
  // instead of the protobuf representation of an object with a `resourceIds` field that contains
  // that array of strings
  const oldBackendPreferences: BackendUserPreferences = {
    theme: Theme.LIGHT,
    clusterPreferences: {
      pinnedResources: ['resource1', 'resource2'],
    },
  };

  const actualUserPreferences: UserPreferences = {
    theme: Theme.LIGHT,
    clusterPreferences: {
      pinnedResources: { resourceIds: ['resource1', 'resource2'] },
    },
  };

  // when we grab the user preferences from the local storage, we check if it is in the old format
  expect(isBackendUserPreferences(oldBackendPreferences)).toBe(true);
  expect(isBackendUserPreferences(actualUserPreferences)).toBe(false);

  // and convert it to the new format if it is
  const newPreferences = convertBackendUserPreferences(oldBackendPreferences);

  expect(newPreferences.clusterPreferences.pinnedResources.resourceIds).toEqual(
    oldBackendPreferences.clusterPreferences.pinnedResources
  );
});

test('should convert the user preferences back to the old format when updating', () => {
  // the backend still expects the old format when updating user preferences

  const actualUserPreferences: UserPreferences = {
    theme: Theme.LIGHT,
    clusterPreferences: {
      pinnedResources: { resourceIds: ['resource1', 'resource2'] },
    },
  };

  const convertedPreferences = convertUserPreferences(actualUserPreferences);

  expect(convertedPreferences.clusterPreferences.pinnedResources).toEqual(
    actualUserPreferences.clusterPreferences.pinnedResources.resourceIds
  );
});
