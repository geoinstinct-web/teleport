/*
Copyright 2019 Gravitational, Inc.

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

import React, { useEffect, useState } from 'react';
import {
  StyleSheetManager,
  ThemeProvider as StyledThemeProvider,
} from 'styled-components';

import { KeysEnum, storageService } from 'teleport/services/storageService';

import { ThemePreference } from 'teleport/services/userPreferences/types';
import cfg from 'teleport/config';

import { darkTheme, lightTheme, bblpTheme } from '../theme';

import { GlobalStyle } from './globals';

function themePreferenceToTheme(themePreference: ThemePreference) {
  return themePreference === ThemePreference.Light ? lightTheme : darkTheme;
}

const ThemeProvider = props => {
  const [themePreference, setThemePreference] = useState<ThemePreference>(
    storageService.getThemePreference()
  );

  useEffect(() => {
    storageService.subscribe(receiveMessage);

    function receiveMessage(event) {
      const { key, newValue } = event;

      if (!newValue || key !== KeysEnum.USER_PREFERENCES) {
        return;
      }

      const preferences = JSON.parse(newValue);
      if (preferences.theme !== themePreference) {
        setThemePreference(preferences.theme);
      }
    }

    // Cleanup on unmount
    return function unsubscribe() {
      storageService.unsubscribe(receiveMessage);
    };
  }, [themePreference]);

  const customThemes = {
    bblp: bblpTheme,
  };

  // If no props.theme is defined, use the custom theme instead of the user preference theme.
  let theme;
  if (props.theme) {
    theme = props.theme;
  } else if (customThemes[cfg.customTheme]) {
    theme = customThemes[cfg.customTheme];
  } else {
    theme = themePreferenceToTheme(themePreference);
  }

  return (
    <StyledThemeProvider theme={theme}>
      <StyleSheetManager disableVendorPrefixes>
        <React.Fragment>
          <GlobalStyle />
          {props.children}
        </React.Fragment>
      </StyleSheetManager>
    </StyledThemeProvider>
  );
};

export default ThemeProvider;
