/*
Copyright 2023 Gravitational, Inc.

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

import { fonts } from '../fonts';
import { blueGrey } from '../palette';
import typography, { fontSizes, fontWeights } from '../typography';

export type ThemeColors = {
  /**
    Colors in `levels` are used to reflect the perceived depth of elements in the UI.
    The further back an element is, the more "sunken" it is, and the more forwards it is, the more "elevated" it is (think CSS z-index).

    A `sunken` color would be used to represent something like the background of the app.
    While `surface` would be the color of the primary surface where most content is located (such as tables).
    Any colors more "elevated" than that would be used for things such as popovers, menus, and dialogs.

    For more information on this concept: https://m3.material.io/styles/elevation/applying-elevation
   */
  levels: {
    deep: string;
    sunken: string;
    surface: string;
    elevated: string;
    popout: string;
  };

  /**
    Spot backgrounds are used as highlights, for example
    to indicate a hover or active state for an item in a menu.
  */
  spotBackground: [string, string, string];

  brand: string;

  /**
   * Interactive colors are used to highlight different actions or states
   * based on intent.
   *
   * For example, primary would be used for as selected states,
   * or hover over primary intent actions.
   */
  interactive: {
    tonal: {
      primary: string[];
      success: string[];
    };
  };

  text: {
    /** The most important text. */
    main: string;
    /** Slightly muted text. */
    slightlyMuted: string;
    /** Muted text. Also used as placeholder text in forms. */
    muted: string;
    /** Disabled text. */
    disabled: string;
    /**
      For text on  a background that is on a color opposite to the theme. For dark theme,
      this would mean text that is on a light background.
    */
    primaryInverse: string;
  };

  buttons: {
    text: string;
    textDisabled: string;
    bgDisabled: string;

    primary: {
      text: string;
      default: string;
      hover: string;
      active: string;
    };

    secondary: {
      default: string;
      hover: string;
      active: string;
    };

    border: {
      default: string;
      hover: string;
      active: string;
      border: string;
    };

    warning: {
      text: string;
      default: string;
      hover: string;
      active: string;
    };

    trashButton: { default: string; hover: string };

    link: {
      default: string;
      hover: string;
      active: string;
    };
  };

  tooltip: {
    background: string;
  };

  progressBarColor: string;

  error: {
    main: string;
    hover: string;
    active: string;
  };
  warning: {
    main: string;
    hover: string;
    active: string;
  };
  success: {
    main: string;
    hover: string;
    active: string;
  };

  notice: {
    background: string;
  };

  action: {
    active: string;
    hover: string;
    hoverOpacity: number;
    selected: string;
    disabled: string;
    disabledBackground: string;
  };

  terminal: {
    foreground: string;
    background: string;
    selectionBackground: string;
    cursor: string;
    cursorAccent: string;
    red: string;
    green: string;
    yellow: string;
    blue: string;
    magenta: string;
    cyan: string;
    brightWhite: string;
    white: string;
    brightBlack: string;
    black: string;
    brightRed: string;
    brightGreen: string;
    brightYellow: string;
    brightBlue: string;
    brightMagenta: string;
    brightCyan: string;
  };

  editor: {
    abbey: string;
    purple: string;
    cyan: string;
    picton: string;
    sunflower: string;
    caribbean: string;
  };

  link: string;

  dataVisualisation: DataVisualisationColors;
  accessGraph: AccessGraphColors;
} & SharedColors;

interface AccessGraphColors {
  dotsColor: string;
  nodes: {
    user: AccessGraphNodeColors;
    userGroup: AccessGraphNodeColors;
    resource: AccessGraphNodeColors;
    resourceGroup: AccessGraphNodeColors;
    allowedAction: AccessGraphNodeColors;
    disallowedAction: AccessGraphNodeColors;
    allowedRequest: AccessGraphNodeColors;
    disallowedRequest: AccessGraphNodeColors;
    allowedReview: AccessGraphNodeColors;
    disallowedReview: AccessGraphNodeColors;
    accessRequest: AccessGraphNodeColors;
    temporaryUserGroup: AccessGraphNodeColors;
    temporaryResourceGroup: AccessGraphNodeColors;
    temporaryAllowedAction: AccessGraphNodeColors;
  };
  edges: {
    dynamicMemberOf: AccessGraphEdgeColors;
    memberOf: AccessGraphEdgeColors;
    reverse: AccessGraphEdgeColors;
    allowed: AccessGraphEdgeColors;
    disallowed: AccessGraphEdgeColors;
    restricted: AccessGraphEdgeColors;
    default: AccessGraphEdgeColors;
    requestedBy: AccessGraphEdgeColors;
    requestedResource: AccessGraphEdgeColors;
    requestedAction: AccessGraphEdgeColors;
  };
}

interface AccessGraphNodeColors {
  background: string;
  borderColor: string;
  typeColor: string;
  iconBackground: string;
  handleColor: string;
  highlightColor: string;
  label: {
    background: string;
    color: string;
  };
}

interface AccessGraphEdgeColors {
  color: string;
  stroke: string;
}

export type SharedColors = {
  interactionHandle: string;
  dark: string;
  light: string;
  grey: typeof blueGrey;
  subtle: string;
  bgTerminal: string;
  highlight: string;
  disabled: string;
  info: string;
};

export type DataVisualisationColors = {
  primary: VisualisationColors;
  secondary: VisualisationColors;
  tertiary: VisualisationColors;
};

type VisualisationColors = {
  purple: string;
  wednesdays: string;
  picton: string;
  sunflower: string;
  caribbean: string;
  abbey: string;
  cyan: string;
};

export type SharedStyles = {
  boxShadow: string[];
  breakpoints: {
    mobile: number;
    tablet: number;
    desktop: number;
  };
  space: number[];
  borders: (string | number)[];
  typography: typeof typography;
  font: string;
  fonts: typeof fonts;
  fontWeights: typeof fontWeights;
  fontSizes: typeof fontSizes;
  radii: (number | string)[];
  regular: number;
  bold: number;
};

export type Theme = {
  name: string;
  /** This field should be either `light` or `dark`. This is used to determine things like which version of logos to use
  so that they contrast properly with the background. */
  type: 'dark' | 'light';
  /** Whether this is a custom theme and not Dark Theme/Light Theme. */
  isCustomTheme: boolean;
  colors: ThemeColors;
} & SharedStyles;
