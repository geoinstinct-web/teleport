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

import { blue, green, orange, pink, purple, red } from 'design/theme/palette';

import { lighten } from '../utils/colorManipulator';

import { sharedColors, sharedStyles } from './sharedStyles';
import { DataVisualisationColors, Theme, ThemeColors } from './types';

const dataVisualisationColors: DataVisualisationColors = {
  primary: {
    purple: '#9F85FF',
    wednesdays: '#F74DFF',
    picton: '#009EFF',
    sunflower: '#FFAB00',
    caribbean: '#00BFA6',
    abbey: '#FF6257',
    cyan: '#00D3F0',
  },
  secondary: {
    purple: '#7D59FF',
    wednesdays: '#D50DE0',
    picton: '#007CC9',
    sunflower: '#AC7400',
    caribbean: '#008775',
    abbey: '#DB3F34',
    cyan: '#009CB1',
  },
  tertiary: {
    purple: '#B9A6FF',
    wednesdays: '#FA96FF',
    picton: '#7BCDFF',
    sunflower: '#FFD98C',
    caribbean: '#2EFFD5',
    abbey: '#FF948D',
    cyan: '#74EEFF',
  },
};

const levels = {
  deep: '#000000',

  sunken: '#191919',

  surface: '#232323',

  elevated: '#282828',

  popout: '#373737',
};

const colors: ThemeColors = {
  ...sharedColors,

  levels,

  spotBackground: [
    'rgba(255,255,255,0.07)',
    'rgba(255,255,255,0.13)',
    'rgba(255,255,255,0.18)',
  ],

  brand: '#FFA028',

  text: {
    main: '#FFFFFF',
    slightlyMuted: '#BEBEBE',
    muted: '#8C8C8C',
    disabled: '#646464',
    primaryInverse: '#000000',
  },

  buttons: {
    text: '#FFFFFF',
    textDisabled: 'rgba(255, 255, 255, 0.3)',
    bgDisabled: 'rgba(255, 255, 255, 0.12)',

    primary: {
      text: '#000000',
      default: '#FFA028',
      hover: '#FFB04C',
      active: '#DB8922',
    },

    secondary: {
      default: 'rgba(255,255,255,0.07)',
      hover: 'rgba(255,255,255,0.13)',
      active: 'rgba(255,255,255,0.18)',
    },

    border: {
      default: 'rgba(255,255,255,0)',
      hover: 'rgba(255, 255, 255, 0.07)',
      active: 'rgba(255, 255, 255, 0.13)',
      border: 'rgba(255, 255, 255, 0.36)',
    },

    warning: {
      text: '#FFFFFF',
      default: '#E51E3C',
      hover: '#FD2D4A',
      active: '#C31834',
    },

    trashButton: {
      default: 'rgba(255, 255, 255, 0.07)',
      hover: 'rgba(255, 255, 255, 0.13)',
    },

    link: {
      default: '#66ABFF',
      hover: '#99C7FF',
      active: '#2B8EFF',
    },
  },

  tooltip: {
    background: '#212B2F',
  },

  progressBarColor: '#00BFA5',

  error: {
    main: '#E51E3C',
    hover: '#FD2D4A',
    active: '#C31834',
  },

  warning: {
    main: '#FA5A28',
    hover: '#FB754C',
    active: '#D64D22',
  },

  notice: {
    background: '#282828', // elevated
  },

  action: {
    active: '#FFFFFF',
    hover: 'rgba(255, 255, 255, 0.1)',
    hoverOpacity: 0.1,
    selected: 'rgba(255, 255, 255, 0.2)',
    disabled: 'rgba(255, 255, 255, 0.3)',
    disabledBackground: 'rgba(255, 255, 255, 0.12)',
  },

  terminal: {
    foreground: '#FFF',
    background: levels.sunken,
    selectionBackground: 'rgba(255, 255, 255, 0.18)',
    cursor: '#FFF',
    cursorAccent: levels.sunken,
    red: dataVisualisationColors.primary.abbey,
    green: dataVisualisationColors.primary.caribbean,
    yellow: dataVisualisationColors.primary.sunflower,
    blue: dataVisualisationColors.primary.picton,
    magenta: dataVisualisationColors.primary.purple,
    cyan: dataVisualisationColors.primary.cyan,
    brightWhite: lighten(levels.sunken, 0.89),
    white: lighten(levels.sunken, 0.78),
    brightBlack: lighten(levels.sunken, 0.61),
    black: '#000',
    brightRed: dataVisualisationColors.tertiary.abbey,
    brightGreen: dataVisualisationColors.tertiary.caribbean,
    brightYellow: dataVisualisationColors.tertiary.sunflower,
    brightBlue: dataVisualisationColors.tertiary.picton,
    brightMagenta: dataVisualisationColors.tertiary.purple,
    brightCyan: dataVisualisationColors.tertiary.cyan,
  },

  accessGraph: {
    dotsColor: 'rgba(255, 255, 255, 0.1)',
    edges: {
      dynamicMemberOf: {
        color: purple[700],
        stroke: purple[500],
      },
      memberOf: {
        color: 'rgba(255, 255, 255, 0.7)',
        stroke: 'rgba(255, 255, 255, 0.2)',
      },
      reverse: {
        color: blue[700],
        stroke: blue[300],
      },
      allowed: {
        color: green[700],
        stroke: green[300],
      },
      disallowed: {
        color: red[700],
        stroke: red[300],
      },
      default: {
        color: 'rgba(255, 255, 255, 0.7)',
        stroke: 'rgba(255, 255, 255, 0.2)',
      },
    },
    nodes: {
      user: {
        background: lighten(purple[300], 0.1),
        borderColor: 'transparent',
        typeColor: purple[700],
        iconBackground: purple[400],
        handleColor: purple[200],
        highlightColor: purple[700],
        label: {
          background: purple[200],
          color: purple[700],
        },
      },
      userGroup: {
        background: lighten(orange[300], 0.1),
        borderColor: 'transparent',
        typeColor: orange[700],
        iconBackground: orange[400],
        handleColor: orange[200],
        highlightColor: orange[700],
        label: {
          background: orange[200],
          color: orange[700],
        },
      },
      resource: {
        background: lighten(blue[300], 0.1),
        borderColor: 'transparent',
        typeColor: blue[700],
        iconBackground: blue[400],
        handleColor: blue[200],
        highlightColor: blue[700],
        label: {
          background: blue[200],
          color: blue[700],
        },
      },
      resourceGroup: {
        background: lighten(pink[300], 0.1),
        borderColor: 'transparent',
        typeColor: pink[700],
        iconBackground: pink[400],
        handleColor: pink[200],
        highlightColor: pink[700],
        label: {
          background: pink[200],
          color: pink[700],
        },
      },
      allowedAction: {
        background: lighten(green[300], 0.1),
        borderColor: 'transparent',
        typeColor: green[700],
        iconBackground: green[400],
        handleColor: green[200],
        highlightColor: green[700],
        label: {
          background: green[200],
          color: green[700],
        },
      },
      disallowedAction: {
        background: lighten(red[300], 0.1),
        borderColor: 'transparent',
        typeColor: red[700],
        iconBackground: red[400],
        handleColor: red[200],
        highlightColor: red[700],
        label: {
          background: red[200],
          color: red[700],
        },
      },
    },
  },

  editor: {
    abbey: dataVisualisationColors.tertiary.abbey,
    purple: dataVisualisationColors.tertiary.purple,
    cyan: dataVisualisationColors.tertiary.cyan,
    picton: dataVisualisationColors.tertiary.picton,
    sunflower: dataVisualisationColors.tertiary.sunflower,
    caribbean: dataVisualisationColors.tertiary.caribbean,
  },

  link: '#66ABFF',
  success: '#00BFA5',

  dataVisualisation: dataVisualisationColors,
};

const theme: Theme = {
  ...sharedStyles,
  name: 'bblp',
  type: 'dark',
  isCustomTheme: true,
  colors,
};

export default theme;
