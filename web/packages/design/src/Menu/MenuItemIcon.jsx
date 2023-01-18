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

import styled from 'styled-components';

import theme from './../theme';
import Icon from './../Icon';

const MenuItemIcon = styled(Icon)`
  &:hover,
  &:focus {
    color: ${props => props.theme.colors.link};
  }
`;

MenuItemIcon.displayName = 'MenuItemIcon';
MenuItemIcon.defaultProps = {
  fontSize: 4,
  theme: theme,
  mr: 2,
  color: 'colors.grey[400]',
};

export default MenuItemIcon;
