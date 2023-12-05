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

import { fontSize, color, space, FontSizeProps, SpaceProps, ColorProps } from 'styled-system';

const defaultValues = {
  fontSize: 1,
  px: 3,
};

const fromTheme = props => {
  const values = {
    ...defaultValues,
    ...props,
  };
  return {
    ...fontSize(values),
    ...space(values),
    ...color(values),
    fontWeight: values.theme.regular,

    '&:hover, &:focus': {
      color: props.disabled
        ? values.theme.colors.text.disabled
        : values.theme.colors.text.main,
      background: values.theme.colors.spotBackground[0],
    },
    '&:active': {
      background: values.theme.colors.spotBackground[1],
    },
  };
};

interface MenuItemBaseProps {
  disabled?: boolean;
}

type MenuItemProps = MenuItemBaseProps & FontSizeProps & SpaceProps & ColorProps;

const MenuItem = styled.div<MenuItemProps>`
  min-height: 40px;
  box-sizing: border-box;
  cursor: ${props => (props.disabled ? 'not-allowed' : 'pointer')};
  display: flex;
  justify-content: flex-start;
  align-items: center;
  min-width: 140px;
  overflow: hidden;
  text-decoration: none;
  white-space: nowrap;
  color: ${props =>
    props.disabled
      ? props.theme.colors.text.disabled
      : props.theme.colors.text.main};

  ${fromTheme}
`;

MenuItem.displayName = 'MenuItem';

export default MenuItem;
