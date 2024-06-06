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

import styled from 'styled-components';

import {
  ColorProps,
  FontSizeProps,
  SpaceProps,
  TextAlignProps,
  ResponsiveValue,
} from 'styled-system';

import { Property } from 'csstype';

import {
  typography,
  fontSize,
  space,
  color,
  textAlign,
  fontWeight,
} from 'design/system';
import { TypographyProps } from 'design/system/typography';
import { fontWeights } from 'design/theme/typography';

interface FontWeightProps {
  fontWeight?: ResponsiveValue<Property.FontWeight | keyof typeof fontWeights>;
}

export interface TextProps
  extends TypographyProps,
    FontSizeProps,
    SpaceProps,
    ColorProps,
    TextAlignProps,
    FontWeightProps {}

const Text = styled.div<TextProps>`
  overflow: hidden;
  text-overflow: ellipsis;
  ${typography}
  ${fontSize}
  ${space}
  ${color}
  ${textAlign}
  ${fontWeight}
`;

Text.displayName = 'Text';

Text.defaultProps = {
  m: 0,
};

export default Text;
