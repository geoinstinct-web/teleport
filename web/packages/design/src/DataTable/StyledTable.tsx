/**
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

import { borderRadius } from 'design/system';

import { decomposeColor, emphasize } from 'design/theme/utils/colorManipulator';

// When `border-collapse: collapse` is set on a table element, Safari incorrectly renders row border with alpha channel.

export const StyledTable = styled.table`
  border-collapse: collapse;
  border-spacing: 0;
  border-style: hidden;
  font-size: ${props => props.theme.fontSizes[1]}px;
  width: 100%;

  & > thead > tr > th,
  & > tbody > tr > th,
  & > tfoot > tr > th,
  & > thead > tr > td,
  & > tbody > tr > td,
  & > tfoot > tr > td {
    padding: ${p => p.theme.space[2]}px ${p => p.theme.space[2]}px;
    vertical-align: middle;

    &:first-child {
      padding-left: ${props => props.theme.space[4]}px;
    }

    &:last-child {
      padding-right: ${props => props.theme.space[4]}px;
    }
  }

  & > tbody > tr > td {
    vertical-align: middle;
  }

  & > thead > tr > th {
    color: ${props => props.theme.colors.text.main};
    ${props => props.theme.typography.h6};
    cursor: pointer;
    padding-bottom: 0;
    padding-top: 0;
    text-align: left;
    white-space: nowrap;

    svg {
      height: 12px;
    }
  }

  & > tbody > tr > td {
    color: ${props => props.theme.colors.text.main};
    ${props => props.theme.typography.table}
  }

  tbody tr {
    transition: all 150ms;
    position: relative;
    border-bottom: ${props => props.theme.borders[2]}
      ${props => props.theme.colors.spotBackground[0]};

    :hover {
      border-bottom: ${props => props.theme.borders[2]} rgba(0, 0, 0, 0);
      background-color: ${props => props.theme.colors.levels.surface};

      // We use a pseudo element for the shadow with position: absolute in order to prevent
      // the shadow from increasing the size of the layout and causing scrollbar flicker.
      :after {
        box-shadow: ${props => props.theme.boxShadow[3]};
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        z-index: -1;
        width: 100%;
        height: 100%;
      }
    }
  }
  ${borderRadius}
`;

export const StyledPanel = styled.nav<{ showTopBorder: boolean }>`
  display: flex;
  flex-shrink: 0;
  align-items: center;
  justify-content: space-between;
  padding: ${p => p.theme.space[3]}px ${p => p.theme.space[4]}px;
  max-height: ${props => props.theme.space[6]}px;
  margin-bottom: ${p => p.theme.space[2]}px;
`;
