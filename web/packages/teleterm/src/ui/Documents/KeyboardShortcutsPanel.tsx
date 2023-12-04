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

import React from 'react';
import { Text } from 'design';

import styled from 'styled-components';

import Document from 'teleterm/ui/Document';
import { useKeyboardShortcutFormatters } from 'teleterm/ui/services/keyboardShortcuts';
import { KeyboardShortcutAction } from 'teleterm/services/config';

export function KeyboardShortcutsPanel() {
  const { getAccelerator } = useKeyboardShortcutFormatters();

  const items: { title: string; shortcutAction: KeyboardShortcutAction }[] = [
    {
      title: 'Open New Tab',
      shortcutAction: 'newTab',
    },
    {
      title: 'Open New Terminal Tab',
      shortcutAction: 'newTerminalTab',
    },
    {
      title: 'Go To Next Tab',
      shortcutAction: 'nextTab',
    },
    {
      title: 'Open Connections',
      shortcutAction: 'openConnections',
    },
    {
      title: 'Open Clusters',
      shortcutAction: 'openClusters',
    },
    {
      title: 'Open Profiles',
      shortcutAction: 'openProfiles',
    },
  ];

  return (
    <Document visible={true}>
      <Grid>
        {items.map(item => (
          <Entry
            title={item.title}
            accelerator={getAccelerator(item.shortcutAction, {
              useWhitespaceSeparator: true,
            })}
            key={item.shortcutAction}
          />
        ))}
      </Grid>
    </Document>
  );
}

function Entry(props: { title: string; accelerator: string }) {
  return (
    <>
      <Text textAlign="right" typography="subtitle1" py="4px">
        {props.title}
      </Text>
      <MonoText
        css={`
          background: ${props => props.theme.colors.spotBackground[0]};
        `}
        textAlign="left"
        px="12px"
        py="4px"
      >
        {props.accelerator}
      </MonoText>
    </>
  );
}

const MonoText = styled(Text)`
  width: fit-content;
  border-radius: 4px;
`;

const Grid = styled.div`
  display: grid;
  grid-template-columns: 1fr 1fr;
  align-items: end;
  column-gap: 32px;
  row-gap: 14px;
  margin: auto;
`;
