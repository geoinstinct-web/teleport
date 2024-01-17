/**
 * Copyright 2023 Gravitational, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import React from 'react';
import { ButtonIcon, Flex, Text } from 'design';
import { Trash, Unlink } from 'design/Icon';

import { ExtendedTrackedConnection } from 'teleterm/ui/services/connectionTracker';
import { ListItem } from 'teleterm/ui/components/ListItem';
import { isDatabaseUri } from 'teleterm/ui/uri';

import { useKeyboardArrowsNavigation } from 'teleterm/ui/components/KeyboardArrowsNavigation';

import { ConnectionStatusIndicator } from './ConnectionStatusIndicator';

interface ConnectionItemProps {
  index: number;
  item: ExtendedTrackedConnection;

  onActivate(): void;

  onRemove(): void;

  onDisconnect(): void;
}

export function ConnectionItem(props: ConnectionItemProps) {
  const offline = !props.item.connected;
  const { isActive } = useKeyboardArrowsNavigation({
    index: props.index,
    onRun: props.onActivate,
  });

  const actionIcons = {
    disconnect: {
      title: 'Disconnect',
      action: props.onDisconnect,
      Icon: Unlink,
    },
    remove: {
      title: 'Remove',
      action: props.onRemove,
      Icon: Trash,
    },
  };

  const actionIcon = offline ? actionIcons.remove : actionIcons.disconnect;

  return (
    <ListItem
      onClick={props.onActivate}
      isActive={isActive}
      css={`
        padding: 6px 8px;
        height: unset;
      `}
    >
      <ConnectionStatusIndicator
        mr={3}
        css={`
          flex-shrink: 0;
        `}
        connected={props.item.connected}
      />
      <Flex
        alignItems="center"
        justifyContent="space-between"
        flex="1"
        minWidth="0"
      >
        <div
          css={`
            min-width: 0;
          `}
        >
          <Text
            typography="body1"
            bold
            color="text.main"
            title={props.item.title}
            css={`
              line-height: 16px;
            `}
          >
            <span
              css={`
                font-size: 10px;
                background: ${props => props.theme.colors.spotBackground[2]};
                opacity: 0.85;
                padding: 1px 2px;
                margin-right: 4px;
                border-radius: 4px;
              `}
            >
              {getKindName(props.item)}
            </span>
            <span
              css={`
                vertical-align: middle;
              `}
            >
              {props.item.title}
            </span>
          </Text>
          <Text
            color="text.slightlyMuted"
            typography="body2"
            title={props.item.clusterName}
          >
            {props.item.clusterName}
          </Text>
        </div>
        <ButtonIcon
          mr="-3px"
          title={actionIcon.title}
          onClick={e => {
            e.stopPropagation();
            actionIcon.action();
          }}
        >
          <actionIcon.Icon size={18} />
        </ButtonIcon>
      </Flex>
    </ListItem>
  );
}

function getKindName(connection: ExtendedTrackedConnection): string {
  switch (connection.kind) {
    case 'connection.gateway':
      if (isDatabaseUri(connection.targetUri)) {
        return 'DB';
      }
      return 'UNKNOWN';
    case 'connection.server':
      return 'SSH';
    case 'connection.kube':
      return 'KUBE';
    default:
      // The default branch is triggered when the state read from the disk
      // contains a connection not supported by the given Connect version.
      //
      // For example, the user can open an app connection in Connect v15
      // and then downgrade to a version that doesn't support apps.
      // That connection should be shown as 'UNKNOWN' in the connection list.
      //
      // `connection satisfies never` checks if we handled all cases,
      // and if not, it causes a compile-time error.
      // It is a pure TS check.
      //
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const _ = connection satisfies never;

      return 'UNKNOWN';
  }
}
