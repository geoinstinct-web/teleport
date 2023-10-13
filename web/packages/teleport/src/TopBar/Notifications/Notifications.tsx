/**
 * Copyright 2023 Gravitational, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import React, { useState } from 'react';
import { formatDistanceToNow } from 'date-fns';
import styled from 'styled-components';
import { Text } from 'design';

import { Notification as NotificationIcon, UserList } from 'design/SVGIcon';
import { useRefClickOutside } from 'shared/hooks/useRefClickOutside';
import { useStore } from 'shared/libs/stores';
import { assertUnreachable } from 'shared/utils/assertUnreachable';

import {
  Dropdown,
  DropdownItem,
  DropdownItemButton,
  DropdownItemIcon,
  STARTING_TRANSITION_DELAY,
  INCREMENT_TRANSITION_DELAY,
  DropdownItemLink,
} from 'teleport/components/Dropdown';
import useTeleport from 'teleport/useTeleport';
import {
  Notification,
  NotificationKind,
} from 'teleport/stores/storeNotifications';

import { ButtonIconContainer } from '../Shared';

export function Notifications() {
  const ctx = useTeleport();
  useStore(ctx.storeNotifications);

  const notices = ctx.storeNotifications.getNotifications();

  const [open, setOpen] = useState(false);

  const ref = useRefClickOutside<HTMLDivElement>({ open, setOpen });

  let transitionDelay = STARTING_TRANSITION_DELAY;
  const items = notices.map(notice => {
    const currentTransitionDelay = transitionDelay;
    transitionDelay += INCREMENT_TRANSITION_DELAY;

    return (
      <DropdownItem
        open={open}
        $transitionDelay={currentTransitionDelay}
        key={notice.id}
      >
        <NotificationItem notice={notice} close={() => setOpen(false)} />
      </DropdownItem>
    );
  });

  return (
    <NotificationButtonContainer ref={ref} data-testid="tb-note">
      <ButtonIconContainer
        onClick={() => setOpen(!open)}
        data-testid="tb-note-button"
      >
        {items.length > 0 && <AttentionDot data-testid="tb-note-attention" />}
        <NotificationIcon />
      </ButtonIconContainer>

      <Dropdown
        open={open}
        style={{ width: '300px' }}
        data-testid="tb-note-dropdown"
      >
        {items.length ? (
          items
        ) : (
          <Text textAlign="center" p={2}>
            No notifications
          </Text>
        )}
      </Dropdown>
    </NotificationButtonContainer>
  );
}

function NotificationItem({
  notice,
  close,
}: {
  notice: Notification;
  close(): void;
}) {
  switch (notice.item.kind) {
    case NotificationKind.AccessList:
      return (
        <NotificationLink to={notice.item.route} onClick={close}>
          <NotificationItemButton>
            <DropdownItemIcon css={{ marginTop: '1px' }}>
              <UserList />
            </DropdownItemIcon>
            <Text>
              Access list <b>{notice.item.resourceName}</b> needs your review
              within {formatDistanceToNow(notice.date)}.
            </Text>
          </NotificationItemButton>
        </NotificationLink>
      );
    default:
      assertUnreachable(notice.item.kind);
  }
}

const NotificationButtonContainer = styled.div`
  position: relative;
`;

const AttentionDot = styled.div`
  position: absolute;
  width: 7px;
  height: 7px;
  border-radius: 100px;
  background-color: ${p => p.theme.colors.buttons.warning.default};
  top: 10px;
  right: 15px;
`;

const NotificationItemButton = styled(DropdownItemButton)`
  align-items: flex-start;
  line-height: 20px;
`;

const NotificationLink = styled(DropdownItemLink)`
  padding: 0;
`;
