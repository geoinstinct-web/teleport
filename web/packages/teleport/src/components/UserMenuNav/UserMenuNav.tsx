/**
 * Copyright 2022 Gravitational, Inc.
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
import styled, { useTheme } from 'styled-components';

import {
  Moon,
  Sun,
  ChevronDown,
  Logout as LogoutIcon,
  Devices,
} from 'design/Icon';
import { Text } from 'design';
import { useRefClickOutside } from 'shared/hooks/useRefClickOutside';

import session from 'teleport/services/websession';
import { useFeatures } from 'teleport/FeaturesContext';
import { useTeleport } from 'teleport';
import { useUser } from 'teleport/User/UserContext';
import { ThemePreference } from 'teleport/services/userPreferences/types';
import {
  Dropdown,
  DropdownItem,
  DropdownItemButton,
  DropdownItemLink,
  DropdownItemIcon,
  DropdownDivider,
  STARTING_TRANSITION_DELAY,
  INCREMENT_TRANSITION_DELAY,
} from 'teleport/components/Dropdown';

import { MobileLoginDialog } from './MobileLoginDialog';

interface UserMenuNavProps {
  username: string;
}

const Container = styled.div`
  position: relative;
  align-self: center;
  margin-right: 30px;
`;

const UserInfo = styled.div`
  display: flex;
  align-items: center;
  padding: 8px;
  border-radius: 5px;
  cursor: pointer;
  user-select: none;
  position: relative;

  &:hover {
    background: ${props => props.theme.colors.spotBackground[0]};
  }
`;

const Username = styled(Text)`
  color: ${props => props.theme.colors.text.main};
  font-size: 14px;
  font-weight: 400;
  padding-right: 40px;
`;

const StyledAvatar = styled.div`
  align-items: center;
  background: ${props => props.theme.colors.brand};
  color: ${props => props.theme.colors.text.primaryInverse};
  border-radius: 50%;
  display: flex;
  font-size: 14px;
  font-weight: bold;
  justify-content: center;
  height: 32px;
  margin-right: 16px;
  width: 100%;
  max-width: 32px;
  min-width: 32px;
`;

const Arrow = styled.div`
  position: absolute;
  right: 10px;
  top: 50%;
  transform: translate(0, -50%);
  line-height: 0;

  svg {
    transform: ${p => (p.open ? 'rotate(-180deg)' : 'none')};
    transition: 0.1s linear transform;
  }
`;

export function UserMenuNav({ username }: UserMenuNavProps) {
  const [open, setOpen] = useState(false);
  const [isMobileDialogOpen, setIsMobileDialogOpen] = useState(false);
  const theme = useTheme();

  const { preferences, updatePreferences } = useUser();

  const ref = useRefClickOutside<HTMLDivElement>({ open, setOpen });

  const ctx = useTeleport();
  const clusterId = ctx.storeUser.getClusterId();
  const features = useFeatures();

  const onThemeChange = () => {
    const nextTheme =
      preferences.theme === ThemePreference.Light
        ? ThemePreference.Dark
        : ThemePreference.Light;

    updatePreferences({ theme: nextTheme });
    setOpen(false);
  };

  const initial =
    username && username.length ? username.trim().charAt(0).toUpperCase() : '';

  const topMenuItems = features.filter(feature => Boolean(feature.topMenuItem));

  const items = [];

  let transitionDelay = STARTING_TRANSITION_DELAY;
  for (const [index, item] of topMenuItems.entries()) {
    items.push(
      <DropdownItem open={open} key={index} $transitionDelay={transitionDelay}>
        <DropdownItemLink
          to={item.topMenuItem.getLink(clusterId)}
          onClick={() => setOpen(false)}
        >
          <DropdownItemIcon>{item.topMenuItem.icon}</DropdownItemIcon>
          {item.topMenuItem.title}
        </DropdownItemLink>
      </DropdownItem>
    );

    transitionDelay += INCREMENT_TRANSITION_DELAY;
  }

  return (
    <>
      <Container ref={ref}>
        <UserInfo onClick={() => setOpen(!open)} open={open}>
          <StyledAvatar>{initial}</StyledAvatar>

          <Username>{username}</Username>

          <Arrow open={open}>
            <ChevronDown size="medium" />
          </Arrow>
        </UserInfo>

        <Dropdown open={open}>
          {items}

          <DropdownItem open={open} $transitionDelay={transitionDelay}>
            <DropdownItemButton onClick={() => setIsMobileDialogOpen(true)}>
              <DropdownItemIcon
                css={`
                  margin-top: 5px;
                `}
              >
                <Devices />
              </DropdownItemIcon>
              Login on iOS app
            </DropdownItemButton>
          </DropdownItem>

          <DropdownDivider />

          {/* Hide ability to switch themes if the theme is a custom theme */}
          {!theme.isCustomTheme && (
            <DropdownItem open={open} $transitionDelay={transitionDelay}>
              <DropdownItemButton onClick={onThemeChange}>
                <DropdownItemIcon>
                  {preferences.theme === ThemePreference.Dark ? (
                    <Sun />
                  ) : (
                    <Moon />
                  )}
                </DropdownItemIcon>
                Switch to{' '}
                {preferences.theme === ThemePreference.Dark ? 'Light' : 'Dark'}{' '}
                Theme
              </DropdownItemButton>
            </DropdownItem>
          )}

          <DropdownItem open={open} $transitionDelay={transitionDelay}>
            <DropdownItemButton onClick={() => session.logout()}>
              <DropdownItemIcon>
                <LogoutIcon />
              </DropdownItemIcon>
              Logout
            </DropdownItemButton>
          </DropdownItem>
        </Dropdown>
      </Container>
      {isMobileDialogOpen && (
        <MobileLoginDialog closeDialog={() => setIsMobileDialogOpen(false)} />
      )}
    </>
  );
}
