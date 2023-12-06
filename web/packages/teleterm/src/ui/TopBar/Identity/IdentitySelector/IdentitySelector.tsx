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

import React, { forwardRef } from 'react';
import { Box } from 'design';

import { getUserWithClusterName } from 'teleterm/ui/utils';

import { TopBarButton } from 'teleterm/ui/TopBar/TopBarButton';

import { UserIcon } from './UserIcon';
import { PamIcon } from './PamIcon';

interface IdentitySelectorProps {
  isOpened: boolean;
  userName: string;
  clusterName: string;

  onClick(): void;
  makeTitle: (userWithClusterName: string | undefined) => string;
}

export const IdentitySelector = forwardRef<
  HTMLButtonElement,
  IdentitySelectorProps
>((props, ref) => {
  const isSelected = props.userName && props.clusterName;
  const selectorText = isSelected && getUserWithClusterName(props);
  const title = props.makeTitle(selectorText);

  return (
    <TopBarButton
      isOpened={props.isOpened}
      ref={ref}
      onClick={props.onClick}
      title={title}
    >
      {isSelected ? (
        <Box>
          <UserIcon letter={props.userName[0]} />
        </Box>
      ) : (
        <PamIcon />
      )}
    </TopBarButton>
  );
});
