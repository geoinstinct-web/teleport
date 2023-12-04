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
import { Flex } from 'design';
import { useRefAutoFocus } from 'shared/hooks';

const Document: React.FC<{
  visible: boolean;
  onContextMenu?(): void;
  autoFocusDisabled?: boolean;
  [x: string]: any;
}> = ({ visible, children, onContextMenu, autoFocusDisabled, ...styles }) => {
  const ref = useRefAutoFocus<HTMLDivElement>({
    shouldFocus: visible && !autoFocusDisabled,
  });

  function handleContextMenu(
    e: React.MouseEvent<HTMLDivElement, MouseEvent>
  ): void {
    if (onContextMenu) {
      // `preventDefault` prevents opening the universal context menu
      // and thus only the document-specific menu gets displayed.
      // Opening two menus at the same time on Linux causes flickering.
      e.preventDefault();
      onContextMenu();
    }
  }

  return (
    <Flex
      tabIndex={visible ? 0 : -1}
      flex="1"
      ref={ref}
      bg="levels.sunken"
      onContextMenu={handleContextMenu}
      style={{
        overflow: 'auto',
        display: visible ? 'flex' : 'none',
        position: 'relative',
        outline: 'none',
      }}
      {...styles}
    >
      {children}
    </Flex>
  );
};

export default Document;
