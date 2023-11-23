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

import React, { useState } from 'react';
import styled from 'styled-components';
import { Popover, Flex, Text } from 'design';

export const HoverTooltip: React.FC<{
  tipContent: string | undefined;
  showOnlyOnOverflow?: boolean;
  className?: string;
}> = ({ tipContent, children, showOnlyOnOverflow = false, className }) => {
  const [anchorEl, setAnchorEl] = useState<Element | undefined>();
  const open = Boolean(anchorEl);

  function handlePopoverOpen(event: React.MouseEvent<Element>) {
    const { target } = event;

    if (showOnlyOnOverflow) {
      // Calculate whether the content is overflowing the parent in order to determine
      // whether we want to show the tooltip.
      if (
        target instanceof Element &&
        target.scrollWidth > target.parentElement.offsetWidth
      ) {
        setAnchorEl(event.currentTarget);
      }
      return;
    }

    setAnchorEl(event.currentTarget);
  }

  function handlePopoverClose() {
    setAnchorEl(null);
  }

  // Don't render the tooltip if the content is undefined.
  if (!tipContent) {
    return <>{children}</>;
  }

  return (
    <Flex
      aria-owns={open ? 'mouse-over-popover' : undefined}
      onMouseEnter={handlePopoverOpen}
      onMouseLeave={handlePopoverClose}
      className={className}
    >
      {children}
      <Popover
        modalCss={modalCss}
        onClose={handlePopoverClose}
        open={open}
        anchorEl={anchorEl}
        anchorOrigin={{
          vertical: 'top',
          horizontal: 'center',
        }}
        transformOrigin={{
          vertical: 'bottom',
          horizontal: 'center',
        }}
        disableRestoreFocus
      >
        <StyledOnHover
          px={2}
          py={1}
          fontWeight="regular"
          typography="subtitle2"
          css={`
            word-wrap: break-word;
          `}
        >
          {tipContent}
        </StyledOnHover>
      </Popover>
    </Flex>
  );
};

const modalCss = () => `
  pointer-events: none;
`;

const StyledOnHover = styled(Text)`
  color: ${props => props.theme.colors.text.main};
  background-color: ${props => props.theme.colors.tooltip.background};
  max-width: 350px;
`;
