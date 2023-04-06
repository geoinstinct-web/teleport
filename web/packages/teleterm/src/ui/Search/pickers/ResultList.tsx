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

import React, {
  ReactElement,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import styled from 'styled-components';

import { Attempt } from 'shared/hooks/useAsync';
import { Box } from 'design';

import LinearProgress from 'teleterm/ui/components/LinearProgress';

type ResultListProps<T> = {
  /**
   * List of attempts containing results to render.
   * Displayed items will follow the order of attempts.
   * If any attempt is loading, then the loading bar is visible.
   */
  attempts: Attempt<T[]>[];
  /**
   * NoResultsComponent is the element that's going to be rendered instead of the list if the
   * attempt has successfully finished but there's no results to show.
   */
  NoResultsComponent?: ReactElement;
  onPick(item: T): void;
  onBack(): void;
  render(item: T): { Component: ReactElement; key: string };
};

export function ResultList<T>(props: ResultListProps<T>) {
  const { attempts, NoResultsComponent, onPick, onBack } = props;
  const activeItemRef = useRef<HTMLDivElement>();
  const [activeItemIndex, setActiveItemIndex] = useState(0);
  const shouldShowNoResultsCopy =
    NoResultsComponent &&
    attempts.every(a => a.status === 'success' && a.data.length === 0);

  const items = useMemo(() => {
    return attempts.map(a => a.data || []).flat();
  }, [attempts]);

  // Reset the active item index if it's greater than the number of available items.
  // This can happen in cases where the user selects the nth item and then filters the list so that
  // there's only one item.
  if (activeItemIndex !== 0 && activeItemIndex >= items.length) {
    setActiveItemIndex(0);
  }

  useEffect(() => {
    const handleArrowKey = (e: KeyboardEvent, nudge: number) => {
      const next = getNext(activeItemIndex + nudge, items.length);
      setActiveItemIndex(next);
      // `false` - bottom of the element will be aligned to the bottom of the visible area of the scrollable ancestor
      activeItemRef.current?.scrollIntoView(false);
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      switch (e.key) {
        case 'Enter': {
          e.stopPropagation();
          e.preventDefault();

          const item = items[activeItemIndex];
          if (item) {
            onPick(item);
          }
          break;
        }
        case 'Escape': {
          onBack();
          break;
        }
        case 'ArrowUp':
          e.stopPropagation();
          e.preventDefault();

          handleArrowKey(e, -1);
          break;
        case 'ArrowDown':
          e.stopPropagation();
          e.preventDefault();

          handleArrowKey(e, 1);
          break;
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [items, onPick, onBack, activeItemIndex]);

  return (
    <StyledGlobalSearchResults role="menu">
      {attempts.some(a => a.status === 'processing') && (
        <div
          style={{
            position: 'absolute',
            top: 0,
            height: '1px',
            left: 0,
            right: 0,
          }}
        >
          <LinearProgress transparentBackground={true} />
        </div>
      )}
      {items.map((r, index) => {
        const isActive = index === activeItemIndex;
        const { Component, key } = props.render(r);

        return (
          <StyledItem
            ref={isActive ? activeItemRef : null}
            role="menuitem"
            $active={isActive}
            key={key}
            onClick={() => props.onPick(r)}
          >
            {Component}
          </StyledItem>
        );
      })}
      {shouldShowNoResultsCopy && NoResultsComponent}
    </StyledGlobalSearchResults>
  );
}

const StyledItem = styled.div`
  &:hover,
  &:focus {
    cursor: pointer;
    background: ${props => props.theme.colors.levels.elevated};
  }

  & mark {
    color: inherit;
    background-color: ${props => props.theme.colors.brand.accent};
  }

  :not(:last-of-type) {
    border-bottom: 2px solid
      ${props => props.theme.colors.levels.surfaceSecondary};
  }

  padding: ${props => props.theme.space[2]}px;
  color: ${props => props.theme.colors.text.contrast};
  background: ${props =>
    props.$active
      ? props.theme.colors.levels.elevated
      : props.theme.colors.levels.surface};
`;

export const EmptyListCopy = styled(Box)`
  width: 100%;
  height: 100%;
  padding: ${props => props.theme.space[2]}px;
  line-height: 1.5em;

  ul {
    margin: 0;
    padding-inline-start: 2em;
  }
`;

function getNext(selectedIndex = 0, max = 0) {
  let index = selectedIndex % max;
  if (index < 0) {
    index += max;
  }
  return index;
}

const StyledGlobalSearchResults = styled.div(({ theme }) => {
  return {
    boxShadow: '8px 8px 18px rgb(0 0 0)',
    color: theme.colors.text.contrast,
    background: theme.colors.levels.surface,
    boxSizing: 'border-box',
    // Account for border.
    width: 'calc(100% + 2px)',
    // Careful, this is hardcoded based on the input height.
    marginTop: '38px',
    display: 'block',
    position: 'absolute',
    border: '1px solid ' + theme.colors.action.hover,
    fontSize: '12px',
    listStyle: 'none outside none',
    textShadow: 'none',
    zIndex: '1000',
    maxHeight: '350px',
    overflow: 'auto',
    // Hardcoded to height of the shortest item.
    minHeight: '42px',
  };
});
