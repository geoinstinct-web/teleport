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

import React, {
  useCallback,
  useState,
  useEffect,
  useLayoutEffect,
  useRef,
} from 'react';
import styled, { css } from 'styled-components';

import { Box, ButtonIcon, ButtonLink, Flex, Label, Text } from 'design';
import copyToClipboard from 'design/utils/copyToClipboard';
import { StyledCheckbox } from 'design/Checkbox';

import { ResourceIcon, ResourceIconName } from 'design/ResourceIcon';
import { Icon, Copy, Check, PushPinFilled, PushPin } from 'design/Icon';

import {
  HoverTooltip,
  PINNING_NOT_SUPPORTED_MESSAGE,
} from './UnifiedResources';

import type { ResourceLabel } from 'teleport/services/agents'; // Since we do a lot of manual resizing and some absolute positioning, we have

// Since we do a lot of manual resizing and some absolute positioning, we have
// to put some layout constants in place here.
const labelRowHeight = 20; // px
const labelVerticalMargin = 1; // px
const labelHeight = labelRowHeight * labelVerticalMargin;

/**
 * This box serves twofold purpose: first, it prevents the underlying icon from
 * being squeezed if the parent flexbox starts shrinking items. Second, it
 * prevents the icon from magically occupying too much space, since the SVG
 * element somehow forces the parent to occupy at least full line height.
 */
const ResTypeIconBox = styled(Box)`
  line-height: 0;
`;

export enum PinningSupport {
  Supported = 'Supported',
  /**
   * Disables pinning functionality if a leaf cluster hasn't been upgraded yet.
   * Shows an appropriate message on hover.
   * */
  NotSupported = 'NotSupported',
  /** Disables the pinning button. */
  Disabled = 'Disabled',
  /** Hides the pinning button completely. */
  Hidden = 'Hidden',
}

type Props = {
  name: string;
  primaryIconName: ResourceIconName;
  SecondaryIcon: typeof Icon;
  description: { primary?: string; secondary?: string };
  labels: ResourceLabel[];
  ActionButton: React.ReactElement;
  onLabelClick?: (label: ResourceLabel) => void;
  pinResource: () => void;
  selectResource: () => void;
  selected: boolean;
  pinned: boolean;
  pinningSupport: PinningSupport;
};

export function ResourceCard({
  name,
  primaryIconName,
  SecondaryIcon,
  onLabelClick,
  description,
  ActionButton,
  labels,
  pinningSupport,
  pinned,
  pinResource,
  selectResource,
  selected,
}: Props) {
  const [showMoreLabelsButton, setShowMoreLabelsButton] = useState(false);
  const [showAllLabels, setShowAllLabels] = useState(false);
  const [numMoreLabels, setNumMoreLabels] = useState(0);
  const [isNameOverflowed, setIsNameOverflowed] = useState(false);

  const [hovered, setHovered] = useState(false);

  const innerContainer = useRef<Element | null>(null);
  const labelsInnerContainer = useRef(null);
  const nameText = useRef<HTMLDivElement | null>(null);
  const collapseTimeout = useRef<ReturnType<typeof setTimeout>>(null);

  // This effect installs a resize observer whose purpose is to detect the size
  // of the component that contains all the labels. If this component is taller
  // than the height of a single label row, we show a "+x more" button.
  useLayoutEffect(() => {
    if (!labelsInnerContainer.current) return;

    const observer = new ResizeObserver(entries => {
      // This check will let us know if the name text has overflowed. We do this
      // to conditionally render a tooltip for only overflowed names
      if (
        nameText.current?.scrollWidth >
        nameText.current?.parentElement.offsetWidth
      ) {
        setIsNameOverflowed(true);
      } else {
        setIsNameOverflowed(false);
      }
      const container = entries[0];

      // We're taking labelRowHeight * 1.5 just in case some glitch adds or
      // removes a pixel here and there.
      const moreThanOneRow =
        container.contentBoxSize[0].blockSize > labelRowHeight * 1.5;
      setShowMoreLabelsButton(moreThanOneRow);

      // Count number of labels in the first row. This will let us calculate and
      // show the number of labels left out from the view.
      const labelElements = [
        ...entries[0].target.querySelectorAll('[data-is-label]'),
      ];
      const firstLabelPos = labelElements[0]?.getBoundingClientRect().top;
      // Find the first one below.
      const firstLabelInSecondRow = labelElements.findIndex(
        e => e.getBoundingClientRect().top > firstLabelPos
      );

      setNumMoreLabels(
        firstLabelInSecondRow > 0
          ? labelElements.length - firstLabelInSecondRow
          : 0
      );
    });

    observer.observe(labelsInnerContainer.current);
    return () => {
      observer.disconnect();
    };
  });

  // Clear the timeout on unmount to prevent changing a state of an unmounted
  // component.
  useEffect(() => () => clearTimeout(collapseTimeout.current), []);

  const onMoreLabelsClick = () => {
    setShowAllLabels(true);
  };

  const onMouseLeave = () => {
    // If the user expanded the labels and then scrolled down enough to hide the
    // top of the card, we scroll back up and collapse the labels with a small
    // delay to keep the user from losing focus on the card that they were
    // looking at. The delay is picked by hand, since there's no (easy) way to
    // know when the animation ends.
    if (
      showAllLabels &&
      (innerContainer.current?.getBoundingClientRect().top ?? 0) < 0
    ) {
      innerContainer.current?.scrollIntoView({
        behavior: 'smooth',
        block: 'start',
      });
      clearTimeout(collapseTimeout.current);
      collapseTimeout.current = setTimeout(() => setShowAllLabels(false), 700);
    } else {
      // Otherwise, we just collapse the labels immediately.
      setShowAllLabels(false);
    }
  };

  return (
    <CardContainer
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <CardOuterContainer showAllLabels={showAllLabels}>
        <CardInnerContainer
          ref={innerContainer}
          p={3}
          // we set padding left a bit larger so we can have space to absolutely
          // position the pin/checkbox buttons
          pl={6}
          alignItems="start"
          onMouseLeave={onMouseLeave}
          pinned={pinned}
          selected={selected}
        >
          <HoverTooltip tipContent={<>{selected ? 'Deselect' : 'Select'}</>}>
            <StyledCheckbox
              css={`
                position: absolute;
                top: 16px;
                left: 16px;
              `}
              checked={selected}
              onChange={selectResource}
            />
          </HoverTooltip>
          <PinButton
            setPinned={pinResource}
            pinned={pinned}
            pinningSupport={pinningSupport}
            hovered={hovered}
          />
          <ResourceIcon
            name={primaryIconName}
            width="45px"
            height="45px"
            ml={2}
          />
          {/* MinWidth is important to prevent descriptions from overflowing. */}
          <Flex flexDirection="column" flex="1" minWidth="0" ml={3} gap={1}>
            <Flex flexDirection="row" alignItems="center">
              <SingleLineBox flex="1">
                {isNameOverflowed ? (
                  <HoverTooltip tipContent={<>{name}</>}>
                    <Text ref={nameText} typography="h5" fontWeight={300}>
                      {name}
                    </Text>
                  </HoverTooltip>
                ) : (
                  <Text ref={nameText} typography="h5" fontWeight={300}>
                    {name}
                  </Text>
                )}
              </SingleLineBox>
              {hovered && <CopyButton name={name} />}
              {ActionButton}
            </Flex>
            <Flex flexDirection="row" alignItems="center">
              <ResTypeIconBox>
                <SecondaryIcon size={18} />
              </ResTypeIconBox>
              {description.primary && (
                <SingleLineBox ml={1} title={description.primary}>
                  <Text typography="body2" color="text.slightlyMuted">
                    {description.primary}
                  </Text>
                </SingleLineBox>
              )}
              {description.secondary && (
                <SingleLineBox ml={2} title={description.secondary}>
                  <Text typography="body2" color="text.muted">
                    {description.secondary}
                  </Text>
                </SingleLineBox>
              )}
            </Flex>
            <LabelsContainer showAll={showAllLabels}>
              <LabelsInnerContainer ref={labelsInnerContainer}>
                <MoreLabelsButton
                  style={{
                    visibility:
                      showMoreLabelsButton && !showAllLabels
                        ? 'visible'
                        : 'hidden',
                  }}
                  onClick={onMoreLabelsClick}
                >
                  + {numMoreLabels} more
                </MoreLabelsButton>
                {labels.map((label, i) => {
                  const { name, value } = label;
                  const labelText = `${name}: ${value}`;
                  return (
                    <StyledLabel
                      key={JSON.stringify([name, value, i])}
                      title={labelText}
                      onClick={() => onLabelClick?.(label)}
                      kind="secondary"
                      data-is-label=""
                    >
                      {labelText}
                    </StyledLabel>
                  );
                })}
              </LabelsInnerContainer>
            </LabelsContainer>
          </Flex>
        </CardInnerContainer>
      </CardOuterContainer>
    </CardContainer>
  );
}

function CopyButton({ name }: { name: string }) {
  const copySuccess = 'Copied!';
  const copyDefault = 'Click to copy';
  const copyAnchorEl = useRef(null);
  const [copiedText, setCopiedText] = useState(copyDefault);

  const handleCopy = useCallback(() => {
    setCopiedText(copySuccess);
    copyToClipboard(name);
    // Change to default text after 1 second
    setTimeout(() => {
      setCopiedText(copyDefault);
    }, 1000);
  }, [name]);

  return (
    <HoverTooltip tipContent={<>{copiedText}</>}>
      <ButtonIcon setRef={copyAnchorEl} size={0} mr={2} onClick={handleCopy}>
        {copiedText === copySuccess ? (
          <Check size="small" />
        ) : (
          <Copy size="small" />
        )}
      </ButtonIcon>
    </HoverTooltip>
  );
}

/**
 * The outer container's purpose is to reserve horizontal space on the resource
 * grid. It holds the inner container that normally holds a regular layout of
 * the card, and is fully contained inside the outer container.  Once the user
 * clicks the "more" button, the inner container "pops out" by changing its
 * position to absolute.
 *
 * TODO(bl-nero): Known issue: this doesn't really work well with one-column
 * layout; we may need to globally set the card height to fixed size on the
 * outer container.
 */
const CardContainer = styled(Box)`
  position: relative;
`;

const CardOuterContainer = styled(Box)`
  border-radius: ${props => props.theme.radii[3]}px;

  ${props =>
    props.showAllLabels &&
    css`
      position: absolute;
      left: 0;
      right: 0;
      z-index: 1;
    `}
  transition: all 150ms;

  ${CardContainer}:hover & {
    background-color: ${props => props.theme.colors.levels.surface};
  }
`;

/**
 * The inner container that normally holds a regular layout of the card, and is
 * fully contained inside the outer container.  Once the user clicks the "more"
 * button, the inner container "pops out" by changing its position to absolute.
 *
 * TODO(bl-nero): Known issue: this doesn't really work well with one-column
 * layout; we may need to globally set the card height to fixed size on the
 * outer container.
 */
const CardInnerContainer = styled(Flex)`
  border: ${props => props.theme.borders[2]}
    ${props => props.theme.colors.spotBackground[0]};
  border-radius: ${props => props.theme.radii[3]}px;
  background-color: ${props => getBackgroundColor(props)};
`;

const getBackgroundColor = props => {
  if (props.selected) {
    return props.theme.colors.interactive.tonal.primary[2];
  }
  if (props.pinned) {
    return props.theme.colors.interactive.tonal.primary[0];
  }
  return 'transparent';
};

const SingleLineBox = styled(Box)`
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
`;

/**
 * The outer labels container is resized depending on whether we want to show a
 * single row, or all labels. It hides the internal container's overflow if more
 * than one row of labels exist, but is not yet visible.
 */
const LabelsContainer = styled(Box)`
  ${props => (props.showAll ? '' : `height: ${labelRowHeight}px;`)}
  overflow: hidden;
`;

const StyledLabel = styled(Label)`
  height: ${labelHeight}px;
  margin: 1px 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  cursor: pointer;
`;

/**
 * The inner labels container always adapts to the size of labels.  Its height
 * is measured by the resize observer.
 */
const LabelsInnerContainer = styled(Flex)`
  position: relative;
  flex-wrap: wrap;
  align-items: start;
  gap: ${props => props.theme.space[1]}px;
  padding-right: 60px;
`;

/**
 * It's important for this button to use absolute positioning; otherwise, its
 * presence in the layout may itself influence the resize logic, potentially
 * causing a feedback loop.
 */
const MoreLabelsButton = styled(ButtonLink)`
  position: absolute;
  right: 0;

  height: ${labelHeight}px;
  margin: ${labelVerticalMargin}px 0;
  min-height: 0;

  background-color: ${props => getBackgroundColor(props)};
  color: ${props => props.theme.colors.text.slightlyMuted};
  font-style: italic;

  transition: visibility 0s;
  transition: background 150ms;
`;

function PinButton({
  pinned,
  pinningSupport,
  hovered,
  setPinned,
}: {
  pinned: boolean;
  pinningSupport: PinningSupport;
  hovered: boolean;
  setPinned: (id: string) => void;
}) {
  const copyAnchorEl = useRef(null);
  const tipContent = getTipContent(pinningSupport, pinned);

  const shouldShowButton =
    pinningSupport !== PinningSupport.Hidden && (pinned || hovered);
  const shouldDisableButton =
    pinningSupport === PinningSupport.Disabled ||
    pinningSupport === PinningSupport.NotSupported;

  const $content = pinned ? (
    <PushPinFilled color="brand" size="small" />
  ) : (
    <PushPin size="small" />
  );

  return (
    <ButtonIcon
      css={`
        // dont display but keep the layout
        visibility: ${shouldShowButton ? 'visible' : 'hidden'};
        position: absolute;
        // we position far from the top so the layout of the pin doesn't change if we expand the card
        top: ${props => props.theme.space[9]}px;
        transition: none;
        left: 16px;
      `}
      disabled={shouldDisableButton}
      setRef={copyAnchorEl}
      size={0}
      onClick={setPinned}
    >
      {tipContent ? (
        <HoverTooltip tipContent={<>{tipContent}</>}>{$content}</HoverTooltip>
      ) : (
        $content
      )}
      <HoverTooltip tipContent={<>{tipContent}</>}></HoverTooltip>
    </ButtonIcon>
  );
}

function getTipContent(
  pinningSupport: PinningSupport,
  pinned: boolean
): string {
  switch (pinningSupport) {
    case PinningSupport.NotSupported:
      return PINNING_NOT_SUPPORTED_MESSAGE;
    case PinningSupport.Supported:
      return pinned ? 'Unpin' : 'Pin';
    default:
      return '';
  }
}
