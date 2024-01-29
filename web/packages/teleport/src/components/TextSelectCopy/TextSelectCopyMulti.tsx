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

import React, { useRef } from 'react';
import styled from 'styled-components';
import { copyToClipboard } from 'design/utils/copyToClipboard';
import selectElementContent from 'design/utils/selectElementContent';
import { ButtonSecondary, Box, Flex } from 'design';
import { Copy, Check, Download } from 'design/Icon';

const ONE_SECOND_IN_MS = 1000;

export function TextSelectCopyMulti({
  lines,
  bash = true,
  maxHeight = 'none',
  saveContent = { save: false, filename: '' },
}: Props) {
  const refs = useRef<HTMLElement[]>([]);

  function onCopyClick(index) {
    copyToClipboard(lines[index].text).then(() => {
      const targetEl =
        refs.current[index].getElementsByClassName('icon-container')[0];
      targetEl.classList.toggle('copied');

      setTimeout(() => {
        targetEl.classList.toggle('copied');
      }, ONE_SECOND_IN_MS);
    });

    const targetEl =
      refs.current[index].getElementsByClassName('text-to-copy')[0];
    selectElementContent(targetEl as HTMLElement);
  }

  function saveContentAsFile(content: string): void {
    const a = document.createElement('a');
    const blob = new Blob([content], { type: 'plain/text' });
    a.href = window.URL.createObjectURL(blob);
    a.download = saveContent.filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }

  const isFirefox = window.navigator?.userAgent
    ?.toLowerCase()
    .includes('firefox');

  return (
    <Box
      bg="bgTerminal"
      pl={3}
      pt={2}
      pr={saveContent.save ? 11 : 7}
      borderRadius={2}
      maxHeight={maxHeight}
      minHeight="50px"
      // Firefox does not add space for visible scrollbars
      // like it does for chrome and safari.
      pb={isFirefox ? 3 : 2}
      css={{
        position: 'relative',
        overflowY: 'scroll',
      }}
      className={props => props.className}
    >
      <Lines mr={1}>
        {lines.map((line, index) => {
          const isLastText = index === lines.length - 1;
          return (
            <Box
              pt={2}
              pb={isLastText ? 0 : 2}
              key={index}
              ref={s => (refs.current[index] = s)}
            >
              {line.comment && <Comment>{line.comment}</Comment>}
              <Flex>
                <Flex>
                  {bash && <Box mr="1">{`$`}</Box>}
                  <div className="text-to-copy">
                    <pre css={{ margin: 0 }}>{line.text}</pre>
                  </div>
                </Flex>
                <Box
                  pr={3}
                  css={`
                    position: absolute;
                    right: 0px;
                  `}
                >
                  <StyledButtonSecondary onClick={() => onCopyClick(index)}>
                    <Icon className="icon-container">
                      <Copy data-testid="btn-copy" color="light" size={16} />
                      <Check data-testid="btn-check" color="light" size={16} />
                    </Icon>
                  </StyledButtonSecondary>
                  {saveContent.save && (
                    <StyledButtonSecondary
                      ml={2}
                      onClick={() => saveContentAsFile(line.text)}
                    >
                      <Download
                        data-testid="btn-download"
                        color="light"
                        size={16}
                      />
                    </StyledButtonSecondary>
                  )}
                </Box>
              </Flex>
            </Box>
          );
        })}
      </Lines>
    </Box>
  );
}

const Icon = styled.div`
  display: flex;
  .icon-check {
    display: none;
  }
  .icon-copy {
    display: inline-flex;
  }

  &.copied {
    .icon-check {
      display: inline-flex;
    }
    .icon-copy {
      display: none;
    }
  }
`;

const Comment = styled.div`
  color: rgb(117 113 94 / 80%);
`;

const StyledButtonSecondary = styled(ButtonSecondary)`
  height: 28px;
  width: 28px;
  border-radius: 20px;
  min-height: auto;
  padding: 0;
  margin-top: -4px;
  background: rgba(255, 255, 255, 0.07);
  &:hover,
  &:focus {
    background: rgba(255, 255, 255, 0.13);
  }
`;

const Lines = styled(Box)`
  white-space: pre;
  word-break: break-all;
  font-size: 12px;
  font-family: ${({ theme }) => theme.fonts.mono};
  overflow-x: scroll;
  line-height: 20px;
  color: ${props => props.theme.colors.light};
`;

type Line = {
  // text is the text to copy.
  text: string;
  // comment is an optional grayed out text that
  // will render above the text to copy.
  comment?: string;
};

export type Props = {
  lines: Line[];
  bash?: boolean;
  saveContent?: saveContent;
  maxHeight?: string;
};

type saveContent = {
  save: boolean;
  filename: string;
};
