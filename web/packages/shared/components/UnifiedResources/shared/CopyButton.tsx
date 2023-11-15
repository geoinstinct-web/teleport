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

import React, { useState, useRef, useEffect } from 'react';

import ButtonIcon from 'design/ButtonIcon';
import { Check, Copy } from 'design/Icon';
import copyToClipboard from 'design/utils/copyToClipboard';

import { HoverTooltip } from 'shared/components/ToolTip';

export function CopyButton({
  name,
  mr,
  ml,
}: {
  name: string;
  mr?: number;
  ml?: number;
}) {
  const copySuccess = 'Copied!';
  const copyDefault = 'Click to copy';
  const timeout = useRef<ReturnType<typeof setTimeout>>();
  const copyAnchorEl = useRef(null);
  const [copiedText, setCopiedText] = useState(copyDefault);

  const clearCurrentTimeout = () => {
    if (timeout.current) {
      clearTimeout(timeout.current);
      timeout.current = undefined;
    }
  };

  const handleCopy = () => {
    clearCurrentTimeout();
    setCopiedText(copySuccess);
    copyToClipboard(name);
    // Change to default text after 1 second
    timeout.current = setTimeout(() => {
      setCopiedText(copyDefault);
    }, 1000);
  };

  useEffect(() => {
    return () => clearCurrentTimeout();
  }, []);

  return (
    <HoverTooltip tipContent={copiedText}>
      <ButtonIcon
        setRef={copyAnchorEl}
        size={0}
        mr={mr}
        ml={ml}
        onClick={handleCopy}
      >
        {copiedText === copySuccess ? (
          <Check size="small" />
        ) : (
          <Copy size="small" />
        )}
      </ButtonIcon>
    </HoverTooltip>
  );
}
