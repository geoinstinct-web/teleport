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
import styled, { keyframes } from 'styled-components';

interface NodeLineProps {
  children?: React.ReactNode;
  width: number;
  height: number;
}

const appear = keyframes`
  from {
    width: 0;
  }
  to {
    width: 260px;
  }
`;

const NodeLineContainer = styled.div`
  position: absolute;
  top: 43px;
  border-bottom-left-radius: 5px;
  border-bottom-right-radius: 5px;
  overflow: hidden;
  animation: ${appear} 1s ease-in forwards;

  svg {
    path {
      fill: none;
    }
  }
`;

const line = keyframes`
  0% {
    stroke-dashoffset: -250;
  }

  100% {
    stroke-dashoffset: 0;
  }
`;

export const StyledSVG = styled.svg`
  position: absolute;
  z-index: 1;

  path {
    stroke: #278348;
    stroke-width: 4;
    fill: none;
  }
`;

export const AnimatedStyledSVG = styled(StyledSVG)`
  stroke-dasharray: 5, 20;
  stroke-dashoffset: 0;
  z-index: 2;
  animation: ${line} 5s cubic-bezier(0.78, 0.11, 0.27, 0.94) alternate infinite
    0.6s;

  path {
    stroke: #32c842;
  }
`;

export function NodeLine(props: NodeLineProps) {
  return (
    <NodeLineContainer
      style={{ width: props.width, height: props.height, left: -props.width }}
    >
      <StyledSVG width={props.width} height={props.height}>
        {props.children}
      </StyledSVG>
      <AnimatedStyledSVG width={props.width} height={props.height}>
        {props.children}
      </AnimatedStyledSVG>
    </NodeLineContainer>
  );
}
