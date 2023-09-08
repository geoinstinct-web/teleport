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

const loading = keyframes`
  0% {
    transform: translateX(-100%);
  }
  100% {
    transform: translateX(100%);
  }
`;

const SkeletonWrapper = styled.div`
  width: 100%;
  height: 100%;
  background-color: ${props => props.theme.colors.levels.surface};
  border-radius: ${props => props.theme.radii[3]}px;
  overflow: hidden;
  position: relative;
`;

const Shimmer = styled.div`
  width: 100%;
  height: 100%;
  background: linear-gradient(
    90deg,
    transparent 25%,
    ${props => props.theme.colors.levels.elevated} 50%,
    transparent 75%
  );
  background-size: 200% 100%;
  animation: ${loading} 1.5s infinite;
`;

export const SkeletonLoader = props => {
  return (
    <SkeletonWrapper {...props}>
      <Shimmer />
    </SkeletonWrapper>
  );
};
