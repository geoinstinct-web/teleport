/*
Copyright 2019 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import React from 'react';
import styled from 'styled-components';

import defaultTheme from 'design/theme';
import { space, color } from 'design/system';

function Link({ ...props }) {
  return <StyledButtonLink {...props} />;
}

Link.defaultProps = {
  theme: defaultTheme,
};

Link.displayName = 'Link';

const StyledButtonLink = styled.a.attrs({
  rel: 'noreferrer',
})`
  color: ${({ theme }) => theme.colors.link};
  font-weight: normal;
  background: none;
  text-decoration: underline;
  text-transform: none;

  ${space}
  ${color}
`;

export default Link;
