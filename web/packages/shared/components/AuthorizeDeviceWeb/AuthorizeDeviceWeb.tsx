/**
 * Teleport
 * Copyright (C) 2024 Gravitational, Inc.
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

import styled from 'styled-components';
import { Box, Flex, ButtonPrimary, Text, ButtonLink } from 'design';
import { Link } from 'react-router-dom';

import cfg from 'teleport/config';

import {
  DownloadConnect,
  DownloadLink,
} from 'shared/components/DownloadConnect/DownloadConnect';

export const DeviceTrustConnectPassthrough = ({
  authorizeWebDeviceDeepLink,
  downloadLinks,
}: {
  authorizeWebDeviceDeepLink: string;
  downloadLinks: Array<DownloadLink>;
}) => {
  return (
    <Wrapper>
      <Flex flexDirection="column">
        <Text fontWeight={300} fontSize={7} mb={7}>
          Click <BoldText>Open Teleport Connect</BoldText> on the dialog shown
          by your browser
        </Text>
        <Text fontSize={7} mb={10} fontWeight={300}>
          If you don't see a dialog, click{' '}
          <BoldText>Launch Teleport Connect</BoldText> below
        </Text>
        <Flex justifyContent="center" mb={9}>
          <ButtonPrimary
            textTransform="none"
            width="280px"
            as="a"
            href={authorizeWebDeviceDeepLink}
          >
            Launch Teleport Connect
          </ButtonPrimary>
        </Flex>
        <Box>
          <Text fontSize={3}>
            Don't have Teleport Connect?{' '}
            {downloadLinks.length === 1 ? (
              <DownloadButton as="a" href={downloadLinks[0].url}>
                Download it now
              </DownloadButton>
            ) : (
              <DownloadConnect downloadLinks={downloadLinks} />
            )}
          </Text>
        </Box>
        <SkipAuthNotice>
          <Text>
            You can{' '}
            <Link
              css={`
                text-decoration: none;
              `}
              to={cfg.routes.root}
            >
              continue without device trust{' '}
            </Link>
            but you will not be able to connect to resources that require Device
            Trust.
          </Text>
        </SkipAuthNotice>
      </Flex>
    </Wrapper>
  );
};

const SkipAuthNotice = styled(Box)`
  text-align: center;
  width: 100%;
  position: absolute;
  bottom: 24px;
`;

const DownloadButton = styled(ButtonLink)`
  text-decoration: none;
  font-size: 16px;
  color: ${props => props.theme.colors.brand};
`;

const BoldText = styled.span`
  font-weight: 700;
`;

const Wrapper = styled(Box)`
  text-align: center;
  line-height: 32px;
`;
