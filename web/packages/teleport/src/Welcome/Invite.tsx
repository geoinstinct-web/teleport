/*
Copyright 2021 Gravitational, Inc.

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

import { Route, Routes, useParams, useNavigate } from 'react-router-dom';

import LogoHero from 'teleport/components/LogoHero';
import cfg from 'teleport/config';

import { NewCredentials } from './NewCredentials';
import { CardWelcome } from './CardWelcome';

export default function Invite() {
  const navigate = useNavigate();

  const { tokenId } = useParams<{ tokenId: string }>();

  const handleOnInviteContinue = () => {
    navigate(cfg.getUserInviteTokenContinueRoute(tokenId));
  };

  return (
    <>
      <LogoHero />
      <Routes>
        <Route
          index
          element={
            <CardWelcome
              title="Welcome to Teleport"
              subTitle="Please click the button below to create an account"
              btnText="Get started"
              onClick={handleOnInviteContinue}
            />
          }
        />
        <Route
          path={'continue'}
          element={<NewCredentials tokenId={tokenId} />}
        />
      </Routes>
    </>
  );
}
