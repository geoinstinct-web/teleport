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
 *
 */

import React from 'react';
import Dialog, {
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from 'design/Dialog';
import { Danger } from 'design/Alert';
import { ButtonPrimary, ButtonSecondary, Text } from 'design';

export default function HeadlessSsoDialog({
  ipAddress,
  onAccept,
  onReject,
  errorText,
}: Props) {
  const dialogContent = () => {
    const getText = (errorText: string) => {
      if (errorText) {
        return (
          <Text textAlign="center">
            The requested session doesn't exist or is invalid. Please generate a new request.
            <br />
            <br />
            You can close this window.
          </Text>
        );
      }

      return (
        <Text textAlign="center">
          Someone has initiated a command from {ipAddress}. If it was not you,
          click reject and contact your administrator.
          <br />
          <br />
          If it was you, please use your hardware key to approve.
        </Text>
      );
    };

    const getButtons = (errorText: string) => {
      if (errorText) {
        return;
      }

      return (
        <>
          <ButtonPrimary onClick={onAccept} autoFocus mr={3} width="130px">
            Approve
          </ButtonPrimary>
          <ButtonSecondary onClick={onReject}>Reject</ButtonSecondary>
        </>
      );
    };

    return (
      <>
        <DialogContent mb={6}>
          {errorText && (
            <Danger mt={2} width="100%">
              {errorText}
            </Danger>
          )}
          {getText(errorText)}
        </DialogContent>
        <DialogFooter textAlign="center">{getButtons(errorText)}</DialogFooter>
      </>
    );
  }

  return (
    <Dialog dialogCss={() => ({ width: '400px' })} open={true}>
      <DialogHeader style={{ flexDirection: 'column' }}>
        <DialogTitle textAlign="center">
          Host {ipAddress} wants to execute a command
        </DialogTitle>
      </DialogHeader>
      {dialogContent()}
    </Dialog>
  );
}

export type Props = {
  ipAddress: string;
  onAccept: () => void;
  onReject: () => void;
  errorText: string;
};
