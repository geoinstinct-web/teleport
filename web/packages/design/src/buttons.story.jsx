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

import ButtonLink from './ButtonLink';
import ButtonIcon from './ButtonIcon';
import { AddUsers, Trash, Ellipsis } from './Icon';
import Flex from './Flex';
import Button, {
  ButtonPrimary,
  ButtonSecondary,
  ButtonWarning,
  ButtonBorder,
  ButtonText,
} from './Button';

export default {
  title: 'Design/Button',
};

export const Buttons = () => (
  <Flex gap={4} flexDirection="column" alignItems="flex-start">
    <Flex gap={3}>
      <ButtonPrimary>Primary</ButtonPrimary>
      <ButtonSecondary>Secondary</ButtonSecondary>
      <ButtonBorder>Border</ButtonBorder>
      <ButtonWarning>Warning</ButtonWarning>
    </Flex>

    <Flex gap={3} alignItems="center">
      <Button size="large">Large</Button>
      <Button size="medium">Medium</Button>
      <Button size="small">Small</Button>
    </Flex>

    <Button block>block = true</Button>

    <Flex gap={3}>
      <Button disabled>Disabled</Button>
      <Button autoFocus>Focused</Button>
    </Flex>

    <Flex gap={3}>
      <ButtonPrimary gap={2}>
        <AddUsers />
        Add users
      </ButtonPrimary>
    </Flex>

    <Flex gap={3}>
      <ButtonLink href="">Button Link</ButtonLink>
      <ButtonText>Button Text</ButtonText>
    </Flex>

    <Flex gap={3}>
      <ButtonIcon size={2}>
        <AddUsers />
      </ButtonIcon>
      <ButtonIcon size={2}>
        <Ellipsis />
      </ButtonIcon>
      <ButtonIcon size={2}>
        <Trash />
      </ButtonIcon>
    </Flex>

    <Flex gap={3}>
      <ButtonIcon size={1}>
        <AddUsers />
      </ButtonIcon>
      <ButtonIcon size={1}>
        <Ellipsis />
      </ButtonIcon>
      <ButtonIcon size={1}>
        <Trash />
      </ButtonIcon>
    </Flex>

    <Flex gap={3}>
      <ButtonIcon size={0}>
        <AddUsers />
      </ButtonIcon>
      <ButtonIcon size={0}>
        <Ellipsis />
      </ButtonIcon>
      <ButtonIcon size={0}>
        <Trash />
      </ButtonIcon>
    </Flex>
  </Flex>
);
