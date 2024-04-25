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

import CardIcon from 'design/CardIcon';
import { CircleCheck } from 'design/Icon';

export default function CardSuccess({ title, children }) {
  return (
    <CardIcon
      title={title}
      icon={<CircleCheck mb={3} fontSize={56} color="success" />}
    >
      {children}
    </CardIcon>
  );
}

export function CardSuccessLogin() {
  return (
    <CardSuccess title="Login Successful">
      You have successfully signed into your account. <br /> You can close this
      window and continue using the product.
    </CardSuccess>
  );
}
