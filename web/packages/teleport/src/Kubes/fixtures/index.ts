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

import { Kube } from 'teleport/services/kube';

export const kubes: Kube[] = [
  {
    name: 'tele.logicoma.dev-prod',
    labels: [
      { name: 'kernel', value: '4.15.0-51-generic' },
      { name: 'env', value: 'prod' },
    ],
  },
  {
    name: 'tele.logicoma.dev-staging',
    labels: [{ name: 'env', value: 'staging' }],
  },
  {
    name: 'cookie',
    labels: [
      { name: 'cluster-name', value: 'some-cluster-name' },
      { name: 'env', value: 'idk' },
    ],
  },
];
