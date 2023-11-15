/*
Copyright 2022 Gravitational, Inc.

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
import { Link } from 'react-router-dom';

import { ButtonPrimary } from 'design';

import cfg from 'teleport/config';
import { SearchResource } from 'teleport/Discover/SelectResource';

export default function AgentButtonAdd(props: Props) {
  const { canCreate, isLeafCluster, onClick, agent, beginsWithVowel } = props;
  const disabled = isLeafCluster || !canCreate;

  // Don't render button if it's disabled and feature hiding is enabled.
  const hidden = disabled && cfg.hideInaccessibleFeatures;

  let title = '';
  if (!canCreate) {
    if (agent === SearchResource.UNIFIED_RESOURCE) {
      title = `You do not have access to add resources.`;
    } else {
      title = `You do not have access to add ${
        beginsWithVowel ? 'an' : 'a'
      } ${agent}`;
    }
  }

  if (isLeafCluster) {
    if (agent === SearchResource.UNIFIED_RESOURCE) {
      title = `Adding resources to a leaf cluster is not supported.`;
    } else {
      title = `Adding ${
        beginsWithVowel ? 'an' : 'a'
      } ${agent} to a leaf cluster is not supported`;
    }
  }

  if (hidden) {
    return null;
  }

  return (
    <Link
      to={{
        pathname: `${cfg.routes.root}/discover`,
        state: { entity: agent !== 'unified_resource' ? agent : null },
      }}
      style={{ textDecoration: 'none' }}
    >
      <ButtonPrimary
        textTransform="none"
        title={title}
        disabled={disabled}
        width="240px"
        onClick={onClick}
      >
        {agent === 'unified_resource' ? 'Enroll New Resource' : `Add ${agent}`}
      </ButtonPrimary>
    </Link>
  );
}

export type Props = {
  isLeafCluster: boolean;
  canCreate: boolean;
  onClick?: () => void;
  agent: SearchResource;
  beginsWithVowel: boolean;
};
