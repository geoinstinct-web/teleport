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
 */

import React, { useState } from 'react';
import { Box, ButtonPrimary, Text, Flex } from 'design';
import FieldSelect from 'shared/components/FieldSelect';
import { Option } from 'shared/components/Select';
import { requiredField } from 'shared/components/Validation/rules';
import Validation, { Validator } from 'shared/components/Validation';

import { awsRegionMap, Regions } from 'teleport/services/integrations';

export function AwsRegionSelector({
  onFetch,
  disableBtn,
  disableSelector,
  clear,
}: {
  onFetch(region: Regions): void;
  disableBtn: boolean;
  disableSelector: boolean;
  clear(): void;
}) {
  const [selectedRegion, setSelectedRegion] = useState<RegionOption>();

  function handleFetch(validator: Validator) {
    if (!validator.validate()) {
      return;
    }
    onFetch(selectedRegion.value);
  }

  function handleRegionSelect(option: RegionOption) {
    clear();
    setSelectedRegion(option);
  }

  return (
    <Validation>
      {({ validator }) => (
        <>
          <Text mt={4}>
            Select the AWS Region you would like to see databases for:
          </Text>
          <Flex alignItems="center" gap={3} mt={2} mb={3}>
            <Box width="320px">
              <FieldSelect
                label="AWS Region"
                rule={requiredField('Region is required')}
                placeholder="Select a Region"
                isSearchable
                isSimpleValue
                value={selectedRegion}
                onChange={handleRegionSelect}
                options={options}
                isDisabled={disableSelector}
              />
            </Box>
            <ButtonPrimary
              disabled={disableBtn || !selectedRegion}
              onClick={() => handleFetch(validator)}
              width="160px"
              height="40px"
              mt={1}
            >
              Fetch Databases
            </ButtonPrimary>
          </Flex>
        </>
      )}
    </Validation>
  );
}

type RegionOption = Option<Regions, React.ReactElement>;

const options: RegionOption[] = Object.keys(awsRegionMap).map(region => ({
  value: region as Regions,
  label: (
    <Flex justifyContent="space-between">
      <div>{awsRegionMap[region]}&nbsp;&nbsp;</div>
      <div>{region}</div>
    </Flex>
  ),
}));
