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

import { Box, LabelInput } from 'design';

import { useRule } from 'shared/components/Validation';

import Select, { Props as SelectProps } from '../Select';

import { LabelTip, defaultRule } from './shared';

export default function FieldSelect({
  components,
  label,
  labelTip,
  value,
  options,
  name,
  onChange,
  placeholder,
  maxMenuHeight,
  isClearable,
  isMulti,
  menuPosition,
  rule = defaultRule,
  stylesConfig,
  isSearchable = false,
  isSimpleValue = false,
  autoFocus = false,
  isDisabled = false,
  elevated = false,
  inputId = 'select',
  ...styles
}: Props) {
  const { valid, message } = useRule(rule(value));
  const hasError = Boolean(!valid);
  const labelText = hasError ? message : label;
  return (
    <Box mb="4" {...styles}>
      {label && (
        <LabelInput htmlFor={inputId} hasError={hasError}>
          {labelText}
          {labelTip && <LabelTip text={labelTip} />}
        </LabelInput>
      )}
      <Select
        components={components}
        stylesConfig={stylesConfig}
        inputId={inputId}
        name={name}
        menuPosition={menuPosition}
        hasError={hasError}
        isSimpleValue={isSimpleValue}
        isSearchable={isSearchable}
        isClearable={isClearable}
        value={value}
        onChange={onChange}
        options={options}
        maxMenuHeight={maxMenuHeight}
        placeholder={placeholder}
        isMulti={isMulti}
        autoFocus={autoFocus}
        isDisabled={isDisabled}
        elevated={elevated}
      />
    </Box>
  );
}

type Props = SelectProps & {
  autoFocus?: boolean;
  label?: string;
  rule?: (options: unknown) => () => unknown;
  // styles
  [key: string]: any;
};
