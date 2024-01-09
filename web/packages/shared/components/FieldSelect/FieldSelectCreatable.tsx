/*
Copyright 2023 Gravitational, Inc.

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

import {
  SelectCreatable,
  CreatableProps as SelectCreatableProps,
} from '../Select';

import { LabelTip, defaultRule } from './shared';

/**
 * Returns a styled SelectCreatable with label, input validation rule and error handling.
 * @param {() => void} onChange - change handler.
 * @param {defaultRule} rule - rules for the select component.
 * @param {boolean} markAsError - manually mark the component as error.
 * @param {string} placeholder - placeholder value.
 * @param {string} formatCreateLabel - custom formatting for create label.
 * @returns SelectCreatable
 */
export function FieldSelectCreatable({
  components,
  label,
  labelTip,
  value,
  name,
  onChange,
  placeholder,
  maxMenuHeight,
  isClearable,
  isMulti,
  menuIsOpen,
  menuPosition,
  inputValue,
  onKeyDown,
  onInputChange,
  onBlur,
  options,
  formatCreateLabel,
  ariaLabel,
  rule = defaultRule,
  stylesConfig,
  isSearchable = false,
  isSimpleValue = false,
  autoFocus = false,
  isDisabled = false,
  elevated = false,
  inputId = 'select',
  markAsError = false,
  ...styles
}: CreatableProps) {
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
      <SelectCreatable
        components={components}
        inputId={inputId}
        name={name}
        menuPosition={menuPosition}
        hasError={hasError || markAsError}
        isSimpleValue={isSimpleValue}
        isSearchable={isSearchable}
        isClearable={isClearable}
        value={value}
        onChange={onChange}
        onKeyDown={onKeyDown}
        onInputChange={onInputChange}
        onBlur={onBlur}
        inputValue={inputValue}
        maxMenuHeight={maxMenuHeight}
        placeholder={placeholder}
        isMulti={isMulti}
        autoFocus={autoFocus}
        isDisabled={isDisabled}
        elevated={elevated}
        menuIsOpen={menuIsOpen}
        stylesConfig={stylesConfig}
        options={options}
        formatCreateLabel={formatCreateLabel}
        aria-label={ariaLabel}
      />
    </Box>
  );
}

type CreatableProps = SelectCreatableProps & {
  autoFocus?: boolean;
  label?: string;
  rule?: (options: unknown) => () => unknown;
  markAsError?: boolean;
  ariaLabel?: string;
  // styles
  [key: string]: any;
};
