import Box from 'design/Box';
import { CheckboxSize, StyledCheckbox } from 'design/Checkbox';
import Flex from 'design/Flex';
import LabelInput from 'design/LabelInput';
import Text from 'design/Text';
import { space } from 'design/system';
import React, { forwardRef } from 'react';
import styled from 'styled-components';

export const FieldCheckboxInternal = forwardRef<
  HTMLInputElement,
  {
    name?: string;
    label?: React.ReactNode;
    helperText?: React.ReactNode;
    checked?: boolean;
    defaultChecked?: boolean;
    disabled?: boolean;
    size?: CheckboxSize;
    onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  }
>(
  (
    {
      name,
      label,
      helperText,
      checked,
      defaultChecked,
      disabled,
      size,
      onChange,
      ...styles
    },
    ref
  ) => {
    const labelColor = disabled ? 'text.disabled' : 'text.main';
    const helperColor = disabled ? 'text.disabled' : 'text.slightlyMuted';
    const labelTypography = size === 'small' ? 'newBody2' : 'newBody1';
    const helperTypography = size === 'small' ? 'newBody3' : 'newBody2';
    return (
      <Box mb={3} {...styles}>
        <StyledLabel disabled={disabled}>
          <Flex flexDirection="row" gap={2}>
            <StyledCheckbox
              size={size}
              ref={ref}
              checked={checked}
              defaultChecked={defaultChecked}
              disabled={disabled}
              name={name}
              onChange={onChange}
            />
            <Box>
              <Text typography={labelTypography} color={labelColor}>
                {label}
              </Text>
              <Text typography={helperTypography} color={helperColor}>
                {helperText}
              </Text>
            </Box>
          </Flex>
        </StyledLabel>
      </Box>
    );
  }
);

const StyledLabel = styled(LabelInput)<{ disabled?: boolean }>`
  display: inline-flex;
  width: auto;
  gap: ${props => props.theme.space[2]}px;
  margin-bottom: 0;
  line-height: 0;
  cursor: ${props => (props.disabled ? 'not-allowed' : 'pointer')};
`;

export const FieldCheckbox = styled(FieldCheckboxInternal)`
  ${space}
`;
