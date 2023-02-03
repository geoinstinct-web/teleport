import React, { DependencyList } from 'react';

import { render } from 'design/utils/testing';

import { useRefAutoFocus } from './useRefAutoFocus';

test('focus automatically when allowed', () => {
  const element = {
    focus: jest.fn(),
  };
  render(<Focusable element={element} shouldFocus={true} />);
  expect(element.focus).toHaveBeenCalledTimes(1);
});

test('do nothing when focus in not allowed', () => {
  const element = {
    focus: jest.fn(),
  };
  render(<Focusable element={element} shouldFocus={false} />);
  expect(element.focus).not.toHaveBeenCalled();
});

test('refocus when deps list changes', () => {
  const element = {
    focus: jest.fn(),
  };
  const { rerender } = render(
    <Focusable
      element={element}
      shouldFocus={true}
      reFocusDeps={['old prop']}
    />
  );
  rerender(
    <Focusable
      element={element}
      shouldFocus={true}
      reFocusDeps={['new prop']}
    />
  );
  expect(element.focus).toHaveBeenCalledTimes(2);
});

test('do not refocus when deps list does not change', () => {
  const element = {
    focus: jest.fn(),
  };
  const { rerender } = render(
    <Focusable
      element={element}
      shouldFocus={true}
      reFocusDeps={['old prop']}
    />
  );
  rerender(
    <Focusable
      element={element}
      shouldFocus={true}
      reFocusDeps={['old prop']}
    />
  );
  expect(element.focus).toHaveBeenCalledTimes(1);
});

const Focusable = (props: {
  element: { focus(): void };
  shouldFocus: boolean;
  reFocusDeps?: DependencyList;
}) => {
  const ref = useRefAutoFocus({
    shouldFocus: props.shouldFocus,
    refocusDeps: props.reFocusDeps,
  });
  ref.current = props.element;
  return null;
};
