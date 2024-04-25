/**
 * Teleport
 * Copyright (C) 2024 Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import { useSyncExternalStore, useCallback } from 'react';

import { useAppContext } from 'teleterm/ui/appContextProvider';
import { IAppContext } from 'teleterm/ui/types';
import { ImmutableStore } from 'teleterm/ui/services/immutableStore';

/**
 * useImmutableStore selects a value out of a store and triggers component update whenever that
 * value changes. The selector needs to have stable identity.
 *
 * @example
 * const isInitialized = useImmutableStore(
 *   'workspacesService',
 *   useCallback(state => state.isInitialized, [])
 * );
 *
 * @example
 * // Defined outside of a component.
 * const getIsInitialized = (selector: WorkspacesState) => state.isInitialized
 *
 * // Defined inside a React component.
 * () => {
 *   const isInitialized = useImmutableStore('workspacesService', getIsInitialized);
 * }
 */
export const useImmutableStore = <
  SelectedState,
  StoreKey extends ImmutableStoreKeys<IAppContext>,
>(
  storeKey: StoreKey,
  selector: (state: IAppContext[StoreKey]['state']) => SelectedState
): SelectedState => {
  const store = useAppContext()[storeKey];

  const subscribe = useCallback(
    (listener: () => void) => store.subscribeWithSelector(selector, listener),
    [store, selector]
  );
  const getSnapshot = useCallback(
    () => selector(store.state),
    [store, selector]
  );

  return useSyncExternalStore(subscribe, getSnapshot);
};

type ImmutableStoreKeys<T> = {
  [K in keyof T]: T[K] extends ImmutableStore<any> ? K : never;
}[keyof T];
