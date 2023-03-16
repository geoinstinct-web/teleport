/**
 * Copyright 2023 Gravitational, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { Platform } from 'teleterm/mainProcess/types';
import {
  KeyboardShortcutAction,
  ConfigService,
} from 'teleterm/services/config';

import {
  KeyboardShortcutEvent,
  KeyboardShortcutEventSubscriber,
} from './types';

export class KeyboardShortcutsService {
  private eventsSubscribers = new Set<KeyboardShortcutEventSubscriber>();
  private readonly acceleratorsToActions = new Map<
    string,
    KeyboardShortcutAction
  >();
  private readonly shortcutsConfig: Record<KeyboardShortcutAction, string>;

  constructor(
    private platform: Platform,
    private configService: ConfigService
  ) {
    this.shortcutsConfig = {
      tab1: this.configService.get('keymap.tab1').value,
      tab2: this.configService.get('keymap.tab2').value,
      tab3: this.configService.get('keymap.tab3').value,
      tab4: this.configService.get('keymap.tab4').value,
      tab5: this.configService.get('keymap.tab5').value,
      tab6: this.configService.get('keymap.tab6').value,
      tab7: this.configService.get('keymap.tab7').value,
      tab8: this.configService.get('keymap.tab8').value,
      tab9: this.configService.get('keymap.tab9').value,
      closeTab: this.configService.get('keymap.closeTab').value,
      previousTab: this.configService.get('keymap.previousTab').value,
      nextTab: this.configService.get('keymap.nextTab').value,
      newTab: this.configService.get('keymap.newTab').value,
      openQuickInput: this.configService.get('keymap.openQuickInput').value,
      openConnections: this.configService.get('keymap.openConnections').value,
      openClusters: this.configService.get('keymap.openClusters').value,
      openProfiles: this.configService.get('keymap.openProfiles').value,
    };
    this.acceleratorsToActions = mapAcceleratorsToActions(this.shortcutsConfig);
    this.attachKeydownHandler();
  }

  subscribeToEvents(subscriber: KeyboardShortcutEventSubscriber): void {
    this.eventsSubscribers.add(subscriber);
  }

  unsubscribeFromEvents(subscriber: KeyboardShortcutEventSubscriber): void {
    this.eventsSubscribers.delete(subscriber);
  }

  getShortcutsConfig() {
    return this.shortcutsConfig;
  }

  private attachKeydownHandler(): void {
    const handleKeydown = (event: KeyboardEvent): void => {
      const shortcutAction = this.getShortcutAction(event);
      if (!shortcutAction) {
        return;
      }

      event.preventDefault();
      event.stopPropagation();
      this.notifyEventsSubscribers({ action: shortcutAction });
    };

    window.addEventListener('keydown', handleKeydown, {
      capture: true,
    });
  }

  private getShortcutAction(
    event: KeyboardEvent
  ): KeyboardShortcutAction | undefined {
    const getEventKey = () =>
      event.key.length === 1 ? event.key.toUpperCase() : event.key;

    const accelerator = [...this.getPlatformModifierKeys(event), getEventKey()]
      .filter(Boolean)
      .join('+');

    return this.acceleratorsToActions.get(accelerator);
  }

  private getPlatformModifierKeys(event: KeyboardEvent): string[] {
    switch (this.platform) {
      case 'darwin':
        return [
          event.metaKey && 'Command',
          event.ctrlKey && 'Control',
          event.altKey && 'Option',
          event.shiftKey && 'Shift',
        ];
      default:
        return [
          event.ctrlKey && 'Ctrl',
          event.altKey && 'Alt',
          event.shiftKey && 'Shift',
        ];
    }
  }

  private notifyEventsSubscribers(event: KeyboardShortcutEvent): void {
    this.eventsSubscribers.forEach(subscriber => subscriber(event));
  }
}

/** Inverts shortcuts-keys pairs to allow accessing shortcut by an accelerator. */
function mapAcceleratorsToActions(
  shortcutsConfig: Record<KeyboardShortcutAction, string>
): Map<string, KeyboardShortcutAction> {
  const acceleratorsToActions = new Map<string, KeyboardShortcutAction>();
  Object.entries(shortcutsConfig).forEach(([action, accelerator]) => {
    acceleratorsToActions.set(accelerator, action as KeyboardShortcutAction);
  });

  return acceleratorsToActions;
}
