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

// This file works both in the browser and Node.js.
// In Node environment, it imports the built-in events module.
// In browser environment, it imports the events package.
import { EventEmitter } from 'events';

import { TshAbortController } from './types';

/**
 * Creates a version of AbortController that can be passed through Electron contextBridge
 */
export default function createAbortController(): TshAbortController {
  const emitter = new EventEmitter();

  const signal = {
    aborted: false,
    // TODO(ravicious): Consider aligning the interface of TshAbortSignal with the interface of
    // browser's AbortSignal so that those two can be used interchangeably, for example in the wait
    // function from the shared package.
    //
    // TshAbortSignal doesn't accept the event name as the first argument.
    addEventListener(cb: (...args: any[]) => void) {
      emitter.once('abort', cb);
    },

    removeEventListener(cb: (...args: any[]) => void) {
      emitter.removeListener('abort', cb);
    },
  };

  return {
    signal,
    abort() {
      // Once abort() has been called and the signal becomes aborted, it cannot be reused.
      // https://dom.spec.whatwg.org/#abortsignal-signal-abort
      if (signal.aborted) {
        return;
      }

      signal.aborted = true;
      emitter.emit('abort');
    },
  };
}
