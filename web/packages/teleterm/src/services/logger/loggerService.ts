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

import { createLogger as createWinston, format, transports } from 'winston';
import { isObject } from 'lodash';

import split2 from 'split2';

import { Logger, NodeLoggerService } from './types';

export default function createLoggerService(opts: Options): NodeLoggerService {
  const instance = createWinston({
    level: 'info',
    exitOnError: false,
    format: format.combine(
      format.timestamp({
        format: 'DD-MM-YY HH:mm:ss',
      }),
      format.printf(({ level, message, timestamp, context }) => {
        const text = stringifier(message as unknown as unknown[]);
        const contextAndLevel = opts.passThroughMode
          ? ''
          : ` [${context}] ${level}`;
        return `[${timestamp}]${contextAndLevel}: ${text}`;
      })
    ),
    transports: [
      new transports.File({
        maxsize: 4194304, // 4 MB - max size of a single file
        maxFiles: 5,
        dirname: opts.dir + '/logs',
        filename: `${opts.name}.log`,
      }),
    ],
  });

  if (opts.dev) {
    instance.add(
      new transports.Console({
        format: format.printf(({ level, message, context }) => {
          const text = stringifier(message as unknown as unknown[]);
          return opts.passThroughMode ? text : `[${context}] ${level}: ${text}`;
        }),
      })
    );
  }

  return {
    pipeProcessOutputIntoLogger(stream): void {
      stream
        .pipe(split2(line => ({ level: 'info', message: [line] })))
        .pipe(instance);
    },
    createLogger(context = 'default'): Logger {
      const logger = instance.child({ context });
      return {
        error: (...args) => {
          logger.error(args);
        },
        warn: (...args) => {
          logger.warn(args);
        },
        info: (...args) => {
          logger.info(args);
        },
      };
    },
  };
}

function stringifier(message: unknown[]): string {
  return message
    .map(singleMessage => {
      if (singleMessage instanceof Error) {
        return singleMessage.stack;
      }
      if (isObject(singleMessage)) {
        return JSON.stringify(singleMessage);
      }
      return singleMessage;
    })
    .join(' ');
}

type Options = {
  dir: string;
  name: string;
  dev?: boolean;
  /**
   * Mode for logger handling logs from other sources. Log level and context are not included in the log message.
   */
  passThroughMode?: boolean;
};
