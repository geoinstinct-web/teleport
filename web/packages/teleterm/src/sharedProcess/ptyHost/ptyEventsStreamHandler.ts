/**
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
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

import { ServerDuplexStream } from '@grpc/grpc-js';

import Logger from 'teleterm/logger';

import {
  ptyEventOneOfIsData,
  ptyEventOneOfIsResize,
  ptyEventOneOfIsStart,
} from 'teleterm/helpers';

import {
  PtyClientEvent,
  PtyEventData,
  PtyEventExit,
  PtyEventOpen,
  PtyEventResize,
  PtyEventStart,
  PtyEventStartError,
  PtyServerEvent,
} from '../api/protogen/ptyHostService_pb';

import { PtyProcess } from './ptyProcess';

export class PtyEventsStreamHandler {
  private readonly ptyId: string;
  private readonly ptyProcess: PtyProcess;
  private readonly logger: Logger;

  constructor(
    private readonly stream: ServerDuplexStream<PtyClientEvent, PtyServerEvent>,
    private readonly ptyProcesses: Map<string, PtyProcess>
  ) {
    this.ptyId = stream.metadata.get('ptyId')[0].toString();
    this.ptyProcess = ptyProcesses.get(this.ptyId)!;
    this.logger = new Logger(`PtyEventsStreamHandler (id: ${this.ptyId})`);

    stream.addListener('data', event => this.handleStreamData(event));
    stream.addListener('error', event => this.handleStreamError(event));
    stream.addListener('end', () => this.handleStreamEnd());
  }

  private handleStreamData(event: PtyClientEvent): void {
    if (ptyEventOneOfIsStart(event.event)) {
      return this.handleStartEvent(event.event.start);
    }

    if (ptyEventOneOfIsData(event.event)) {
      return this.handleDataEvent(event.event.data);
    }

    if (ptyEventOneOfIsResize(event.event)) {
      return this.handleResizeEvent(event.event.resize);
    }
  }

  private handleStartEvent(event: PtyEventStart): void {
    this.ptyProcess.onData(data =>
      this.stream.write(
        PtyServerEvent.create({
          event: {
            oneofKind: 'data',
            data: PtyEventData.create({ message: data }),
          },
        })
      )
    );
    this.ptyProcess.onOpen(() =>
      this.stream.write(
        PtyServerEvent.create({
          event: {
            oneofKind: 'open',
            open: PtyEventOpen.create(),
          },
        })
      )
    );
    this.ptyProcess.onExit(({ exitCode, signal }) =>
      this.stream.write(
        PtyServerEvent.create({
          event: {
            oneofKind: 'exit',
            exit: PtyEventExit.create({ exitCode, signal }),
          },
        })
      )
    );
    this.ptyProcess.onStartError(message => {
      this.stream.write(
        PtyServerEvent.create({
          event: {
            oneofKind: 'startError',
            startError: PtyEventStartError.create({ message }),
          },
        })
      );
    });
    this.ptyProcess.start(event.columns, event.rows);
    this.logger.info(`stream has started`);
  }

  private handleDataEvent(event: PtyEventData): void {
    this.ptyProcess.write(event.message);
  }

  private handleResizeEvent(event: PtyEventResize): void {
    this.ptyProcess.resize(event.columns, event.rows);
  }

  private handleStreamError(error: Error): void {
    this.logger.error(`stream has ended with error`, error);
    this.cleanResources();
  }

  private handleStreamEnd(): void {
    this.logger.info(`stream has ended`);
    this.cleanResources();
  }

  private cleanResources(): void {
    this.ptyProcess.dispose();
    if (this.ptyId) {
      this.ptyProcesses.delete(this.ptyId);
    }
    this.stream.destroy();
    this.stream.removeAllListeners();
  }
}
