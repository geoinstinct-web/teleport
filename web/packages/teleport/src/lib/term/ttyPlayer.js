/*
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

import { throttle } from 'shared/utils/highbar';
import Logger from 'shared/libs/logger';

import Tty from './tty';
import { TermEvent, WebsocketCloseCode } from './enums';

const logger = Logger.create('TtyPlayer');

export const StatusEnum = {
  PLAYING: 'PLAYING',
  ERROR: 'ERROR',
  PAUSED: 'PAUSED',
  LOADING: 'LOADING',
  COMPLETE: 'COMPLETE',
};

const messageTypePty = 1;
const messageTypeError = 2;
const messageTypePlayPause = 3;
const messageTypeSeek = 4;
const messageTypeResize = 5;

const actionPlay = 0;
const actionPause = 1;

// we update the time every time we receive data, or
// at this interval (which ensures that the progress
// bar updates even when we aren't receiving data)
const PROGRESS_UPDATE_INTERVAL_MS = 50;

export default class TtyPlayer extends Tty {
  constructor({ url, setPlayerStatus, setStatusText, setTime }) {
    super({});

    this._url = url;
    this._setPlayerStatus = setPlayerStatus;
    this._setStatusText = setStatusText;

    this._paused = false;
    this._lastPlayedTimestamp = 0;

    this._sendTimeUpdates = true;
    this._setTime = throttle(t => setTime(t), PROGRESS_UPDATE_INTERVAL_MS);
    this._lastUpdate = 0;
    this._timeout = null;
  }

  // Override the base class connection, which uses the envelope-based
  // websocket protocol (this protocol doesn't support sending timing data).
  connect() {
    this._setPlayerStatus(StatusEnum.LOADING);

    this.webSocket = new WebSocket(this._url);
    this.webSocket.binaryType = 'arraybuffer';
    this.webSocket.onopen = () => this.emit('open');
    this.webSocket.onmessage = m => this.onMessage(m);
    this.webSocket.onclose = e => {
      logger.debug('websocket closed', e);
      this.cancelTimeUpdate();

      this.webSocket.close();
      this.webSocket.onopen = null;
      this.webSocket.onclose = null;
      this.webSocket.onmessage = null;
      this.webSocket = null;

      this.emit(TermEvent.CONN_CLOSE, e);
      this._setPlayerStatus(StatusEnum.COMPLETE);
    };
  }

  suspendTimeUpdates() {
    this._sendTimeUpdates = false;
  }

  resumeTimeUpdates() {
    this._sendTimeUpdates = true;
  }

  setTime(t) {
    // time updates are suspended when a user is dragging the slider to
    // a new position (it's very disruptive if we're updating the slider
    // position every few milliseconds while the user is trying to
    // reposition it)
    if (this._sendTimeUpdates) {
      this._setTime(t);
    }
  }

  disconnect(closeCode = WebsocketCloseCode.NORMAL) {
    this.cancelTimeUpdate();
    if (this.webSocket !== null) {
      this.webSocket.close(closeCode);
    }
  }

  scheduleNextUpdate(current) {
    this._timeout = setTimeout(() => {
      const delta = Date.now() - this._lastUpdate;
      const next = current + delta;
      this.setTime(next);
      this._lastUpdate = Date.now();

      this.scheduleNextUpdate(next);
    }, PROGRESS_UPDATE_INTERVAL_MS);
  }

  cancelTimeUpdate() {
    if (this._timeout != null) {
      clearTimeout(this._timeout);
      this._timeout = null;
    }
  }

  onMessage(m) {
    try {
      const dv = new DataView(m.data);
      const typ = dv.getUint8(0);
      const len = dv.getUint16(1);

      // see lib/web/tty_playback.go for details on this protocol
      switch (typ) {
        case messageTypePty:
          this.cancelTimeUpdate();

          const delay = Number(dv.getBigUint64(3));
          const data = dv.buffer.slice(
            dv.byteOffset + 11,
            dv.byteOffset + 11 + len
          );

          this.emit(TermEvent.DATA, data);
          this._lastPlayedTimestamp = delay;

          this._lastUpdate = Date.now();
          this.setTime(delay);

          // schedule the next time update (in case this
          // part of the recording is dead time)
          // TODO(zmb3): implement this for desktops too
          if (!this._paused) {
            this.scheduleNextUpdate(delay);
          }
          break;

        case messageTypeError:
          // ignore the severity byte at index 3 (we display all errors identically)
          const msgLen = dv.getUint16(4);
          const msg = new TextDecoder().decode(
            dv.buffer.slice(dv.byteOffset + 6, dv.byteOffset + 6 + msgLen)
          );
          this._setStatusText(msg);
          this._setPlayerStatus(StatusEnum.ERROR);
          this.disconnect();
          return;

        case messageTypeResize:
          const w = dv.getUint16(3);
          const h = dv.getUint16(5);
          this.emit(TermEvent.RESIZE, { w, h });
          return;

        default:
          logger.warn('unexpected message type', typ);
          return;
      }
    } catch (err) {
      logger.error('failed to parse incoming message', err);
    }
  }

  // override
  send() {}
  pauseFlow() {}
  resumeFlow() {}

  move(newPos) {
    this.cancelTimeUpdate();

    try {
      const buffer = new ArrayBuffer(11);
      const dv = new DataView(buffer);
      dv.setUint8(0, messageTypeSeek);
      dv.setUint16(1, 8 /* length */);
      dv.setBigUint64(3, BigInt(newPos));
      this.webSocket.send(dv);
    } catch (e) {
      logger.error('error seeking', e);
    }

    if (newPos < this._lastPlayedTimestamp) {
      this.emit(TermEvent.RESET);
    } else if (this._paused) {
      // if we're paused, we want the scrubber to "stick" at the new
      // time until we press play (rather than waiting for us to click
      // play and start receiving new data)
      this._setTime(newPos);
    }
  }

  stop() {
    this._paused = true;
    this.cancelTimeUpdate();
    this._setPlayerStatus(StatusEnum.PAUSED);

    const buffer = new ArrayBuffer(4);
    const dv = new DataView(buffer);
    dv.setUint8(0, messageTypePlayPause);
    dv.setUint16(1, 1 /* size */);
    dv.setUint8(3, actionPause);
    this.webSocket.send(dv);
  }

  play() {
    this._paused = false;
    this._setPlayerStatus(StatusEnum.PLAYING);

    // the very first play call happens before we've even
    // connected - we only need to send the websocket message
    // for subsequent calls
    if (this.webSocket.readyState !== WebSocket.OPEN) {
      return;
    }

    const buffer = new ArrayBuffer(4);
    const dv = new DataView(buffer);
    dv.setUint8(0, messageTypePlayPause);
    dv.setUint16(1, 1 /* size */);
    dv.setUint8(3, actionPlay);
    this.webSocket.send(dv);
  }
}
