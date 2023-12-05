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

import { ipcMain, ipcRenderer } from 'electron';

import {
  FileStorageEventChannel,
  FileStorageEventType,
} from '../../mainProcess/types';

import { FileStorage } from './fileStorage';

export function subscribeToFileStorageEvents(configService: FileStorage): void {
  ipcMain.on(
    FileStorageEventChannel,
    (event, eventType: FileStorageEventType, item) => {
      switch (eventType) {
        case FileStorageEventType.Get:
          return (event.returnValue = configService.get(item.key));
        case FileStorageEventType.Put:
          return configService.put(item.key, item.json);
        case FileStorageEventType.Write:
          return configService.write();
        case FileStorageEventType.Replace:
          return configService.replace(item.json);
        case FileStorageEventType.GetFilePath:
          return configService.getFilePath();
        case FileStorageEventType.GetFileLoadingError:
          return configService.getFileLoadingError();
      }
    }
  );
}

export function createFileStorageClient(): FileStorage {
  return {
    get: key =>
      ipcRenderer.sendSync(FileStorageEventChannel, FileStorageEventType.Get, {
        key,
      }),
    put: (key, json) =>
      ipcRenderer.send(FileStorageEventChannel, FileStorageEventType.Put, {
        key,
        json,
      }),
    write: () =>
      ipcRenderer.invoke(
        FileStorageEventChannel,
        FileStorageEventType.Write,
        {}
      ),
    replace: json =>
      ipcRenderer.send(FileStorageEventChannel, FileStorageEventType.Replace, {
        json,
      }),
    getFilePath: () =>
      ipcRenderer.sendSync(
        FileStorageEventChannel,
        FileStorageEventType.GetFilePath,
        {}
      ),
    getFileLoadingError: () =>
      ipcRenderer.sendSync(
        FileStorageEventChannel,
        FileStorageEventType.GetFileLoadingError,
        {}
      ),
  };
}
