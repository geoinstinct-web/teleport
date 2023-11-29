// Copyright 2023 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::{
    path::UnixPath,
    tdp::{self, TdpErrCode},
};
use crate::{
    client::ClientHandle, tdp_sd_create_request, tdp_sd_delete_request, tdp_sd_info_request,
    tdp_sd_list_request, CGOErrCode, CgoHandle,
};
use ironrdp_pdu::{cast_length, custom_err, other_err, PduResult};
use ironrdp_rdpdr::pdu::efs::{self, NtStatus};
use std::collections::HashMap;
use std::convert::TryInto;

/// `FilesystemBackend` implements the filesystem redirection backend as described in [\[MS-RDPEFS\]: Remote Desktop Protocol: File System Virtual Channel Extension].
/// It does so in concert with the TDP directory sharing extension described in [RFD 0067].
///
/// [\[MS-RDPEFS\]: Remote Desktop Protocol: File System Virtual Channel Extension]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/34d9de58-b2b5-40b6-b970-f82d4603bdb5
/// [RFD 0067]: https://github.com/gravitational/teleport/blob/master/rfd/0067-desktop-access-file-system-sharing.md
#[derive(Debug)]
pub struct FilesystemBackend {
    cgo_handle: CgoHandle,
    client_handle: ClientHandle,
    /// FileId-indexed cache of [`FileCacheObject`]s.
    ///
    /// See the documentation for [`FileCacheObject`].
    file_cache: FileCache,
    pending_tdp_sd_info_resp_handlers: ResponseCache<tdp::SharedDirectoryInfoResponse>,
    pending_sd_create_resp_handlers: ResponseCache<tdp::SharedDirectoryCreateResponse>,
    pending_sd_delete_resp_handlers: ResponseCache<tdp::SharedDirectoryDeleteResponse>,
    pending_sd_list_resp_handlers: ResponseCache<tdp::SharedDirectoryListResponse>,
}

impl FilesystemBackend {
    pub fn new(cgo_handle: CgoHandle, client_handle: ClientHandle) -> Self {
        Self {
            cgo_handle,
            client_handle,
            file_cache: FileCache::new(),
            pending_tdp_sd_info_resp_handlers: ResponseCache::new(),
            pending_sd_create_resp_handlers: ResponseCache::new(),
            pending_sd_delete_resp_handlers: ResponseCache::new(),
            pending_sd_list_resp_handlers: ResponseCache::new(),
        }
    }

    pub fn handle(&mut self, req: efs::ServerDriveIoRequest) -> PduResult<()> {
        match req {
            efs::ServerDriveIoRequest::ServerCreateDriveRequest(req) => {
                self.handle_device_create_req(req)
            }
            efs::ServerDriveIoRequest::ServerDriveQueryInformationRequest(req) => {
                self.handle_query_information_req(req)
            }
            efs::ServerDriveIoRequest::DeviceCloseRequest(req) => self.handle_device_close_req(req),
            efs::ServerDriveIoRequest::ServerDriveQueryDirectoryRequest(req) => {
                self.handle_query_directory_req(req)
            }
            efs::ServerDriveIoRequest::ServerDriveQueryVolumeInformationRequest(req) => {
                self.handle_query_volume_req(req)
            }
        }
    }

    /// Handles an RDP [`efs::DeviceCreateRequest`] received from the RDP server.
    fn handle_device_create_req(&mut self, rdp_req: efs::DeviceCreateRequest) -> PduResult<()> {
        // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L210
        self.send_tdp_sd_info_request(tdp::SharedDirectoryInfoRequest::from(&rdp_req))?;
        self.pending_tdp_sd_info_resp_handlers.insert(
            rdp_req.device_io_request.completion_id,
            SharedDirectoryInfoResponseHandler::new(
                |this: &mut FilesystemBackend,
                 tdp_resp: tdp::SharedDirectoryInfoResponse|
                 -> PduResult<()> {
                    this.handle_device_create_req_continued(rdp_req, tdp_resp)
                },
            ),
        );
        Ok(())
    }

    /// Continues [`Self::handle_rdp_device_create_req`] after a [`tdp::SharedDirectoryInfoResponse`] is received from the browser,
    /// returning any [`RdpdrPdu`]s that need to be sent back to the RDP server.
    fn handle_device_create_req_continued(
        &mut self,
        req: efs::DeviceCreateRequest,
        res: tdp::SharedDirectoryInfoResponse,
    ) -> PduResult<()> {
        match res.err_code {
            TdpErrCode::Failed | TdpErrCode::AlreadyExists => {
                return Err(custom_err!(
                    "FilesystemBackend::pending_tdp_sd_info_resp_handlers",
                    FilesystemBackendError(format!(
                        "received unexpected TDP error code in SharedDirectoryInfoResponse: {:?}",
                        res.err_code,
                    ))
                ));
            }
            TdpErrCode::Nil => {
                // The file exists
                // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L214
                if res.fso.file_type == tdp::FileType::Directory {
                    if req.create_disposition == efs::CreateDisposition::FILE_CREATE {
                        // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L221
                        return self.send_device_create_response(
                            &req,
                            efs::NtStatus::OBJECT_NAME_COLLISION,
                            0,
                        );
                    }

                    if req
                        .create_options
                        .contains(efs::CreateOptions::FILE_NON_DIRECTORY_FILE)
                    {
                        // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L227
                        return self.send_device_create_response(
                            &req,
                            efs::NtStatus::ACCESS_DENIED,
                            0,
                        );
                    }
                } else if req
                    .create_options
                    .contains(efs::CreateOptions::FILE_DIRECTORY_FILE)
                {
                    // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L237
                    return self.send_device_create_response(
                        &req,
                        efs::NtStatus::NOT_A_DIRECTORY,
                        0,
                    );
                }
            }
            TdpErrCode::DoesNotExist => {
                // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L242
                if req
                    .create_options
                    .contains(efs::CreateOptions::FILE_DIRECTORY_FILE)
                {
                    if req.create_disposition.intersects(
                        efs::CreateDisposition::FILE_OPEN_IF | efs::CreateDisposition::FILE_CREATE,
                    ) {
                        // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L252
                        self.tdp_sd_create(req, tdp::FileType::Directory)?;
                        return Ok(());
                    } else {
                        // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L258
                        return self.send_device_create_response(
                            &req,
                            efs::NtStatus::NO_SUCH_FILE,
                            0,
                        );
                    }
                }
            }
        }

        // The actual creation of files and error mapping in FreeRDP happens here, for reference:
        // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/winpr/libwinpr/file/file.c#L781
        match req.create_disposition {
            efs::CreateDisposition::FILE_SUPERSEDE => {
                // If the file already exists, replace it with the given file. If it does not, create the given file.
                if res.err_code == TdpErrCode::Nil {
                    self.tdp_sd_overwrite(req)?;
                    return Ok(());
                } else if res.err_code == TdpErrCode::DoesNotExist {
                    self.tdp_sd_create(req, tdp::FileType::File)?;
                    return Ok(());
                }
            }
            efs::CreateDisposition::FILE_OPEN => {
                // If the file already exists, open it instead of creating a new file. If it does not, fail the request and do not create a new file.
                if res.err_code == TdpErrCode::Nil {
                    let file_id = self
                        .file_cache
                        .insert(FileCacheObject::new(UnixPath::from(&req.path), res.fso))?;
                    return self.send_device_create_response(&req, efs::NtStatus::SUCCESS, file_id);
                } else if res.err_code == TdpErrCode::DoesNotExist {
                    return self.send_device_create_response(&req, efs::NtStatus::NO_SUCH_FILE, 0);
                }
            }
            efs::CreateDisposition::FILE_CREATE => {
                // If the file already exists, fail the request and do not create or open the given file. If it does not, create the given file.
                if res.err_code == TdpErrCode::Nil {
                    return self.send_device_create_response(
                        &req,
                        efs::NtStatus::OBJECT_NAME_COLLISION,
                        0,
                    );
                } else if res.err_code == TdpErrCode::DoesNotExist {
                    self.tdp_sd_create(req, tdp::FileType::File)?;
                    return Ok(());
                }
            }
            efs::CreateDisposition::FILE_OPEN_IF => {
                // If the file already exists, open it. If it does not, create the given file.
                if res.err_code == TdpErrCode::Nil {
                    let file_id = self
                        .file_cache
                        .insert(FileCacheObject::new(UnixPath::from(&req.path), res.fso))?;
                    return self.send_device_create_response(&req, efs::NtStatus::SUCCESS, file_id);
                } else if res.err_code == TdpErrCode::DoesNotExist {
                    self.tdp_sd_create(req, tdp::FileType::File)?;
                    return Ok(());
                }
            }
            efs::CreateDisposition::FILE_OVERWRITE => {
                // If the file already exists, open it and overwrite it. If it does not, fail the request.
                if res.err_code == TdpErrCode::Nil {
                    self.tdp_sd_overwrite(req)?;
                    return Ok(());
                } else if res.err_code == TdpErrCode::DoesNotExist {
                    return self.send_device_create_response(&req, efs::NtStatus::NO_SUCH_FILE, 0);
                }
            }
            efs::CreateDisposition::FILE_OVERWRITE_IF => {
                // If the file already exists, open it and overwrite it. If it does not, create the given file.
                if res.err_code == TdpErrCode::Nil {
                    self.tdp_sd_overwrite(req)?;
                    return Ok(());
                } else if res.err_code == TdpErrCode::DoesNotExist {
                    self.tdp_sd_create(req, tdp::FileType::File)?;
                    return Ok(());
                }
            }
            _ => {
                return Err(custom_err!(
                    "FilesystemBackend::pending_tdp_sd_info_resp_handlers",
                    FilesystemBackendError(format!(
                        "received unknown CreateDisposition value for RDP {req:?}",
                        req = req
                    ))
                ));
            }
        }

        Err(other_err!(
            "FilesystemBackend::pending_tdp_sd_info_resp_handlers",
            "Programmer error, this line should never be reached"
        ))
    }

    /// Handles an RDP [`efs::ServerDriveQueryInformationRequest`] received from the RDP server.
    fn handle_query_information_req(
        &mut self,
        rdp_req: efs::ServerDriveQueryInformationRequest,
    ) -> PduResult<()> {
        let file = self.file_cache.get(rdp_req.device_io_request.file_id);
        self.send_client_drive_query_information_response(rdp_req, file)?;
        Ok(())
    }

    /// Handles an RDP [`efs::DeviceCloseRequest`] received from the RDP server.
    fn handle_device_close_req(&mut self, rdp_req: efs::DeviceCloseRequest) -> PduResult<()> {
        if let Some(file) = self.file_cache.remove(rdp_req.device_io_request.file_id) {
            if file.delete_pending {
                return self.tdp_sd_delete(rdp_req, file);
            }
            return self.send_device_close_response(rdp_req, NtStatus::SUCCESS);
        }

        self.send_device_close_response(rdp_req, NtStatus::UNSUCCESSFUL)
    }

    /// Handles an RDP [`efs::ServerDriveQueryDirectoryRequest`] received from the RDP server.
    fn handle_query_directory_req(
        &mut self,
        rdp_req: efs::ServerDriveQueryDirectoryRequest,
    ) -> PduResult<()> {
        let file_id = rdp_req.device_io_request.file_id;
        // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L610
        match self.file_cache.get(file_id) {
            // File not found in cache, return a failure
            None => self.send_drive_query_dir_response(
                rdp_req.device_io_request,
                NtStatus::UNSUCCESSFUL,
                None,
            ),
            Some(dir) => {
                if dir.fso.file_type != tdp::FileType::Directory {
                    return Err(other_err!(
                        "FilesystemBackend::handle_query_directory_req",
                        "received ServerDriveQueryDirectoryRequest request for a file rather than a directory",
                    ));
                }

                if rdp_req.initial_query == 0 {
                    // This isn't the initial query, ergo we already have this dir's contents filled in.
                    // Just send the next item.
                    return self.send_next_drive_query_dir_response(&rdp_req);
                }

                // On the initial query, we need to get the list of files in this directory from
                // the client by sending a TDP SharedDirectoryListRequest.
                // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L775
                let path = dir.path.clone();

                // Ask the client for the list of files in this directory.
                self.send_tdp_sd_list_request(tdp::SharedDirectoryListRequest {
                    completion_id: rdp_req.device_io_request.completion_id,
                    directory_id: rdp_req.device_io_request.device_id,
                    path,
                })?;

                // When we get the response for that list of files...
                self.pending_sd_list_resp_handlers.insert(
                    rdp_req.device_io_request.completion_id,
                    SharedDirectoryListResponseHandler::new(
                        move |cli: &mut Self,
                              tdp_resp: tdp::SharedDirectoryListResponse|
                              -> PduResult<()> {
                            cli.handle_query_directory_req_continued(rdp_req, tdp_resp)
                        },
                    ),
                );

                // Return nothing yet, an RDP message will be returned when the pending_sd_list_resp_handlers
                // closure gets called.
                Ok(())
            }
        }
    }

    /// Continues [`Self::handle_query_directory_req`] after a [`tdp::SharedDirectoryListResponse`] is received from the browser,
    /// returning any [`RdpdrPdu`]s that need to be sent back to the RDP server.
    fn handle_query_directory_req_continued(
        &mut self,
        rdp_req: efs::ServerDriveQueryDirectoryRequest,
        tdp_resp: tdp::SharedDirectoryListResponse,
    ) -> PduResult<()> {
        if tdp_resp.err_code != TdpErrCode::Nil {
            // For now any error will kill the session.
            // In the future, we might want to make this send back
            // an NTSTATUS::STATUS_UNSUCCESSFUL instead.
            return Err(custom_err!(
                "FilesystemBackend::handle_query_directory_req",
                FilesystemBackendError(format!(
                    "SharedDirectoryListRequest failed with err_code = {:?}",
                    tdp_resp.err_code
                ))
            ));
        }

        // If SharedDirectoryListRequest succeeded, move the
        // list of FileSystemObjects that correspond to this directory's
        // contents to its entry in the file cache.
        if let Some(dir) = self.file_cache.get_mut(rdp_req.device_io_request.file_id) {
            dir.contents = tdp_resp.fso_list;
            // And send back the "." directory over RDP
            return self.send_next_drive_query_dir_response(&rdp_req);
        }

        self.send_drive_query_dir_response(rdp_req.device_io_request, NtStatus::UNSUCCESSFUL, None)
    }

    fn handle_query_volume_req(
        &mut self,
        rdp_req: efs::ServerDriveQueryVolumeInformationRequest,
    ) -> PduResult<()> {
        match self.file_cache.get(rdp_req.device_io_request.file_id) {
            // File not found in cache
            None => Err(custom_err!(
                "FilesystemBackend::handle_query_volume_req",
                FilesystemBackendError(format!(
                    "failed to retrieve an item from the file cache with FileId = {}",
                    rdp_req.device_io_request.file_id
                ))
            )),
            Some(dir) => {
                let buffer: Option<efs::FileSystemInformationClass> = match rdp_req
                    .fs_info_class_lvl
                {
                    efs::FileSystemInformationClassLevel::FILE_FS_VOLUME_INFORMATION => {
                        Some(
                            efs::FileFsVolumeInformation {
                                volume_creation_time: cast_length!(
                                    "FilesystemBackend::handle_query_volume_req",
                                    "dir.fso.last_modified",
                                    dir.fso.last_modified
                                )?,
                                // Equivalent to `u32::MAX & 0xffff` which is what FreeRDP does between
                                // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/winpr/libwinpr/file/file.c#L1018-L1021
                                // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L492
                                volume_serial_number: 0xffff,
                                // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L494
                                supports_objects: efs::Boolean::False,
                                // volume_label can just be something we make up
                                // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L446
                                volume_label: "TELEPORT".to_string(),
                            }
                            .into(),
                        )
                    }
                    efs::FileSystemInformationClassLevel::FILE_FS_ATTRIBUTE_INFORMATION => {
                        Some(
                            efs::FileFsAttributeInformation {
                                file_system_attributes:
                                    efs::FileSystemAttributes::FILE_CASE_SENSITIVE_SEARCH
                                        | efs::FileSystemAttributes::FILE_CASE_PRESERVED_NAMES
                                        | efs::FileSystemAttributes::FILE_UNICODE_ON_DISK,
                                // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L536
                                // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/winpr/include/winpr/file.h#L36
                                max_component_name_len: 260,
                                // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L447
                                // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L519
                                // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L538
                                file_system_name: "FAT32".to_string(),
                            }
                            .into(),
                        )
                    }
                    efs::FileSystemInformationClassLevel::FILE_FS_FULL_SIZE_INFORMATION => Some(
                        // Fill these out with the default fallback values FreeRDP uses
                        // Written here: https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L552-L557
                        // With default fallback values ultimately found here:
                        // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/winpr/libwinpr/file/file.c#L1018-L1021
                        efs::FileFsFullSizeInformation {
                            total_alloc_units: u32::MAX as i64,
                            caller_available_alloc_units: u32::MAX as i64,
                            actual_available_alloc_units: u32::MAX as i64,
                            sectors_per_alloc_unit: u32::MAX,
                            bytes_per_sector: 1,
                        }
                        .into(),
                    ),
                    efs::FileSystemInformationClassLevel::FILE_FS_DEVICE_INFORMATION => Some(
                        // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L570-L571
                        efs::FileFsDeviceInformation {
                            device_type: 0x00000007, // FILE_DEVICE_DISK
                            characteristics: efs::Characteristics::empty(),
                        }
                        .into(),
                    ),
                    efs::FileSystemInformationClassLevel::FILE_FS_SIZE_INFORMATION => Some(
                        // Fill these out with the default fallback values FreeRDP uses
                        // Written here: https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L510-L513
                        // With default fallback values ultimately found here:
                        // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/winpr/libwinpr/file/file.c#L1018-L1021
                        efs::FileFsSizeInformation {
                            total_alloc_units: u32::MAX as i64,
                            available_alloc_units: u32::MAX as i64,
                            sectors_per_alloc_unit: u32::MAX,
                            bytes_per_sector: 1,
                        }
                        .into(),
                    ),
                    _ => None,
                };

                let io_status = match buffer {
                    Some(_) => NtStatus::SUCCESS,
                    None => NtStatus::UNSUCCESSFUL,
                };

                self.send_query_vol_info_response(rdp_req.device_io_request, io_status, buffer)
            }
        }
    }

    /// Helper function for writing a [`tdp::SharedDirectoryCreateRequest`] to the browser
    /// and handling the [`tdp::SharedDirectoryCreateResponse`] that is received in response.
    fn tdp_sd_create(
        &mut self,
        rdp_req: efs::DeviceCreateRequest,
        file_type: tdp::FileType,
    ) -> PduResult<()> {
        self.send_tdp_sd_create_request(tdp::SharedDirectoryCreateRequest::from(
            &rdp_req, file_type,
        ))?;
        self.pending_sd_create_resp_handlers.insert(
            rdp_req.device_io_request.completion_id,
            SharedDirectoryCreateResponseHandler::new(
                move |this: &mut FilesystemBackend,
                      tdp_resp: tdp::SharedDirectoryCreateResponse|
                      -> PduResult<()> {
                    if tdp_resp.err_code != TdpErrCode::Nil {
                        return this.send_device_create_response(
                            &rdp_req,
                            NtStatus::UNSUCCESSFUL,
                            0,
                        );
                    }
                    let file_id = this.file_cache.insert(FileCacheObject::new(
                        UnixPath::from(&rdp_req.path),
                        tdp_resp.fso,
                    ))?;
                    this.send_device_create_response(&rdp_req, NtStatus::SUCCESS, file_id)
                },
            ),
        );
        Ok(())
    }

    /// Helper function for combining a [`tdp::SharedDirectoryDeleteRequest`]
    /// with a [`tdp::SharedDirectoryCreateRequest`] to overwrite a file.
    fn tdp_sd_overwrite(&mut self, rdp_req: efs::DeviceCreateRequest) -> PduResult<()> {
        let tdp_req = tdp::SharedDirectoryDeleteRequest::from(&rdp_req);
        self.send_tdp_sd_delete_request(tdp_req)?;
        self.pending_sd_delete_resp_handlers.insert(
            rdp_req.device_io_request.completion_id,
            SharedDirectoryDeleteResponseHandler::new(
                move |this: &mut FilesystemBackend,
                      tdp_resp: tdp::SharedDirectoryDeleteResponse|
                      -> PduResult<()> {
                    match tdp_resp.err_code {
                        TdpErrCode::Nil => {
                            this.tdp_sd_create(rdp_req, tdp::FileType::File)?;
                            Ok(())
                        }
                        _ => this.send_device_create_response(&rdp_req, NtStatus::UNSUCCESSFUL, 0),
                    }
                },
            ),
        );
        Ok(())
    }

    fn tdp_sd_delete(
        &mut self,
        rdp_req: efs::DeviceCloseRequest,
        file: FileCacheObject,
    ) -> PduResult<()> {
        let tdp_req = tdp::SharedDirectoryDeleteRequest::from_fco(&rdp_req, file);
        self.send_tdp_sd_delete_request(tdp_req)?;
        self.pending_sd_delete_resp_handlers.insert(
            rdp_req.device_io_request.completion_id,
            SharedDirectoryDeleteResponseHandler::new(
                move |this: &mut FilesystemBackend,
                      tdp_resp: tdp::SharedDirectoryDeleteResponse|
                      -> PduResult<()> {
                    let io_status = if tdp_resp.err_code == TdpErrCode::Nil {
                        NtStatus::SUCCESS
                    } else {
                        NtStatus::UNSUCCESSFUL
                    };
                    this.send_device_close_response(rdp_req, io_status)
                },
            ),
        );
        Ok(())
    }

    /// Sends a [`tdp::SharedDirectoryInfoRequest`] to the browser.
    fn send_tdp_sd_info_request(&self, tdp_req: tdp::SharedDirectoryInfoRequest) -> PduResult<()> {
        debug!("sending tdp: {:?}", tdp_req);
        let mut req = tdp_req.into_cgo()?;
        let err = unsafe { tdp_sd_info_request(self.cgo_handle, req.cgo()) };
        if err != CGOErrCode::ErrCodeSuccess {
            return Err(custom_err!(
                "FilesystemBackend::send_tdp_sd_info_request",
                FilesystemBackendError(format!("call to tdp_sd_info_request failed: {:?}", err))
            ));
        };
        Ok(())
    }

    /// Sends a [`tdp::SharedDirectoryCreateRequest`] to the browser.
    fn send_tdp_sd_create_request(
        &self,
        tdp_req: tdp::SharedDirectoryCreateRequest,
    ) -> PduResult<()> {
        debug!("sending tdp: {:?}", tdp_req);
        let mut req = tdp_req.into_cgo()?;
        let err = unsafe { tdp_sd_create_request(self.cgo_handle, req.cgo()) };
        if err != CGOErrCode::ErrCodeSuccess {
            return Err(custom_err!(
                "FilesystemBackend::send_tdp_sd_create_request",
                FilesystemBackendError(format!("call to tdp_sd_create_request failed: {:?}", err))
            ));
        };
        Ok(())
    }

    /// Sends a [`tdp::SharedDirectoryDeleteRequest`] to the browser.
    fn send_tdp_sd_delete_request(
        &self,
        tdp_req: tdp::SharedDirectoryDeleteRequest,
    ) -> PduResult<()> {
        debug!("sending tdp: {:?}", tdp_req);
        let mut req = tdp_req.into_cgo()?;
        let err = unsafe { tdp_sd_delete_request(self.cgo_handle, req.cgo()) };
        if err != CGOErrCode::ErrCodeSuccess {
            return Err(custom_err!(
                "FilesystemBackend::send_tdp_sd_delete_request",
                FilesystemBackendError(format!("call to tdp_sd_create_request failed: {:?}", err))
            ));
        };
        Ok(())
    }

    /// Sends a [`tdp::SharedDirectoryListRequest`] to the browser.
    fn send_tdp_sd_list_request(&self, tdp_req: tdp::SharedDirectoryListRequest) -> PduResult<()> {
        debug!("sending tdp: {:?}", tdp_req);
        let mut req = tdp_req.into_cgo()?;
        let err = unsafe { tdp_sd_list_request(self.cgo_handle, req.cgo()) };
        if err != CGOErrCode::ErrCodeSuccess {
            return Err(custom_err!(
                "FilesystemBackend::send_tdp_sd_list_request",
                FilesystemBackendError(format!("call to tdp_sd_list_request failed: {:?}", err))
            ));
        };
        Ok(())
    }

    /// Called from the Go code when a [`tdp::SharedDirectoryInfoResponse`] is received from the browser.
    ///
    /// Calls the [`SharedDirectoryInfoResponseHandler`] associated with the completion id of the
    /// [`tdp::SharedDirectoryInfoResponse`].
    pub fn handle_tdp_sd_info_response(
        &mut self,
        tdp_resp: tdp::SharedDirectoryInfoResponse,
    ) -> PduResult<()> {
        if let Some(handler) = self
            .pending_tdp_sd_info_resp_handlers
            .remove(&tdp_resp.completion_id)
        {
            handler.call(self, tdp_resp)
        } else {
            Err(custom_err!(
                "FilesystemBackend::handle_tdp_sd_info_response",
                FilesystemBackendError(format!(
                    "received invalid completion id: {}",
                    tdp_resp.completion_id
                ))
            ))
        }
    }

    /// Called from the Go code when a [`tdp::SharedDirectoryCreateResponse`] is received from the browser.
    ///
    /// Calls the [`SharedDirectoryCreateResponseHandler`] associated with the completion id of the
    /// [`tdp::SharedDirectoryCreateResponse`].
    pub fn handle_tdp_sd_create_response(
        &mut self,
        tdp_resp: tdp::SharedDirectoryCreateResponse,
    ) -> PduResult<()> {
        if let Some(handler) = self
            .pending_sd_create_resp_handlers
            .remove(&tdp_resp.completion_id)
        {
            handler.call(self, tdp_resp)
        } else {
            Err(custom_err!(
                "FilesystemBackend::handle_tdp_sd_create_response",
                FilesystemBackendError(format!(
                    "received invalid completion id: {}",
                    tdp_resp.completion_id
                ))
            ))
        }
    }

    /// Called from the Go code when a [`tdp::SharedDirectoryDeleteResponse`] is received from the browser.
    ///
    /// Calls the [`SharedDirectoryDeleteResponseHandler`] associated with the completion id of the
    /// [`tdp::SharedDirectoryDeleteResponse`].
    pub fn handle_tdp_sd_delete_response(
        &mut self,
        tdp_resp: tdp::SharedDirectoryDeleteResponse,
    ) -> PduResult<()> {
        if let Some(handler) = self
            .pending_sd_delete_resp_handlers
            .remove(&tdp_resp.completion_id)
        {
            handler.call(self, tdp_resp)
        } else {
            Err(custom_err!(
                "FilesystemBackend::client_handle_tdp_sd_delete_response",
                FilesystemBackendError(format!(
                    "received invalid completion id: {}",
                    tdp_resp.completion_id
                ))
            ))
        }
    }

    /// Called from the Go code when a [`tdp::SharedDirectoryListResponse`] is received from the browser.
    ///
    /// Calls the [`SharedDirectoryListResponseHandler`] associated with the completion id of the
    /// [`tdp::SharedDirectoryListResponse`].
    pub fn handle_tdp_sd_list_response(
        &mut self,
        tdp_resp: tdp::SharedDirectoryListResponse,
    ) -> PduResult<()> {
        if let Some(handler) = self
            .pending_sd_list_resp_handlers
            .remove(&tdp_resp.completion_id)
        {
            handler.call(self, tdp_resp)
        } else {
            Err(custom_err!(
                "FilesystemBackend::handle_tdp_sd_list_response",
                FilesystemBackendError(format!(
                    "received invalid completion id: {}",
                    tdp_resp.completion_id
                ))
            ))
        }
    }

    /// Helper function for sending an RDP [`efs::DeviceCreateResponse`] based on an RDP [`efs::DeviceCreateRequest`].
    fn send_device_create_response(
        &self,
        device_create_request: &efs::DeviceCreateRequest,
        io_status: efs::NtStatus,
        new_file_id: u32,
    ) -> PduResult<()> {
        // See https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L187-L228
        let information = if io_status != efs::NtStatus::SUCCESS
            || device_create_request.create_disposition.intersects(
                efs::CreateDisposition::FILE_SUPERSEDE
                    | efs::CreateDisposition::FILE_OPEN
                    | efs::CreateDisposition::FILE_CREATE
                    | efs::CreateDisposition::FILE_OVERWRITE,
            ) {
            Ok(efs::Information::FILE_SUPERSEDED)
        } else if device_create_request.create_disposition == efs::CreateDisposition::FILE_OPEN_IF {
            Ok(efs::Information::FILE_OPENED)
        } else if device_create_request.create_disposition
            == efs::CreateDisposition::FILE_OVERWRITE_IF
        {
            Ok(efs::Information::FILE_OVERWRITTEN)
        } else {
            Err(other_err!(
                "FilesystemBackend::make_device_create_response",
                "program error, CreateDispositionFlags check should be exhaustive"
            ))
        }?;

        self.client_handle.write_rdpdr(
            efs::DeviceCreateResponse {
                device_io_reply: efs::DeviceIoResponse::new(
                    device_create_request.device_io_request.clone(),
                    io_status,
                ),
                file_id: new_file_id,
                information,
            }
            .into(),
        )?;
        Ok(())
    }

    /// Helper function for sending an RDP [`efs::ClientDriveQueryInformationResponse`]
    /// to the RDP server.
    fn send_client_drive_query_information_response(
        &self,
        rdp_req: efs::ServerDriveQueryInformationRequest,
        file: Option<&FileCacheObject>,
    ) -> PduResult<()> {
        let file = match file {
            Some(file) => file,
            None => {
                // Early return with NtStatus::UNSUCCESSFUL if the file is not found
                self.client_handle.write_rdpdr(
                    efs::ClientDriveQueryInformationResponse {
                        device_io_response: efs::DeviceIoResponse::new(
                            rdp_req.device_io_request.clone(),
                            NtStatus::UNSUCCESSFUL,
                        ),
                        buffer: None,
                    }
                    .into(),
                )?;
                return Ok(());
            }
        };

        let device_io_response =
            efs::DeviceIoResponse::new(rdp_req.device_io_request.clone(), NtStatus::SUCCESS);

        // We support all the FsInformationClasses that FreeRDP does here
        // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L482
        match rdp_req.file_info_class_lvl {
            efs::FileInformationClassLevel::FILE_BASIC_INFORMATION => {
                self.send_file_basic_info(device_io_response, file)
            }
            efs::FileInformationClassLevel::FILE_STANDARD_INFORMATION => {
                self.send_file_standard_info(device_io_response, file)
            }
            efs::FileInformationClassLevel::FILE_ATTRIBUTE_TAG_INFORMATION => {
                self.send_file_attr_tag_info(device_io_response, file)
            }
            _ => Err(custom_err!(
                "FilesystemBackend::make_client_drive_query_information_response",
                FilesystemBackendError(format!(
                    "received unsupported FileInformationClass: {:?}",
                    rdp_req.file_info_class_lvl
                ))
            )),
        }
    }

    fn send_file_basic_info(
        &self,
        device_io_response: efs::DeviceIoResponse,
        file: &FileCacheObject,
    ) -> PduResult<()> {
        self.client_handle.write_rdpdr(
            efs::ClientDriveQueryInformationResponse {
                device_io_response,
                buffer: Some(efs::FileInformationClass::Basic(
                    efs::FileBasicInformation {
                        creation_time: tdp::to_windows_time(file.fso.last_modified),
                        last_access_time: tdp::to_windows_time(file.fso.last_modified),
                        last_write_time: tdp::to_windows_time(file.fso.last_modified),
                        change_time: tdp::to_windows_time(file.fso.last_modified),
                        file_attributes: if file.fso.file_type == tdp::FileType::File {
                            efs::FileAttributes::FILE_ATTRIBUTE_NORMAL
                        } else {
                            efs::FileAttributes::FILE_ATTRIBUTE_DIRECTORY
                        },
                    },
                )),
            }
            .into(),
        )?;
        Ok(())
    }

    fn send_file_standard_info(
        &self,
        device_io_response: efs::DeviceIoResponse,
        file: &FileCacheObject,
    ) -> PduResult<()> {
        let file_fso_size: i64 = cast_length!(
            "FilesystemBackend::send_file_standard_info",
            "file.fso.size",
            file.fso.size
        )?;

        self.client_handle.write_rdpdr(
            efs::ClientDriveQueryInformationResponse {
                device_io_response,
                buffer: Some(efs::FileInformationClass::Standard(
                    efs::FileStandardInformation {
                        allocation_size: file_fso_size,
                        end_of_file: file_fso_size,
                        number_of_links: 0,
                        delete_pending: if file.delete_pending {
                            efs::Boolean::True
                        } else {
                            efs::Boolean::False
                        },
                        directory: if file.fso.file_type == tdp::FileType::File {
                            efs::Boolean::False
                        } else {
                            efs::Boolean::True
                        },
                    },
                )),
            }
            .into(),
        )?;
        Ok(())
    }

    fn send_file_attr_tag_info(
        &self,
        device_io_response: efs::DeviceIoResponse,
        file: &FileCacheObject,
    ) -> PduResult<()> {
        self.client_handle.write_rdpdr(
            efs::ClientDriveQueryInformationResponse {
                device_io_response,
                buffer: Some(efs::FileInformationClass::AttributeTag(
                    efs::FileAttributeTagInformation {
                        file_attributes: if file.fso.file_type == tdp::FileType::File {
                            efs::FileAttributes::FILE_ATTRIBUTE_NORMAL
                        } else {
                            efs::FileAttributes::FILE_ATTRIBUTE_DIRECTORY
                        },
                        reparse_tag: 0,
                    },
                )),
            }
            .into(),
        )?;
        Ok(())
    }

    /// Sends an RDP [`efs::DeviceCloseResponse`] to the RDP server.
    fn send_device_close_response(
        &self,
        rdp_req: efs::DeviceCloseRequest,
        io_status: NtStatus,
    ) -> PduResult<()> {
        self.client_handle.write_rdpdr(
            efs::DeviceCloseResponse {
                device_io_response: efs::DeviceIoResponse::new(
                    rdp_req.device_io_request.clone(),
                    io_status,
                ),
            }
            .into(),
        )?;
        Ok(())
    }

    /// Sends the next RDP [`efs::ClientDriveQueryDirectoryResponse`] in the series of expected
    /// responses to the RDP server.
    fn send_next_drive_query_dir_response(
        &mut self,
        req: &efs::ServerDriveQueryDirectoryRequest,
    ) -> PduResult<()> {
        // req gives us a FileId, which we use to get the FileCacheObject for the directory that
        // this request is targeted at. We use that FileCacheObject as an iterator, grabbing the
        // next() FileSystemObject (starting with ".", then "..", then iterating through the contents
        // of the target directory), which we then convert to an RDP FileInformationClass for sending back
        // to the RDP server.
        if let Some(dir) = self.file_cache.get_mut(req.device_io_request.file_id) {
            if let Some(fso) = dir.next() {
                let buffer = match req.file_info_class_lvl {
                    efs::FileInformationClassLevel::FILE_BOTH_DIRECTORY_INFORMATION => Some(
                        efs::FileInformationClass::BothDirectory(fso.into_both_directory()?),
                    ),
                    efs::FileInformationClassLevel::FILE_FULL_DIRECTORY_INFORMATION => Some(
                        efs::FileInformationClass::FullDirectory(fso.into_full_directory()?),
                    ),
                    efs::FileInformationClassLevel::FILE_NAMES_INFORMATION => {
                        Some(efs::FileInformationClass::Names(fso.into_names()?))
                    }
                    efs::FileInformationClassLevel::FILE_DIRECTORY_INFORMATION => {
                        Some(efs::FileInformationClass::Directory(fso.into_directory()?))
                    }
                    _ => {
                        return Err(custom_err!(
                            "FilesystemBackend::send_next_drive_query_dir_response",
                            FilesystemBackendError(format!(
                                "received unsupported file information class level: {:?}",
                                req.file_info_class_lvl,
                            ))
                        ));
                    }
                };

                return self.send_drive_query_dir_response(
                    req.device_io_request.clone(),
                    NtStatus::SUCCESS,
                    buffer,
                );
            }

            // If we reach here it means our iterator is exhausted,
            // so we send back a NtStatus::NO_MORE_FILES to
            // alert RDP that we've listed all the contents of this directory.
            // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/winpr/libwinpr/file/generic.c#L1193
            // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L114
            return self.send_drive_query_dir_response(
                req.device_io_request.clone(),
                NtStatus::NO_MORE_FILES,
                None,
            );
        }

        // File not found in cache
        self.send_drive_query_dir_response(
            req.device_io_request.clone(),
            NtStatus::UNSUCCESSFUL,
            None,
        )
    }

    /// Sends an RDP [`efs::ClientDriveQueryDirectoryResponse`] to the RDP server.
    fn send_drive_query_dir_response(
        &self,
        device_io_request: efs::DeviceIoRequest,
        io_status: NtStatus,
        buffer: Option<efs::FileInformationClass>,
    ) -> PduResult<()> {
        self.client_handle.write_rdpdr(
            efs::ClientDriveQueryDirectoryResponse {
                device_io_reply: efs::DeviceIoResponse::new(device_io_request, io_status),
                buffer,
            }
            .into(),
        )?;
        Ok(())
    }

    /// Sends an RDP [`efs::ClientDriveQueryVolumeInformationResponse`] to the RDP server.
    fn send_query_vol_info_response(
        &self,
        device_io_request: efs::DeviceIoRequest,
        io_status: NtStatus,
        buffer: Option<efs::FileSystemInformationClass>,
    ) -> PduResult<()> {
        self.client_handle.write_rdpdr(
            efs::ClientDriveQueryVolumeInformationResponse::new(
                device_io_request,
                io_status,
                buffer,
            )
            .into(),
        )?;
        Ok(())
    }
}

#[derive(Debug)]
struct FileCache {
    cache: HashMap<u32, FileCacheObject>,
    next_file_id: u32,
}

impl FileCache {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
            next_file_id: 0,
        }
    }

    /// Insert a [`FileCacheObject`] into the file cache.
    ///
    /// Returns the `file_id` of the inserted [`FileCacheObject`],
    /// or an error if the `file_id` already exists in the cache.
    fn insert(&mut self, file: FileCacheObject) -> PduResult<u32> {
        self.next_file_id = self.next_file_id.wrapping_add(1);
        if self.cache.insert(self.next_file_id, file).is_none() {
            Ok(self.next_file_id)
        } else {
            Err(other_err!(
                "FileCache::insert",
                "attempted to insert a FileCacheObject into the file cache with a file_id that already exists in the cache"
            ))
        }
    }

    /// Retrieves a FileCacheObject from the file cache,
    /// without removing it from the cache.
    fn get(&self, file_id: u32) -> Option<&FileCacheObject> {
        self.cache.get(&file_id)
    }
    /// Retrieves a mutable FileCacheObject from the file cache,
    /// without removing it from the cache.
    fn get_mut(&mut self, file_id: u32) -> Option<&mut FileCacheObject> {
        self.cache.get_mut(&file_id)
    }

    /// Retrieves a FileCacheObject from the file cache,
    /// removing it from the cache.
    fn remove(&mut self, file_id: u32) -> Option<FileCacheObject> {
        self.cache.remove(&file_id)
    }
}

/// FileCacheObject is an in-memory representation of
/// of a file or directory holding the metadata necessary
/// for RDP drive redirection. They are stored in map indexed
/// by their RDP FileId.
///
/// The lifecycle for a FileCacheObject is a function of the
/// MajorFunction of RDP DeviceIoRequests:
///
/// | Sequence | MajorFunction | results in                                               |
/// | -------- | ------------- | ---------------------------------------------------------|
/// | 1        | IRP_MJ_CREATE | A new FileCacheObject is created and assigned a FileId   |
/// | -------- | ------------- | ---------------------------------------------------------|
/// | 2        | <other>       | The FCO is retrieved from the cache by the FileId in the |
/// |          |               | DeviceIoRequest and metadata is used to craft a response |
/// | -------- | ------------- | ---------------------------------------------------------|
/// | 3        | IRP_MJ_CLOSE  | The FCO is deleted from the cache                        |
/// | -------- | ------------- | ---------------------------------------------------------|
#[derive(Debug, Clone)]
pub struct FileCacheObject {
    path: UnixPath,
    delete_pending: bool,
    /// The tdp::FileSystemObject pertaining to the file or directory at path.
    fso: tdp::FileSystemObject,
    /// A vector of the contents of the directory at path.
    contents: Vec<tdp::FileSystemObject>,

    /// Book-keeping variable, see Iterator implementation
    contents_i: usize,
    /// Book-keeping variable, see Iterator implementation
    dot_sent: bool,
    /// Book-keeping variable, see Iterator implementation
    dotdot_sent: bool,
}

impl FileCacheObject {
    fn new(path: UnixPath, fso: tdp::FileSystemObject) -> Self {
        Self {
            path,
            delete_pending: false,
            fso,
            contents: Vec::new(),

            contents_i: 0,
            dot_sent: false,
            dotdot_sent: false,
        }
    }

    pub fn path(&self) -> UnixPath {
        self.path.clone()
    }
}

/// FileCacheObject is used as an iterator for the implementation of
/// IRP_MJ_DIRECTORY_CONTROL, which requires that we iterate through
/// all the files of a directory one by one. In this case, the directory
/// is the FileCacheObject itself, with it's own fso field representing
/// the directory, and its contents being represented by tdp::FileSystemObject's
/// in its contents field.
///
/// We account for an idiosyncrasy of the RDP protocol here: when fielding an
/// IRP_MJ_DIRECTORY_CONTROL, RDP first expects to receive an entry for the "."
/// directory, and next an entry for the ".." directory. Only after those two
/// directories have been sent do we begin sending the actual contents of this
/// directory (the contents field). (This is why we maintain dot_sent and dotdot_sent
/// fields on each FileCacheObject)
///
/// Note that this implementation only makes sense in the case that this FileCacheObject
/// is itself a directory (fso.file_type == FileType::Directory). We leave it up to the
/// caller to ensure iteration makes sense in the given context that it's used.
impl Iterator for FileCacheObject {
    type Item = tdp::FileSystemObject;

    fn next(&mut self) -> Option<Self::Item> {
        // On the first call to next, return the "." directory
        if !self.dot_sent {
            self.dot_sent = true;
            Some(tdp::FileSystemObject {
                last_modified: self.fso.last_modified,
                size: self.fso.size,
                file_type: self.fso.file_type,
                is_empty: tdp::FALSE,
                path: UnixPath::from(".".to_string()),
            })
        } else if !self.dotdot_sent {
            // On the second call to next, return the ".." directory
            self.dotdot_sent = true;
            Some(tdp::FileSystemObject {
                last_modified: self.fso.last_modified,
                size: 0,
                file_type: tdp::FileType::Directory,
                is_empty: tdp::FALSE,
                path: UnixPath::from("..".to_string()),
            })
        } else {
            // "." and ".." have been sent, now start iterating through
            // the actual contents of the directory
            if self.contents_i < self.contents.len() {
                let i = self.contents_i;
                self.contents_i += 1;
                return Some(self.contents[i].clone());
            }
            None
        }
    }
}

/// A generic error type for the FilesystemBackend that can contain any arbitrary error message.
#[derive(Debug)]
struct FilesystemBackendError(pub String);

impl std::fmt::Display for FilesystemBackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#?}", self)
    }
}

impl std::error::Error for FilesystemBackendError {}

type Handler<T> = Box<dyn FnOnce(&mut FilesystemBackend, T) -> PduResult<()> + Send>;

/// When we send a TDP Shared Directory Request to the browser, we expect a response
/// which we will need to call a function on. A [`ResponseHandler`] is a wrapper around
/// the function that will be called when the response is received.
struct ResponseHandler<T>(Handler<T>);

impl<T> ResponseHandler<T> {
    fn new(
        handler: impl FnOnce(&mut FilesystemBackend, T) -> PduResult<()> + Send + 'static,
    ) -> Self {
        Self(Box::new(handler))
    }

    fn call(self, this: &mut FilesystemBackend, res: T) -> PduResult<()> {
        (self.0)(this, res)
    }
}

impl<T> std::fmt::Debug for ResponseHandler<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<{}>", std::any::type_name::<T>())
    }
}

type SharedDirectoryInfoResponseHandler = ResponseHandler<tdp::SharedDirectoryInfoResponse>;
type SharedDirectoryCreateResponseHandler = ResponseHandler<tdp::SharedDirectoryCreateResponse>;
type SharedDirectoryDeleteResponseHandler = ResponseHandler<tdp::SharedDirectoryDeleteResponse>;
type SharedDirectoryListResponseHandler = ResponseHandler<tdp::SharedDirectoryListResponse>;

type CompletionId = u32;

/// A generic cache for storing [`ResponseHandler`]s indexed by [`CompletionId`].
#[derive(Debug)]
struct ResponseCache<T> {
    cache: HashMap<CompletionId, ResponseHandler<T>>,
}

impl<T> ResponseCache<T> {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    fn insert(&mut self, completion_id: CompletionId, handler: ResponseHandler<T>) {
        self.cache.insert(completion_id, handler);
    }

    fn remove(&mut self, completion_id: &CompletionId) -> Option<ResponseHandler<T>> {
        self.cache.remove(completion_id)
    }
}
