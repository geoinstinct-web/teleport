// Copyright 2021 Gravitational, Inc
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

mod consts;
mod flags;
mod scard;

use crate::errors::{
    invalid_data_error, not_implemented_error, try_error, NTSTATUS_OK, SPECIAL_NO_RESPONSE,
};
use crate::util;
use crate::vchan;
use crate::{
    FileSystemObject, FileType, Payload, SharedDirectoryAcknowledge, SharedDirectoryCreateRequest,
    SharedDirectoryCreateResponse, SharedDirectoryDeleteRequest, SharedDirectoryDeleteResponse,
    SharedDirectoryInfoRequest, SharedDirectoryInfoResponse, SharedDirectoryListRequest,
    SharedDirectoryListResponse, TdpErrCode,
};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use consts::{
    CapabilityType, Component, DeviceType, FsInformationClassLevel, MajorFunction, MinorFunction,
    PacketId, DRIVE_CAPABILITY_VERSION_02, GENERAL_CAPABILITY_VERSION_02, NTSTATUS,
    SCARD_DEVICE_ID, SMARTCARD_CAPABILITY_VERSION_01, VERSION_MAJOR, VERSION_MINOR,
};
use num_traits::{FromPrimitive, ToPrimitive};
use rdp::core::mcs;
use rdp::core::tpkt;
use rdp::model::data::Message;
use rdp::model::error::Error as RdpError;
use rdp::model::error::*;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::io::{Read, Write};

pub use consts::CHANNEL_NAME;

/// Client implements a device redirection (RDPDR) client, as defined in
/// https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-RDPEFS/%5bMS-RDPEFS%5d.pdf
///
/// This client only supports a single smartcard device.
pub struct Client {
    vchan: vchan::Client,
    scard: scard::Client,

    allow_directory_sharing: bool,
    active_device_ids: Vec<u32>,
    /// FileId-indexed cache of FileCacheObjects
    file_cache: FileCache,
    next_file_id: u32, // used to generate file id's

    // Functions for sending tdp messages to the browser client.
    tdp_sd_acknowledge: SharedDirectoryAcknowledgeSender,
    tdp_sd_info_request: SharedDirectoryInfoRequestSender,
    tdp_sd_create_request: SharedDirectoryCreateRequestSender,
    tdp_sd_delete_request: SharedDirectoryDeleteRequestSender,
    tdp_sd_list_request: SharedDirectoryListRequestSender,

    // CompletionId-indexed maps of handlers for tdp messages coming from the browser client.
    pending_sd_info_resp_handlers: HashMap<u32, SharedDirectoryInfoResponseHandler>,
    pending_sd_create_resp_handlers: HashMap<u32, SharedDirectoryCreateResponseHandler>,
    pending_sd_delete_resp_handlers: HashMap<u32, SharedDirectoryDeleteResponseHandler>,
    pending_sd_list_resp_handlers: HashMap<u32, SharedDirectoryListResponseHandler>,
}

pub struct Config {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub pin: String,
    pub allow_directory_sharing: bool,

    pub tdp_sd_acknowledge: SharedDirectoryAcknowledgeSender,
    pub tdp_sd_info_request: SharedDirectoryInfoRequestSender,
    pub tdp_sd_create_request: SharedDirectoryCreateRequestSender,
    pub tdp_sd_delete_request: SharedDirectoryDeleteRequestSender,
    pub tdp_sd_list_request: SharedDirectoryListRequestSender,
}

impl Client {
    pub fn new(cfg: Config) -> Self {
        if cfg.allow_directory_sharing {
            debug!("creating rdpdr client with directory sharing enabled")
        } else {
            debug!("creating rdpdr client with directory sharing disabled")
        }
        Client {
            vchan: vchan::Client::new(),
            scard: scard::Client::new(cfg.cert_der, cfg.key_der, cfg.pin),

            allow_directory_sharing: cfg.allow_directory_sharing,
            active_device_ids: vec![],
            file_cache: FileCache::new(),
            next_file_id: 0,

            tdp_sd_acknowledge: cfg.tdp_sd_acknowledge,
            tdp_sd_info_request: cfg.tdp_sd_info_request,
            tdp_sd_create_request: cfg.tdp_sd_create_request,
            tdp_sd_delete_request: cfg.tdp_sd_delete_request,
            tdp_sd_list_request: cfg.tdp_sd_list_request,

            pending_sd_info_resp_handlers: HashMap::new(),
            pending_sd_create_resp_handlers: HashMap::new(),
            pending_sd_delete_resp_handlers: HashMap::new(),
            pending_sd_list_resp_handlers: HashMap::new(),
        }
    }
    /// Reads raw RDP messages sent on the rdpdr virtual channel and replies as necessary.
    pub fn read_and_reply<S: Read + Write>(
        &mut self,
        payload: tpkt::Payload,
        mcs: &mut mcs::Client<S>,
    ) -> RdpResult<()> {
        if let Some(mut payload) = self.vchan.read(payload)? {
            let header = SharedHeader::decode(&mut payload)?;
            if let Component::RDPDR_CTYP_PRN = header.component {
                warn!("got {:?} RDPDR header from RDP server, ignoring because we're not redirecting any printers", header);
                return Ok(());
            }
            let responses = match header.packet_id {
                PacketId::PAKID_CORE_SERVER_ANNOUNCE => {
                    self.handle_server_announce(&mut payload)?
                }
                PacketId::PAKID_CORE_SERVER_CAPABILITY => {
                    self.handle_server_capability(&mut payload)?
                }
                PacketId::PAKID_CORE_CLIENTID_CONFIRM => {
                    self.handle_client_id_confirm(&mut payload)?
                }
                PacketId::PAKID_CORE_DEVICE_REPLY => self.handle_device_reply(&mut payload)?,
                // Device IO request is where communication with the smartcard and shared drive actually happens.
                // Everything up to this point was negotiation (and smartcard device registration).
                PacketId::PAKID_CORE_DEVICE_IOREQUEST => {
                    self.handle_device_io_request(&mut payload)?
                }
                _ => {
                    // We don't implement the full set of messages.
                    error!(
                        "RDPDR packets {:?} are not implemented yet, ignoring",
                        header.packet_id
                    );
                    vec![]
                }
            };

            let chan = &CHANNEL_NAME.to_string();
            for resp in responses {
                mcs.write(chan, resp)?;
            }
        }
        Ok(())
    }

    fn handle_server_announce(&self, payload: &mut Payload) -> RdpResult<Vec<Vec<u8>>> {
        let req = ServerAnnounceRequest::decode(payload)?;
        debug!("received RDP {:?}", req);

        let resp = ClientAnnounceReply::new(req);
        debug!("sending RDP {:?}", resp);
        let resp =
            self.add_headers_and_chunkify(PacketId::PAKID_CORE_CLIENTID_CONFIRM, resp.encode()?)?;

        Ok(resp)
    }

    fn handle_server_capability(&self, payload: &mut Payload) -> RdpResult<Vec<Vec<u8>>> {
        let req = ServerCoreCapabilityRequest::decode(payload)?;
        debug!("received RDP {:?}", req);

        let resp = ClientCoreCapabilityResponse::new_response();
        debug!("sending RDP {:?}", resp);
        let resp =
            self.add_headers_and_chunkify(PacketId::PAKID_CORE_CLIENT_CAPABILITY, resp.encode()?)?;

        Ok(resp)
    }

    fn handle_client_id_confirm(&mut self, payload: &mut Payload) -> RdpResult<Vec<Vec<u8>>> {
        let req = ServerClientIdConfirm::decode(payload)?;
        debug!("received RDP {:?}", req);

        // The smartcard initialization sequence that contains this message happens once at session startup,
        // and once when login succeeds. We only need to announce the smartcard once.
        let resp = if !self.active_device_ids.contains(&SCARD_DEVICE_ID) {
            self.push_active_device_id(SCARD_DEVICE_ID)?;
            let resp = ClientDeviceListAnnounceRequest::new_smartcard(SCARD_DEVICE_ID);
            debug!("sending RDP {:?}", resp);
            self.add_headers_and_chunkify(PacketId::PAKID_CORE_DEVICELIST_ANNOUNCE, resp.encode()?)?
        } else {
            let resp = ClientDeviceListAnnounceRequest::new_empty();
            debug!("sending RDP {:?}", resp);
            self.add_headers_and_chunkify(PacketId::PAKID_CORE_DEVICELIST_ANNOUNCE, resp.encode()?)?
        };
        Ok(resp)
    }

    fn handle_device_reply(&self, payload: &mut Payload) -> RdpResult<Vec<Vec<u8>>> {
        let req = ServerDeviceAnnounceResponse::decode(payload)?;
        debug!("received RDP: {:?}", req);

        if !self.active_device_ids.contains(&req.device_id) {
            let resp = SharedDirectoryAcknowledge {
                err_code: TdpErrCode::Failed,
                directory_id: req.device_id,
            };
            (self.tdp_sd_acknowledge)(resp)?;
            Err(invalid_data_error(&format!(
                "got ServerDeviceAnnounceResponse for unknown device_id {}",
                &req.device_id
            )))
        } else if req.result_code != NTSTATUS_OK {
            let resp = SharedDirectoryAcknowledge {
                err_code: TdpErrCode::Failed,
                directory_id: req.device_id,
            };
            (self.tdp_sd_acknowledge)(resp)?;
            Err(invalid_data_error(&format!(
                "got unsuccessful ServerDeviceAnnounceResponse result code NTSTATUS({})",
                &req.result_code
            )))
        } else {
            debug!("ServerDeviceAnnounceResponse was valid");
            if req.device_id != self.get_scard_device_id()? {
                let resp = SharedDirectoryAcknowledge {
                    err_code: TdpErrCode::Nil,
                    directory_id: req.device_id,
                };
                (self.tdp_sd_acknowledge)(resp)?;
                debug!("TDP directory sharing initial negotiation succeeded");
            } else {
                debug!("RDP smart card redirection initial negotiation succeeded");
            }
            Ok(vec![])
        }
    }

    fn handle_device_io_request(&mut self, payload: &mut Payload) -> RdpResult<Vec<Vec<u8>>> {
        let device_io_request = DeviceIoRequest::decode(payload)?;
        let major_function = device_io_request.major_function.clone();

        // Smartcard control only uses IRP_MJ_DEVICE_CONTROL; directory control uses IRP_MJ_DEVICE_CONTROL along with
        // all the other MajorFunctions supported by this Client. Therefore if we receive any major function when drive
        // redirection is not allowed, something has gone wrong. In such a case, we return an error as a security measure
        // to ensure directories are never shared when RBAC doesn't permit it.
        if major_function != MajorFunction::IRP_MJ_DEVICE_CONTROL && !self.allow_directory_sharing {
            return Err(Error::TryError(
                "received a drive redirection major function when drive redirection was not allowed"
                    .to_string(),
            ));
        }

        match major_function {
            MajorFunction::IRP_MJ_DEVICE_CONTROL => {
                self.process_irp_device_control(device_io_request, payload)
            }
            MajorFunction::IRP_MJ_CREATE => self.process_irp_create(device_io_request, payload),
            MajorFunction::IRP_MJ_QUERY_INFORMATION => {
                self.process_irp_query_information(device_io_request, payload)
            }
            MajorFunction::IRP_MJ_CLOSE => self.process_irp_close(device_io_request),
            MajorFunction::IRP_MJ_DIRECTORY_CONTROL => {
                self.process_irp_directory_control(device_io_request, payload)
            }
            _ => Err(invalid_data_error(&format!(
                // TODO(isaiah): send back a not implemented response(?)
                "got unsupported major_function in DeviceIoRequest: {:?}",
                &major_function
            ))),
        }
    }

    fn process_irp_device_control(
        &mut self,
        device_io_request: DeviceIoRequest,
        payload: &mut Payload,
    ) -> RdpResult<Vec<Vec<u8>>> {
        let ioctl = DeviceControlRequest::decode(device_io_request, payload)?;
        let is_smart_card_op = ioctl.header.device_id == self.get_scard_device_id()?;
        debug!("received RDP: {:?}", ioctl);

        // IRP_MJ_DEVICE_CONTROL is the one major function used by both the smartcard controller (always enabled)
        // and shared directory controller (potentially disabled by RBAC). Here we check that directory sharing
        // is enabled here before proceeding with any shared directory controls as an additional security measure.
        if !is_smart_card_op && !self.allow_directory_sharing {
            return Err(Error::TryError("received a drive redirection major function when drive redirection was not allowed".to_string()));
        }
        let resp = if is_smart_card_op {
            // Smart card control
            let (code, res) = self.scard.ioctl(ioctl.io_control_code, payload)?;
            if code == SPECIAL_NO_RESPONSE {
                return Ok(vec![]);
            }
            DeviceControlResponse::new(&ioctl, code, res)
        } else {
            // Drive redirection, mimic FreeRDP's "no-op"
            // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L677-L684
            DeviceControlResponse::new(&ioctl, NTSTATUS::STATUS_SUCCESS.to_u32().unwrap(), vec![])
        };
        debug!("sending RDP: {:?}", resp);
        let resp = self
            .add_headers_and_chunkify(PacketId::PAKID_CORE_DEVICE_IOCOMPLETION, resp.encode()?)?;
        Ok(resp)
    }

    fn process_irp_create(
        &mut self,
        device_io_request: DeviceIoRequest,
        payload: &mut Payload,
    ) -> RdpResult<Vec<Vec<u8>>> {
        // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L207
        let rdp_req = ServerCreateDriveRequest::decode(device_io_request, payload)?;
        debug!("received RDP: {:?}", rdp_req);

        // Send a TDP Shared Directory Info Request
        // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L210
        let tdp_req = SharedDirectoryInfoRequest::from(rdp_req.clone());
        (self.tdp_sd_info_request)(tdp_req)?;

        // Add a TDP Shared Directory Info Response handler to the handler cache.
        // When we receive a TDP Shared Directory Info Response with this completion_id,
        // this handler will be called.
        self.pending_sd_info_resp_handlers.insert(
            rdp_req.device_io_request.completion_id,
            Box::new(
                |cli: &mut Self, res: SharedDirectoryInfoResponse| -> RdpResult<Vec<Vec<u8>>> {
                    let rdp_req = rdp_req;
                    match res.err_code {
                        TdpErrCode::Nil => {
                            // The file exists
                            // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L214
                            if res.fso.file_type == FileType::Directory {
                                if rdp_req.create_disposition
                                    == flags::CreateDisposition::FILE_CREATE
                                {
                                    // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L221
                                    // ERROR_ALREADY_EXISTS --> STATUS_OBJECT_NAME_COLLISION: https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L102
                                    return cli.prep_device_create_response(
                                        &rdp_req,
                                        NTSTATUS::STATUS_OBJECT_NAME_COLLISION,
                                        0,
                                    );
                                }

                                if rdp_req
                                    .create_options
                                    .contains(flags::CreateOptions::FILE_NON_DIRECTORY_FILE)
                                {
                                    // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L227
                                    // ERROR_ACCESS_DENIED --> STATUS_ACCESS_DENIED: https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L81
                                    return cli.prep_device_create_response(
                                        &rdp_req,
                                        NTSTATUS::STATUS_ACCESS_DENIED,
                                        0,
                                    );
                                }
                            } else if rdp_req
                                .create_options
                                .contains(flags::CreateOptions::FILE_DIRECTORY_FILE)
                            {
                                // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L237
                                // ERROR_DIRECTORY --> STATUS_NOT_A_DIRECTORY: https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L118
                                return cli.prep_device_create_response(
                                    &rdp_req,
                                    NTSTATUS::STATUS_NOT_A_DIRECTORY,
                                    0,
                                );
                            }
                        }
                        TdpErrCode::DNE => {
                            // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L242
                            if rdp_req
                                .create_options
                                .contains(flags::CreateOptions::FILE_DIRECTORY_FILE)
                            {
                                if rdp_req.create_disposition.intersects(
                                    flags::CreateDisposition::FILE_OPEN_IF
                                        | flags::CreateDisposition::FILE_CREATE,
                                ) {
                                    // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L252
                                    return cli.tdp_sd_create(
                                        rdp_req,
                                        FileType::Directory,
                                        res.fso,
                                    );
                                } else {
                                    // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L258
                                    // ERROR_FILE_NOT_FOUND --> STATUS_NO_SUCH_FILE: https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L85
                                    return cli.prep_device_create_response(
                                        &rdp_req,
                                        NTSTATUS::STATUS_NO_SUCH_FILE,
                                        0,
                                    );
                                }
                            }
                        }
                        TdpErrCode::Failed | TdpErrCode::AE => {
                            return Err(try_error(&format!(
                                "received unexpected TDP error code: {:?}",
                                res.err_code,
                            )));
                        }
                    }

                    // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L263
                    // Note: the above line in FreeRDP will always evaluate to true:
                    // - drive_file_init is called here: https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L362
                    // - it is always passed a file where file->file_handle = INVALID_HANDLE_VALUE: https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L351
                    // - None of the calls up to the line in question can have changed it

                    // The actual creation of files and error mapping device_io_request.completion_id happens here, for reference:
                    // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/winpr/libwinpr/file/file.c#L781
                    if rdp_req.create_disposition == flags::CreateDisposition::FILE_SUPERSEDE {
                        // If the file already exists, replace it with the given file. If it does not, create the given file.
                        if res.err_code == TdpErrCode::Nil {
                            return cli.tdp_sd_overwrite(rdp_req, res.fso);
                        } else {
                            // The match statement on res.err_code above ensures that this means res.err_code == TdpErrCode::DNE
                            return cli.tdp_sd_create(rdp_req, FileType::File, res.fso);
                        }
                    } else if rdp_req.create_disposition == flags::CreateDisposition::FILE_OPEN {
                        // If the file already exists, open it instead of creating a new file. If it does not, fail the request and do not create a new file.
                        if res.err_code == TdpErrCode::Nil {
                            let file_id = cli.generate_file_id();
                            cli.file_cache.insert(
                                file_id,
                                FileCacheObject::new(rdp_req.path.clone(), res.fso),
                            );
                            return cli.prep_device_create_response(
                                &rdp_req,
                                NTSTATUS::STATUS_SUCCESS,
                                file_id,
                            );
                        } else {
                            // The match statement on res.err_code above ensures that this means res.err_code == TdpErrCode::DNE
                            return cli.prep_device_create_response(
                                &rdp_req,
                                NTSTATUS::STATUS_NO_SUCH_FILE,
                                0,
                            );
                        }
                    } else if rdp_req.create_disposition == flags::CreateDisposition::FILE_CREATE {
                        // If the file already exists, fail the request and do not create or open the given file. If it does not, create the given file.
                        if res.err_code == TdpErrCode::Nil {
                            return cli.prep_device_create_response(
                                &rdp_req,
                                NTSTATUS::STATUS_OBJECT_NAME_COLLISION,
                                0,
                            );
                        } else {
                            // The match statement on res.err_code above ensures that this means res.err_code == TdpErrCode::DNE
                            return cli.tdp_sd_create(rdp_req, FileType::File, res.fso);
                        }
                    } else if rdp_req.create_disposition == flags::CreateDisposition::FILE_OPEN_IF {
                        // If the file already exists, open it. If it does not, create the given file.
                        if res.err_code == TdpErrCode::Nil {
                            let file_id = cli.generate_file_id();
                            cli.file_cache.insert(
                                file_id,
                                FileCacheObject::new(rdp_req.path.clone(), res.fso),
                            );
                            return cli.prep_device_create_response(
                                &rdp_req,
                                NTSTATUS::STATUS_SUCCESS,
                                file_id,
                            );
                        } else {
                            // The match statement on res.err_code above ensures that this means res.err_code == TdpErrCode::DNE
                            return cli.tdp_sd_create(rdp_req, FileType::File, res.fso);
                        }
                    } else if rdp_req.create_disposition == flags::CreateDisposition::FILE_OVERWRITE
                    {
                        // If the file already exists, open it and overwrite it. If it does not, fail the request.
                        if res.err_code == TdpErrCode::Nil {
                            return cli.tdp_sd_overwrite(rdp_req, res.fso);
                        } else {
                            // The match statement on res.err_code above ensures that this means res.err_code == TdpErrCode::DNE
                            return cli.prep_device_create_response(
                                &rdp_req,
                                NTSTATUS::STATUS_NO_SUCH_FILE,
                                0,
                            );
                        }
                    } else if rdp_req.create_disposition
                        == flags::CreateDisposition::FILE_OVERWRITE_IF
                    {
                        // If the file already exists, open it and overwrite it. If it does not, create the given file.
                        if res.err_code == TdpErrCode::Nil {
                            return cli.tdp_sd_overwrite(rdp_req, res.fso);
                        } else {
                            // The match statement on res.err_code above ensures that this means res.err_code == TdpErrCode::DNE
                            return cli.tdp_sd_create(rdp_req, FileType::File, res.fso);
                        }
                    }
                    Ok(vec![])
                },
            ),
        );
        Ok(vec![])
    }

    fn process_irp_query_information(
        &mut self,
        device_io_request: DeviceIoRequest,
        payload: &mut Payload,
    ) -> RdpResult<Vec<Vec<u8>>> {
        // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L373
        let rdp_req = ServerDriveQueryInformationRequest::decode(device_io_request, payload)?;
        debug!("received RDP: {:?}", rdp_req);
        if let Some(file) = self.file_cache.get(rdp_req.device_io_request.file_id) {
            self.prep_query_info_response(&rdp_req, Some(file), NTSTATUS::STATUS_SUCCESS)
        } else {
            self.prep_query_info_response(&rdp_req, None, NTSTATUS::STATUS_UNSUCCESSFUL)
        }
    }

    fn process_irp_close(&mut self, device_io_request: DeviceIoRequest) -> RdpResult<Vec<Vec<u8>>> {
        // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L236
        let rdp_req = DeviceCloseRequest::decode(device_io_request);
        debug!("received RDP: {:?}", rdp_req);
        // Remove the file from our cache
        if let Some(file) = self.file_cache.remove(rdp_req.device_io_request.file_id) {
            if file.delete_pending {
                self.tdp_sd_delete(rdp_req, file)
            } else {
                self.prep_device_close_response(rdp_req, NTSTATUS::STATUS_SUCCESS)
            }
        } else {
            self.prep_device_close_response(rdp_req, NTSTATUS::STATUS_UNSUCCESSFUL)
        }
    }

    /// The IRP_MJ_DIRECTORY_CONTROL function we support is when it's sent with minor function IRP_MN_QUERY_DIRECTORY,
    /// which is used to retrieve the contents of a directory. RDP does this by repeatedly sending
    /// IRP_MN_QUERY_DIRECTORY's, expecting to retrieve the next item in the directory in each reply.
    /// (Which directory is being queried is specified by the FileId in each request).
    ///
    /// An idiosyncrasy of the protocol is that on the first IRP_MN_QUERY_DIRECTORY in a sequence, RDP expects back an
    /// entry for the "." directory, on the second call it expects an entry for the ".." directory, and on subsequent
    /// calls it expects entries for the actual contents of the directory.
    ///
    /// Once all of the directory's contents has been sent back, we alert RDP to stop sending IRP_MN_QUERY_DIRECTORY's
    /// by sending it back an NTSTATUS::STATUS_NO_MORE_FILES.
    fn process_irp_directory_control(
        &mut self,
        device_io_request: DeviceIoRequest,
        payload: &mut Payload,
    ) -> RdpResult<Vec<Vec<u8>>> {
        let minor_function = device_io_request.minor_function.clone();
        // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L650
        match minor_function {
            MinorFunction::IRP_MN_QUERY_DIRECTORY => {
                let rdp_req = ServerDriveQueryDirectoryRequest::decode(device_io_request, payload)?;
                debug!("received RDP: {:?}", rdp_req);
                let file_id = rdp_req.device_io_request.file_id;
                // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L610
                if let Some(dir) = self.file_cache.get(file_id) {
                    if dir.fso.file_type != FileType::Directory {
                        return Err(invalid_data_error("received an IRP_MN_QUERY_DIRECTORY request for a file rather than a directory"));
                    }

                    // On the initial query, we need to get the list of files in this directory from
                    // the client by sending a TDP SharedDirectoryListRequest.
                    if rdp_req.initial_query != 0 {
                        // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L775
                        // TODO(isaiah): I'm observing that sometimes rdp_req.path will not be precisely equal to dir.path. For example, we will
                        // get a ServerDriveQueryDirectoryRequest where path == "\\*", whereas the corresponding entry in the file_cache will have
                        // path == "\\". I'm not quite sure what to do with this yet, so just leaving this as a note to self.
                        let path = dir.path.clone();

                        // Ask the client for the list of files in this directory.
                        (self.tdp_sd_list_request)(SharedDirectoryListRequest {
                            completion_id: rdp_req.device_io_request.completion_id,
                            directory_id: rdp_req.device_io_request.device_id,
                            path,
                        })?;

                        // When we get the response for that list of files...
                        self.pending_sd_list_resp_handlers.insert(
                            rdp_req.device_io_request.completion_id,
                            Box::new(
                                move |cli: &mut Self,
                                      res: SharedDirectoryListResponse|
                                      -> RdpResult<Vec<Vec<u8>>> {
                                    if res.err_code == TdpErrCode::Nil {
                                        // If SharedDirectoryListRequest succeeded, move the
                                        // list of FileSystemObjects that correspond to this directory's
                                        // contents to its entry in the file cache.
                                        if let Some(dir) = cli.file_cache.get_mut(file_id) {
                                            dir.contents = res.fso_list;
                                        } else {
                                            return cli
                                                .prep_file_cache_fail_drive_query_dir_response(
                                                    &rdp_req,
                                                );
                                        }

                                        // And send back the "." directory over RDP
                                        cli.prep_next_drive_query_dir_response(&rdp_req)
                                    } else {
                                        // TODO(isaiah): For now any error will kill the session.
                                        // In the future, we might want to make this send back
                                        // an NTSTATUS::STATUS_UNSUCCESSFUL instead.
                                        Err(try_error(&format!("SharedDirectoryListRequest failed with err_code = {:?}", res.err_code)))
                                    }
                                },
                            ),
                        );

                        // Return nothing yet, an RDP message will be returned when the pending_sd_list_resp_handlers
                        // closure gets called.
                        Ok(vec![])
                    } else {
                        // This isn't the initial query, ergo we already have this dir's contents filled in.
                        // Just send the next item.
                        self.prep_next_drive_query_dir_response(&rdp_req)
                    }
                } else {
                    self.prep_file_cache_fail_drive_query_dir_response(&rdp_req)
                }
            }
            MinorFunction::IRP_MN_NOTIFY_CHANGE_DIRECTORY => {
                debug!("received RDP: {:?}", device_io_request);
                debug!(
                    "ignoring IRP_MN_NOTIFY_CHANGE_DIRECTORY: {:?}",
                    device_io_request
                );
                // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L661
                Ok(vec![])
            }
            _ => {
                debug!("received RDP: {:?}", device_io_request);
                // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L663
                self.prep_drive_query_dir_response(
                    &device_io_request,
                    NTSTATUS::STATUS_NOT_SUPPORTED,
                    None,
                )
            }
        }
    }

    pub fn write_client_device_list_announce<S: Read + Write>(
        &mut self,
        req: ClientDeviceListAnnounce,
        mcs: &mut mcs::Client<S>,
    ) -> RdpResult<()> {
        self.push_active_device_id(req.device_list[0].device_id)?;
        debug!("sending new drive for redirection over RDP: {:?}", req);

        let responses =
            self.add_headers_and_chunkify(PacketId::PAKID_CORE_DEVICELIST_ANNOUNCE, req.encode()?)?;
        let chan = &CHANNEL_NAME.to_string();
        for resp in responses {
            mcs.write(chan, resp)?;
        }

        Ok(())
    }

    pub fn handle_tdp_sd_info_response<S: Read + Write>(
        &mut self,
        res: SharedDirectoryInfoResponse,
        mcs: &mut mcs::Client<S>,
    ) -> RdpResult<()> {
        debug!("received TDP SharedDirectoryInfoResponse: {:?}", res);
        if let Some(tdp_resp_handler) = self
            .pending_sd_info_resp_handlers
            .remove(&res.completion_id)
        {
            let rdp_responses = tdp_resp_handler(self, res)?;
            let chan = &CHANNEL_NAME.to_string();
            for resp in rdp_responses {
                mcs.write(chan, resp)?;
            }
            Ok(())
        } else {
            return Err(try_error(&format!(
                "received invalid completion id: {}",
                res.completion_id
            )));
        }
    }

    pub fn handle_tdp_sd_create_response<S: Read + Write>(
        &mut self,
        res: SharedDirectoryCreateResponse,
        mcs: &mut mcs::Client<S>,
    ) -> RdpResult<()> {
        debug!("received TDP SharedDirectoryCreateResponse: {:?}", res);
        if let Some(tdp_resp_handler) = self
            .pending_sd_create_resp_handlers
            .remove(&res.completion_id)
        {
            let rdp_responses = tdp_resp_handler(self, res)?;
            let chan = &CHANNEL_NAME.to_string();
            for resp in rdp_responses {
                mcs.write(chan, resp)?;
            }
            Ok(())
        } else {
            return Err(try_error(&format!(
                "received invalid completion id: {}",
                res.completion_id
            )));
        }
    }

    pub fn handle_tdp_sd_delete_response<S: Read + Write>(
        &mut self,
        res: SharedDirectoryDeleteResponse,
        mcs: &mut mcs::Client<S>,
    ) -> RdpResult<()> {
        debug!("received TDP SharedDirectoryDeleteResponse: {:?}", res);
        if let Some(tdp_resp_handler) = self
            .pending_sd_delete_resp_handlers
            .remove(&res.completion_id)
        {
            let rdp_responses = tdp_resp_handler(self, res)?;
            let chan = &CHANNEL_NAME.to_string();
            for resp in rdp_responses {
                mcs.write(chan, resp)?;
            }
            Ok(())
        } else {
            return Err(try_error(&format!(
                "received invalid completion id: {}",
                res.completion_id
            )));
        }
    }

    pub fn handle_tdp_sd_list_response<S: Read + Write>(
        &mut self,
        res: SharedDirectoryListResponse,
        mcs: &mut mcs::Client<S>,
    ) -> RdpResult<()> {
        debug!("received TDP SharedDirectoryListResponse: {:?}", res);
        if let Some(tdp_resp_handler) = self
            .pending_sd_list_resp_handlers
            .remove(&res.completion_id)
        {
            let rdp_responses = tdp_resp_handler(self, res)?;
            let chan = &CHANNEL_NAME.to_string();
            for resp in rdp_responses {
                mcs.write(chan, resp)?;
            }
            Ok(())
        } else {
            return Err(try_error(&format!(
                "received invalid completion id: {}",
                res.completion_id
            )));
        }
    }

    fn prep_device_create_response(
        &mut self,
        req: &DeviceCreateRequest,
        io_status: NTSTATUS,
        new_file_id: u32,
    ) -> RdpResult<Vec<Vec<u8>>> {
        let resp = DeviceCreateResponse::new(req, io_status, new_file_id);
        debug!("sending RDP: {:?}", resp);
        let resp = self
            .add_headers_and_chunkify(PacketId::PAKID_CORE_DEVICE_IOCOMPLETION, resp.encode()?)?;
        Ok(resp)
    }

    fn prep_query_info_response(
        &self,
        req: &ServerDriveQueryInformationRequest,
        file: Option<&FileCacheObject>,
        io_status: NTSTATUS,
    ) -> RdpResult<Vec<Vec<u8>>> {
        let resp = ClientDriveQueryInformationResponse::new(req, file, io_status)?;
        debug!("sending RDP: {:?}", resp);
        let resp = self
            .add_headers_and_chunkify(PacketId::PAKID_CORE_DEVICE_IOCOMPLETION, resp.encode()?)?;
        Ok(resp)
    }

    fn prep_device_close_response(
        &self,
        req: DeviceCloseRequest,
        io_status: NTSTATUS,
    ) -> RdpResult<Vec<Vec<u8>>> {
        let resp = DeviceCloseResponse::new(req, io_status);
        debug!("replying with: {:?}", resp);
        let resp = self
            .add_headers_and_chunkify(PacketId::PAKID_CORE_DEVICE_IOCOMPLETION, resp.encode()?)?;
        Ok(resp)
    }

    fn prep_drive_query_dir_response(
        &self,
        device_io_request: &DeviceIoRequest,
        io_status: NTSTATUS,
        buffer: Option<FsInformationClass>,
    ) -> RdpResult<Vec<Vec<u8>>> {
        let resp = ClientDriveQueryDirectoryResponse::new(device_io_request, io_status, buffer)?;
        debug!("sending RDP: {:?}", resp);
        let resp = self
            .add_headers_and_chunkify(PacketId::PAKID_CORE_DEVICE_IOCOMPLETION, resp.encode()?)?;
        Ok(resp)
    }

    /// prep_next_drive_query_dir_response is a helper function that takes advantage of the
    /// Iterator implementation for FileCacheObject in order to respond appropriately to
    /// Server Drive Query Directory Requests as they come in.
    ///
    /// req gives us a FileId, which we use to get the FileCacheObject for the directory that
    /// this request is targeted at. We use that FileCacheObject as an iterator, grabbing the
    /// next() FileSystemObject (starting with ".", then "..", then iterating through the contents
    /// of the target directory), which we then convert to an RDP FsInformationClass for sending back
    /// to the RDP server.
    fn prep_next_drive_query_dir_response(
        &mut self,
        req: &ServerDriveQueryDirectoryRequest,
    ) -> RdpResult<Vec<Vec<u8>>> {
        if let Some(dir) = self.file_cache.get_mut(req.device_io_request.file_id) {
            // Get the next FileSystemObject from the FileCacheObject for translation
            // into an RDP data structure. Because of how next() is implemented for FileCacheObject,
            // the first time this is called we will get an object for the "." directory, the second
            // time will give us "..", and then we will iterate through any files/directories stored
            // within dir.
            if let Some(fso) = dir.next() {
                match req.fs_information_class_lvl {
                // TODO(isaiah): we should support all the fs_information_class_lvl's that FreeRDP does:
                // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L794
                FsInformationClassLevel::FileBothDirectoryInformation => {
                    let buffer = Some(FsInformationClass::FileBothDirectoryInformation(
                        FileBothDirectoryInformation::from(fso)?
                    ));
                    self.prep_drive_query_dir_response(
                        &req.device_io_request,
                        NTSTATUS::STATUS_SUCCESS,
                        buffer
                    )
                },
                FsInformationClassLevel::FileFullDirectoryInformation => {
                    let buffer = Some(FsInformationClass::FileFullDirectoryInformation(
                        FileFullDirectoryInformation::from(fso)?
                    ));
                    self.prep_drive_query_dir_response(
                        &req.device_io_request,
                        NTSTATUS::STATUS_SUCCESS,
                        buffer
                    )
                }
                FsInformationClassLevel::FileDirectoryInformation |
                FsInformationClassLevel::FileNamesInformation => {
                    Err(not_implemented_error(&format!(
                        "support for ServerDriveQueryDirectoryRequest with fs_information_class_lvl = {:?} is not implemented",
                        req.fs_information_class_lvl
                    )))
                },
                _ => {
                    Err(invalid_data_error("received invalid FsInformationClassLevel in ServerDriveQueryDirectoryRequest"))
                }
            }
            } else {
                // Once our iterator is exhausted, send back a NTSTATUS::STATUS_NO_MORE_FILES to alert RDP that we've listed all the
                // contents of this directory.
                // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/winpr/libwinpr/file/generic.c#L1193
                // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L114
                self.prep_drive_query_dir_response(
                    &req.device_io_request,
                    NTSTATUS::STATUS_NO_MORE_FILES,
                    None,
                )
            }
        } else {
            self.prep_file_cache_fail_drive_query_dir_response(req)
        }
    }

    fn prep_file_cache_fail_drive_query_dir_response(
        &self,
        req: &ServerDriveQueryDirectoryRequest,
    ) -> RdpResult<Vec<Vec<u8>>> {
        debug!(
            "failed to retrieve an item from the file cache with FileId = {}",
            req.device_io_request.file_id
        );
        // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L633
        self.prep_drive_query_dir_response(
            &req.device_io_request,
            NTSTATUS::STATUS_UNSUCCESSFUL,
            None,
        )
    }

    /// Helper function for sending a TDP SharedDirectoryCreateRequest based on an
    /// RDP DeviceCreateRequest and handling the TDP SharedDirectoryCreateResponse.
    fn tdp_sd_create(
        &mut self,
        rdp_req: DeviceCreateRequest,
        file_type: FileType,
        fso: FileSystemObject,
    ) -> RdpResult<Vec<Vec<u8>>> {
        let tdp_req = SharedDirectoryCreateRequest {
            completion_id: rdp_req.device_io_request.completion_id,
            directory_id: rdp_req.device_io_request.device_id,
            file_type,
            path: rdp_req.path.clone(),
        };
        (self.tdp_sd_create_request)(tdp_req)?;

        self.pending_sd_create_resp_handlers.insert(
            rdp_req.device_io_request.completion_id,
            Box::new(
                move |cli: &mut Self,
                      res: SharedDirectoryCreateResponse|
                      -> RdpResult<Vec<Vec<u8>>> {
                    if res.err_code == TdpErrCode::Nil {
                        let file_id = cli.generate_file_id();
                        cli.file_cache
                            .insert(file_id, FileCacheObject::new(rdp_req.path.clone(), fso));
                        cli.prep_device_create_response(&rdp_req, NTSTATUS::STATUS_SUCCESS, file_id)
                    } else {
                        cli.prep_device_create_response(&rdp_req, NTSTATUS::STATUS_UNSUCCESSFUL, 0)
                    }
                },
            ),
        );
        Ok(vec![])
    }

    /// Helper function for combining a TDP SharedDirectoryDeleteRequest
    /// with a TDP SharedDirectoryCreateRequest to overwrite a file, based
    /// on an RDP DeviceCreateRequest.
    fn tdp_sd_overwrite(
        &mut self,
        rdp_req: DeviceCreateRequest,
        fso: FileSystemObject,
    ) -> RdpResult<Vec<Vec<u8>>> {
        let tdp_req = SharedDirectoryDeleteRequest {
            completion_id: rdp_req.device_io_request.completion_id,
            directory_id: rdp_req.device_io_request.device_id,
            path: rdp_req.path.clone(),
        };
        (self.tdp_sd_delete_request)(tdp_req)?;
        self.pending_sd_delete_resp_handlers.insert(
            rdp_req.device_io_request.completion_id,
            Box::new(
                |cli: &mut Self, res: SharedDirectoryDeleteResponse| -> RdpResult<Vec<Vec<u8>>> {
                    if res.err_code == TdpErrCode::Nil {
                        cli.tdp_sd_create(rdp_req, FileType::File, fso)
                    } else {
                        cli.prep_device_create_response(&rdp_req, NTSTATUS::STATUS_UNSUCCESSFUL, 0)
                    }
                },
            ),
        );
        Ok(vec![])
    }

    fn tdp_sd_delete(
        &mut self,
        rdp_req: DeviceCloseRequest,
        file: FileCacheObject,
    ) -> RdpResult<Vec<Vec<u8>>> {
        let tdp_req = SharedDirectoryDeleteRequest {
            completion_id: rdp_req.device_io_request.completion_id,
            directory_id: rdp_req.device_io_request.device_id,
            path: file.path,
        };
        (self.tdp_sd_delete_request)(tdp_req)?;
        self.pending_sd_delete_resp_handlers.insert(
            rdp_req.device_io_request.completion_id,
            Box::new(
                |cli: &mut Self, res: SharedDirectoryDeleteResponse| -> RdpResult<Vec<Vec<u8>>> {
                    if res.err_code == TdpErrCode::Nil {
                        cli.prep_device_close_response(rdp_req, NTSTATUS::STATUS_SUCCESS)
                    } else {
                        cli.prep_device_close_response(rdp_req, NTSTATUS::STATUS_UNSUCCESSFUL)
                    }
                },
            ),
        );
        Ok(vec![])
    }

    /// add_headers_and_chunkify takes an encoded PDU ready to be sent over a virtual channel (payload),
    /// adds on the Shared Header based the passed packet_id, adds the appropriate (virtual) Channel PDU Header,
    /// and splits the entire payload into chunks if the payload exceeds the maximum size.
    fn add_headers_and_chunkify(
        &self,
        packet_id: PacketId,
        payload: Vec<u8>,
    ) -> RdpResult<Vec<Vec<u8>>> {
        let mut inner = SharedHeader::new(Component::RDPDR_CTYP_CORE, packet_id).encode()?;
        inner.extend_from_slice(&payload);
        self.vchan.add_header_and_chunkify(None, inner)
    }

    fn push_active_device_id(&mut self, device_id: u32) -> RdpResult<()> {
        if self.active_device_ids.contains(&device_id) {
            return Err(RdpError::TryError(format!(
                "attempted to add a duplicate device_id {} to active_device_ids {:?}",
                device_id, self.active_device_ids
            )));
        }
        self.active_device_ids.push(device_id);
        Ok(())
    }

    fn get_scard_device_id(&self) -> RdpResult<u32> {
        // We always push it into the list first
        if !self.active_device_ids.is_empty() {
            return Ok(self.active_device_ids[0]);
        }
        Err(RdpError::TryError("no active device ids".to_string()))
    }

    fn generate_file_id(&mut self) -> u32 {
        self.next_file_id = self.next_file_id.wrapping_add(1);
        self.next_file_id
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct FileCacheObject {
    path: String,
    delete_pending: bool,
    /// The FileSystemObject pertaining to the file or directory at path.
    fso: FileSystemObject,
    /// A vector of the contents of the directory at path.
    contents: Vec<FileSystemObject>,

    /// Book-keeping variable, see Iterator implementation
    contents_i: usize,
    /// Book-keeping variable, see Iterator implementation
    dot_sent: bool,
    /// Book-keeping variable, see Iterator implementation
    dotdot_sent: bool,
}

impl FileCacheObject {
    fn new(path: String, fso: FileSystemObject) -> Self {
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
}

/// FileCacheObject is used as an iterator for the implementation of
/// IRP_MJ_DIRECTORY_CONTROL, which requires that we iterate through
/// all the files of a directory one by one. In this case, the directory
/// is the FileCacheObject itself, with it's own fso field representing
/// the directory, and its contents being represented by FileSystemObject's
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
    type Item = FileSystemObject;

    fn next(&mut self) -> Option<Self::Item> {
        // On the first call to next, return the "." directory
        if !self.dot_sent {
            self.dot_sent = true;
            Some(FileSystemObject {
                last_modified: self.fso.last_modified,
                size: self.fso.size,
                file_type: self.fso.file_type,
                path: ".".to_string(),
            })
        } else if !self.dotdot_sent {
            // On the second call to next, return the ".." directory
            self.dotdot_sent = true;
            Some(FileSystemObject {
                last_modified: self.fso.last_modified,
                size: 0,
                file_type: FileType::Directory,
                path: "..".to_string(),
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

struct FileCache {
    cache: HashMap<u32, FileCacheObject>,
}

impl FileCache {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    fn insert(&mut self, file_id: u32, file: FileCacheObject) -> Option<FileCacheObject> {
        self.cache.insert(file_id, file)
    }

    // TODO(isaiah): update get, get_mut, and remove to return RdpResult, because presumably none of them
    // should ever fail, if they do it means our cache has gotten out of sync with the remote RDP server

    fn get(&self, file_id: u32) -> Option<&FileCacheObject> {
        self.cache.get(&file_id)
    }

    fn get_mut(&mut self, file_id: u32) -> Option<&mut FileCacheObject> {
        self.cache.get_mut(&file_id)
    }

    fn remove(&mut self, file_id: u32) -> Option<FileCacheObject> {
        self.cache.remove(&file_id)
    }
}

/// 2.2.1.1 Shared Header (RDPDR_HEADER)
/// This header is present at the beginning of every message in sent over the rdpdr virtual channel.
/// The purpose of this header is to describe the type of the message.
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/29d4108f-8163-4a67-8271-e48c4b9c2a7c
#[derive(Debug)]
struct SharedHeader {
    component: Component,
    packet_id: PacketId,
}

impl SharedHeader {
    fn new(component: Component, packet_id: PacketId) -> Self {
        Self {
            component,
            packet_id,
        }
    }
    fn decode(payload: &mut Payload) -> RdpResult<Self> {
        let component = payload.read_u16::<LittleEndian>()?;
        let packet_id = payload.read_u16::<LittleEndian>()?;
        Ok(Self {
            component: Component::from_u16(component).ok_or_else(|| {
                invalid_data_error(&format!("invalid component value {:#06x}", component))
            })?,
            packet_id: PacketId::from_u16(packet_id).ok_or_else(|| {
                invalid_data_error(&format!("invalid packet_id value {:#06x}", packet_id))
            })?,
        })
    }
    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.write_u16::<LittleEndian>(self.component.to_u16().unwrap())?;
        w.write_u16::<LittleEndian>(self.packet_id.to_u16().unwrap())?;
        Ok(w)
    }
}

type ServerAnnounceRequest = ClientIdMessage;
type ClientAnnounceReply = ClientIdMessage;
type ServerClientIdConfirm = ClientIdMessage;

#[derive(Debug)]
struct ClientIdMessage {
    version_major: u16,
    version_minor: u16,
    client_id: u32,
}

impl ClientIdMessage {
    fn new(req: ServerAnnounceRequest) -> Self {
        Self {
            version_major: VERSION_MAJOR,
            version_minor: VERSION_MINOR,
            client_id: req.client_id,
        }
    }

    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.write_u16::<LittleEndian>(self.version_major)?;
        w.write_u16::<LittleEndian>(self.version_minor)?;
        w.write_u32::<LittleEndian>(self.client_id)?;
        Ok(w)
    }

    fn decode(payload: &mut Payload) -> RdpResult<Self> {
        Ok(Self {
            version_major: payload.read_u16::<LittleEndian>()?,
            version_minor: payload.read_u16::<LittleEndian>()?,
            client_id: payload.read_u32::<LittleEndian>()?,
        })
    }
}

#[derive(Debug)]
struct ServerCoreCapabilityRequest {
    num_capabilities: u16,
    padding: u16,
    capabilities: Vec<CapabilitySet>,
}

impl ServerCoreCapabilityRequest {
    fn new_response() -> Self {
        // Clients are always required to send the "general" capability set.
        // In addition, we also send the optional smartcard capability (CAP_SMARTCARD_TYPE)
        // and drive capability (CAP_DRIVE_TYPE).
        let capabilities = vec![
            CapabilitySet {
                header: CapabilityHeader {
                    cap_type: CapabilityType::CAP_GENERAL_TYPE,
                    length: 8 + 36, // 8 byte header + 36 byte capability descriptor
                    version: GENERAL_CAPABILITY_VERSION_02,
                },
                data: Capability::General(GeneralCapabilitySet {
                    os_type: 0,
                    os_version: 0,
                    protocol_major_version: VERSION_MAJOR,
                    protocol_minor_version: VERSION_MINOR,
                    io_code_1: 0x00007fff, // Combination of all the required bits.
                    io_code_2: 0,
                    extended_pdu: 0x00000001 | 0x00000002, // RDPDR_DEVICE_REMOVE_PDUS | RDPDR_CLIENT_DISPLAY_NAME_PDU
                    extra_flags_1: 0,
                    extra_flags_2: 0,
                    special_type_device_cap: 1, // Request redirection of 1 special device - smartcard.
                }),
            },
            CapabilitySet {
                header: CapabilityHeader {
                    cap_type: CapabilityType::CAP_SMARTCARD_TYPE,
                    length: 8, // 8 byte header + empty capability descriptor
                    version: SMARTCARD_CAPABILITY_VERSION_01,
                },
                data: Capability::Smartcard,
            },
            CapabilitySet {
                header: CapabilityHeader {
                    cap_type: CapabilityType::CAP_DRIVE_TYPE,
                    length: 8, // 8 byte header + empty capability descriptor
                    version: DRIVE_CAPABILITY_VERSION_02,
                },
                data: Capability::Drive,
            },
        ];

        Self {
            padding: 0,
            num_capabilities: u16::try_from(capabilities.len()).unwrap(),
            capabilities,
        }
    }

    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.write_u16::<LittleEndian>(self.num_capabilities)?;
        w.write_u16::<LittleEndian>(self.padding)?;
        for cap in self.capabilities.iter() {
            w.extend_from_slice(&cap.encode()?);
        }
        Ok(w)
    }

    fn decode(payload: &mut Payload) -> RdpResult<Self> {
        let num_capabilities = payload.read_u16::<LittleEndian>()?;
        let padding = payload.read_u16::<LittleEndian>()?;
        let mut capabilities = vec![];
        for _ in 0..num_capabilities {
            capabilities.push(CapabilitySet::decode(payload)?);
        }

        Ok(Self {
            num_capabilities,
            padding,
            capabilities,
        })
    }
}

#[derive(Debug)]
struct CapabilitySet {
    header: CapabilityHeader,
    data: Capability,
}

impl CapabilitySet {
    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = self.header.encode()?;
        w.extend_from_slice(&self.data.encode()?);
        Ok(w)
    }
    fn decode(payload: &mut Payload) -> RdpResult<Self> {
        let header = CapabilityHeader::decode(payload)?;
        let data = Capability::decode(payload, &header)?;

        Ok(Self { header, data })
    }
}

#[derive(Debug)]
struct CapabilityHeader {
    cap_type: CapabilityType,
    length: u16,
    version: u32,
}

impl CapabilityHeader {
    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.write_u16::<LittleEndian>(self.cap_type.to_u16().unwrap())?;
        w.write_u16::<LittleEndian>(self.length)?;
        w.write_u32::<LittleEndian>(self.version)?;
        Ok(w)
    }
    fn decode(payload: &mut Payload) -> RdpResult<Self> {
        let cap_type = payload.read_u16::<LittleEndian>()?;
        Ok(Self {
            cap_type: CapabilityType::from_u16(cap_type).ok_or_else(|| {
                invalid_data_error(&format!("invalid capability type {:#06x}", cap_type))
            })?,
            length: payload.read_u16::<LittleEndian>()?,
            version: payload.read_u32::<LittleEndian>()?,
        })
    }
}

#[derive(Debug)]
enum Capability {
    General(GeneralCapabilitySet),
    Printer,
    Port,
    Drive,
    Smartcard,
}

impl Capability {
    fn encode(&self) -> RdpResult<Vec<u8>> {
        match self {
            Capability::General(general) => Ok(general.encode()?),
            _ => Ok(vec![]),
        }
    }

    fn decode(payload: &mut Payload, header: &CapabilityHeader) -> RdpResult<Self> {
        match header.cap_type {
            CapabilityType::CAP_GENERAL_TYPE => Ok(Capability::General(
                GeneralCapabilitySet::decode(payload, header.version)?,
            )),
            CapabilityType::CAP_PRINTER_TYPE => Ok(Capability::Printer),
            CapabilityType::CAP_PORT_TYPE => Ok(Capability::Port),
            CapabilityType::CAP_DRIVE_TYPE => Ok(Capability::Drive),
            CapabilityType::CAP_SMARTCARD_TYPE => Ok(Capability::Smartcard),
        }
    }
}

#[derive(Debug)]
struct GeneralCapabilitySet {
    os_type: u32,
    os_version: u32,
    protocol_major_version: u16,
    protocol_minor_version: u16,
    io_code_1: u32,
    io_code_2: u32,
    extended_pdu: u32,
    extra_flags_1: u32,
    extra_flags_2: u32,
    special_type_device_cap: u32,
}

impl GeneralCapabilitySet {
    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.write_u32::<LittleEndian>(self.os_type)?;
        w.write_u32::<LittleEndian>(self.os_version)?;
        w.write_u16::<LittleEndian>(self.protocol_major_version)?;
        w.write_u16::<LittleEndian>(self.protocol_minor_version)?;
        w.write_u32::<LittleEndian>(self.io_code_1)?;
        w.write_u32::<LittleEndian>(self.io_code_2)?;
        w.write_u32::<LittleEndian>(self.extended_pdu)?;
        w.write_u32::<LittleEndian>(self.extra_flags_1)?;
        w.write_u32::<LittleEndian>(self.extra_flags_2)?;
        w.write_u32::<LittleEndian>(self.special_type_device_cap)?;
        Ok(w)
    }

    fn decode(payload: &mut Payload, version: u32) -> RdpResult<Self> {
        Ok(Self {
            os_type: payload.read_u32::<LittleEndian>()?,
            os_version: payload.read_u32::<LittleEndian>()?,
            protocol_major_version: payload.read_u16::<LittleEndian>()?,
            protocol_minor_version: payload.read_u16::<LittleEndian>()?,
            io_code_1: payload.read_u32::<LittleEndian>()?,
            io_code_2: payload.read_u32::<LittleEndian>()?,
            extended_pdu: payload.read_u32::<LittleEndian>()?,
            extra_flags_1: payload.read_u32::<LittleEndian>()?,
            extra_flags_2: payload.read_u32::<LittleEndian>()?,
            special_type_device_cap: if version == GENERAL_CAPABILITY_VERSION_02 {
                payload.read_u32::<LittleEndian>()?
            } else {
                0
            },
        })
    }
}

type ClientCoreCapabilityResponse = ServerCoreCapabilityRequest;

#[derive(Debug)]
pub struct ClientDeviceListAnnounceRequest {
    device_count: u32,
    device_list: Vec<DeviceAnnounceHeader>,
}

pub type ClientDeviceListAnnounce = ClientDeviceListAnnounceRequest;

impl ClientDeviceListAnnounceRequest {
    // We only need to announce the smartcard in this Client Device List Announce Request.
    // Drives (directories) can be announced at any time with a Client Drive Device List Announce.
    fn new_smartcard(device_id: u32) -> Self {
        Self {
            device_count: 1,
            device_list: vec![DeviceAnnounceHeader {
                device_type: DeviceType::RDPDR_DTYP_SMARTCARD,
                device_id,
                // This name is a constant defined by the spec.
                preferred_dos_name: "SCARD".to_string(),
                device_data_length: 0,
                device_data: vec![],
            }],
        }
    }

    pub fn new_drive(device_id: u32, drive_name: String) -> Self {
        // According to the spec:
        //
        // If the client supports DRIVE_CAPABILITY_VERSION_02 in the Drive Capability Set,
        // then the full name MUST also be specified in the DeviceData field, as a null-terminated
        // Unicode string. If the DeviceDataLength field is nonzero, the content of the
        // PreferredDosName field is ignored.
        //
        // In the RDP spec, Unicode typically means null-terminated UTF-16LE, however empirically it
        // appears that this field expects null-terminated UTF-8.
        let device_data = util::to_utf8(&drive_name);

        Self {
            device_count: 1,
            device_list: vec![DeviceAnnounceHeader {
                device_type: DeviceType::RDPDR_DTYP_FILESYSTEM,
                device_id,
                preferred_dos_name: drive_name,
                device_data_length: device_data.len() as u32,
                device_data,
            }],
        }
    }

    fn new_empty() -> Self {
        Self {
            device_count: 0,
            device_list: vec![],
        }
    }

    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.write_u32::<LittleEndian>(self.device_count)?;
        for dev in self.device_list.iter() {
            w.extend_from_slice(&dev.encode()?);
        }
        Ok(w)
    }
}

/// 2.2.1.3 Device Announce Header (DEVICE_ANNOUNCE)
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/32e34332-774b-4ead-8c9d-5d64720d6bf9
#[derive(Debug)]
struct DeviceAnnounceHeader {
    device_type: DeviceType,
    device_id: u32,
    preferred_dos_name: String,
    device_data_length: u32,
    device_data: Vec<u8>,
}

impl DeviceAnnounceHeader {
    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.write_u32::<LittleEndian>(self.device_type.to_u32().unwrap())?;
        w.write_u32::<LittleEndian>(self.device_id)?;
        let mut name: &str = &self.preferred_dos_name;
        if name.len() > 7 {
            name = &name[..7];
        }
        w.extend_from_slice(&format!("{:\x00<8}", name).into_bytes());
        w.write_u32::<LittleEndian>(self.device_data_length)?;
        w.extend_from_slice(&self.device_data);
        Ok(w)
    }
}

#[derive(Debug)]
struct ServerDeviceAnnounceResponse {
    device_id: u32,
    result_code: u32,
}

impl ServerDeviceAnnounceResponse {
    fn decode(payload: &mut Payload) -> RdpResult<Self> {
        Ok(Self {
            device_id: payload.read_u32::<LittleEndian>()?,
            result_code: payload.read_u32::<LittleEndian>()?,
        })
    }
}

/// 2.2.1.4 Device I/O Request (DR_DEVICE_IOREQUEST)
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/a087ffa8-d0d5-4874-ac7b-0494f63e2d5d
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DeviceIoRequest {
    pub device_id: u32,
    file_id: u32,
    pub completion_id: u32,
    major_function: MajorFunction,
    minor_function: MinorFunction,
}

impl DeviceIoRequest {
    fn decode(payload: &mut Payload) -> RdpResult<Self> {
        let device_id = payload.read_u32::<LittleEndian>()?;
        let file_id = payload.read_u32::<LittleEndian>()?;
        let completion_id = payload.read_u32::<LittleEndian>()?;
        let major_function = payload.read_u32::<LittleEndian>()?;
        let major_function = MajorFunction::from_u32(major_function).ok_or_else(|| {
            invalid_data_error(&format!(
                "invalid major function value {:#010x}",
                major_function
            ))
        })?;
        let minor_function = payload.read_u32::<LittleEndian>()?;
        // From the spec (2.2.1.4 Device I/O Request (DR_DEVICE_IOREQUEST)):
        // "This field [MinorFunction] is valid only when the MajorFunction field
        // is set to IRP_MJ_DIRECTORY_CONTROL. If the MajorFunction field is set
        // to another value, the MinorFunction field value SHOULD be 0x00000000.""
        //
        // SHOULD means implementations are not guaranteed to give us 0x00000000,
        // so handle that possibility here.
        let minor_function = if major_function == MajorFunction::IRP_MJ_DIRECTORY_CONTROL {
            minor_function
        } else {
            0x00000000
        };
        let minor_function = MinorFunction::from_u32(minor_function).ok_or_else(|| {
            invalid_data_error(&format!(
                "invalid minor function value {:#010x}",
                minor_function
            ))
        })?;

        Ok(Self {
            device_id,
            file_id,
            completion_id,
            major_function,
            minor_function,
        })
    }
}

/// 2.2.1.4.5 Device Control Request (DR_CONTROL_REQ)
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/30662c80-ec6e-4ed1-9004-2e6e367bb59f
#[derive(Debug)]
#[allow(dead_code)]
struct DeviceControlRequest {
    header: DeviceIoRequest,
    output_buffer_length: u32,
    input_buffer_length: u32,
    io_control_code: u32,
    padding: [u8; 20],
}

impl DeviceControlRequest {
    fn decode(header: DeviceIoRequest, payload: &mut Payload) -> RdpResult<Self> {
        let output_buffer_length = payload.read_u32::<LittleEndian>()?;
        let input_buffer_length = payload.read_u32::<LittleEndian>()?;
        let io_control_code = payload.read_u32::<LittleEndian>()?;
        let mut padding: [u8; 20] = [0; 20];
        payload.read_exact(&mut padding)?;
        Ok(Self {
            header,
            output_buffer_length,
            input_buffer_length,
            io_control_code,
            padding,
        })
    }
}

/// 2.2.1.5 Device I/O Response (DR_DEVICE_IOCOMPLETION)
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/1c412a84-0776-4984-b35c-3f0445fcae65
#[derive(Debug)]
struct DeviceIoResponse {
    device_id: u32,
    completion_id: u32,
    io_status: u32,
}

impl DeviceIoResponse {
    fn new(req: &DeviceIoRequest, io_status: u32) -> Self {
        Self {
            device_id: req.device_id,
            completion_id: req.completion_id,
            io_status,
        }
    }

    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.write_u32::<LittleEndian>(self.device_id)?;
        w.write_u32::<LittleEndian>(self.completion_id)?;
        w.write_u32::<LittleEndian>(self.io_status)?;
        Ok(w)
    }
}

#[derive(Debug)]
struct DeviceControlResponse {
    header: DeviceIoResponse,
    output_buffer_length: u32,
    output_buffer: Vec<u8>,
}

impl DeviceControlResponse {
    fn new(req: &DeviceControlRequest, io_status: u32, output: Vec<u8>) -> Self {
        Self {
            header: DeviceIoResponse::new(&req.header, io_status),
            output_buffer_length: output.length() as u32,
            output_buffer: output,
        }
    }

    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.extend_from_slice(&self.header.encode()?);
        w.write_u32::<LittleEndian>(self.output_buffer_length)?;
        w.extend_from_slice(&self.output_buffer);
        Ok(w)
    }
}

/// 2.2.3.3.1 Server Create Drive Request (DR_DRIVE_CREATE_REQ)
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/95b16fd0-d530-407c-a310-adedc85e9897
pub type ServerCreateDriveRequest = DeviceCreateRequest;

/// 2.2.1.4.1 Device Create Request (DR_CREATE_REQ)
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/5f71f6d2-d9ff-40c2-bdb5-a739447d3c3e
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DeviceCreateRequest {
    /// The MajorFunction field in this header MUST be set to IRP_MJ_CREATE.
    pub device_io_request: DeviceIoRequest,
    desired_access: flags::DesiredAccess,
    allocation_size: u64,
    file_attributes: flags::FileAttributes,
    shared_access: flags::SharedAccess,
    create_disposition: flags::CreateDisposition,
    create_options: flags::CreateOptions,
    path_length: u32,
    pub path: String,
}

#[allow(dead_code)]
impl DeviceCreateRequest {
    fn decode(device_io_request: DeviceIoRequest, payload: &mut Payload) -> RdpResult<Self> {
        let invalid_flags = || invalid_data_error("invalid flags in Device Create Request");

        let desired_access = flags::DesiredAccess::from_bits(payload.read_u32::<LittleEndian>()?)
            .ok_or_else(invalid_flags)?;
        let allocation_size = payload.read_u64::<LittleEndian>()?;
        let file_attributes = flags::FileAttributes::from_bits(payload.read_u32::<LittleEndian>()?)
            .ok_or_else(invalid_flags)?;
        let shared_access = flags::SharedAccess::from_bits(payload.read_u32::<LittleEndian>()?)
            .ok_or_else(invalid_flags)?;
        let create_disposition =
            flags::CreateDisposition::from_bits(payload.read_u32::<LittleEndian>()?)
                .ok_or_else(invalid_flags)?;
        let create_options = flags::CreateOptions::from_bits(payload.read_u32::<LittleEndian>()?)
            .ok_or_else(invalid_flags)?;
        let path_length = payload.read_u32::<LittleEndian>()?;

        // usize is 32 bits on a 32 bit target and 64 on a 64, so we can safely say try_into().unwrap()
        // for a u32 will never panic on the machines that run teleport.
        let mut path = vec![0u8; path_length.try_into().unwrap()];
        payload.read_exact(&mut path)?;
        let path = util::from_unicode(path)?;

        Ok(Self {
            device_io_request,
            desired_access,
            allocation_size,
            file_attributes,
            shared_access,
            create_disposition,
            create_options,
            path_length,
            path,
        })
    }
}

/// 2.2.1.5.1 Device Create Response (DR_CREATE_RSP)
/// A message with this header describes a response to a Device Create Request (section 2.2.1.4.1).
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/99e5fca5-b37a-41e4-bc69-8d7da7860f76
#[derive(Debug)]
#[allow(dead_code)]
struct DeviceCreateResponse {
    device_io_reply: DeviceIoResponse,
    file_id: u32,
    /// The values of the CreateDisposition field in the Device Create Request (section 2.2.1.4.1) that determine the value
    /// of the Information field are associated as follows:
    /// +---------------------+--------------------+
    /// | CreateDisposition   |   Information      |
    /// +---------------------+--------------------+
    /// | FILE_SUPERSEDE      |   FILE_SUPERSEDED  |
    /// | FILE_OPEN           |                    |
    /// | FILE_CREATE         |                    |
    /// | FILE_OVERWRITE      |                    |
    /// +---------------------+--------------------+
    /// | FILE_OPEN_IF        |   FILE_OPENED      |
    /// +---------------------+--------------------+
    /// | FILE_OVERWRITE_IF   |   FILE_OVERWRITTEN |
    /// +---------------------+--------------------+
    information: flags::Information,
}

impl DeviceCreateResponse {
    fn new(device_create_request: &DeviceCreateRequest, io_status: NTSTATUS, file_id: u32) -> Self {
        let device_io_request = &device_create_request.device_io_request;

        let information: flags::Information;
        if io_status != NTSTATUS::STATUS_SUCCESS
            || device_create_request.create_disposition.intersects(
                flags::CreateDisposition::FILE_SUPERSEDE
                    | flags::CreateDisposition::FILE_OPEN
                    | flags::CreateDisposition::FILE_CREATE
                    | flags::CreateDisposition::FILE_OVERWRITE,
            )
        {
            // if io_status != NTSTATUS::STATUS_SUCCESS because that's what FreeRDP sets information to in the case of failure, see
            // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_main.c#L191
            information = flags::Information::FILE_SUPERSEDED;
        } else if device_create_request.create_disposition == flags::CreateDisposition::FILE_OPEN_IF
        {
            information = flags::Information::FILE_OPENED;
        } else if device_create_request.create_disposition
            == flags::CreateDisposition::FILE_OVERWRITE_IF
        {
            information = flags::Information::FILE_OVERWRITTEN;
        } else {
            panic!("program error, CreateDispositionFlags check should be exhaustive");
        }

        Self {
            device_io_reply: DeviceIoResponse::new(
                device_io_request,
                NTSTATUS::to_u32(&io_status).unwrap(),
            ),
            file_id,
            information,
        }
    }

    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.extend_from_slice(&self.device_io_reply.encode()?);
        w.write_u32::<LittleEndian>(self.file_id)?;
        w.write_u8(self.information.bits())?;
        Ok(w)
    }
}

/// 2.2.3.3.8 Server Drive Query Information Request (DR_DRIVE_QUERY_INFORMATION_REQ)
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/e43dcd68-2980-40a9-9238-344b6cf94946
#[derive(Debug)]
#[allow(dead_code)]
struct ServerDriveQueryInformationRequest {
    /// A DR_DEVICE_IOREQUEST (section 2.2.1.4) header. The MajorFunction field in the DR_DEVICE_IOREQUEST header MUST be set to IRP_MJ_QUERY_INFORMATION.
    device_io_request: DeviceIoRequest,
    /// A 32-bit unsigned integer.
    /// This field MUST contain one of the following values:
    /// FileBasicInformation
    /// This information class is used to query a file for the times of creation, last access, last write, and change, in addition to file attribute information. The Reserved field of the FileBasicInformation structure ([MS-FSCC] section 2.4.7) MUST NOT be present.
    ///
    /// FileStandardInformation
    /// This information class is used to query for file information such as allocation size, end-of-file position, and number of links. The Reserved field of the FileStandardInformation structure ([MS-FSCC] section 2.4.41) MUST NOT be present.
    ///
    /// FileAttributeTagInformation
    /// This information class is used to query for file attribute and reparse tag information.
    fs_information_class_lvl: FsInformationClassLevel,
    // Length, Padding, and QueryBuffer appear to be vestigial fields and can safely be ignored. Their description
    // is provided below for documentation purposes.
    //
    // Length (4 bytes): A 32-bit unsigned integer that specifies the number of bytes in the QueryBuffer field.
    //
    // Padding (24 bytes): An array of 24 bytes. This field is unused and MUST be ignored.
    //
    // QueryBuffer (variable): A variable-length array of bytes. The size of the array is specified by the Length field.
    // The content of this field is based on the value of the FsInformationClass field, which determines the different
    // structures that MUST be contained in the QueryBuffer field. For a complete list of these structures, see [MS-FSCC]
    // section 2.4. The "File information class" table defines all the possible values for the FsInformationClass field.
}

#[allow(dead_code)]
impl ServerDriveQueryInformationRequest {
    fn decode(device_io_request: DeviceIoRequest, payload: &mut Payload) -> RdpResult<Self> {
        if let Some(fs_information_class_lvl) =
            FsInformationClassLevel::from_u32(payload.read_u32::<LittleEndian>()?)
        {
            Ok(Self {
                device_io_request,
                fs_information_class_lvl,
            })
        } else {
            Err(invalid_data_error(
                "received invalid FsInformationClass in ServerDriveQueryInformationRequest",
            ))
        }
    }
}

/// 2.4 File Information Classes [MS-FSCC]
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4718fc40-e539-4014-8e33-b675af74e3e1
#[derive(Debug)]
#[allow(dead_code, clippy::enum_variant_names)]
enum FsInformationClass {
    FileBasicInformation(FileBasicInformation),
    FileStandardInformation(FileStandardInformation),
    FileBothDirectoryInformation(FileBothDirectoryInformation),
    FileAttributeTagInformation(FileAttributeTagInformation),
    FileFullDirectoryInformation(FileFullDirectoryInformation),
}

#[allow(dead_code)]
impl FsInformationClass {
    fn encode(&self) -> RdpResult<Vec<u8>> {
        match self {
            Self::FileBasicInformation(fs_info_class) => fs_info_class.encode(),
            Self::FileStandardInformation(fs_info_class) => fs_info_class.encode(),
            Self::FileBothDirectoryInformation(fs_info_class) => fs_info_class.encode(),
            Self::FileAttributeTagInformation(fs_info_class) => fs_info_class.encode(),
            Self::FileFullDirectoryInformation(fs_info_class) => fs_info_class.encode(),
        }
    }
}

/// 2.4.7 FileBasicInformation [MS-FSCC]
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/16023025-8a78-492f-8b96-c873b042ac50
#[derive(Debug)]
struct FileBasicInformation {
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    file_attributes: flags::FileAttributes,
    // NOTE: The `reserved` field in the spec MUST not be serialized and sent over RDP, or it will break the server implementation.
    // FreeRDP does the same: https://github.com/FreeRDP/FreeRDP/blob/1adb263813ca2e76a893ef729a04db8f94b5d757/channels/drive/client/drive_file.c#L508
    //reserved: u32,
}

#[allow(dead_code)]
/// 4 i64's and 1 u32's = (4 * 8) + 4
const FILE_BASIC_INFORMATION_SIZE: u32 = (4 * 8) + 4;

impl FileBasicInformation {
    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.write_i64::<LittleEndian>(self.creation_time)?;
        w.write_i64::<LittleEndian>(self.last_access_time)?;
        w.write_i64::<LittleEndian>(self.last_write_time)?;
        w.write_i64::<LittleEndian>(self.change_time)?;
        w.write_u32::<LittleEndian>(self.file_attributes.bits())?;
        Ok(w)
    }
}

/// 2.4.41 FileStandardInformation [MS-FSCC]
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/5afa7f66-619c-48f3-955f-68c4ece704ae
#[derive(Debug)]
struct FileStandardInformation {
    /// A 64-bit signed integer that contains the file allocation size, in bytes. The value of this field MUST be an
    /// integer multiple of the cluster size.
    /// Cluster size is the size of the logical minimal unit of disk space used by the operating system. FreeRDP
    /// doesn't give the actual size here, but rather just gives the file size itself, which we will mimic.
    /// (ttps://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L518-L519).
    ///
    /// When FileStandardInformation is requested for a directory, its not entirely clear what "file size" means.
    /// FreeRDP derives this value from the st_size field of a stat struct (https://linux.die.net/man/2/lstat), which says
    /// "The st_size field gives the size of the file (if it is a regular file or a symbolic link) in bytes. The size of
    /// a symbolic link is the length of the pathname it contains, without a terminating null byte." Since it's not
    /// entirely clear what is offered here in the case of a directory, we will just use 0.
    allocation_size: i64,
    /// A 64-bit signed integer that contains the absolute end-of-file position as a byte offset from the start of the
    /// file. EndOfFile specifies the offset to the byte immediately following the last valid byte in the file. Because
    /// this value is zero-based, it actually refers to the first free byte in the file. That is, it is the offset from
    /// the beginning of the file at which new bytes appended to the file will be written. The value of this field MUST
    /// be greater than or equal to 0.
    end_of_file: i64,
    /// A 32-bit unsigned integer that contains the number of non-deleted [hard] links to this file.
    /// NOTE: this information is not available to us in the browser, so we will simply set this field to 0.
    number_of_links: u32,
    /// Set to TRUE to indicate that a file deletion has been requested; set to FALSE
    /// otherwise.
    delete_pending: Boolean,
    /// Set to TRUE to indicate that the file is a directory; set to FALSE otherwise.
    directory: Boolean,
    // NOTE: `reserved` field omitted, see NOTE in FileBasicInformation struct.
    // reserved: u16,
}

impl FileStandardInformation {
    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.write_i64::<LittleEndian>(self.allocation_size)?;
        w.write_i64::<LittleEndian>(self.end_of_file)?;
        w.write_u32::<LittleEndian>(self.number_of_links)?;
        w.write_u8(Boolean::to_u8(&self.delete_pending).unwrap())?;
        w.write_u8(Boolean::to_u8(&self.directory).unwrap())?;
        Ok(w)
    }
}

// 2 i64's + 1 u32 + 2 Boolean (u8) = (2 * 8) + 4 + 2
const FILE_STANDARD_INFORMATION_SIZE: u32 = (2 * 8) + 4 + 2;

/// 2.4.6 FileAttributeTagInformation [MS-FSCC]
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/d295752f-ce89-4b98-8553-266d37c84f0e?redirectedfrom=MSDN
#[derive(Debug)]
struct FileAttributeTagInformation {
    file_attributes: flags::FileAttributes,
    reparse_tag: u32,
}

impl FileAttributeTagInformation {
    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.write_u32::<LittleEndian>(self.file_attributes.bits())?;
        w.write_u32::<LittleEndian>(self.reparse_tag)?;
        Ok(w)
    }
}

// 2 u32's
const FILE_ATTRIBUTE_TAG_INFO_SIZE: u32 = 8;

/// 2.1.8 Boolean
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/8ce7b38c-d3cc-415d-ab39-944000ea77ff
#[derive(Debug, ToPrimitive)]
#[repr(u8)]
enum Boolean {
    True = 1,
    False = 0,
}

/// 2.4.8 FileBothDirectoryInformation
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/270df317-9ba5-4ccb-ba00-8d22be139bc5
#[derive(Debug)]
struct FileBothDirectoryInformation {
    next_entry_offset: u32,
    file_index: u32,
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    end_of_file: i64,
    allocation_size: i64,
    file_attributes: flags::FileAttributes,
    file_name_length: u32,
    ea_size: u32,
    short_name_length: i8,
    // reserved: u8: MUST NOT be added,
    // see https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L907
    short_name: [u8; 24], // 24 bytes
    file_name: String,
}

/// Base size of the FileBothDirectoryInformation, not accounting for variably sized file_name.
/// Note that file_name's size should be calculated as if it were a Unicode string.
/// 5 u32's (including FileAttributesFlags) + 6 i64's + 1 i8 + 24 bytes
const FILE_BOTH_DIRECTORY_INFORMATION_BASE_SIZE: u32 = (5 * 4) + (6 * 8) + 1 + 24; // 93

#[allow(dead_code)]
impl FileBothDirectoryInformation {
    fn new(
        creation_time: i64,
        last_access_time: i64,
        last_write_time: i64,
        change_time: i64,
        file_size: i64,
        file_attributes: flags::FileAttributes,
        file_name: String,
    ) -> Self {
        // Default field values taken from
        // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L871
        Self {
            next_entry_offset: 0,
            file_index: 0,
            creation_time,
            last_access_time,
            last_write_time,
            change_time,
            end_of_file: file_size,
            allocation_size: file_size,
            file_attributes,
            file_name_length: util::unicode_size(&file_name),
            ea_size: 0,
            short_name_length: 0,
            short_name: [0; 24],
            file_name,
        }
    }

    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.write_u32::<LittleEndian>(self.next_entry_offset)?;
        w.write_u32::<LittleEndian>(self.file_index)?;
        w.write_i64::<LittleEndian>(self.creation_time)?;
        w.write_i64::<LittleEndian>(self.last_access_time)?;
        w.write_i64::<LittleEndian>(self.last_write_time)?;
        w.write_i64::<LittleEndian>(self.change_time)?;
        w.write_i64::<LittleEndian>(self.end_of_file)?;
        w.write_i64::<LittleEndian>(self.allocation_size)?;
        w.write_u32::<LittleEndian>(self.file_attributes.bits())?;
        w.write_u32::<LittleEndian>(self.file_name_length)?;
        w.write_u32::<LittleEndian>(self.ea_size)?;
        w.write_i8(self.short_name_length)?;
        // reserved u8, MUST NOT be added!
        w.extend_from_slice(&self.short_name);
        // When working with this field, use file_name_length to determine the length of the file name rather
        // than assuming the presence of a trailing null delimiter. Dot directory names are valid for this field.
        w.extend_from_slice(&util::to_unicode(&self.file_name, false));
        Ok(w)
    }

    fn from(fso: FileSystemObject) -> RdpResult<Self> {
        let file_attributes = if fso.file_type == FileType::Directory {
            flags::FileAttributes::FILE_ATTRIBUTE_DIRECTORY
        } else {
            flags::FileAttributes::FILE_ATTRIBUTE_NORMAL
        };
        Ok(FileBothDirectoryInformation::new(
            i64::try_from(fso.last_modified)?,
            i64::try_from(fso.last_modified)?,
            i64::try_from(fso.last_modified)?,
            i64::try_from(fso.last_modified)?,
            i64::try_from(fso.size)?,
            file_attributes,
            fso.name()?,
        ))
    }
}

/// Base size of the FileFullDirectoryInformation, not accounting for variably sized file_name.
/// Note that file_name's size should be calculated as if it were a Unicode string.
/// 4 u32's (including FileAttributesFlags) + 6 i64's
const FILE_FULL_DIRECTORY_INFORMATION_BASE_SIZE: u32 = (5 * 4) + (6 * 8); // 68

/// 2.4.14 FileFullDirectoryInformation
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e8d926d1-3a22-4654-be9c-58317a85540b
#[derive(Debug)]
struct FileFullDirectoryInformation {
    next_entry_offset: u32,
    file_index: u32,
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    end_of_file: i64,
    allocation_size: i64,
    file_attributes: flags::FileAttributes,
    file_name_length: u32,
    ea_size: u32,
    file_name: String,
}

impl FileFullDirectoryInformation {
    fn new(
        creation_time: i64,
        last_access_time: i64,
        last_write_time: i64,
        change_time: i64,
        file_size: i64,
        file_attributes: flags::FileAttributes,
        file_name: String,
    ) -> Self {
        // Default field values taken from
        // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L871
        Self {
            next_entry_offset: 0,
            file_index: 0,
            creation_time,
            last_access_time,
            last_write_time,
            change_time,
            end_of_file: file_size,
            allocation_size: file_size,
            file_attributes,
            file_name_length: util::unicode_size(&file_name),
            ea_size: 0,
            file_name,
        }
    }

    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.write_u32::<LittleEndian>(self.next_entry_offset)?;
        w.write_u32::<LittleEndian>(self.file_index)?;
        w.write_i64::<LittleEndian>(self.creation_time)?;
        w.write_i64::<LittleEndian>(self.last_access_time)?;
        w.write_i64::<LittleEndian>(self.last_write_time)?;
        w.write_i64::<LittleEndian>(self.change_time)?;
        w.write_i64::<LittleEndian>(self.end_of_file)?;
        w.write_i64::<LittleEndian>(self.allocation_size)?;
        w.write_u32::<LittleEndian>(self.file_attributes.bits())?;
        w.write_u32::<LittleEndian>(self.file_name_length)?;
        w.write_u32::<LittleEndian>(self.ea_size)?;
        // When working with this field, use file_name_length to determine the length of the file name rather
        // than assuming the presence of a trailing null delimiter. Dot directory names are valid for this field.
        w.extend_from_slice(&util::to_unicode(&self.file_name, false));
        Ok(w)
    }

    fn from(fso: FileSystemObject) -> RdpResult<Self> {
        let file_attributes = if fso.file_type == FileType::Directory {
            flags::FileAttributes::FILE_ATTRIBUTE_DIRECTORY
        } else {
            flags::FileAttributes::FILE_ATTRIBUTE_NORMAL
        };
        Ok(Self::new(
            i64::try_from(fso.last_modified)?,
            i64::try_from(fso.last_modified)?,
            i64::try_from(fso.last_modified)?,
            i64::try_from(fso.last_modified)?,
            i64::try_from(fso.size)?,
            file_attributes,
            fso.name()?,
        ))
    }
}

/// 2.2.3.4.8 Client Drive Query Information Response (DR_DRIVE_QUERY_INFORMATION_RSP)
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/37ef4fb1-6a95-4200-9fbf-515464f034a4
#[derive(Debug)]
#[allow(dead_code)]

struct ClientDriveQueryInformationResponse {
    device_io_response: DeviceIoResponse,
    length: Option<u32>,
    buffer: Option<FsInformationClass>,
}

#[allow(dead_code)]
impl ClientDriveQueryInformationResponse {
    /// Constructs a ClientDriveQueryInformationResponse from a ServerDriveQueryInformationRequest and an NTSTATUS.
    fn new(
        req: &ServerDriveQueryInformationRequest,
        file: Option<&FileCacheObject>,
        io_status: NTSTATUS,
    ) -> RdpResult<Self> {
        // If io_status == NTSTATUS::STATUS_UNSUCCESSFUL, we can just fill out the
        // device_io_response and don't need to create/encode the rest.
        if io_status == NTSTATUS::STATUS_UNSUCCESSFUL {
            return Ok(Self {
                device_io_response: DeviceIoResponse::new(
                    &req.device_io_request,
                    NTSTATUS::to_u32(&io_status).unwrap(),
                ),
                length: None,
                buffer: None,
            });
        }

        if let Some(file) = file {
            // We support all the FsInformationClasses that FreeRDP does here
            // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L482
            let (length, buffer) = match req.fs_information_class_lvl {
                FsInformationClassLevel::FileBasicInformation => (
                    Some(FILE_BASIC_INFORMATION_SIZE),
                    Some(FsInformationClass::FileBasicInformation(
                        FileBasicInformation {
                            creation_time: to_windows_time(file.fso.last_modified),
                            last_access_time: to_windows_time(file.fso.last_modified),
                            last_write_time: to_windows_time(file.fso.last_modified),
                            change_time: to_windows_time(file.fso.last_modified),
                            file_attributes: if file.fso.file_type == FileType::File {
                                flags::FileAttributes::FILE_ATTRIBUTE_NORMAL
                            } else {
                                flags::FileAttributes::FILE_ATTRIBUTE_DIRECTORY
                            },
                        },
                    )),
                ),
                FsInformationClassLevel::FileStandardInformation => (
                    Some(FILE_STANDARD_INFORMATION_SIZE),
                    Some(FsInformationClass::FileStandardInformation(
                        FileStandardInformation {
                            allocation_size: file.fso.size as i64,
                            end_of_file: file.fso.size as i64,
                            number_of_links: 0,
                            delete_pending: if file.delete_pending {
                                Boolean::True
                            } else {
                                Boolean::False
                            },
                            directory: if file.fso.file_type == FileType::File {
                                Boolean::False
                            } else {
                                Boolean::True
                            },
                        },
                    )),
                ),
                FsInformationClassLevel::FileAttributeTagInformation => (
                    Some(FILE_ATTRIBUTE_TAG_INFO_SIZE),
                    Some(FsInformationClass::FileAttributeTagInformation(
                        FileAttributeTagInformation {
                            file_attributes: if file.fso.file_type == FileType::File {
                                flags::FileAttributes::FILE_ATTRIBUTE_NORMAL
                            } else {
                                flags::FileAttributes::FILE_ATTRIBUTE_DIRECTORY
                            },
                            reparse_tag: 0,
                        },
                    )),
                ),
                _ => {
                    return Err(not_implemented_error(&format!(
                        "received unsupported FsInformationClass: {:?}",
                        req.fs_information_class_lvl
                    )))
                }
            };

            Ok(Self {
                device_io_response: DeviceIoResponse::new(
                    &req.device_io_request,
                    NTSTATUS::to_u32(&io_status).unwrap(),
                ),
                length,
                buffer,
            })
        } else {
            Err(try_error(
                "if io_status != NTSTATUS::STATUS_UNSUCCESSFUL a &FileCacheObject must be provided",
            ))
        }
    }

    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.extend_from_slice(&self.device_io_response.encode()?);
        if let Some(length) = self.length {
            w.write_u32::<LittleEndian>(length)?;
        }
        if let Some(buffer) = &self.buffer {
            w.extend_from_slice(&buffer.encode()?);
        }
        Ok(w)
    }
}

/// 2.2.1.4.2 Device Close Request (DR_CLOSE_REQ)
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/3ec6627f-9e0f-4941-a828-3fc6ed63d9e7
#[derive(Debug)]
#[allow(dead_code)]
struct DeviceCloseRequest {
    device_io_request: DeviceIoRequest,
    // Padding (32 bytes):  An array of 32 bytes. Reserved. This field can be set to any value, and MUST be ignored.
}

#[allow(dead_code)]
impl DeviceCloseRequest {
    fn decode(device_io_request: DeviceIoRequest) -> Self {
        Self { device_io_request }
    }
}

/// 2.2.1.5.2 Device Close Response (DR_CLOSE_RSP)
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/0dae7031-cfd8-4f14-908c-ec06e14997b5
#[derive(Debug)]
#[allow(dead_code)]
struct DeviceCloseResponse {
    /// The CompletionId field of this header MUST match a Device I/O Request (section 2.2.1.4) message that had the MajorFunction field set to IRP_MJ_CLOSE.
    device_io_response: DeviceIoResponse,
    /// This field can be set to any value and MUST be ignored.
    padding: u32,
}
#[allow(dead_code)]
impl DeviceCloseResponse {
    fn new(device_close_request: DeviceCloseRequest, io_status: NTSTATUS) -> Self {
        Self {
            device_io_response: DeviceIoResponse::new(
                &device_close_request.device_io_request,
                NTSTATUS::to_u32(&io_status).unwrap(),
            ),
            padding: 0,
        }
    }

    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.extend_from_slice(&self.device_io_response.encode()?);
        w.write_u32::<LittleEndian>(self.padding)?;
        Ok(w)
    }
}

/// 2.2.3.3.11 Server Drive NotifyChange Directory Request (DR_DRIVE_NOTIFY_CHANGE_DIRECTORY_REQ)
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/ed05e73d-e53e-4261-a1e1-365a70ba6512
#[derive(Debug)]
#[allow(dead_code)]
struct ServerDriveNotifyChangeDirectoryRequest {
    /// The MajorFunction field in the DR_DEVICE_IOREQUEST header MUST be set to IRP_MJ_DIRECTORY_CONTROL,
    /// and the MinorFunction field MUST be set to IRP_MN_NOTIFY_CHANGE_DIRECTORY.
    device_io_request: DeviceIoRequest,
    /// If nonzero, a change anywhere within the tree MUST trigger the notification response; otherwise, only a change in the root directory will do so.
    watch_tree: u8,
    completion_filter: flags::CompletionFilter,
    // Padding (27 bytes):  An array of 27 bytes. This field is unused and MUST be ignored.
}

#[allow(dead_code)]
impl ServerDriveNotifyChangeDirectoryRequest {
    fn decode(device_io_request: DeviceIoRequest, payload: &mut Payload) -> RdpResult<Self> {
        let invalid_flags =
            || invalid_data_error("invalid flags in Server Drive NotifyChange Directory Request");

        let watch_tree = payload.read_u8()?;
        let completion_filter =
            flags::CompletionFilter::from_bits(payload.read_u32::<LittleEndian>()?)
                .ok_or_else(invalid_flags)?;

        Ok(Self {
            device_io_request,
            watch_tree,
            completion_filter,
        })
    }
}

/// 2.2.1.4.3 Device Read Request (DR_READ_REQ)
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/3192516d-36a6-47c5-987a-55c214aa0441
#[derive(Debug)]
#[allow(dead_code)]
struct DeviceReadRequest {
    /// The MajorFunction field in this header MUST be set to IRP_MJ_READ.
    device_io_request: DeviceIoRequest,
    /// This field specifies the maximum number of bytes to be read from the device.
    length: u32,
    /// This field specifies the file offset where the read operation is performed.
    offset: u64,
    // Padding (20 bytes):  An array of 20 bytes. Reserved. This field can be set to any value and MUST be ignored.
}

#[allow(dead_code)]
impl DeviceReadRequest {
    fn decode(device_io_request: DeviceIoRequest, payload: &mut Payload) -> RdpResult<Self> {
        Ok(Self {
            device_io_request,
            length: payload.read_u32::<LittleEndian>()?,
            offset: payload.read_u64::<LittleEndian>()?,
        })
    }
}

/// 2.2.1.5.3 Device Read Response (DR_READ_RSP)
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/d35d3f91-fc5b-492b-80be-47f483ad1dc9
#[derive(Debug)]
#[allow(dead_code)]
struct DeviceReadResponse {
    /// The CompletionId field of this header MUST match a Device I/O Request (section 2.2.1.4) message that had the MajorFunction field set to IRP_MJ_READ.
    device_io_reply: DeviceIoResponse,
    /// Specifies the number of bytes in the ReadData field.
    length: u32,
    /// A variable-length array of bytes that specifies the output data from the read request.
    read_data: Vec<u8>,
}

#[allow(dead_code)]
impl DeviceReadResponse {
    fn new(
        device_read_request: &DeviceReadRequest,
        io_status: NTSTATUS,
        read_data: Vec<u8>,
    ) -> Self {
        let device_io_request = &device_read_request.device_io_request;

        Self {
            device_io_reply: DeviceIoResponse::new(
                device_io_request,
                NTSTATUS::to_u32(&io_status).unwrap(),
            ),
            length: u32::try_from(read_data.len()).unwrap(),
            read_data,
        }
    }

    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.extend_from_slice(&self.device_io_reply.encode()?);
        w.write_u32::<LittleEndian>(self.length)?;
        w.extend_from_slice(&self.read_data);
        Ok(w)
    }
}

/// 2.2.3.3.10 Server Drive Query Directory Request (DR_DRIVE_QUERY_DIRECTORY_REQ)
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/458019d2-5d5a-4fd4-92ef-8c05f8d7acb1
#[derive(Debug)]
#[allow(dead_code)]
struct ServerDriveQueryDirectoryRequest {
    /// The MajorFunction field in the DR_DEVICE_IOREQUEST header MUST be set to IRP_MJ_DIRECTORY_CONTROL,
    /// and the MinorFunction field MUST be set to IRP_MN_QUERY_DIRECTORY.
    device_io_request: DeviceIoRequest,
    /// Must contain one of FileDirectoryInformation, FileFullDirectoryInformation, FileBothDirectoryInformation, FileNamesInformation
    fs_information_class_lvl: FsInformationClassLevel,
    /// If the value of this field is zero, the request is for the next file in the directory that was specified in a previous
    /// Server Drive Query Directory Request. If such a file does not exist, the client MUST complete this request with STATUS_NO_MORE_FILES
    /// in the IoStatus field of the Client Drive I/O Response packet (section 2.2.3.4).  If the value of this field is non-zero and such a
    /// file does not exist, the client MUST complete this request with STATUS_NO_SUCH_FILE in the IoStatus field of the Client Drive I/O Response.
    initial_query: u8,
    /// Specifies the number of bytes in the Path field, including the null-terminator.
    path_length: u32,
    // Padding (23 bytes): An array of 23 bytes. This field is unused and MUST be ignored.
    /// A variable-length array of Unicode characters (we will store this as a regular rust String) that specifies the directory
    /// on which this operation will be performed. The Path field MUST be null-terminated. If the value of the InitialQuery field
    /// is zero, then the contents of the Path field MUST be ignored, irrespective of the value specified in the PathLength field.
    path: String,
}

impl ServerDriveQueryDirectoryRequest {
    fn decode(device_io_request: DeviceIoRequest, payload: &mut Payload) -> RdpResult<Self> {
        let fs_information_class_lvl =
            FsInformationClassLevel::from_u32(payload.read_u32::<LittleEndian>()?)
                .ok_or_else(|| invalid_data_error("failed to read FsInformationClassLevel"))?;
        if fs_information_class_lvl != FsInformationClassLevel::FileDirectoryInformation
            && fs_information_class_lvl != FsInformationClassLevel::FileFullDirectoryInformation
            && fs_information_class_lvl != FsInformationClassLevel::FileBothDirectoryInformation
            && fs_information_class_lvl != FsInformationClassLevel::FileNamesInformation
        {
            return Err(invalid_data_error(&format!(
                "read invalid FsInformationClassLevel: {:?}, expected one of {:?}",
                fs_information_class_lvl,
                vec![
                    FsInformationClassLevel::FileDirectoryInformation,
                    FsInformationClassLevel::FileFullDirectoryInformation,
                    FsInformationClassLevel::FileBothDirectoryInformation,
                    FsInformationClassLevel::FileNamesInformation
                ]
            )));
        }
        let initial_query = payload.read_u8()?;
        let mut path_length: u32 = 0;
        let mut path = String::from("");
        if initial_query != 0 {
            path_length = payload.read_u32::<LittleEndian>()?;

            // TODO(isaiah): make a payload.skip(n)
            let mut padding: [u8; 23] = [0; 23];
            payload.read_exact(&mut padding)?;

            // TODO(isaiah): make a from_unicode_exact
            let mut path_as_vec = vec![0u8; path_length.try_into().unwrap()];
            payload.read_exact(&mut path_as_vec)?;
            path = util::from_unicode(path_as_vec)?;
        }

        Ok(Self {
            device_io_request,
            fs_information_class_lvl,
            initial_query,
            path_length,
            path,
        })
    }
}

/// 2.2.3.4.10 Client Drive Query Directory Response (DR_DRIVE_QUERY_DIRECTORY_RSP)
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/9c929407-a833-4893-8f20-90c984756140
#[derive(Debug)]
#[allow(dead_code)]
struct ClientDriveQueryDirectoryResponse {
    /// The CompletionId field of the DR_DEVICE_IOCOMPLETION header MUST match a Device I/O Request (section 2.2.1.4) that
    /// has the MajorFunction field set to IRP_MJ_DIRECTORY_CONTROL and the MinorFunction field set to IRP_MN_QUERY_DIRECTORY.
    device_io_reply: DeviceIoResponse,
    /// Specifies the number of bytes in the Buffer field.
    length: u32,
    /// The content of this field is based on the value of the FsInformationClass field in the Server Drive Query Directory Request
    /// message, which determines the different structures that MUST be contained in the Buffer field.
    buffer: Option<FsInformationClass>,
    // Padding (1 byte): This field is unused and MUST be ignored.
}

impl ClientDriveQueryDirectoryResponse {
    fn new(
        device_io_request: &DeviceIoRequest,
        io_status: NTSTATUS,
        buffer: Option<FsInformationClass>,
    ) -> RdpResult<Self> {
        // This match block ensures that the passed parameters are in a configuration that's
        // explicitly supported by the length calculation (below) and the self.encode() method.
        match io_status {
            NTSTATUS::STATUS_SUCCESS if buffer.is_none() => {
                return Err(invalid_data_error(
                    "a ClientDriveQueryDirectoryResponse with NTSTATUS::STATUS_SUCCESS \
                        should have Some(FsInformationClass) buffer, got None",
                ));
            }
            NTSTATUS::STATUS_NOT_SUPPORTED
            | NTSTATUS::STATUS_NO_MORE_FILES
            | NTSTATUS::STATUS_UNSUCCESSFUL => {
                if buffer.is_some() {
                    return Err(invalid_data_error(&format!(
                        "a ClientDriveQueryDirectoryResponse with NTSTATUS = {:?} \
                        should have a None buffer, got {:?}",
                        io_status, buffer,
                    )));
                }
            }
            _ => {
                return Err(invalid_data_error(&format!(
                    "received unsupported io_status for ClientDriveQueryDirectoryResponse: {:?}",
                    io_status
                )))
            }
        }

        let length = match buffer {
            Some(ref fs_information_class) => match fs_information_class {
                FsInformationClass::FileBothDirectoryInformation(fs_info_class) => {
                    FILE_BOTH_DIRECTORY_INFORMATION_BASE_SIZE + fs_info_class.file_name_length
                }
                FsInformationClass::FileFullDirectoryInformation(fs_info_class) => {
                    FILE_FULL_DIRECTORY_INFORMATION_BASE_SIZE + fs_info_class.file_name_length
                }
                _ => {
                    return Err(not_implemented_error(&format!("ClientDriveQueryDirectoryResponse not implemented for fs_information_class {:?}", fs_information_class)));
                }
            },
            None => 0,
        };

        Ok(Self {
            device_io_reply: DeviceIoResponse::new(
                device_io_request,
                NTSTATUS::to_u32(&io_status).unwrap(),
            ),
            length,
            buffer,
        })
    }

    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.extend_from_slice(&self.device_io_reply.encode()?);
        w.write_u32::<LittleEndian>(self.length)?;
        if let Some(buffer) = &self.buffer {
            w.extend_from_slice(&buffer.encode()?);
        }
        if self.device_io_reply.io_status
            == NTSTATUS::to_u32(&NTSTATUS::STATUS_NO_MORE_FILES).unwrap()
        {
            // https://github.com/FreeRDP/FreeRDP/blob/511444a65e7aa2f537c5e531fa68157a50c1bd4d/channels/drive/client/drive_file.c#L937
            w.write_u8(0)?;
        }

        Ok(w)
    }
}

/// TDP handles time in milliseconds since the UNIX epoch (https://en.wikipedia.org/wiki/Unix_time),
/// whereas Windows prefers 64-bit signed integers representing the number of 100-nanosecond intervals
/// that have elapsed since January 1, 1601, Coordinated Universal Time (UTC)
/// (https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/a69cc039-d288-4673-9598-772b6083f8bf).
fn to_windows_time(tdp_time_ms: u64) -> i64 {
    // https://stackoverflow.com/a/5471380/6277051
    let tdp_time_sec = tdp_time_ms / 1000;
    ((tdp_time_sec * 10000000) + 116444736000000000) as i64
}

type SharedDirectoryAcknowledgeSender = Box<dyn Fn(SharedDirectoryAcknowledge) -> RdpResult<()>>;
type SharedDirectoryInfoRequestSender = Box<dyn Fn(SharedDirectoryInfoRequest) -> RdpResult<()>>;
type SharedDirectoryCreateRequestSender =
    Box<dyn Fn(SharedDirectoryCreateRequest) -> RdpResult<()>>;
type SharedDirectoryDeleteRequestSender =
    Box<dyn Fn(SharedDirectoryDeleteRequest) -> RdpResult<()>>;
type SharedDirectoryListRequestSender = Box<dyn Fn(SharedDirectoryListRequest) -> RdpResult<()>>;

type SharedDirectoryInfoResponseHandler =
    Box<dyn FnOnce(&mut Client, SharedDirectoryInfoResponse) -> RdpResult<Vec<Vec<u8>>>>;
type SharedDirectoryCreateResponseHandler =
    Box<dyn FnOnce(&mut Client, SharedDirectoryCreateResponse) -> RdpResult<Vec<Vec<u8>>>>;
type SharedDirectoryDeleteResponseHandler =
    Box<dyn FnOnce(&mut Client, SharedDirectoryDeleteResponse) -> RdpResult<Vec<Vec<u8>>>>;
type SharedDirectoryListResponseHandler =
    Box<dyn FnOnce(&mut Client, SharedDirectoryListResponse) -> RdpResult<Vec<Vec<u8>>>>;
