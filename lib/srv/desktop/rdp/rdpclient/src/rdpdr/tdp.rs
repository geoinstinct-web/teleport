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

use super::{filesystem::FileCacheObject, path::UnixPath};
use crate::{
    util::{self, from_c_string, from_go_array},
    CGOSharedDirectoryAnnounce, CGOSharedDirectoryCreateRequest, CGOSharedDirectoryCreateResponse,
    CGOSharedDirectoryDeleteRequest, CGOSharedDirectoryInfoRequest, CGOSharedDirectoryInfoResponse,
    CGOSharedDirectoryListResponse, CGOSharedDirectoryReadResponse,
};
use ironrdp_pdu::{cast_length, custom_err, PduResult};
use ironrdp_rdpdr::pdu::efs::{self, DeviceCloseRequest, DeviceCreateRequest};
use std::convert::TryInto;
use std::ffi::CString;

/// SharedDirectoryAnnounce is sent by the TDP client to the server
/// to announce a new directory to be shared over TDP.
#[derive(Debug)]
pub struct SharedDirectoryAnnounce {
    pub directory_id: u32,
    pub name: String,
}

impl From<CGOSharedDirectoryAnnounce> for SharedDirectoryAnnounce {
    fn from(cgo: CGOSharedDirectoryAnnounce) -> SharedDirectoryAnnounce {
        // # Safety
        //
        // This function MUST NOT hang on to any of the pointers passed in to it after it returns.
        // In other words, all pointer data that needs to persist after this function returns MUST
        // be copied into Rust-owned memory.
        unsafe {
            SharedDirectoryAnnounce {
                directory_id: cgo.directory_id,
                name: from_c_string(cgo.name),
            }
        }
    }
}

/// SharedDirectoryAcknowledge is sent by the TDP server to the client
/// to acknowledge that a SharedDirectoryAnnounce was received.
#[derive(Debug)]
#[repr(C)]
pub struct SharedDirectoryAcknowledge {
    pub err_code: TdpErrCode,
    pub directory_id: u32,
}

/// SharedDirectoryInfoRequest is sent from the TDP server to the client
/// to request information about a file or directory at a given path.
#[derive(Debug)]
pub struct SharedDirectoryInfoRequest {
    pub completion_id: u32,
    pub directory_id: u32,
    pub path: UnixPath,
}

impl SharedDirectoryInfoRequest {
    /// See [`CGOWithStrings`].
    pub fn into_cgo(self) -> PduResult<CGOWithStrings<CGOSharedDirectoryInfoRequest>> {
        let path = self.path.to_cstring()?;
        Ok(CGOWithStrings {
            cgo: CGOSharedDirectoryInfoRequest {
                completion_id: self.completion_id,
                directory_id: self.directory_id,
                path: path.as_ptr(),
            },
            _strings: vec![path],
        })
    }
}

impl From<&DeviceCreateRequest> for SharedDirectoryInfoRequest {
    fn from(req: &DeviceCreateRequest) -> SharedDirectoryInfoRequest {
        SharedDirectoryInfoRequest {
            completion_id: req.device_io_request.completion_id,
            directory_id: req.device_io_request.device_id,
            path: UnixPath::from(&req.path),
        }
    }
}

/// SharedDirectoryInfoResponse is sent by the TDP client to the server
/// in response to a `Shared Directory Info Request`.
#[derive(Debug)]
pub struct SharedDirectoryInfoResponse {
    pub completion_id: u32,
    pub err_code: TdpErrCode,
    pub fso: FileSystemObject,
}

impl From<CGOSharedDirectoryInfoResponse> for SharedDirectoryInfoResponse {
    fn from(cgo_res: CGOSharedDirectoryInfoResponse) -> SharedDirectoryInfoResponse {
        // # Safety
        //
        // This function MUST NOT hang on to any of the pointers passed in to it after it returns.
        // In other words, all pointer data that needs to persist after this function returns MUST
        // be copied into Rust-owned memory.
        SharedDirectoryInfoResponse {
            completion_id: cgo_res.completion_id,
            err_code: cgo_res.err_code,
            fso: cgo_res.fso.into(),
        }
    }
}

#[derive(Debug, Clone)]
/// FileSystemObject is a TDP structure containing the metadata
/// of a file or directory.
pub struct FileSystemObject {
    pub last_modified: u64,
    pub size: u64,
    pub file_type: FileType,
    pub is_empty: u8,
    pub path: UnixPath,
}

impl FileSystemObject {
    pub fn name(&self) -> PduResult<String> {
        if let Some(name) = self.path.last() {
            Ok(name.to_string())
        } else {
            Err(custom_err!(
                "FileSystemObject::name",
                TdpHandlingError(format!("failed to extract name from path: {:?}", self.path))
            ))
        }
    }

    pub fn into_both_directory(self) -> PduResult<efs::FileBothDirectoryInformation> {
        let file_attributes = if self.file_type == FileType::Directory {
            efs::FileAttributes::FILE_ATTRIBUTE_DIRECTORY
        } else {
            efs::FileAttributes::FILE_ATTRIBUTE_NORMAL
        };

        let last_modified = to_windows_time(self.last_modified);

        Ok(efs::FileBothDirectoryInformation::new(
            last_modified,
            last_modified,
            last_modified,
            last_modified,
            cast_length!(
                "FileSystemObject::into_both_directory",
                "self.size",
                self.size
            )?,
            file_attributes,
            self.name()?,
        ))
    }

    pub fn into_full_directory(self) -> PduResult<efs::FileFullDirectoryInformation> {
        let file_attributes = if self.file_type == FileType::Directory {
            efs::FileAttributes::FILE_ATTRIBUTE_DIRECTORY
        } else {
            efs::FileAttributes::FILE_ATTRIBUTE_NORMAL
        };

        let last_modified = to_windows_time(self.last_modified);

        Ok(efs::FileFullDirectoryInformation::new(
            last_modified,
            last_modified,
            last_modified,
            last_modified,
            cast_length!(
                "FileSystemObject::into_both_directory",
                "self.size",
                self.size
            )?,
            file_attributes,
            self.name()?,
        ))
    }

    pub fn into_names(self) -> PduResult<efs::FileNamesInformation> {
        Ok(efs::FileNamesInformation::new(self.name()?))
    }

    pub fn into_directory(self) -> PduResult<efs::FileDirectoryInformation> {
        let file_attributes = if self.file_type == FileType::Directory {
            efs::FileAttributes::FILE_ATTRIBUTE_DIRECTORY
        } else {
            efs::FileAttributes::FILE_ATTRIBUTE_NORMAL
        };

        let last_modified = to_windows_time(self.last_modified);

        Ok(efs::FileDirectoryInformation::new(
            last_modified,
            last_modified,
            last_modified,
            last_modified,
            cast_length!("FileSystemObject::into_directory", "self.size", self.size)?,
            file_attributes,
            self.name()?,
        ))
    }
}

/// SharedDirectoryWriteRequest is sent by the TDP server to the client
/// to write to a file.
#[derive(Clone)]
pub struct SharedDirectoryWriteRequest {
    pub completion_id: u32,
    pub directory_id: u32,
    pub offset: u64,
    pub path: UnixPath,
    pub write_data: Vec<u8>,
}

impl std::fmt::Debug for SharedDirectoryWriteRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedDirectoryWriteRequest")
            .field("completion_id", &self.completion_id)
            .field("directory_id", &self.directory_id)
            .field("offset", &self.offset)
            .field("path", &self.path)
            .field("write_data", &util::vec_u8_debug(&self.write_data))
            .finish()
    }
}

/// SharedDirectoryReadRequest is sent by the TDP server to the client
/// to request the contents of a file.
#[derive(Debug)]
pub struct SharedDirectoryReadRequest {
    pub completion_id: u32,
    pub directory_id: u32,
    pub path: UnixPath,
    pub offset: u64,
    pub length: u32,
}

/// SharedDirectoryReadResponse is sent by the TDP client to the server
/// with the data as requested by a SharedDirectoryReadRequest.
#[repr(C)]
pub struct SharedDirectoryReadResponse {
    pub completion_id: u32,
    pub err_code: TdpErrCode,
    pub read_data: Vec<u8>,
}

impl std::fmt::Debug for SharedDirectoryReadResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedDirectoryReadResponse")
            .field("completion_id", &self.completion_id)
            .field("err_code", &self.err_code)
            .field("read_data", &util::vec_u8_debug(&self.read_data))
            .finish()
    }
}

impl From<CGOSharedDirectoryReadResponse> for SharedDirectoryReadResponse {
    fn from(cgo_response: CGOSharedDirectoryReadResponse) -> SharedDirectoryReadResponse {
        unsafe {
            SharedDirectoryReadResponse {
                completion_id: cgo_response.completion_id,
                err_code: cgo_response.err_code,
                read_data: from_go_array(cgo_response.read_data, cgo_response.read_data_length),
            }
        }
    }
}

/// SharedDirectoryWriteResponse is sent by the TDP client to the server
/// to acknowledge the completion of a SharedDirectoryWriteRequest.
#[derive(Debug)]
#[repr(C)]
pub struct SharedDirectoryWriteResponse {
    pub completion_id: u32,
    pub err_code: TdpErrCode,
    pub bytes_written: u32,
}

/// SharedDirectoryCreateRequest is sent by the TDP server to
/// the client to request the creation of a new file or directory.
#[derive(Debug)]
pub struct SharedDirectoryCreateRequest {
    pub completion_id: u32,
    pub directory_id: u32,
    pub file_type: FileType,
    pub path: UnixPath,
}

impl SharedDirectoryCreateRequest {
    pub fn from(req: &DeviceCreateRequest, file_type: FileType) -> SharedDirectoryCreateRequest {
        SharedDirectoryCreateRequest {
            completion_id: req.device_io_request.completion_id,
            directory_id: req.device_io_request.device_id,
            file_type,
            path: UnixPath::from(&req.path),
        }
    }

    /// See [`CGOWithStrings`].
    pub fn into_cgo(self) -> PduResult<CGOWithStrings<CGOSharedDirectoryCreateRequest>> {
        let path = self.path.to_cstring()?;
        Ok(CGOWithStrings {
            cgo: CGOSharedDirectoryCreateRequest {
                completion_id: self.completion_id,
                directory_id: self.directory_id,
                file_type: self.file_type,
                path: path.as_ptr(),
            },
            _strings: vec![path],
        })
    }
}

/// SharedDirectoryListResponse is sent by the TDP client to the server
/// in response to a SharedDirectoryInfoRequest.
#[derive(Debug)]
pub struct SharedDirectoryListResponse {
    pub completion_id: u32,
    pub err_code: TdpErrCode,
    pub fso_list: Vec<FileSystemObject>,
}

impl From<CGOSharedDirectoryListResponse> for SharedDirectoryListResponse {
    fn from(cgo: CGOSharedDirectoryListResponse) -> SharedDirectoryListResponse {
        // # Safety
        //
        // This function MUST NOT hang on to any of the pointers passed in to it after it returns.
        // In other words, all pointer data that needs to persist after this function returns MUST
        // be copied into Rust-owned memory.
        unsafe {
            let cgo_fso_list = from_go_array(cgo.fso_list, cgo.fso_list_length);
            let mut fso_list = vec![];
            for cgo_fso in cgo_fso_list.into_iter() {
                fso_list.push(cgo_fso.into());
            }

            SharedDirectoryListResponse {
                completion_id: cgo.completion_id,
                err_code: cgo.err_code,
                fso_list,
            }
        }
    }
}

/// SharedDirectoryMoveRequest is sent from the TDP server to the client
/// to request a file at original_path be moved to new_path.
#[derive(Debug)]
pub struct SharedDirectoryMoveRequest {
    pub completion_id: u32,
    pub directory_id: u32,
    pub original_path: UnixPath,
    pub new_path: UnixPath,
}

/// SharedDirectoryCreateResponse is sent by the TDP client to the server
/// to acknowledge a SharedDirectoryCreateRequest was received and executed.
#[derive(Debug)]
pub struct SharedDirectoryCreateResponse {
    pub completion_id: u32,
    pub err_code: TdpErrCode,
    pub fso: FileSystemObject,
}

impl From<CGOSharedDirectoryCreateResponse> for SharedDirectoryCreateResponse {
    fn from(cgo_res: CGOSharedDirectoryCreateResponse) -> SharedDirectoryCreateResponse {
        // # Safety
        //
        // This function MUST NOT hang on to any of the pointers passed in to it after it returns.
        // In other words, all pointer data that needs to persist after this function returns MUST
        // be copied into Rust-owned memory.
        SharedDirectoryCreateResponse {
            completion_id: cgo_res.completion_id,
            err_code: cgo_res.err_code,
            fso: cgo_res.fso.into(),
        }
    }
}

/// SharedDirectoryDeleteRequest is sent by the TDP server to the client
/// to request the deletion of a file or directory at path.
#[derive(Debug)]
pub struct SharedDirectoryDeleteRequest {
    pub completion_id: u32,
    pub directory_id: u32,
    pub path: UnixPath,
}

impl SharedDirectoryDeleteRequest {
    pub fn from_fco(rdp_req: &DeviceCloseRequest, file: FileCacheObject) -> Self {
        SharedDirectoryDeleteRequest {
            completion_id: rdp_req.device_io_request.completion_id,
            directory_id: rdp_req.device_io_request.device_id,
            path: file.path(),
        }
    }

    /// See [`CGOWithStrings`].
    pub fn into_cgo(self) -> PduResult<CGOWithStrings<CGOSharedDirectoryDeleteRequest>> {
        let path = self.path.to_cstring()?;
        Ok(CGOWithStrings {
            cgo: CGOSharedDirectoryDeleteRequest {
                completion_id: self.completion_id,
                directory_id: self.directory_id,
                path: path.as_ptr(),
            },
            _strings: vec![path],
        })
    }
}

impl From<&DeviceCreateRequest> for SharedDirectoryDeleteRequest {
    fn from(req: &DeviceCreateRequest) -> SharedDirectoryDeleteRequest {
        SharedDirectoryDeleteRequest {
            completion_id: req.device_io_request.completion_id,
            directory_id: req.device_io_request.device_id,
            path: UnixPath::from(&req.path),
        }
    }
}

/// SharedDirectoryDeleteResponse is sent by the TDP client to the server
/// to acknowledge a SharedDirectoryDeleteRequest was received and executed.
#[derive(Debug)]
#[repr(C)]
pub struct SharedDirectoryDeleteResponse {
    pub completion_id: u32,
    pub err_code: TdpErrCode,
}

/// SharedDirectoryMoveResponse is sent by the TDP client to the server
/// to acknowledge a SharedDirectoryMoveRequest was received and expected.
#[derive(Debug)]
#[repr(C)]
pub struct SharedDirectoryMoveResponse {
    pub completion_id: u32,
    pub err_code: TdpErrCode,
}

/// SharedDirectoryListRequest is sent by the TDP server to the client
/// to request the contents of a directory.
#[derive(Debug)]
pub struct SharedDirectoryListRequest {
    pub completion_id: u32,
    pub directory_id: u32,
    pub path: UnixPath,
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TdpErrCode {
    /// nil (no error, operation succeeded)
    Nil = 0,
    /// operation failed
    Failed = 1,
    /// resource does not exist
    DoesNotExist = 2,
    /// resource already exists
    AlreadyExists = 3,
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FileType {
    File = 0,
    Directory = 1,
}

/// Some CGO* structs contain `*const c_char` fields that are backed by [`CString`]\(s\).
/// We commonly need to pass these structs to Go, so we need to ensure that the
/// CStrings live long enough for the structs to be copied into Go-owned memory.
///
/// This struct is a wrapper around a CGO* struct that contains [`CString`]\(s\),
/// which can be used to ensure that the CStrings live long enough.
///
/// # Example
///
/// ```
/// use std::ffi::CString;
///
/// let path = CString::new("/path/to/file").unwrap();
/// let mut cgo_with_strings = CGOWithStrings {
///     cgo: CGOSharedDirectoryCreateRequest {
///         completion_id: 1,
///         directory_id: 2,
///         file_type: FileType::File,
///         path: path,
///     },
///     _strings: vec![path],
/// };
///
/// // Pass the CGO* struct to Go.
/// //
/// // Because `path` is owned by `cgo_with_strings`,
/// // it will live long enough for `pass_to_go`
/// // to copy it into Go-owned memory.
/// pass_to_go(cgo_with_strings.cgo());
/// ```
pub struct CGOWithStrings<T> {
    cgo: T,
    _strings: Vec<CString>,
}

impl<T> CGOWithStrings<T> {
    pub fn cgo(&mut self) -> *mut T {
        &mut self.cgo
    }
}

pub const FALSE: u8 = 0;
#[allow(dead_code)]
pub const TRUE: u8 = 1;

/// TDP handles time in milliseconds since the UNIX epoch (https://en.wikipedia.org/wiki/Unix_time),
/// whereas Windows prefers 64-bit signed integers representing the number of 100-nanosecond intervals
/// that have elapsed since January 1, 1601, Coordinated Universal Time (UTC)
/// (https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/a69cc039-d288-4673-9598-772b6083f8bf).
pub(crate) fn to_windows_time(tdp_time_ms: u64) -> i64 {
    // https://stackoverflow.com/a/5471380/6277051
    // https://docs.microsoft.com/en-us/windows/win32/sysinfo/converting-a-time-t-value-to-a-file-time
    let tdp_time_sec = tdp_time_ms / 1000;
    ((tdp_time_sec * 10000000) + 116444736000000000) as i64
}

/// A generic error type that can contain any arbitrary error message.
///
/// TODO: This is a temporary solution until we can figure out a better error handling system.
#[derive(Debug)]
pub struct TdpHandlingError(pub String);

impl std::fmt::Display for TdpHandlingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#?}", self)
    }
}

impl std::error::Error for TdpHandlingError {}
