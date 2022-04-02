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

pub mod cliprdr;
pub mod errors;
pub mod piv;
pub mod rdpdr;
pub mod scard;
pub mod vchan;

#[macro_use]
extern crate log;
#[macro_use]
extern crate num_derive;

use libc::{fd_set, select, FD_SET};
use rand::Rng;
use rand::SeedableRng;
use rdp::core::event::*;
use rdp::core::gcc::KeyboardLayout;
use rdp::core::global;
use rdp::core::mcs;
use rdp::core::sec;
use rdp::core::tpkt;
use rdp::core::x224;
use rdp::model::error::{Error as RdpError, RdpError as RdpProtocolError, RdpErrorKind, RdpResult};
use rdp::model::link::{Link, Stream};
use std::convert::TryFrom;
use std::ffi::{CStr, CString};
use std::io::Error as IoError;
use std::io::ErrorKind;
use std::io::{Cursor, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::raw::c_char;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};
use std::{mem, ptr, slice, time};

#[no_mangle]
pub extern "C" fn init() {
    env_logger::try_init().unwrap_or_else(|e| println!("failed to initialize Rust logger: {}", e));
}

/// Client has an unusual lifecycle:
/// - connect_rdp creates it on the heap, grabs a raw pointer and returns in to Go
/// - most other exported rdp functions take the raw pointer, convert it to a reference for use
///   without dropping the Client
/// - close_rdp takes the raw pointer and drops it
///
/// All of the exported rdp functions could run concurrently, so the rdp_client is synchronized.
/// tcp_fd is only set in connect_rdp and used as read-only afterwards, so it does not need
/// synchronization.
pub struct Client {
    rdp_client: Arc<Mutex<RdpClient<TcpStream>>>,
    tcp_fd: usize,
    go_ref: usize,
}

impl Client {
    fn into_raw(self: Box<Self>) -> *mut Self {
        Box::into_raw(self)
    }
    unsafe fn from_ptr<'a>(ptr: *const Self) -> Result<&'a Client, CGOError> {
        match ptr.as_ref() {
            Some(c) => Ok(c),
            None => Err(to_cgo_error("invalid Rust client pointer".to_string())),
        }
    }
    unsafe fn from_raw(ptr: *mut Self) -> Box<Self> {
        Box::from_raw(ptr)
    }
}

#[repr(C)]
pub struct ClientOrError {
    client: *mut Client,
    err: CGOError,
}

impl From<Result<Client, ConnectError>> for ClientOrError {
    fn from(r: Result<Client, ConnectError>) -> ClientOrError {
        match r {
            Ok(client) => ClientOrError {
                client: Box::new(client).into_raw(),
                err: CGO_OK,
            },
            Err(e) => ClientOrError {
                client: ptr::null_mut(),
                err: to_cgo_error(format!("{:?}", e)),
            },
        }
    }
}

/// connect_rdp establishes an RDP connection to go_addr with the provided credentials and screen
/// size. If succeeded, the client is internally registered under client_ref. When done with the
/// connection, the caller must call close_rdp.
///
/// # Safety
///
/// The caller mmust ensure that go_addr, go_username, cert_der, key_der point to valid buffers in respect
/// to their corresponding parameters.
#[no_mangle]
pub unsafe extern "C" fn connect_rdp(
    go_ref: usize,
    go_addr: *mut c_char,
    go_username: *mut c_char,
    cert_der_len: u32,
    cert_der: *mut u8,
    key_der_len: u32,
    key_der: *mut u8,
    screen_width: u16,
    screen_height: u16,
    allow_clipboard: bool,
) -> ClientOrError {
    // Convert from C to Rust types.
    let addr = from_go_string(go_addr);
    let username = from_go_string(go_username);
    let cert_der = from_go_array(cert_der_len, cert_der);
    let key_der = from_go_array(key_der_len, key_der);

    connect_rdp_inner(
        go_ref,
        &addr,
        ConnectParams {
            username,
            cert_der,
            key_der,
            screen_width,
            screen_height,
            allow_clipboard,
        },
    )
    .into()
}

#[derive(Debug)]
enum ConnectError {
    Tcp(IoError),
    Rdp(RdpError),
    InvalidAddr(),
}

impl From<IoError> for ConnectError {
    fn from(e: IoError) -> ConnectError {
        ConnectError::Tcp(e)
    }
}

impl From<RdpError> for ConnectError {
    fn from(e: RdpError) -> ConnectError {
        ConnectError::Rdp(e)
    }
}

const RDP_CONNECT_TIMEOUT: time::Duration = time::Duration::from_secs(5);

struct ConnectParams {
    username: String,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    screen_width: u16,
    screen_height: u16,
    allow_clipboard: bool,
}

fn connect_rdp_inner(
    go_ref: usize,
    addr: &str,
    params: ConnectParams,
) -> Result<Client, ConnectError> {
    // Connect and authenticate.
    let addr = addr
        .to_socket_addrs()?
        .next()
        .ok_or(ConnectError::InvalidAddr())?;
    let tcp = TcpStream::connect_timeout(&addr, RDP_CONNECT_TIMEOUT)?;
    let tcp_fd = tcp.as_raw_fd() as usize;
    // Domain name "." means current domain.
    let domain = ".";

    // From rdp-rs/src/core/client.rs
    let tcp = Link::new(Stream::Raw(tcp));
    let protocols = x224::Protocols::ProtocolSSL as u32 | x224::Protocols::ProtocolRDP as u32;
    let x224 = x224::Client::connect(tpkt::Client::new(tcp), protocols, false, None, false, false)?;
    let mut mcs = mcs::Client::new(x224);

    // request the static channels we'll need:
    // rdpdr: derive redirection (smart cards)
    // rdpsnd: sound (for some reason we need to request this)
    // cliprdr: clipboard
    let mut static_channels = vec![rdpdr::CHANNEL_NAME.to_string(), "rdpsnd".to_string()];
    if params.allow_clipboard {
        static_channels.push(cliprdr::CHANNEL_NAME.to_string())
    }
    mcs.connect(
        "rdp-rs".to_string(),
        params.screen_width,
        params.screen_height,
        KeyboardLayout::US,
        &static_channels,
    )?;
    // Generate a random 8-digit PIN for our smartcard.
    let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
    let pin = format!("{:08}", rng.gen_range(0..99999999));
    sec::connect(
        &mut mcs,
        &domain.to_string(),
        &params.username,
        &pin,
        true,
        // InfoPasswordIsScPin means that the user will not be prompted for the smartcard PIN code,
        // which is known only to Teleport and unique for each RDP session.
        Some(sec::InfoFlag::InfoPasswordIsScPin as u32 | sec::InfoFlag::InfoMouseHasWheel as u32),
    )?;
    // Client for the "global" channel - video output and user input.
    let global = global::Client::new(
        mcs.get_user_id(),
        mcs.get_global_channel_id(),
        params.screen_width,
        params.screen_height,
        KeyboardLayout::US,
        "rdp-rs",
    );
    // Client for the "rdpdr" channel - smartcard emulation.
    let rdpdr = rdpdr::Client::new(params.cert_der, params.key_der, pin);

    // Client for the "cliprdr" channel - clipboard sharing.
    let cliprdr = if params.allow_clipboard {
        Some(cliprdr::Client::new(Box::new(move |v| unsafe {
            handle_remote_copy(go_ref, v.as_ptr() as _, v.len() as u32);
        })))
    } else {
        None
    };

    let rdp_client = RdpClient {
        mcs,
        global,
        rdpdr,
        cliprdr,
    };
    Ok(Client {
        rdp_client: Arc::new(Mutex::new(rdp_client)),
        tcp_fd,
        go_ref,
    })
}

/// From rdp-rs/src/core/client.rs
struct RdpClient<S> {
    mcs: mcs::Client<S>,
    global: global::Client,
    rdpdr: rdpdr::Client,

    cliprdr: Option<cliprdr::Client>,
}

impl<S: Read + Write> RdpClient<S> {
    pub fn read<T>(&mut self, callback: T) -> RdpResult<()>
    where
        T: FnMut(RdpEvent),
    {
        let (channel_name, message) = self.mcs.read()?;
        // De-multiplex static channels. Forward messages to the correct channel client based on
        // name.
        match channel_name.as_str() {
            "global" => self.global.read(message, &mut self.mcs, callback),
            rdpdr::CHANNEL_NAME => self.rdpdr.read_and_reply(message, &mut self.mcs),
            cliprdr::CHANNEL_NAME => match self.cliprdr {
                Some(ref mut clip) => clip.read_and_reply(message, &mut self.mcs),
                None => Ok(()),
            },
            _ => Err(RdpError::RdpError(RdpProtocolError::new(
                RdpErrorKind::UnexpectedType,
                &format!("Invalid channel name {:?}", channel_name),
            ))),
        }
    }

    pub fn write(&mut self, event: RdpEvent) -> RdpResult<()> {
        match event {
            RdpEvent::Pointer(pointer) => {
                self.global.write_input_event(pointer.into(), &mut self.mcs)
            }
            RdpEvent::Key(key) => self.global.write_input_event(key.into(), &mut self.mcs),
            _ => Err(RdpError::RdpError(RdpProtocolError::new(
                RdpErrorKind::UnexpectedType,
                "RDPCLIENT: This event can't be sent",
            ))),
        }
    }

    pub fn shutdown(&mut self) -> RdpResult<()> {
        self.mcs.shutdown()
    }
}

/// CGOBitmap is a CGO-compatible version of BitmapEvent that we pass back to Go.
/// BitmapEvent is a video output update from the server.
#[repr(C)]
pub struct CGOBitmap {
    pub dest_left: u16,
    pub dest_top: u16,
    pub dest_right: u16,
    pub dest_bottom: u16,
    /// The memory of this field is managed by the Rust side.
    pub data_ptr: *mut u8,
    pub data_len: usize,
    pub data_cap: usize,
}

impl TryFrom<BitmapEvent> for CGOBitmap {
    type Error = RdpError;

    fn try_from(e: BitmapEvent) -> Result<Self, Self::Error> {
        let mut res = CGOBitmap {
            dest_left: e.dest_left,
            dest_top: e.dest_top,
            dest_right: e.dest_right,
            dest_bottom: e.dest_bottom,
            data_ptr: ptr::null_mut(),
            data_len: 0,
            data_cap: 0,
        };

        // e.decompress consumes e, so we need to call it separately, after populating the fields
        // above.
        let mut data = if e.is_compress {
            e.decompress()?
        } else {
            e.data
        };
        res.data_ptr = data.as_mut_ptr();
        res.data_len = data.len();
        res.data_cap = data.capacity();

        // Prevent the data field from being freed while Go handles it.
        // It will be dropped once CGOBitmap is dropped (see below).
        mem::forget(data);

        Ok(res)
    }
}

impl Drop for CGOBitmap {
    fn drop(&mut self) {
        // Reconstruct into Vec to drop the allocated buffer.
        unsafe {
            Vec::from_raw_parts(self.data_ptr, self.data_len, self.data_cap);
        }
    }
}

#[cfg(unix)]
fn wait_for_fd(fd: usize) -> bool {
    unsafe {
        let mut raw_fds: fd_set = mem::zeroed();

        FD_SET(fd as i32, &mut raw_fds);

        let result = select(
            fd as i32 + 1,
            &mut raw_fds,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        result == 1
    }
}

/// `update_clipboard` is called from Go, and caches data that was copied
/// client-side while notifying the RDP server that new clipboard data is available.
///
/// # Safety
///
/// `client_ptr` must be a valid pointer to a Client.
#[no_mangle]
pub unsafe extern "C" fn update_clipboard(
    client_ptr: *mut Client,
    data: *mut u8,
    len: u32,
) -> CGOError {
    let client = match Client::from_ptr(client_ptr) {
        Ok(client) => client,
        Err(cgo_error) => {
            return cgo_error;
        }
    };
    let data = from_go_array(len, data);
    let mut lock = client.rdp_client.lock().unwrap();

    match lock.cliprdr {
        Some(ref mut clip) => match clip.update_clipboard(data) {
            Ok(messages) => {
                for message in messages {
                    if let Err(e) = lock.mcs.write(&cliprdr::CHANNEL_NAME.to_string(), message) {
                        return to_cgo_error(format!(
                            "failed writing cliprdr format list: {:?}",
                            e
                        ));
                    }
                }
                CGO_OK
            }
            Err(e) => to_cgo_error(format!("failed updating clipboard: {:?}", e)),
        },
        None => CGO_OK,
    }
}

/// `read_rdp_output` reads incoming RDP bitmap frames from client at client_ref and forwards them to
/// handle_bitmap.
///
/// # Safety
///
/// `client_ptr` must be a valid pointer to a Client.
/// `handle_bitmap` *must not* free the memory of CGOBitmap.
#[no_mangle]
pub unsafe extern "C" fn read_rdp_output(client_ptr: *mut Client) -> CGOError {
    let client = match Client::from_ptr(client_ptr) {
        Ok(client) => client,
        Err(cgo_error) => {
            return cgo_error;
        }
    };
    if let Some(err) = read_rdp_output_inner(client) {
        to_cgo_error(err)
    } else {
        CGO_OK
    }
}

fn read_rdp_output_inner(client: &Client) -> Option<String> {
    let tcp_fd = client.tcp_fd;
    let client_ref = client.go_ref;
    // Read incoming events.
    //
    // Wait for some data to be available on the TCP socket FD before consuming it. This prevents
    // us from locking the mutex in Client permanently while no data is available.
    while wait_for_fd(tcp_fd as usize) {
        let mut err = CGO_OK;
        let res = client
            .rdp_client
            .lock()
            .unwrap()
            .read(|rdp_event| match rdp_event {
                RdpEvent::Bitmap(bitmap) => {
                    let mut cbitmap = match CGOBitmap::try_from(bitmap) {
                        Ok(cb) => cb,
                        Err(e) => {
                            error!(
                                "failed to convert RDP bitmap to CGO representation: {:?}",
                                e
                            );
                            return;
                        }
                    };
                    unsafe {
                        err = handle_bitmap(client_ref, &mut cbitmap) as CGOError;
                    };
                }
                // These should never really be sent by the server to us.
                RdpEvent::Pointer(_) => {
                    debug!("got unexpected pointer event from RDP server, ignoring");
                }
                RdpEvent::Key(_) => {
                    debug!("got unexpected keyboard event from RDP server, ignoring");
                }
            });
        match res {
            Err(RdpError::Io(io_err)) if io_err.kind() == ErrorKind::UnexpectedEof => return None,
            Err(e) => {
                return Some(format!("failed forwarding RDP bitmap frame: {:?}", e));
            }
            _ => {}
        }
        if err != CGO_OK {
            let err_str = unsafe { from_cgo_error(err) };
            return Some(format!("failed forwarding RDP bitmap frame: {}", err_str));
        }
    }
    None
}

/// CGOMousePointerEvent is a CGO-compatible version of PointerEvent that we pass back to Go.
/// PointerEvent is a mouse move or click update from the user.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CGOMousePointerEvent {
    pub x: u16,
    pub y: u16,
    pub button: CGOPointerButton,
    pub down: bool,
    pub wheel: CGOPointerWheel,
    pub wheel_delta: i16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub enum CGOPointerButton {
    PointerButtonNone,
    PointerButtonLeft,
    PointerButtonRight,
    PointerButtonMiddle,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub enum CGOPointerWheel {
    PointerWheelNone,
    PointerWheelVertical,
    PointerWheelHorizontal,
}

impl From<CGOMousePointerEvent> for PointerEvent {
    fn from(p: CGOMousePointerEvent) -> PointerEvent {
        PointerEvent {
            x: p.x,
            y: p.y,
            button: match p.button {
                CGOPointerButton::PointerButtonNone => PointerButton::None,
                CGOPointerButton::PointerButtonLeft => PointerButton::Left,
                CGOPointerButton::PointerButtonRight => PointerButton::Right,
                CGOPointerButton::PointerButtonMiddle => PointerButton::Middle,
            },
            down: p.down,
            wheel: match p.wheel {
                CGOPointerWheel::PointerWheelNone => PointerWheel::None,
                CGOPointerWheel::PointerWheelVertical => PointerWheel::Vertical,
                CGOPointerWheel::PointerWheelHorizontal => PointerWheel::Horizontal,
            },
            wheel_delta: p.wheel_delta,
        }
    }
}

/// # Safety
///
/// client_ptr must be a valid pointer to a Client.
#[no_mangle]
pub unsafe extern "C" fn write_rdp_pointer(
    client_ptr: *mut Client,
    pointer: CGOMousePointerEvent,
) -> CGOError {
    let client = match Client::from_ptr(client_ptr) {
        Ok(client) => client,
        Err(cgo_error) => {
            return cgo_error;
        }
    };
    let res = client
        .rdp_client
        .lock()
        .unwrap()
        .write(RdpEvent::Pointer(pointer.into()));

    if let Err(e) = res {
        to_cgo_error(format!("failed writing RDP pointer event: {:?}", e))
    } else {
        CGO_OK
    }
}

/// CGOKeyboardEvent is a CGO-compatible version of KeyboardEvent that we pass back to Go.
/// KeyboardEvent is a keyboard update from the user.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CGOKeyboardEvent {
    // Note: there's only one key code sent at a time. A key combo is sent as a sequence of
    // KeyboardEvent messages, one key at a time in the "down" state. The RDP server takes care of
    // interpreting those.
    pub code: u16,
    pub down: bool,
}

impl From<CGOKeyboardEvent> for KeyboardEvent {
    fn from(k: CGOKeyboardEvent) -> KeyboardEvent {
        KeyboardEvent {
            code: k.code,
            down: k.down,
        }
    }
}

/// # Safety
///
/// client_ptr must be a valid pointer to a Client.
#[no_mangle]
pub unsafe extern "C" fn write_rdp_keyboard(
    client_ptr: *mut Client,
    key: CGOKeyboardEvent,
) -> CGOError {
    let client = match Client::from_ptr(client_ptr) {
        Ok(client) => client,
        Err(cgo_error) => {
            return cgo_error;
        }
    };
    let res = client
        .rdp_client
        .lock()
        .unwrap()
        .write(RdpEvent::Key(key.into()));
    if let Err(e) = res {
        to_cgo_error(format!("failed writing RDP keyboard event: {:?}", e))
    } else {
        CGO_OK
    }
}

/// # Safety
///
/// client_ptr must be a valid pointer to a Client.
#[no_mangle]
pub unsafe extern "C" fn close_rdp(client_ptr: *mut Client) -> CGOError {
    let client = match Client::from_ptr(client_ptr) {
        Ok(client) => client,
        Err(cgo_error) => {
            return cgo_error;
        }
    };
    if let Err(e) = client.rdp_client.lock().unwrap().shutdown() {
        to_cgo_error(format!("failed writing RDP keyboard event: {:?}", e))
    } else {
        CGO_OK
    }
}

/// free_rdp lets the Go side inform us when it's done with Client and it can be dropped.
///
/// # Safety
///
/// client_ptr must be a valid pointer to a Client.
#[no_mangle]
pub unsafe extern "C" fn free_rdp(client_ptr: *mut Client) {
    drop(Client::from_raw(client_ptr))
}

/// # Safety
///
/// The passed pointer must point to a C-style string allocated by Rust.
#[no_mangle]
pub unsafe extern "C" fn free_rust_string(s: *mut c_char) {
    let _ = CString::from_raw(s);
}

/// # Safety
///
/// s must be a C-style null terminated string.
unsafe fn from_go_string(s: *mut c_char) -> String {
    CStr::from_ptr(s).to_string_lossy().into_owned()
}

/// # Safety
///
/// ptr must be a valid buffer of len bytes.
unsafe fn from_go_array(len: u32, ptr: *mut u8) -> Vec<u8> {
    slice::from_raw_parts(ptr, len as usize).to_vec()
}

/// CGOError is an alias for a C string pointer, for C API clarity.
pub type CGOError = *mut c_char;

/// CGO_OK is a CGOError value that means "success".
const CGO_OK: CGOError = ptr::null_mut();

fn to_cgo_error(s: String) -> CGOError {
    CString::new(s).expect("CString::new failed").into_raw()
}

/// from_cgo_error copies CGOError into a String and frees the underlying Go memory.
///
/// # Safety
///
/// The pointer inside the CGOError must point to a valid null terminated Go string.
unsafe fn from_cgo_error(e: CGOError) -> String {
    let s = from_go_string(e);
    free_go_string(e);
    s
}

// These functions are defined on the Go side. Look for functions with '//export funcname'
// comments.
extern "C" {
    fn free_go_string(s: *mut c_char);
    fn handle_bitmap(client_ref: usize, b: *mut CGOBitmap) -> CGOError;
    fn handle_remote_copy(client_ref: usize, data: *mut u8, len: u32) -> CGOError;
}

/// Payload is a generic type used to represent raw incoming RDP messages for parsing.
pub(crate) type Payload = Cursor<Vec<u8>>;
