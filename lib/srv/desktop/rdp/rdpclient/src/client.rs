pub mod global;

use crate::rdpdr::tdp;
use crate::{
    handle_fastpath_pdu, handle_rdp_channel_ids, handle_remote_copy, CGOErrCode, CGOKeyboardEvent,
    CGOMousePointerEvent, CGOPointerButton, CGOPointerWheel, CgoHandle,
};
use bytes::BytesMut;
use ironrdp_cliprdr::{Cliprdr, CliprdrSvcMessages};
use ironrdp_connector::{Config, ConnectorError, Credentials};
use ironrdp_pdu::input::fast_path::{FastPathInput, FastPathInputEvent, KeyboardFlags};
use ironrdp_pdu::input::mouse::PointerFlags;
use ironrdp_pdu::input::{InputEventError, MousePdu};
use ironrdp_pdu::nego::SecurityProtocol;
use ironrdp_pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp_pdu::rdp::RdpError;
use ironrdp_pdu::{custom_err, PduError, PduParsing};
use ironrdp_rdpdr::pdu::efs::ClientDeviceListAnnounce;
use ironrdp_rdpdr::pdu::RdpdrPdu;
use ironrdp_rdpdr::Rdpdr;
use ironrdp_rdpsnd::Rdpsnd;
use ironrdp_session::x224::{Processor as X224Processor, Processor};
use ironrdp_session::SessionErrorKind::Reason;
use ironrdp_session::{reason_err, SessionError, SessionResult};
use ironrdp_svc::{StaticVirtualChannelProcessor, SvcMessage, SvcProcessorMessages};
use ironrdp_tls::TlsStream;
use ironrdp_tokio::{Framed, TokioStream};
use rand::{Rng, SeedableRng};
use std::fmt::{Debug, Display, Formatter};
use std::io::Error as IoError;
use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::io::{split, ReadHalf, WriteHalf};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::mpsc::{channel, error::SendError, Receiver, Sender};
use tokio::task::JoinError;
// Export this for crate level use.
use crate::cliprdr::{ClipboardFn, TeleportCliprdrBackend};
use crate::rdpdr::scard::SCARD_DEVICE_ID;
use crate::rdpdr::TeleportRdpdrBackend;

#[macro_use]
mod macros {
    macro_rules! get_svc_processor {
        ($x224_processor:expr, $svc_processor:ty) => {
            $x224_processor
                .get_svc_processor::<$svc_processor>()
                .ok_or(ClientError::InternalError)?
        };
    }

    macro_rules! get_svc_processor_mut {
        ($x224_processor:expr, $svc_processor:ty) => {
            $x224_processor
                .get_svc_processor_mut::<$svc_processor>()
                .ok_or(ClientError::InternalError)?
        };
    }

    macro_rules! get_backend_mut {
        ($x224_processor:expr, $svc_processor:ty, $backend:ty) => {
            get_svc_processor_mut!($x224_processor, $svc_processor)
                .downcast_backend_mut::<$backend>()
                .ok_or(ClientError::InternalError)?
        };
    }
}

/// The RDP client on the Rust side of things. Each `Client`
/// corresponds with a Go `Client` specified by `cgo_handle`.
pub struct Client {
    cgo_handle: CgoHandle,
    client_handle: ClientHandle,
    read_stream: Option<RdpReadStream>,
    write_stream: Option<RdpWriteStream>,
    function_receiver: Option<FunctionReceiver>,
    x224_processor: Arc<Mutex<X224Processor>>,
}

impl Client {
    /// Connects a new client to the RDP server specified by `params` and starts the session.
    ///
    /// After creating the connection, this function registers the newly made Client with
    /// the [`global::ClientHandles`] map, and creates a task for reading frames from the  RDP
    /// server and sending them back to Go, and receiving function calls via [`ClientHandle`]
    /// and executing them.
    ///
    /// This function hangs until the RDP session ends or a [`ClientFunction::Stop`] is dispatched
    /// (see [`ClientHandle::stop`]).
    pub fn run(cgo_handle: CgoHandle, params: ConnectParams) -> ClientResult<()> {
        global::TOKIO_RT.block_on(async {
            Self::connect(cgo_handle, params)
                .await?
                .register()?
                .run_loops()
                .await
        })
    }

    /// Initializes the RDP connection with the given [`ConnectParams`].
    async fn connect(cgo_handle: CgoHandle, params: ConnectParams) -> ClientResult<Self> {
        let server_addr = params.addr.clone();
        let server_socket_addr = server_addr
            .to_socket_addrs()?
            .next()
            .ok_or(ClientError::UnknownAddress)?;

        let stream = TokioTcpStream::connect(&server_socket_addr).await?;

        // Create a framed stream for use by connect_begin
        let mut framed = ironrdp_tokio::TokioFramed::new(stream);

        // Generate a random 8-digit PIN for our smartcard.
        let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
        let pin = format!("{:08}", rng.gen_range(0i32..=99999999i32));

        let connector_config =
            create_config(params.screen_width, params.screen_height, pin.clone());

        // Create a channel for sending/receiving function calls to/from the Client.
        let (client_handle, function_receiver) = ClientHandle::new(100);

        let mut rdpdr = Rdpdr::new(
            Box::new(TeleportRdpdrBackend::new(
                client_handle.clone(),
                params.cert_der,
                params.key_der,
                pin,
                cgo_handle,
            )),
            "IronRDP".to_string(),
        )
        .with_smartcard(SCARD_DEVICE_ID);

        if params.allow_directory_sharing {
            debug!("creating rdpdr client with directory sharing enabled");
            rdpdr = rdpdr.with_drives(None);
        } else {
            debug!("creating rdpdr client with directory sharing disabled")
        }

        let mut connector = ironrdp_connector::ClientConnector::new(connector_config)
            .with_server_addr(server_socket_addr)
            .with_server_name(server_addr)
            .with_static_channel(Rdpsnd::new()) // required for rdpdr to work
            .with_static_channel(rdpdr);

        if params.allow_clipboard {
            connector = connector.with_static_channel(Cliprdr::new(Box::new(
                TeleportCliprdrBackend::new(client_handle.clone()),
            )));
        }

        let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector).await?;

        // Take the stream back out of the framed object for upgrading
        let initial_stream = framed.into_inner_no_leftover();
        let (upgraded_stream, server_public_key) =
            ironrdp_tls::upgrade(initial_stream, &server_socket_addr.ip().to_string()).await?;

        // Upgrade the stream
        let upgraded =
            ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector, server_public_key);

        // Frame the stream again for use by connect_finalize
        let mut rdp_stream = ironrdp_tokio::TokioFramed::new(upgraded_stream);

        let connection_result =
            ironrdp_tokio::connect_finalize(upgraded, &mut rdp_stream, connector).await?;

        debug!("connection_result: {:?}", connection_result);

        // Register the RDP channels with the browser client.
        unsafe {
            ClientResult::from(handle_rdp_channel_ids(
                cgo_handle,
                connection_result.io_channel_id,
                connection_result.user_channel_id,
            ))
        }?;

        // Take the stream back out of the framed object for splitting.
        let rdp_stream = rdp_stream.into_inner_no_leftover();
        let (read_stream, write_stream) = split(rdp_stream);
        let read_stream = ironrdp_tokio::TokioFramed::new(read_stream);
        let write_stream = ironrdp_tokio::TokioFramed::new(write_stream);

        let x224_processor = X224Processor::new(
            connection_result.static_channels,
            connection_result.user_channel_id,
            connection_result.io_channel_id,
            None,
            None,
        );

        Ok(Self {
            cgo_handle,
            client_handle,
            read_stream: Some(read_stream),
            write_stream: Some(write_stream),
            function_receiver: Some(function_receiver),
            x224_processor: Arc::new(Mutex::new(x224_processor)),
        })
    }

    /// Registers the Client with the [`global::CLIENT_HANDLES`] cache.
    ///
    /// This constitutes storing the [`ClientHandle`] (indexed by `self.cgo_handle`)
    /// in [`global::CLIENT_HANDLES`].
    fn register(self) -> ClientResult<Self> {
        global::CLIENT_HANDLES.insert(self.cgo_handle, self.client_handle.clone());

        Ok(self)
    }

    /// Spawns separate tasks for the input and output loops:
    ///
    /// 1. Read Loop: reads new messages from the RDP server and processes them.
    ///
    /// 2. Write Loop: listens on the Client's function_receiver for function calls
    ///    which it then executes.
    ///
    /// When either loop returns, the other is aborted and the result is returned.
    async fn run_loops(mut self) -> ClientResult<()> {
        let read_stream = self
            .read_stream
            .take()
            .ok_or_else(|| ClientError::InternalError)?;

        let write_stream = self
            .write_stream
            .take()
            .ok_or_else(|| ClientError::InternalError)?;

        let function_receiver = self
            .function_receiver
            .take()
            .ok_or_else(|| ClientError::InternalError)?;

        let mut read_loop_handle = Client::run_read_loop(
            self.cgo_handle,
            read_stream,
            self.x224_processor.clone(),
            self.client_handle.clone(),
        );

        let mut write_loop_handle = Client::run_write_loop(
            self.cgo_handle,
            write_stream,
            function_receiver,
            self.x224_processor.clone(),
        );

        // Wait for either loop to finish. When one does, abort the other and return the result.
        tokio::select! {
            res = &mut read_loop_handle => {
                write_loop_handle.abort();
                res?
            },
            res = &mut write_loop_handle => {
                read_loop_handle.abort();
                res?
            }
        }
    }

    fn run_read_loop(
        cgo_handle: CgoHandle,
        mut read_stream: RdpReadStream,
        x224_processor: Arc<Mutex<X224Processor>>,
        write_requester: ClientHandle,
    ) -> tokio::task::JoinHandle<ClientResult<()>> {
        global::TOKIO_RT.spawn(async move {
            loop {
                let (action, mut frame) = read_stream.read_pdu().await?;
                match action {
                    // Fast-path PDU, send to the browser for processing / rendering.
                    ironrdp_pdu::Action::FastPath => {
                        global::TOKIO_RT
                            .spawn_blocking(move || unsafe {
                                let err_code = handle_fastpath_pdu(
                                    cgo_handle,
                                    frame.as_mut_ptr(),
                                    frame.len() as u32,
                                );
                                ClientResult::from(err_code)
                            })
                            .await??
                    }
                    ironrdp_pdu::Action::X224 => {
                        // X224 PDU, process it and send any immediate response frames to the write loop
                        // for writing to the RDP server.
                        let res = Client::x224_process(x224_processor.clone(), frame).await?;
                        // Send response frames to write loop for writing to RDP server.
                        write_requester.write_raw_pdu_async(res).await?;
                    }
                }
            }
        })
    }

    fn run_write_loop(
        cgo_handle: CgoHandle,
        mut write_stream: RdpWriteStream,
        mut write_receiver: FunctionReceiver,
        x224_processor: Arc<Mutex<X224Processor>>,
    ) -> tokio::task::JoinHandle<ClientResult<()>> {
        global::TOKIO_RT.spawn(async move {
            loop {
                match write_receiver.recv().await {
                    Some(write_request) => match write_request {
                        ClientFunction::WriteRdpKey(args) => {
                            Client::write_rdp_key(&mut write_stream, args).await?;
                        }
                        ClientFunction::WriteRdpPointer(args) => {
                            Client::write_rdp_pointer(&mut write_stream, args).await?;
                        }
                        ClientFunction::WriteRawPdu(args) => {
                            Client::write_raw_pdu(&mut write_stream, args).await?;
                        }
                        ClientFunction::WriteRdpdr(args) => {
                            Client::write_rdpdr(&mut write_stream, x224_processor.clone(), args)
                                .await?;
                        }
                        ClientFunction::HandleTdpSdAnnounce(sda) => {
                            Client::handle_tdp_sd_announce(
                                &mut write_stream,
                                x224_processor.clone(),
                                sda,
                            )
                            .await?;
                        }
                        ClientFunction::HandleTdpSdInfoResponse(res) => {
                            Client::handle_tdp_sd_info_response(x224_processor.clone(), res)
                                .await?;
                        }
                        ClientFunction::HandleTdpSdCreateResponse(res) => {
                            Client::handle_tdp_sd_create_response(x224_processor.clone(), res)
                                .await?;
                        }
                        ClientFunction::HandleTdpSdDeleteResponse(res) => {
                            Client::handle_tdp_sd_delete_response(x224_processor.clone(), res)
                                .await?;
                        }
                        ClientFunction::WriteCliprdr(f) => {
                            Client::write_cliprdr(x224_processor.clone(), &mut write_stream, f)
                                .await?;
                        }
                        ClientFunction::HandleRemoteCopy(data) => {
                            Client::handle_remote_copy(cgo_handle, data).await?;
                        }
                        ClientFunction::UpdateClipboard(data) => {
                            Client::update_clipboard(x224_processor.clone(), data).await?;
                        }
                        ClientFunction::Stop => {
                            // Stop this write loop. The read loop will then be stopped by the caller.
                            return Ok(());
                        }
                    },
                    None => {
                        return Ok(());
                    }
                }
            }
        })
    }

    async fn update_clipboard(
        x224_processor: Arc<Mutex<Processor>>,
        data: String,
    ) -> ClientResult<()> {
        global::TOKIO_RT
            .spawn_blocking(move || {
                let mut x224_processor = Self::x224_lock(&x224_processor)?;
                let cliprdr = get_backend_mut!(x224_processor, Cliprdr, TeleportCliprdrBackend);
                cliprdr.set_clipboard_data(data.clone());
                Ok(())
            })
            .await?
    }

    async fn handle_remote_copy(cgo_handle: CgoHandle, mut data: Vec<u8>) -> ClientResult<()> {
        let code = global::TOKIO_RT
            .spawn_blocking(move || unsafe {
                handle_remote_copy(cgo_handle, data.as_mut_ptr(), data.len() as u32)
            })
            .await?;
        ClientResult::from(code)
    }

    async fn write_cliprdr(
        x224_processor: Arc<Mutex<X224Processor>>,
        write_stream: &mut RdpWriteStream,
        fun: Box<dyn ClipboardFn>,
    ) -> ClientResult<()> {
        let processor = x224_processor.clone();
        let messages: ClientResult<CliprdrSvcMessages> = global::TOKIO_RT
            .spawn_blocking(move || {
                let mut x224_processor = Self::x224_lock(&processor)?;
                let cliprdr = get_svc_processor!(x224_processor, Cliprdr);
                Ok(fun.call(cliprdr)?)
            })
            .await?;
        let encoded = Client::x224_process_svc_messages(x224_processor, messages?).await?;
        write_stream.write_all(&encoded).await?;
        Ok(())
    }

    async fn write_rdp_key(
        write_stream: &mut RdpWriteStream,
        key: CGOKeyboardEvent,
    ) -> ClientResult<()> {
        let mut fastpath_events = Vec::new();

        let mut flags: KeyboardFlags = KeyboardFlags::empty();
        if !key.down {
            flags = KeyboardFlags::RELEASE;
        }
        let event = FastPathInputEvent::KeyboardEvent(flags, key.code as u8);
        fastpath_events.push(event);

        let mut data: Vec<u8> = Vec::new();
        let input_pdu = FastPathInput(fastpath_events);
        input_pdu.to_buffer(&mut data)?;

        write_stream.write_all(&data).await?;
        Ok(())
    }

    async fn write_rdp_pointer(
        write_stream: &mut RdpWriteStream,
        pointer: CGOMousePointerEvent,
    ) -> ClientResult<()> {
        let mut fastpath_events = Vec::new();

        let mut flags = match pointer.button {
            CGOPointerButton::PointerButtonLeft => PointerFlags::LEFT_BUTTON,
            CGOPointerButton::PointerButtonRight => PointerFlags::RIGHT_BUTTON,
            CGOPointerButton::PointerButtonMiddle => PointerFlags::MIDDLE_BUTTON_OR_WHEEL,
            _ => PointerFlags::empty(),
        };

        flags |= match pointer.wheel {
            CGOPointerWheel::PointerWheelVertical => PointerFlags::VERTICAL_WHEEL,
            CGOPointerWheel::PointerWheelHorizontal => PointerFlags::HORIZONTAL_WHEEL,
            _ => PointerFlags::empty(),
        };

        if pointer.button == CGOPointerButton::PointerButtonNone
            && pointer.wheel == CGOPointerWheel::PointerWheelNone
        {
            flags |= PointerFlags::MOVE;
        }

        if pointer.down {
            flags |= PointerFlags::DOWN;
        }

        // MousePdu.to_buffer takes care of the rest of the flags.
        let event = FastPathInputEvent::MouseEvent(MousePdu {
            flags,
            number_of_wheel_rotation_units: pointer.wheel_delta,
            x_position: pointer.x,
            y_position: pointer.y,
        });
        fastpath_events.push(event);

        let mut data: Vec<u8> = Vec::new();
        let input_pdu = FastPathInput(fastpath_events);
        input_pdu.to_buffer(&mut data)?;

        write_stream.write_all(&data).await?;
        Ok(())
    }

    /// Writes a fully encoded PDU to the RDP server.
    async fn write_raw_pdu(write_stream: &mut RdpWriteStream, resp: Vec<u8>) -> ClientResult<()> {
        write_stream.write_all(&resp).await?;
        Ok(())
    }

    async fn write_rdpdr(
        write_stream: &mut RdpWriteStream,
        x224_processor: Arc<Mutex<X224Processor>>,
        pdu: RdpdrPdu,
    ) -> ClientResult<()> {
        debug!("sending rdp: {:?}", pdu);
        // Process the RDPDR PDU.
        let encoded = Client::x224_process_svc_messages(
            x224_processor,
            SvcProcessorMessages::<Rdpdr>::new(vec![SvcMessage::from(pdu)]),
        )
        .await?;

        // Write the RDPDR PDU to the RDP server.
        write_stream.write_all(&encoded).await?;
        Ok(())
    }

    async fn handle_tdp_sd_announce(
        write_stream: &mut RdpWriteStream,
        x224_processor: Arc<Mutex<X224Processor>>,
        sda: tdp::SharedDirectoryAnnounce,
    ) -> ClientResult<()> {
        debug!("received tdp: {:?}", sda);
        let pdu = Self::add_drive(x224_processor.clone(), sda).await?;
        Self::write_rdpdr(
            write_stream,
            x224_processor,
            RdpdrPdu::ClientDeviceListAnnounce(pdu),
        )
        .await?;
        Ok(())
    }

    async fn handle_tdp_sd_info_response(
        x224_processor: Arc<Mutex<X224Processor>>,
        res: tdp::SharedDirectoryInfoResponse,
    ) -> ClientResult<()> {
        global::TOKIO_RT
            .spawn_blocking(move || {
                debug!("received tdp: {:?}", res);
                let mut x224_processor = Self::x224_lock(&x224_processor)?;
                let rdpdr = get_backend_mut!(x224_processor, Rdpdr, TeleportRdpdrBackend);
                rdpdr.handle_tdp_sd_info_response(res)?;
                Ok(())
            })
            .await?
    }

    async fn handle_tdp_sd_create_response(
        x224_processor: Arc<Mutex<X224Processor>>,
        res: tdp::SharedDirectoryCreateResponse,
    ) -> ClientResult<()> {
        global::TOKIO_RT
            .spawn_blocking(move || {
                debug!("received tdp: {:?}", res);
                let mut x224_processor = Self::x224_lock(&x224_processor)?;
                let rdpdr = get_backend_mut!(x224_processor, Rdpdr, TeleportRdpdrBackend);
                rdpdr.handle_tdp_sd_create_response(res)?;
                Ok(())
            })
            .await?
    }

    async fn handle_tdp_sd_delete_response(
        x224_processor: Arc<Mutex<X224Processor>>,
        res: tdp::SharedDirectoryDeleteResponse,
    ) -> ClientResult<()> {
        global::TOKIO_RT
            .spawn_blocking(move || {
                debug!("received tdp: {:?}", res);
                let mut x224_processor = Self::x224_lock(&x224_processor)?;
                let rdpdr = get_backend_mut!(x224_processor, Rdpdr, TeleportRdpdrBackend);
                rdpdr.handle_tdp_sd_delete_response(res)?;
                Ok(())
            })
            .await?
    }

    async fn add_drive(
        x224_processor: Arc<Mutex<X224Processor>>,
        sda: tdp::SharedDirectoryAnnounce,
    ) -> ClientResult<ClientDeviceListAnnounce> {
        global::TOKIO_RT
            .spawn_blocking(move || {
                let mut x224_processor = Self::x224_lock(&x224_processor)?;
                let rdpdr = x224_processor
                    .get_svc_processor_mut::<Rdpdr>()
                    .ok_or(ClientError::InternalError)?;
                let pdu = rdpdr.add_drive(sda.directory_id, sda.name);
                Ok(pdu)
            })
            .await?
    }

    /// Processes an x224 frame on a blocking thread.
    ///
    /// We use a blocking task here so we don't block the tokio runtime
    /// while waiting for the `x224_processor` lock, or while processing the frame.
    /// This function ensures `x224_processor` is locked only for the necessary duration
    /// of the function call.
    async fn x224_process(
        x224_processor: Arc<Mutex<X224Processor>>,
        frame: BytesMut,
    ) -> SessionResult<Vec<u8>> {
        global::TOKIO_RT
            .spawn_blocking(move || Self::x224_lock(&x224_processor)?.process(&frame))
            .await
            .map_err(|err| reason_err!("tokio::spawn_blocking", "JoinError: {:?}", err))?
    }

    /// Processes some [`SvcProcessorMessages`] on a blocking thread.
    ///
    /// We use a blocking task here so we don't block the tokio runtime
    /// while waiting for the `x224_processor` lock, or while processing the frame.
    /// This function ensures `x224_processor` is locked only for the necessary duration
    /// of the function call.
    async fn x224_process_svc_messages<C: StaticVirtualChannelProcessor + 'static>(
        x224_processor: Arc<Mutex<X224Processor>>,
        messages: SvcProcessorMessages<C>,
    ) -> SessionResult<Vec<u8>> {
        global::TOKIO_RT
            .spawn_blocking(move || {
                Self::x224_lock(&x224_processor)?.process_svc_processor_messages(messages)
            })
            .await
            .map_err(|err| reason_err!("tokio::spawn_blocking", "JoinError: {:?}", err))?
    }

    fn x224_lock(
        x224_processor: &Arc<Mutex<X224Processor>>,
    ) -> Result<MutexGuard<X224Processor>, SessionError> {
        x224_processor
            .lock()
            .map_err(|err| reason_err!("x224_processor.lock()", "PoisonError: {:?}", err))
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        global::CLIENT_HANDLES.remove(self.cgo_handle)
    }
}

/// [`ClientFunction`] is an enum representing the different functions that can be called on a client.
/// Each variant corresponds to a different function, and carries the necessary arguments for that function.
///
/// This enum is used by [`ClientHandle`]'s methods to dispatch function calls to the corresponding [`Client`] instance.
#[derive(Debug)]
enum ClientFunction {
    /// Corresponds to [`Client::write_rdp_pointer`]
    WriteRdpPointer(CGOMousePointerEvent),
    /// Corresponds to [`Client::write_rdp_key`]
    WriteRdpKey(CGOKeyboardEvent),
    /// Corresponds to [`Client::write_raw_pdu`]
    WriteRawPdu(Vec<u8>),
    /// Corresponds to [`Client::write_rdpdr`]
    WriteRdpdr(RdpdrPdu),
    /// Corresponds to [`Client::handle_tdp_sd_announce`]
    HandleTdpSdAnnounce(tdp::SharedDirectoryAnnounce),
    /// Corresponds to [`Client::handle_tdp_sd_info_response`]
    HandleTdpSdInfoResponse(tdp::SharedDirectoryInfoResponse),
    /// Corresponds to [`Client::handle_tdp_sd_create_response`]
    HandleTdpSdCreateResponse(tdp::SharedDirectoryCreateResponse),
    /// Corresponds to [`Client::handle_tdp_sd_delete_response`]
    HandleTdpSdDeleteResponse(tdp::SharedDirectoryDeleteResponse),
    /// Corresponds to [`Client::write_cliprdr`]
    WriteCliprdr(Box<dyn ClipboardFn>),
    /// Corresponds to [`Client::update_clipboard`]
    UpdateClipboard(String),
    /// Corresponds to [`Client::handle_remote_copy`]
    HandleRemoteCopy(Vec<u8>),
    /// Aborts the client by stopping both the read and write loops.
    Stop,
}

/// `ClientHandle` is used to dispatch [`ClientFunction`]s calls
/// to a corresponding [`FunctionReceiver`] on a `Client`.
#[derive(Clone, Debug)]
pub struct ClientHandle(Sender<ClientFunction>);

impl ClientHandle {
    /// Creates a new `ClientHandle` and corresponding [`FunctionReceiver`] with a buffer of size `buffer`.
    fn new(buffer: usize) -> (Self, FunctionReceiver) {
        let (sender, receiver) = channel(buffer);
        (Self(sender), FunctionReceiver(receiver))
    }

    pub fn write_rdp_pointer(&self, pointer: CGOMousePointerEvent) -> ClientResult<()> {
        self.blocking_send(ClientFunction::WriteRdpPointer(pointer))
    }

    pub async fn write_rdp_pointer_async(&self, pointer: CGOMousePointerEvent) -> ClientResult<()> {
        self.send(ClientFunction::WriteRdpPointer(pointer)).await
    }

    pub fn write_rdp_key(&self, key: CGOKeyboardEvent) -> ClientResult<()> {
        self.blocking_send(ClientFunction::WriteRdpKey(key))
    }

    pub async fn write_rdp_key_async(&self, key: CGOKeyboardEvent) -> ClientResult<()> {
        self.send(ClientFunction::WriteRdpKey(key)).await
    }

    pub fn write_raw_pdu(&self, resp: Vec<u8>) -> ClientResult<()> {
        self.blocking_send(ClientFunction::WriteRawPdu(resp))
    }

    pub async fn write_raw_pdu_async(&self, resp: Vec<u8>) -> ClientResult<()> {
        self.send(ClientFunction::WriteRawPdu(resp)).await
    }

    pub fn write_rdpdr(&self, pdu: RdpdrPdu) -> ClientResult<()> {
        self.blocking_send(ClientFunction::WriteRdpdr(pdu))
    }

    pub async fn write_rdpdr_async(&self, pdu: RdpdrPdu) -> ClientResult<()> {
        self.send(ClientFunction::WriteRdpdr(pdu)).await
    }

    pub fn handle_tdp_sd_announce(&self, sda: tdp::SharedDirectoryAnnounce) -> ClientResult<()> {
        self.blocking_send(ClientFunction::HandleTdpSdAnnounce(sda))
    }

    pub async fn handle_tdp_sd_announce_async(
        &self,
        sda: tdp::SharedDirectoryAnnounce,
    ) -> ClientResult<()> {
        self.send(ClientFunction::HandleTdpSdAnnounce(sda)).await
    }

    pub fn handle_tdp_sd_info_response(
        &self,
        res: tdp::SharedDirectoryInfoResponse,
    ) -> ClientResult<()> {
        self.blocking_send(ClientFunction::HandleTdpSdInfoResponse(res))
    }

    pub async fn handle_tdp_sd_info_response_async(
        &self,
        res: tdp::SharedDirectoryInfoResponse,
    ) -> ClientResult<()> {
        self.send(ClientFunction::HandleTdpSdInfoResponse(res))
            .await
    }

    pub fn handle_tdp_sd_create_response(
        &self,
        res: tdp::SharedDirectoryCreateResponse,
    ) -> ClientResult<()> {
        self.blocking_send(ClientFunction::HandleTdpSdCreateResponse(res))
    }

    pub async fn handle_tdp_sd_create_response_async(
        &self,
        res: tdp::SharedDirectoryCreateResponse,
    ) -> ClientResult<()> {
        self.send(ClientFunction::HandleTdpSdCreateResponse(res))
            .await
    }

    pub fn handle_tdp_sd_delete_response(
        &self,
        res: tdp::SharedDirectoryDeleteResponse,
    ) -> ClientResult<()> {
        self.blocking_send(ClientFunction::HandleTdpSdDeleteResponse(res))
    }

    pub async fn handle_tdp_sd_delete_response_async(
        &self,
        res: tdp::SharedDirectoryDeleteResponse,
    ) -> ClientResult<()> {
        self.send(ClientFunction::HandleTdpSdDeleteResponse(res))
            .await
    }

    pub fn write_cliprdr(&self, f: Box<dyn ClipboardFn>) -> ClientResult<()> {
        self.blocking_send(ClientFunction::WriteCliprdr(f))
    }

    pub async fn write_cliprdr_async(&self, f: Box<dyn ClipboardFn>) -> ClientResult<()> {
        self.send(ClientFunction::WriteCliprdr(f)).await
    }

    pub fn update_clipboard(&self, data: String) -> ClientResult<()> {
        self.blocking_send(ClientFunction::UpdateClipboard(data))
    }

    pub async fn update_clipboard_async(&self, data: String) -> ClientResult<()> {
        self.send(ClientFunction::UpdateClipboard(data)).await
    }

    pub fn handle_remote_copy(&self, data: Vec<u8>) -> ClientResult<()> {
        self.blocking_send(ClientFunction::HandleRemoteCopy(data))
    }

    pub async fn handle_remote_copy_async(&self, data: Vec<u8>) -> ClientResult<()> {
        self.send(ClientFunction::HandleRemoteCopy(data)).await
    }

    pub fn stop(&self) -> ClientResult<()> {
        self.blocking_send(ClientFunction::Stop)
    }

    pub async fn stop_async(&self) -> ClientResult<()> {
        self.send(ClientFunction::Stop).await
    }

    fn blocking_send(&self, fun: ClientFunction) -> ClientResult<()> {
        self.0
            .blocking_send(fun)
            .map_err(|e| ClientError::SendError(format!("{:?}", e)))
    }

    async fn send(&self, fun: ClientFunction) -> ClientResult<()> {
        self.0
            .send(fun)
            .await
            .map_err(|e| ClientError::SendError(format!("{:?}", e)))
    }
}

/// Each `Client` has a `FunctionReceiver` that it listens to for
/// incoming [`ClientFunction`] calls sent via its corresponding
/// [`ClientHandle`].
pub struct FunctionReceiver(Receiver<ClientFunction>);

impl FunctionReceiver {
    /// Receives a [`ClientFunction`] call from the `FunctionReceiver`.
    async fn recv(&mut self) -> Option<ClientFunction> {
        self.0.recv().await
    }
}

type RdpReadStream = Framed<TokioStream<ReadHalf<TlsStream<TokioTcpStream>>>>;
type RdpWriteStream = Framed<TokioStream<WriteHalf<TlsStream<TokioTcpStream>>>>;

fn create_config(width: u16, height: u16, pin: String) -> Config {
    Config {
        desktop_size: ironrdp_connector::DesktopSize { width, height },
        security_protocol: SecurityProtocol::SSL,
        credentials: Credentials::SmartCard { pin },
        domain: None,
        // Windows 10, Version 1909, same as FreeRDP as of October 5th, 2021.
        // This determines which Smart Card Redirection dialect we use per
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpesc/568e22ee-c9ee-4e87-80c5-54795f667062.
        client_build: 18363,
        client_name: "Teleport".to_string(),
        keyboard_type: ironrdp_pdu::gcc::KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        ime_file_name: "".to_string(),
        graphics: None,
        bitmap: Some(ironrdp_connector::BitmapConfig {
            lossy_compression: true,
            color_depth: 32, // Changing this to 16 gets us uncompressed bitmaps on machines configured like https://github.com/Devolutions/IronRDP/blob/55d11a5000ebd474c2ddc294b8b3935554443112/README.md?plain=1#L17-L36
        }),
        dig_product_id: "".to_string(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_string(),
        platform: MajorPlatformType::UNSPECIFIED,
        no_server_pointer: false,
        autologon: true,
    }
}

#[derive(Debug)]
pub struct ConnectParams {
    pub addr: String,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub screen_width: u16,
    pub screen_height: u16,
    pub allow_clipboard: bool,
    pub allow_directory_sharing: bool,
    pub show_desktop_wallpaper: bool,
}

#[derive(Debug)]
pub enum ClientError {
    Tcp(IoError),
    Rdp(RdpError),
    PduError(PduError),
    SessionError(SessionError),
    ConnectorError(ConnectorError),
    CGOErrCode(CGOErrCode),
    SendError(String),
    JoinError(JoinError),
    InternalError,
    UnknownAddress,
    InputEventError(InputEventError),
}

impl std::error::Error for ClientError {}

impl Display for ClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Tcp(e) => Display::fmt(e, f),
            ClientError::Rdp(e) => Display::fmt(e, f),
            ClientError::SessionError(e) => match &e.kind {
                Reason(reason) => Display::fmt(reason, f),
                _ => Display::fmt(e, f),
            },
            ClientError::ConnectorError(e) => Display::fmt(e, f),
            ClientError::InputEventError(e) => Display::fmt(e, f),
            ClientError::JoinError(e) => Display::fmt(e, f),
            ClientError::CGOErrCode(e) => Debug::fmt(e, f),
            ClientError::SendError(msg) => Display::fmt(&msg.to_string(), f),
            ClientError::InternalError => Display::fmt("Internal error", f),
            ClientError::UnknownAddress => Display::fmt("Unknown address", f),
            ClientError::PduError(e) => Display::fmt(e, f),
        }
    }
}

impl From<IoError> for ClientError {
    fn from(e: IoError) -> ClientError {
        ClientError::Tcp(e)
    }
}

impl From<RdpError> for ClientError {
    fn from(e: RdpError) -> ClientError {
        ClientError::Rdp(e)
    }
}

impl From<ConnectorError> for ClientError {
    fn from(value: ConnectorError) -> Self {
        ClientError::ConnectorError(value)
    }
}

impl From<CGOErrCode> for ClientError {
    fn from(value: CGOErrCode) -> Self {
        ClientError::CGOErrCode(value)
    }
}

impl From<SessionError> for ClientError {
    fn from(value: SessionError) -> Self {
        ClientError::SessionError(value)
    }
}

impl<T> From<SendError<T>> for ClientError {
    fn from(value: SendError<T>) -> Self {
        ClientError::SendError(format!("{:?}", value))
    }
}

impl From<JoinError> for ClientError {
    fn from(e: JoinError) -> Self {
        ClientError::JoinError(e)
    }
}

impl From<PduError> for ClientError {
    fn from(e: PduError) -> Self {
        ClientError::PduError(e)
    }
}

impl From<ClientError> for PduError {
    fn from(e: ClientError) -> Self {
        custom_err!("ClientError", e)
    }
}

type ClientResult<T> = Result<T, ClientError>;

impl From<CGOErrCode> for ClientResult<()> {
    fn from(value: CGOErrCode) -> Self {
        match value {
            CGOErrCode::ErrCodeSuccess => Ok(()),
            _ => Err(ClientError::from(value)),
        }
    }
}

impl From<InputEventError> for ClientError {
    fn from(e: InputEventError) -> Self {
        ClientError::InputEventError(e)
    }
}
