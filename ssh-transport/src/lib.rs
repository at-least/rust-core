//! S-spike (PLAN.md W9): the russh transport crate — terminal-core's
//! former `ssh_spike` module, extracted verbatim at S1 (PLAN.md §3.6).
//! Default builds (`cargo test` in this crate, no features) are the
//! plain-Rust no-FFI shape; the UniFFI namespace `ssh_transport` compiles
//! in behind the `uniffi` feature and reaches the apps through
//! terminal-core's cdylib when that crate's `uniffi` + `ssh-spike`
//! features are on together (the COMMITTED artifacts, regenerated via
//! `CONCH_SSH_FEATURES=ssh-spike` — the apps' S direct cutover, the only
//! transport since 2026-09-09).
//!
//! **Streaming FFI design (adjudicated, W9):** the shell channel streams
//! through a UniFFI CALLBACK INTERFACE (push), not polling/streams. The
//! channel's read half lives in a Rust pump task on this module's own
//! tokio runtime and pushes `SshSpikeEvent`s to the foreign sink; the
//! write half stays in the `SshSpikeSession` object for foreign-side
//! `write`/`resize`/`exec`. Rationale: terminal data is server-push and
//! both apps already consume event-driven callbacks today (Android
//! `SshSession.Callbacks.onData` → `feedAndInvalidate`; iOS SSHSession's
//! output handler); a poll model would need a foreign-side pump thread
//! anyway and adds latency.
//!
//! **Host-key verification (advisor requirement):** `check_server_key`
//! hands the wire `(algorithm, blob)` to the FOREIGN
//! `SshSpikeHostKeyVerifier` callback — the seam where each app's
//! KnownHostsStore/Tofu flow plugs in (Android backs it with the real
//! `KnownHostsStore`; see KnownHostsShadowTest for the store-backed
//! verifier). russh's default is deny, and this module never bypasses it.
//!
//! **Keepalive/reconnect mapping (adjudicated):** keepalive maps to
//! russh `Config.keepalive_interval` (set here); reconnection stays
//! NATIVE (SessionReconnector/ReconnectController own the backoff policy
//! and simply dial a new session — a transport swap does not move it).
//!
//! SFTP rides russh-sftp =3.0.0 (russh 0.63's own dev-dependency version)
//! over a session channel with the `sftp` subsystem.
//!
//! Threading contract: `connect`/`exec`/`sftp_read`/`direct_tcpip_banner`
//! block the calling thread (call from a background thread, exactly like
//! the sshj/Citadel paths today); `write`/`resize`/`close` are
//! fire-and-forget sends.

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

pub mod known_hosts;

use std::sync::{Arc, Mutex};

/// Bumped whenever this namespace's FFI surface changes, so a stale
/// committed binding fails loudly instead of misbehaving (mirrors
/// terminal-core's `UNIFFI_BRIDGE_VERSION`; S2 made this crate
/// cross-repo consumed, so the const must live with the crate).
pub const SSH_TRANSPORT_BRIDGE_VERSION: u32 = 1;

/// The namespace bridge version, exported through the FFI.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn ssh_transport_bridge_version() -> u32 {
    SSH_TRANSPORT_BRIDGE_VERSION
}

use std::time::Duration;

use russh::client::ChannelOpenHandle;
use russh::client::{Handler, Msg};
use russh::{Channel, ChannelMsg, ChannelReadHalf, ChannelWriteHalf};

/// Typed error surface — UniFFI requires a declared error for Result
/// exports (the bindgen rejects `Result<_, String>`: "unknown throw type").
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
#[derive(Debug, thiserror::Error)]
pub enum SshSpikeError {
    #[error("connection failed: {0}")]
    Connect(String),
    /// russh's kex/host-key/cipher negotiation found no overlap with the
    /// server's offer — the platforms map this to their user-facing "no
    /// common algorithm" case (was stringified into `Connect`, which the
    /// UI rendered as a generic transport failure).
    #[error("no common algorithm ({0})")]
    NoCommonAlgorithm(String),
    #[error("host key rejected by verifier")]
    HostKeyRejected,
    #[error("auth failed: {0}")]
    Auth(String),
    #[error("channel failed: {0}")]
    Channel(String),
    #[error("sftp failed: {0}")]
    Sftp(String),
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug, Clone)]
pub enum SshSpikeAuth {
    Password {
        password: String,
    },
    /// OpenSSH/PEM text (the apps already hold keys in this form); parsed
    /// with russh's `decode_secret_key` — the K layer's parse domain.
    PrivateKey {
        pem: String,
        passphrase: Option<String>,
    },
}

/// Push events for a session's interactive shell channel (the streaming
/// contract; see the module header for the callback-vs-poll adjudication).
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug, Clone, PartialEq)]
pub enum SshSpikeEvent {
    Data {
        data: Vec<u8>,
    },
    ExitStatus {
        code: u32,
    },
    /// The server sent CHANNEL_CLOSE — a deliberate channel end (the user's
    /// `exit`, a detached tmux). iOS parity: this is the "clean" close.
    Closed,
    /// The read half ended WITHOUT a CHANNEL_CLOSE — the transport itself
    /// died (link loss, keepalive timeout, process kill). iOS parity: this
    /// is the unclean drop Citadel reports as a stream failure.
    Died,
}

/// Foreign sink for session events. Called from this module's runtime
/// threads — foreign implementations hop to their own dispatchers (the
/// existing `Callbacks`/output-handler contracts do this already).
#[cfg_attr(feature = "uniffi", uniffi::export(callback_interface))]
pub trait SshSpikeEventSink: Send + Sync {
    fn on_event(&self, event: SshSpikeEvent);
}

/// Host-key verification seam — THE place the KnownHostsStore status path
/// plugs in. Receives the SSH wire blob (same encoding the known_hosts
/// codec and the H shadow already speak) PLUS the endpoint being verified:
/// with jump chains every hop presents its own key, so the foreign side can
/// only make the right TOFU decision when told WHICH (host, port) it is
/// looking at — the stream behind a jumped dial has no socket address.
#[cfg_attr(feature = "uniffi", uniffi::export(callback_interface))]
pub trait SshSpikeHostKeyVerifier: Send + Sync {
    fn verify_host_key(
        &self,
        hostname: String,
        port: u16,
        algorithm: String,
        blob: Vec<u8>,
    ) -> bool;
}

/// Inbound remote-forward (-R) connections: the server accepted a TCP
/// connection on the bound port and opened a forwarded-tcpip channel back
/// to us. The foreign side owns the byte pipe through the channel object.
/// Facades MUST catch-and-decide around the callback body — a foreign throw
/// must never cross back into Rust.
#[cfg_attr(feature = "uniffi", uniffi::export(callback_interface))]
pub trait SshSpikeForwardSink: Send + Sync {
    fn on_connection(
        &self,
        bind_host: String,
        bind_port: u32,
        channel: std::sync::Arc<SshSpikeChannel>,
    );
}

/// One forwarded/opened TCP channel: the byte pipe the foreign side pumps.
/// `read` returns the next chunk of server data — an EMPTY vector means the
/// remote half-closed (CHANNEL_EOF) or the channel closed; `write` sends;
/// `eof` half-closes the local side; `disconnect` shuts the whole channel.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SshSpikeChannel {
    read_half: Mutex<ChannelReadHalf>,
    write_half: Mutex<Option<ChannelWriteHalf<Msg>>>,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl SshSpikeChannel {
    /// Blocking read of the next data chunk; empty = EOF. Call from a
    /// background thread. EOF is BOTH the remote half-close (CHANNEL_EOF)
    /// and the channel close — surfacing it is what lets a forwarding
    /// bridge propagate the remote FIN instead of idling forever.
    #[allow(clippy::await_holding_lock)] // the read half is foreign-caller-serialized by contract
    pub fn read(&self) -> Result<Vec<u8>, SshSpikeError> {
        runtime().block_on(async {
            let mut rh = self.read_half.lock().unwrap();
            loop {
                match rh.wait().await {
                    Some(ChannelMsg::Data { data }) => return Ok(data.to_vec()),
                    Some(ChannelMsg::ExtendedData { data, .. }) => return Ok(data.to_vec()),
                    // EOF means the remote side will never send more data:
                    // surfacing it (empty) is what lets a bridge propagate
                    // the remote FIN instead of idling forever
                    Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => return Ok(Vec::new()),
                    _ => {}
                }
            }
        })
    }

    pub fn write(&self, data: Vec<u8>) -> Result<(), SshSpikeError> {
        let guard = self.write_half.lock().unwrap();
        let Some(wh) = guard.as_ref() else {
            return Err(SshSpikeError::Channel("channel closed".to_string()));
        };
        runtime()
            .block_on(wh.data_bytes(data))
            .map_err(|e| SshSpikeError::Channel(e.to_string()))
    }

    /// Half-closes the local side (SSH CHANNEL_EOF): the remote sees EOF
    /// but may keep sending — `read` keeps returning its data until its own
    /// EOF/close. This is the strict-proxy FIN propagation the teardown in
    /// `disconnect` cannot express. Idempotent; errors once disconnected.
    pub fn eof(&self) -> Result<(), SshSpikeError> {
        let guard = self.write_half.lock().unwrap();
        let Some(wh) = guard.as_ref() else {
            return Err(SshSpikeError::Channel("channel closed".to_string()));
        };
        runtime()
            .block_on(wh.eof())
            .map_err(|e| SshSpikeError::Channel(e.to_string()))
    }

    /// Named `disconnect` (not `close`): UniFFI objects already carry an
    /// AutoCloseable close() — the collision broke the generated Kotlin.
    pub fn disconnect(&self) {
        if let Some(wh) = self.write_half.lock().unwrap().take() {
            runtime().spawn(async move {
                let _ = wh.eof().await;
                let _ = wh.close().await;
            });
        }
    }
}

/// A streaming remote-file handle (the TransferQueue contract): chunked
/// reads/writes for large files — the whole-file `read`/`write` helpers on
/// [SshSpikeSftp] are for the small-file paths. `read` returns the next
/// chunk; an EMPTY vector means EOF. `disconnect` (not `close`: UniFFI
/// AutoCloseable collision, the §9 gotcha) closes the handle.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SshSpikeRemoteFile {
    file: Mutex<Option<russh_sftp::client::fs::File>>,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl SshSpikeRemoteFile {
    /// Next chunk of file content; empty = EOF. Blocks the caller.
    #[allow(clippy::await_holding_lock)] // the file handle is foreign-caller-serialized by contract
    pub fn read(&self, max: u32) -> Result<Vec<u8>, SshSpikeError> {
        runtime().block_on(async {
            use tokio::io::AsyncReadExt;
            let mut guard = self.file.lock().unwrap();
            let Some(file) = guard.as_mut() else {
                return Err(SshSpikeError::Sftp("handle closed".to_string()));
            };
            let mut buf = vec![0u8; max as usize];
            let n = file
                .read(&mut buf)
                .await
                .map_err(|e| SshSpikeError::Sftp(e.to_string()))?;
            buf.truncate(n);
            Ok(buf)
        })
    }

    /// Appends `data` at the current position (writes only: handles opened
    /// for writing). Blocks the caller.
    #[allow(clippy::await_holding_lock)] // the file handle is foreign-caller-serialized by contract
    pub fn write(&self, data: Vec<u8>) -> Result<(), SshSpikeError> {
        runtime().block_on(async {
            use tokio::io::AsyncWriteExt;
            let mut guard = self.file.lock().unwrap();
            let Some(file) = guard.as_mut() else {
                return Err(SshSpikeError::Sftp("handle closed".to_string()));
            };
            file.write_all(&data)
                .await
                .map_err(|e| SshSpikeError::Sftp(e.to_string()))
        })
    }

    pub fn disconnect(&self) {
        if let Some(file) = self.file.lock().unwrap().take() {
            runtime().spawn(async move {
                let _ = file.close().await;
            });
        }
    }
}

/// Routes inbound forwarded-tcpip channels off the handler thread (advisor
/// rule: never block a Handler callback — forward to a channel and let a
/// runtime task call the foreign sink).
#[derive(Clone)]
struct ForwardRouter {
    tx: tokio::sync::mpsc::UnboundedSender<(String, u32, std::sync::Arc<SshSpikeChannel>)>,
}

impl ForwardRouter {
    fn dispatch_loop(
        sink: std::sync::Arc<dyn SshSpikeForwardSink>,
        mut rx: tokio::sync::mpsc::UnboundedReceiver<(
            String,
            u32,
            std::sync::Arc<SshSpikeChannel>,
        )>,
    ) {
        runtime().spawn(async move {
            while let Some((bind_host, bind_port, channel)) = rx.recv().await {
                sink.on_connection(bind_host, bind_port, channel);
            }
        });
    }
}

/// Connection handler: routes host keys to the foreign verifier.
struct ProbeHandler {
    verifier: std::sync::Arc<dyn SshSpikeHostKeyVerifier>,
    accepted_host_keys: Mutex<Vec<String>>,
    endpoint: (String, u16),
    forwards: Option<ForwardRouter>,
}

impl Handler for ProbeHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let (algorithm, blob) = match key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => {
                let blob = key.to_bytes().map_err(|_e| russh::Error::UnknownKey)?;
                (key.algorithm().as_str().to_string(), blob)
            }
            russh::keys::PublicKeyOrCertificate::Certificate(c) => {
                // a certificate's wire form replaces the plain key check
                let blob = c.to_bytes().map_err(|_e| russh::Error::UnknownKey)?;
                (c.public_key().algorithm().as_str().to_string(), blob)
            }
        };
        let ok = self.verifier.verify_host_key(
            self.endpoint.0.clone(),
            self.endpoint.1,
            algorithm.clone(),
            blob.clone(),
        );
        if ok {
            self.accepted_host_keys.lock().unwrap().push(format!(
                "{}:{}",
                algorithm,
                crate::known_hosts::blob_fingerprint(&blob)
            ));
        }
        Ok(ok)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        if let Some(router) = self.forwards.clone() {
            let (rh, wh) = channel.split();
            let obj = std::sync::Arc::new(SshSpikeChannel {
                read_half: Mutex::new(rh),
                write_half: Mutex::new(Some(wh)),
            });
            // sync unbounded send: the handler never blocks
            let _ = router
                .tx
                .send((connected_address.to_string(), connected_port, obj));
        }
        Ok(())
    }
}

/// Connection parameters (bundled to keep the FFI surface narrow).
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone)]
pub struct SshSpikeConnectParams {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: SshSpikeAuth,
    pub cols: u32,
    pub rows: u32,
    /// ProxyJump chain, OUTERmost first (the hop dialed directly, …, the
    /// hop adjacent to `host`); empty = direct dial. Each hop authenticates
    /// with its own credentials and is host-key verified against its own
    /// endpoint. Ownership: the target's session keeps every hop's handle
    /// alive and tears them down in reverse.
    pub via: Vec<SshSpikeJump>,
    /// Transport keepalive interval in seconds; 0 = off (the app contract's
    /// keepAlive toggle). 15 matches the native keep-alive loops' interval.
    pub keep_alive_seconds: u32,
}

/// One jump hop: an independent SSH connection whose direct-tcpip channel
/// carries the next hop's transport.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone)]
pub struct SshSpikeJump {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: SshSpikeAuth,
}

/// The interactive session: one PTY+shell channel whose read half is
/// pumped into the foreign sink, plus a handle for exec/SFTP/direct-tcpip.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SshSpikeSession {
    write_half: Mutex<Option<ChannelWriteHalf<Msg>>>,
    handle: Mutex<Option<russh::client::Handle<ProbeHandler>>>,
    /// Jump hops this dial went through (empty for a direct dial). Dropping
    /// a parent handle kills every child riding its channel — the advisor
    /// pitfall — so the TARGET owns its hops and disconnect tears them down
    /// in reverse order.
    parents: Mutex<Vec<russh::client::Handle<ProbeHandler>>>,
}

static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();

fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("spike tokio runtime")
    })
}

fn pump(read_half: ChannelReadHalf, events: Arc<Box<dyn SshSpikeEventSink>>) {
    runtime().spawn(async move {
        let mut read_half = read_half;
        loop {
            match read_half.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    events.on_event(SshSpikeEvent::Data {
                        data: data.to_vec(),
                    });
                }
                Some(ChannelMsg::ExtendedData { data, .. }) => {
                    events.on_event(SshSpikeEvent::Data {
                        data: data.to_vec(),
                    });
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    events.on_event(SshSpikeEvent::ExitStatus { code: exit_status });
                }
                Some(ChannelMsg::Eof) => {}
                Some(ChannelMsg::Close) => {
                    events.on_event(SshSpikeEvent::Closed);
                    break;
                }
                None => {
                    // no CHANNEL_CLOSE arrived: the transport went away
                    events.on_event(SshSpikeEvent::Died);
                    break;
                }
                _ => {}
            }
        }
    });
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl SshSpikeSession {
    /// Dials, authenticates, opens a PTY + shell channel, and starts the
    /// event pump. Blocks the calling thread for the handshake — call from
    /// a background thread (same contract as the sshj/Citadel paths).
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn connect(
        params: SshSpikeConnectParams,
        events: Box<dyn SshSpikeEventSink>,
        verifier: Box<dyn SshSpikeHostKeyVerifier>,
        forwards: Box<dyn SshSpikeForwardSink>,
    ) -> Result<Arc<SshSpikeSession>, SshSpikeError> {
        runtime().block_on(Self::connect_inner(params, events, verifier, forwards))
    }

    /// One-shot exec on a fresh session channel (SshSession.exec parity):
    /// blocks until the command's output completes.
    #[allow(clippy::await_holding_lock)] // handle mutex is foreign-caller-serialized; the pump never takes it
    pub fn exec(&self, command: String) -> Result<String, SshSpikeError> {
        runtime().block_on(async {
            let mut handle_guard = self.handle.lock().unwrap();
            let handle = handle_guard
                .as_mut()
                .ok_or_else(|| SshSpikeError::Channel("session closed".to_string()))?;
            let mut channel = handle
                .channel_open_session()
                .await
                .map_err(|e| SshSpikeError::Channel(e.to_string()))?;
            channel
                .exec(false, command)
                .await
                .map_err(|e| SshSpikeError::Channel(e.to_string()))?;
            let mut got = Vec::new();
            // Read until the channel closes — exit-status can overtake
            // in-flight Data (the server sends it as soon as the process
            // ends while earlier chunks are still queued), so breaking on it
            // loses output. Once the status IS seen, the command is over:
            // keep collecting stragglers but stop when the channel goes
            // quiet, because some servers never send CHANNEL_CLOSE or EOF at
            // all (paramiko's demo server) — hanging on them costs forever;
            // OpenSSH's Close lands immediately and costs nothing here.
            let mut status_seen = false;
            loop {
                let msg = if status_seen {
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(300),
                        channel.wait(),
                    )
                    .await
                    {
                        Ok(m) => m,
                        Err(_) => break,
                    }
                } else {
                    channel.wait().await
                };
                let Some(m) = msg else { break };
                match m {
                    ChannelMsg::Data { ref data } => got.extend_from_slice(data),
                    ChannelMsg::ExitStatus { .. } => status_seen = true,
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
            String::from_utf8(got).map_err(|e| SshSpikeError::Channel(e.to_string()))
        })
    }

    /// Writes keystrokes/data into the shell channel (synchronous send).
    pub fn write(&self, data: Vec<u8>) -> Result<(), SshSpikeError> {
        let guard = self.write_half.lock().unwrap();
        let Some(wh) = guard.as_ref() else {
            return Err(SshSpikeError::Channel("session closed".to_string()));
        };
        runtime()
            .block_on(wh.data_bytes(data))
            .map_err(|e| SshSpikeError::Channel(e.to_string()))
    }

    /// PTY resize (window_change).
    pub fn resize(&self, cols: u32, rows: u32) -> Result<(), SshSpikeError> {
        let guard = self.write_half.lock().unwrap();
        let Some(wh) = guard.as_ref() else {
            return Err(SshSpikeError::Channel("session closed".to_string()));
        };
        runtime()
            .block_on(wh.window_change(cols, rows, 0, 0))
            .map_err(|e| SshSpikeError::Channel(e.to_string()))
    }

    /// Disconnects: closes the shell channel and the transport. Named
    /// `disconnect` (not `close`) because UniFFI objects already carry an
    /// AutoCloseable close() in the generated bindings.
    pub fn disconnect(&self) {
        if let Some(wh) = self.write_half.lock().unwrap().take() {
            runtime().spawn(async move {
                let _ = wh.eof().await;
                let _ = wh.close().await;
            });
        }
        if let Some(handle) = self.handle.lock().unwrap().take() {
            let parents: Vec<russh::client::Handle<ProbeHandler>> =
                self.parents.lock().unwrap().drain(..).collect();
            runtime().spawn(async move {
                // Handle::disconnect awaits the server's confirmation and
                // can hang on a dead link (advisor pitfall) — bound it.
                let _ = tokio::time::timeout(
                    Duration::from_secs(5),
                    handle.disconnect(russh::Disconnect::ByApplication, "closed", "en"),
                )
                .await;
                // then tear the jump hops down in REVERSE order: dropping a
                // parent handle would kill children silently, so each hop
                // gets its own graceful, bounded bye.
                for parent in parents.into_iter().rev() {
                    let _ = tokio::time::timeout(
                        Duration::from_secs(5),
                        parent.disconnect(russh::Disconnect::ByApplication, "closed", "en"),
                    )
                    .await;
                }
            });
        }
    }

    /// Opens a direct-tcpip channel (the jump/forwarding primitive) and
    /// returns the first bytes the target sent — the S probe for the
    /// forwarding path: a dial to the matrix's inner sshd reads its
    /// `SSH-2.0-OpenSSH` banner. Blocks the caller.
    #[allow(clippy::await_holding_lock)] // handle mutex is foreign-caller-serialized; the pump never takes it
    pub fn direct_tcpip_banner(
        &self,
        host_to_connect: String,
        port_to_connect: u16,
    ) -> Result<String, SshSpikeError> {
        runtime().block_on(async {
            let mut handle_guard = self.handle.lock().unwrap();
            let handle = handle_guard
                .as_mut()
                .ok_or_else(|| SshSpikeError::Channel("session closed".to_string()))?;
            let mut channel = handle
                .channel_open_direct_tcpip(host_to_connect, port_to_connect as u32, "127.0.0.1", 0)
                .await
                .map_err(|e| SshSpikeError::Channel(e.to_string()))?;
            let mut got = Vec::new();
            while let Some(msg) = channel.wait().await {
                match msg {
                    ChannelMsg::Data { ref data } => {
                        got.extend_from_slice(data);
                        if got.len() >= 4 {
                            break;
                        }
                    }
                    ChannelMsg::Close | ChannelMsg::Eof => break,
                    _ => {}
                }
            }
            String::from_utf8(got).map_err(|e| SshSpikeError::Channel(e.to_string()))
        })
    }

    /// Opens a direct-tcpip channel (-L / SOCKS primitive): the returned
    /// object is the raw byte pipe to host:port as seen from the SERVER.
    /// Blocks the caller while the channel opens.
    #[allow(clippy::await_holding_lock)] // handle mutex is foreign-caller-serialized; the pump never takes it
    pub fn open_direct_tcpip(
        &self,
        host_to_connect: String,
        port_to_connect: u32,
    ) -> Result<Arc<SshSpikeChannel>, SshSpikeError> {
        runtime().block_on(async {
            let mut handle_guard = self.handle.lock().unwrap();
            let handle = handle_guard
                .as_mut()
                .ok_or_else(|| SshSpikeError::Channel("session closed".to_string()))?;
            let channel = handle
                .channel_open_direct_tcpip(host_to_connect, port_to_connect, "127.0.0.1", 0)
                .await
                .map_err(|e| SshSpikeError::Channel(e.to_string()))?;
            let (rh, wh) = channel.split();
            Ok(Arc::new(SshSpikeChannel {
                read_half: Mutex::new(rh),
                write_half: Mutex::new(Some(wh)),
            }))
        })
    }

    /// Asks the server to bind a remote-forward port (-R); returns the port
    /// ACTUALLY bound (request 0 to have the server pick one). Inbound
    /// connections arrive through [SshSpikeForwardSink::on_connection].
    #[allow(clippy::await_holding_lock)] // handle mutex is foreign-caller-serialized; the pump never takes it
    pub fn request_remote_forward(
        &self,
        bind_host: String,
        bind_port: u32,
    ) -> Result<u32, SshSpikeError> {
        runtime().block_on(async {
            let handle_guard = self.handle.lock().unwrap();
            let handle = handle_guard
                .as_ref()
                .ok_or_else(|| SshSpikeError::Channel("session closed".to_string()))?;
            handle
                .tcpip_forward(&bind_host, bind_port)
                .await
                .map_err(|e| SshSpikeError::Channel(e.to_string()))
        })
    }

    /// Takes a remote forward back off the server. In-flight channels may
    /// still arrive after this returns — dispatch must tolerate them.
    #[allow(clippy::await_holding_lock)] // handle mutex is foreign-caller-serialized; the pump never takes it
    pub fn cancel_remote_forward(
        &self,
        bind_host: String,
        bind_port: u32,
    ) -> Result<(), SshSpikeError> {
        runtime().block_on(async {
            let handle_guard = self.handle.lock().unwrap();
            let handle = handle_guard
                .as_ref()
                .ok_or_else(|| SshSpikeError::Channel("session closed".to_string()))?;
            handle
                .cancel_tcpip_forward(&bind_host, bind_port)
                .await
                .map_err(|e| SshSpikeError::Channel(e.to_string()))
        })
    }

    /// SFTP probe: opens the sftp subsystem on a fresh session channel and
    /// reads a small file (russh-sftp over `Channel::into_stream`).
    #[allow(clippy::await_holding_lock)] // handle mutex is foreign-caller-serialized; the pump never takes it
    pub fn sftp_read(&self, path: String) -> Result<Vec<u8>, SshSpikeError> {
        runtime().block_on(async {
            let sftp = self.sftp_open().await?;
            sftp.read(path)
                .await
                .map_err(|e| SshSpikeError::Sftp(e.to_string()))
        })
    }

    /// SFTP tree surface (S parity): opens the sftp subsystem on a fresh
    /// session channel. The returned object owns that channel; its methods
    /// block the caller (background threads only, same contract as `exec`).
    #[allow(clippy::await_holding_lock)] // handle mutex is foreign-caller-serialized; the pump never takes it
    pub fn sftp(&self) -> Result<Arc<SshSpikeSftp>, SshSpikeError> {
        runtime().block_on(async {
            let sftp = self.sftp_open().await?;
            Ok(Arc::new(SshSpikeSftp { sftp }))
        })
    }
}

impl SshSpikeSession {
    /// Private helper (NOT an FFI export): opens one sftp-subsystem
    /// channel off the shared connection.
    #[allow(clippy::await_holding_lock)] // handle mutex is foreign-caller-serialized; the pump never takes it
    async fn sftp_open(&self) -> Result<russh_sftp::client::SftpSession, SshSpikeError> {
        let mut handle_guard = self.handle.lock().unwrap();
        let handle = handle_guard
            .as_mut()
            .ok_or_else(|| SshSpikeError::Channel("session closed".to_string()))?;
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| SshSpikeError::Channel(e.to_string()))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| SshSpikeError::Channel(e.to_string()))?;
        russh_sftp::client::SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| SshSpikeError::Channel(e.to_string()))
    }
}

impl SshSpikeSession {
    async fn connect_inner(
        params: SshSpikeConnectParams,
        events: Box<dyn SshSpikeEventSink>,
        verifier: Box<dyn SshSpikeHostKeyVerifier>,
        forwards: Box<dyn SshSpikeForwardSink>,
    ) -> Result<Arc<Self>, SshSpikeError> {
        let SshSpikeConnectParams {
            host,
            port,
            username,
            auth,
            cols,
            rows,
            via,
            keep_alive_seconds,
        } = params;
        let events: Arc<Box<dyn SshSpikeEventSink>> = Arc::new(events);
        // One verifier object serves the WHOLE chain; every hop presents its
        // own key, and the handler passes the endpoint alongside so the
        // foreign side knows which hop it is deciding on.
        let verifier: Arc<dyn SshSpikeHostKeyVerifier> = Arc::from(verifier);
        // Remote forwards (-R) are requested on the TARGET connection only:
        // the sink rides the target's handler; hop handlers get none.
        let sink: Arc<dyn SshSpikeForwardSink> = Arc::from(forwards);
        let (forward_tx, forward_rx) = tokio::sync::mpsc::unbounded_channel();
        ForwardRouter::dispatch_loop(Arc::clone(&sink), forward_rx);
        let router = ForwardRouter { tx: forward_tx };

        // The dial list: hops OUTERmost first, then the target with its own
        // credentials (params carries the target's; `via` only the hops).
        let mut chain: Vec<(String, u16, String, SshSpikeAuth)> = via
            .iter()
            .map(|j| (j.host.clone(), j.port, j.username.clone(), j.auth.clone()))
            .collect();
        chain.push((host, port, username, auth));

        let mut parents: Vec<russh::client::Handle<ProbeHandler>> =
            Vec::with_capacity(chain.len() - 1);
        let mut target: Option<russh::client::Handle<ProbeHandler>> = None;
        for (i, (h, p, user, hop_auth)) in chain.iter().enumerate() {
            let is_target = i + 1 == chain.len();
            let handler = ProbeHandler {
                verifier: Arc::clone(&verifier),
                accepted_host_keys: Mutex::new(Vec::new()),
                endpoint: (h.clone(), *p),
                forwards: if is_target {
                    Some(router.clone())
                } else {
                    None
                },
            };
            let mut conn = if i == 0 {
                russh::client::connect(
                    transport_config(keep_alive_seconds),
                    (h.as_str(), *p),
                    handler,
                )
                .await
                .map_err(map_connect_error)?
            } else {
                // This hop rides a direct-tcpip channel of the PREVIOUS hop:
                // the channel stream is the child transport (connect_stream),
                // and the dialed address is the CHILD's view (advisor
                // pitfall: direct-tcpip dials use the remote host's own
                // view of the target).
                let parent = parents.last().expect("previous hop handle");
                let channel = parent
                    .channel_open_direct_tcpip(h.clone(), *p as u32, "127.0.0.1".to_string(), 0)
                    .await
                    .map_err(|e| SshSpikeError::Connect(format!("jump to {h}:{p} failed: {e}")))?;
                russh::client::connect_stream(
                    transport_config(keep_alive_seconds),
                    channel.into_stream(),
                    handler,
                )
                .await
                .map_err(map_connect_error)?
            };
            if let Err(e) = authenticate(&mut conn, user, hop_auth).await {
                // per-hop attribution (the sshj path re-labels the same way):
                // the user must learn WHICH hop rejected the credential.
                // The target keeps its plain wording.
                if i + 1 == chain.len() {
                    return Err(e);
                }
                return Err(SshSpikeError::Auth(format!("jump to {h}:{p}: {e}")));
            }
            if i + 1 == chain.len() {
                target = Some(conn);
            } else {
                parents.push(conn);
            }
        }
        let handle = target.expect("chain always ends with the target");

        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| SshSpikeError::Channel(e.to_string()))?;
        channel
            .request_pty(false, "xterm-256color", cols, rows, 0, 0, &[])
            .await
            .map_err(|e| SshSpikeError::Channel(e.to_string()))?;
        channel
            .request_shell(false)
            .await
            .map_err(|e| SshSpikeError::Channel(e.to_string()))?;
        let (read_half, write_half) = channel.split();

        let session = Arc::new(Self {
            write_half: Mutex::new(Some(write_half)),
            handle: Mutex::new(Some(handle)),
            parents: Mutex::new(parents),
        });
        pump(read_half, events);
        Ok(session)
    }
}

fn transport_config(keep_alive_seconds: u32) -> Arc<russh::client::Config> {
    Arc::new(russh::client::Config {
        // keepalive mapping (adjudicated): the native keepalive loops'
        // interval semantics, enforced by the transport itself. Every hop
        // in a chain carries it — an idle child means an idle parent TCP.
        keepalive_interval: if keep_alive_seconds == 0 {
            None
        } else {
            Some(Duration::from_secs(keep_alive_seconds as u64))
        },
        inactivity_timeout: None,
        ..Default::default()
    })
}

fn map_connect_error(e: russh::Error) -> SshSpikeError {
    match e {
        // the verifier's false comes back as UnknownKey from russh
        russh::Error::UnknownKey => SshSpikeError::HostKeyRejected,
        // typed payload, not message text (facade wiring rule 2): the kind
        // tells the UI WHICH negotiation failed (kex/key/cipher/mac/…)
        russh::Error::NoCommonAlgo { kind, .. } => {
            SshSpikeError::NoCommonAlgorithm(format!("{kind:?}").to_lowercase())
        }
        other => SshSpikeError::Connect(other.to_string()),
    }
}

async fn authenticate(
    handle: &mut russh::client::Handle<ProbeHandler>,
    username: &str,
    auth: &SshSpikeAuth,
) -> Result<(), SshSpikeError> {
    match auth {
        SshSpikeAuth::Password { password } => {
            // russh does NOT error on a rejected password — it returns
            // success=false and the server then drops the next request with
            // a bare "Disconnected" (measured against the matrix), which
            // would read as a network failure instead of an auth failure.
            let result = handle
                .authenticate_password(username, password)
                .await
                .map_err(|e| SshSpikeError::Auth(e.to_string()))?;
            if !result.success() {
                return Err(SshSpikeError::Auth("password rejected".to_string()));
            }
        }
        SshSpikeAuth::PrivateKey { pem, passphrase } => {
            let key = russh::keys::decode_secret_key(pem, passphrase.as_deref())
                .map_err(|e| SshSpikeError::Auth(e.to_string()))?;
            let with_hash = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None);
            let result = handle
                .authenticate_publickey(username, with_hash)
                .await
                .map_err(|e| SshSpikeError::Auth(e.to_string()))?;
            if !result.success() {
                return Err(SshSpikeError::Auth("key rejected".to_string()));
            }
        }
    }
    Ok(())
}

/// SFTP tree surface (S parity, PLAN.md §4): one sftp subsystem channel
/// multiplexed beside the shell. Write semantics are create-or-truncate —
/// the app contract — which russh-sftp's own `write` (WRITE-only flags)
/// does not provide, hence the explicit flags here. All methods block the
/// caller; call from a background thread (same contract as `exec`).
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SshSpikeSftp {
    sftp: russh_sftp::client::SftpSession,
}

/// File metadata for the SFTP tree (the fields the apps' file browsers
/// render); timestamps are unix seconds.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone)]
pub struct SshSpikeFileMeta {
    pub size: u64,
    pub is_dir: bool,
    pub is_file: bool,
    pub is_symlink: bool,
    pub mtime_unix: Option<i64>,
    pub permissions: Option<u32>,
}

/// One `read_dir` entry: name plus the same metadata fields.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone)]
pub struct SshSpikeDirEntry {
    pub file_name: String,
    pub size: u64,
    pub is_dir: bool,
    pub is_file: bool,
    pub is_symlink: bool,
    pub mtime_unix: Option<i64>,
    pub permissions: Option<u32>,
}

fn meta_record(
    m: &russh_sftp::client::fs::Metadata,
) -> (u64, bool, bool, bool, Option<i64>, Option<u32>) {
    let ft = m.file_type();
    (
        m.len(),
        ft.is_dir(),
        ft.is_file(),
        ft.is_symlink(),
        m.modified().ok().and_then(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs() as i64)
        }),
        m.permissions,
    )
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl SshSpikeSftp {
    /// Full file contents (small-file convenience, SftpInteraction parity).
    pub fn read(&self, path: String) -> Result<Vec<u8>, SshSpikeError> {
        runtime().block_on(async {
            self.sftp
                .read(&path)
                .await
                .map_err(|e| SshSpikeError::Sftp(e.to_string()))
        })
    }

    /// create-or-truncate write (the app contract; NOT russh-sftp's
    /// WRITE-only `write`, which fails on a missing file and leaves
    /// trailing bytes on a longer one).
    pub fn write(&self, path: String, data: Vec<u8>) -> Result<(), SshSpikeError> {
        runtime().block_on(async {
            use tokio::io::AsyncWriteExt;
            let mut file = self
                .sftp
                .open_with_flags(
                    &path,
                    russh_sftp::protocol::OpenFlags::CREATE
                        | russh_sftp::protocol::OpenFlags::TRUNCATE
                        | russh_sftp::protocol::OpenFlags::WRITE,
                )
                .await
                .map_err(|e| SshSpikeError::Sftp(e.to_string()))?;
            file.write_all(&data)
                .await
                .map_err(|e| SshSpikeError::Sftp(e.to_string()))?;
            file.close()
                .await
                .map_err(|e| SshSpikeError::Sftp(e.to_string()))
        })
    }

    /// Rename (server-side move) old -> new.
    pub fn rename(&self, old_path: String, new_path: String) -> Result<(), SshSpikeError> {
        runtime().block_on(async {
            self.sftp
                .rename(&old_path, &new_path)
                .await
                .map_err(|e| SshSpikeError::Sftp(e.to_string()))
        })
    }

    pub fn remove_file(&self, path: String) -> Result<(), SshSpikeError> {
        runtime().block_on(async {
            self.sftp
                .remove_file(&path)
                .await
                .map_err(|e| SshSpikeError::Sftp(e.to_string()))
        })
    }

    pub fn remove_dir(&self, path: String) -> Result<(), SshSpikeError> {
        runtime().block_on(async {
            self.sftp
                .remove_dir(&path)
                .await
                .map_err(|e| SshSpikeError::Sftp(e.to_string()))
        })
    }

    pub fn create_dir(&self, path: String) -> Result<(), SshSpikeError> {
        runtime().block_on(async {
            self.sftp
                .create_dir(&path)
                .await
                .map_err(|e| SshSpikeError::Sftp(e.to_string()))
        })
    }

    pub fn metadata(&self, path: String) -> Result<SshSpikeFileMeta, SshSpikeError> {
        runtime().block_on(async {
            let m = self
                .sftp
                .metadata(&path)
                .await
                .map_err(|e| SshSpikeError::Sftp(e.to_string()))?;
            let (size, is_dir, is_file, is_symlink, mtime_unix, permissions) = meta_record(&m);
            Ok(SshSpikeFileMeta {
                size,
                is_dir,
                is_file,
                is_symlink,
                mtime_unix,
                permissions,
            })
        })
    }

    /// Directory listing (including `.`/`..` entries, like sshj's ls).
    pub fn read_dir(&self, path: String) -> Result<Vec<SshSpikeDirEntry>, SshSpikeError> {
        runtime().block_on(async {
            let dir = self
                .sftp
                .read_dir(&path)
                .await
                .map_err(|e| SshSpikeError::Sftp(e.to_string()))?;
            Ok(dir
                .map(|entry| {
                    let (size, is_dir, is_file, is_symlink, mtime_unix, permissions) =
                        meta_record(&entry.metadata());
                    SshSpikeDirEntry {
                        file_name: entry.file_name(),
                        size,
                        is_dir,
                        is_file,
                        is_symlink,
                        mtime_unix,
                        permissions,
                    }
                })
                .collect())
        })
    }

    pub fn read_link(&self, path: String) -> Result<String, SshSpikeError> {
        runtime().block_on(async {
            self.sftp
                .read_link(&path)
                .await
                .map_err(|e| SshSpikeError::Sftp(e.to_string()))
        })
    }

    /// Opens a streaming READ handle (TransferQueue's large-file path).
    pub fn open_read(&self, path: String) -> Result<Arc<SshSpikeRemoteFile>, SshSpikeError> {
        self.open_file(&path, true, false, 0)
    }

    /// Streaming READ handle positioned at [offset] (transfer resume).
    pub fn open_read_at(
        &self,
        path: String,
        offset: u64,
    ) -> Result<Arc<SshSpikeRemoteFile>, SshSpikeError> {
        self.open_file(&path, true, false, offset)
    }

    /// Opens a streaming create-or-truncate WRITE handle.
    pub fn open_write(&self, path: String) -> Result<Arc<SshSpikeRemoteFile>, SshSpikeError> {
        self.open_write_at(path, 0, true)
    }

    /// Streaming WRITE handle positioned at [offset]; `truncate` only on a
    /// fresh upload (offset 0) — a resume MUST NOT truncate (TransferQueue's
    /// `.part` contract).
    pub fn open_write_at(
        &self,
        path: String,
        offset: u64,
        truncate: bool,
    ) -> Result<Arc<SshSpikeRemoteFile>, SshSpikeError> {
        self.open_file(&path, false, truncate, offset)
    }

    fn open_file(
        &self,
        path: &str,
        read_only: bool,
        truncate: bool,
        offset: u64,
    ) -> Result<Arc<SshSpikeRemoteFile>, SshSpikeError> {
        runtime().block_on(async {
            use russh_sftp::protocol::OpenFlags;
            use tokio::io::AsyncSeekExt;
            let flags = if read_only {
                OpenFlags::READ
            } else {
                let mut f = OpenFlags::WRITE | OpenFlags::CREATE;
                if truncate {
                    f |= OpenFlags::TRUNCATE;
                }
                f
            };
            let mut file = self
                .sftp
                .open_with_flags(path, flags)
                .await
                .map_err(|e| SshSpikeError::Sftp(e.to_string()))?;
            if offset > 0 {
                file.seek(std::io::SeekFrom::Start(offset))
                    .await
                    .map_err(|e| SshSpikeError::Sftp(e.to_string()))?;
            }
            Ok(Arc::new(SshSpikeRemoteFile {
                file: Mutex::new(Some(file)),
            }))
        })
    }

    /// Absolute-path canonicalization (SFTP REALPATH).
    pub fn canonicalize(&self, path: String) -> Result<String, SshSpikeError> {
        runtime().block_on(async {
            self.sftp
                .canonicalize(&path)
                .await
                .map_err(|e| SshSpikeError::Sftp(e.to_string()))
        })
    }
}

// ------------------------------------------------------------- tests
// Gated on the docker sshd matrix being reachable
// (android/tools/sshd-matrix; `run.sh` starts it) and compiled only under
// `--features ssh-spike`. Tests skip with a note when it is down so local
// `cargo test` stays green without the matrix; CI sets
// CONCH_SSHD_MATRIX_REQUIRED=1 so a down matrix FAILS instead of skipping
// green.

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddr, TcpStream};

    const HOST: &str = "127.0.0.1";
    const PW_PORT: u16 = 2233; // pwuser/conch-pw-1, pw+pubkey (host map of :2223)
    const KEY_PORT: u16 = 2234; // bothuser with keyA, pubkey-only
    const FWD_PORT: u16 = 2235; // forwarding allowed
    /// The forwarding server dials from INSIDE the container, where the
    /// password sshd listens on its own 2223 — host-side port maps don't apply.
    const INNER_SSHD_PORT: u16 = 2223;
    const USER: &str = "pwuser";

    #[test]
    fn no_common_kex_maps_to_a_typed_variant_not_a_string() {
        // The platforms turn this into their user-facing "no common
        // algorithm" case; stringifying it into Connect rendered a raw
        // russh dump instead.
        let mapped = map_connect_error(russh::Error::NoCommonAlgo {
            kind: russh::AlgorithmKind::Kex,
            ours: vec!["sntrup761x25519-sha512".into()],
            theirs: vec!["diffie-hellman-group14-sha1".into()],
        });
        match mapped {
            SshSpikeError::NoCommonAlgorithm(kind) => assert_eq!(kind, "kex"),
            other => panic!("expected the typed variant, got {other:?}"),
        }
    }
    const PASSWORD: &str = "conch-pw-1";

    fn matrix_required() -> bool {
        std::env::var("CONCH_SSHD_MATRIX_REQUIRED").ok().as_deref() == Some("1")
    }

    fn matrix_ready(port: u16) -> bool {
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let up = TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok();
        // A skip is indistinguishable from a pass in the summary, so CI
        // (CONCH_SSHD_MATRIX_REQUIRED=1) must fail loudly instead.
        if !up && matrix_required() {
            panic!(
                "CONCH_SSHD_MATRIX_REQUIRED is set but the sshd matrix is not reachable at {addr} \
                 (android/tools/sshd-matrix/run.sh)"
            );
        }
        up
    }

    fn password_auth() -> SshSpikeAuth {
        SshSpikeAuth::Password {
            password: PASSWORD.to_string(),
        }
    }

    #[derive(Default, Clone)]
    struct Collector(Arc<Mutex<Vec<SshSpikeEvent>>>);

    impl SshSpikeEventSink for Collector {
        fn on_event(&self, event: SshSpikeEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    impl Collector {
        fn wait_for(
            &self,
            pred: impl Fn(&SshSpikeEvent) -> bool,
            what: &str,
        ) -> Option<SshSpikeEvent> {
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            while std::time::Instant::now() < deadline {
                if let Some(e) = self.0.lock().unwrap().iter().find(|e| pred(e)) {
                    return Some(e.clone());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            eprintln!("timeout waiting for {what}");
            None
        }
    }

    /// Always-accept verifier that records what it saw.
    type SeenKey = (String, String, Vec<u8>);

    #[derive(Clone)]
    struct AcceptVerifier(Arc<Mutex<Vec<SeenKey>>>);

    impl Default for AcceptVerifier {
        fn default() -> Self {
            Self(Arc::new(Mutex::new(Vec::new())))
        }
    }

    impl SshSpikeHostKeyVerifier for AcceptVerifier {
        fn verify_host_key(
            &self,
            hostname: String,
            port: u16,
            algorithm: String,
            blob: Vec<u8>,
        ) -> bool {
            self.0
                .lock()
                .unwrap()
                .push((format!("{hostname}:{port}"), algorithm, blob));
            true
        }
    }

    #[derive(Default)]
    struct NullForwardSink;

    impl SshSpikeForwardSink for NullForwardSink {
        fn on_connection(
            &self,
            _bind_host: String,
            _bind_port: u32,
            _channel: std::sync::Arc<SshSpikeChannel>,
        ) {
        }
    }

    struct RejectVerifier;

    impl SshSpikeHostKeyVerifier for RejectVerifier {
        fn verify_host_key(
            &self,
            _hostname: String,
            _port: u16,
            _algorithm: String,
            _blob: Vec<u8>,
        ) -> bool {
            false
        }
    }

    fn connect_shell(
        verifier: Box<dyn SshSpikeHostKeyVerifier>,
        events: Box<dyn SshSpikeEventSink>,
    ) -> Result<Arc<SshSpikeSession>, SshSpikeError> {
        SshSpikeSession::connect(
            SshSpikeConnectParams {
                host: HOST.to_string(),
                port: PW_PORT,
                username: USER.to_string(),
                auth: password_auth(),
                cols: 80,
                rows: 24,
                via: Vec::new(),
                keep_alive_seconds: 15,
            },
            events,
            verifier,
            Box::new(NullForwardSink),
        )
    }

    #[test]
    fn shell_session_streams_echo_and_accepts_writes() {
        if !matrix_ready(PW_PORT) {
            eprintln!("sshd matrix down — skipping");
            return;
        }
        let collector = Collector::default();
        let session = connect_shell(
            Box::new(AcceptVerifier::default()),
            Box::new(collector.clone()),
        )
        .expect("connect");
        session
            .write(b"echo ok-session\r\n".to_vec())
            .expect("write");
        let seen = collector
            .wait_for(
                |e| {
                    matches!(e, SshSpikeEvent::Data { data }
                        if data.windows(10).any(|w| w == b"ok-session"))
                },
                "shell echo output",
            )
            .expect("echo output must stream through the callback");
        assert!(matches!(seen, SshSpikeEvent::Data { .. }));
        session.disconnect();
    }

    #[test]
    fn resize_is_accepted_after_shell() {
        if !matrix_ready(PW_PORT) {
            eprintln!("sshd matrix down — skipping");
            return;
        }
        let session = connect_shell(
            Box::new(AcceptVerifier::default()),
            Box::new(Collector::default()),
        )
        .expect("connect");
        session.resize(120, 40).expect("window_change must succeed");
        // the session still works after a resize
        session
            .write(b"true\r\n".to_vec())
            .expect("write after resize");
        session.disconnect();
    }

    #[test]
    fn exec_returns_command_output() {
        if !matrix_ready(PW_PORT) {
            eprintln!("sshd matrix down — skipping");
            return;
        }
        let session = connect_shell(
            Box::new(AcceptVerifier::default()),
            Box::new(Collector::default()),
        )
        .expect("connect");
        let out = session.exec("echo ok-exec".to_string()).expect("exec");
        assert_eq!(out.trim(), "ok-exec");
        session.disconnect();
    }

    #[test]
    fn exec_does_not_lose_output_when_exit_status_arrives_early() {
        if !matrix_ready(PW_PORT) {
            eprintln!("sshd matrix down — skipping");
            return;
        }
        let session = connect_shell(
            Box::new(AcceptVerifier::default()),
            Box::new(Collector::default()),
        )
        .expect("connect");
        // 200k numbered lines: the process ends while earlier chunks are
        // still in flight, so exit-status can overtake queued Data —
        // breaking the read loop on it dropped 2-3% of the output.
        let lines = 200_000;
        let out = session.exec(format!("seq 1 {lines}")).expect("exec");
        let produced = out.lines().filter(|l| !l.is_empty()).count();
        assert_eq!(produced, lines, "output was truncated");
        assert_eq!(out.lines().next(), Some("1"));
        assert_eq!(out.lines().last(), Some(lines.to_string()).as_deref());
        session.disconnect();
    }

    #[test]
    fn host_key_verifier_sees_a_plausible_wire_blob() {
        if !matrix_ready(PW_PORT) {
            eprintln!("sshd matrix down — skipping");
            return;
        }
        let verifier = AcceptVerifier::default();
        let session = connect_shell(Box::new(verifier.clone()), Box::new(Collector::default()))
            .expect("connect");
        let seen = verifier.0.lock().unwrap();
        assert_eq!(seen.len(), 1, "exactly one host-key check per connect");
        let (endpoint, algorithm, blob) = &seen[0];
        assert_eq!(endpoint, &format!("{HOST}:{PW_PORT}"));
        assert!(
            algorithm.starts_with("ssh-") || algorithm.starts_with("ecdsa-"),
            "algorithm={algorithm}"
        );
        // the blob is the same wire encoding the known_hosts codec speaks:
        // it must pass the H layer's plausibility check
        assert!(crate::known_hosts::is_plausible_blob(blob));
        drop(seen);
        session.disconnect();
    }

    #[test]
    fn host_key_rejection_fails_the_connect() {
        if !matrix_ready(PW_PORT) {
            eprintln!("sshd matrix down — skipping");
            return;
        }
        let err = connect_shell(Box::new(RejectVerifier), Box::new(Collector::default()))
            .err()
            .expect("connect must fail when the verifier rejects");
        assert!(matches!(err, SshSpikeError::HostKeyRejected));
    }

    #[test]
    fn private_key_auth_works() {
        if !matrix_ready(KEY_PORT) {
            eprintln!("sshd matrix down — skipping");
            return;
        }
        // keyA is installed for bothuser on the key-only instance. Resolve
        // the keys dir the way run.sh does so RUST_CORE_MATRIX_KEYS /
        // XDG_CACHE_HOME layouts find it too.
        let keys_dir = std::env::var("RUST_CORE_MATRIX_KEYS").unwrap_or_else(|_| {
            match std::env::var("XDG_CACHE_HOME") {
                Ok(x) => format!("{x}/rust-core/sshd-matrix/keys"),
                Err(_) => format!(
                    "{}/.cache/rust-core/sshd-matrix/keys",
                    std::env::var("HOME").unwrap()
                ),
            }
        });
        let key_path = format!("{keys_dir}/keyA");
        let Ok(pem) = std::fs::read_to_string(&key_path) else {
            // Matrix up but keys missing is a degraded matrix — the same
            // skip-green-as-pass defect, so CI must fail loudly here too.
            if matrix_required() {
                panic!(
                    "CONCH_SSHD_MATRIX_REQUIRED is set but {key_path} is unreadable \
                     (android/tools/sshd-matrix/run.sh generates it)"
                );
            }
            eprintln!("matrix keyA not generated — skipping");
            return;
        };
        let events = Collector::default();
        let session = SshSpikeSession::connect(
            SshSpikeConnectParams {
                host: HOST.to_string(),
                port: KEY_PORT,
                username: "bothuser".to_string(),
                auth: SshSpikeAuth::PrivateKey {
                    pem,
                    passphrase: None,
                },
                cols: 80,
                rows: 24,
                via: Vec::new(),
                keep_alive_seconds: 15,
            },
            Box::new(events.clone()),
            Box::new(AcceptVerifier::default()),
            Box::new(NullForwardSink),
        )
        .expect("key-auth connect");
        session
            .write(b"echo ok-pubkey\r\n".to_vec())
            .expect("write");
        assert!(events
            .wait_for(
                |e| matches!(e, SshSpikeEvent::Data { data }
                    if data.windows(9).any(|w| w == b"ok-pubkey")),
                "pubkey echo output"
            )
            .is_some());
        session.disconnect();
    }

    #[test]
    fn direct_tcpip_reaches_the_inner_sshd_banner() {
        if !matrix_ready(FWD_PORT) || !matrix_ready(PW_PORT) {
            eprintln!("sshd matrix down — skipping");
            return;
        }
        // connect to the FORWARDING instance (host 2235); the pwpub
        // instance has AllowTcpForwarding no
        let events = Collector::default();
        let session = SshSpikeSession::connect(
            SshSpikeConnectParams {
                host: HOST.to_string(),
                port: FWD_PORT,
                username: USER.to_string(),
                auth: password_auth(),
                cols: 80,
                rows: 24,
                via: Vec::new(),
                keep_alive_seconds: 15,
            },
            Box::new(events.clone()),
            Box::new(AcceptVerifier::default()),
            Box::new(NullForwardSink),
        )
        .expect("connect to fwd instance");
        // dial the matrix's own password sshd through the forwarding server
        let banner = session
            .direct_tcpip_banner("127.0.0.1".to_string(), INNER_SSHD_PORT)
            .expect("direct-tcpip");
        assert!(
            banner.starts_with("SSH-2.0-OpenSSH"),
            "expected the inner sshd banner, got {banner:?}"
        );
        session.disconnect();
    }

    #[test]
    fn sftp_tree_write_rename_remove_round_trip() {
        if !matrix_ready(PW_PORT) {
            eprintln!("sshd matrix down — skipping");
            return;
        }
        let session = connect_shell(
            Box::new(AcceptVerifier::default()),
            Box::new(Collector::default()),
        )
        .expect("connect");
        let sftp = session.sftp().expect("sftp open");

        // create-or-truncate write, then read back
        let dir = "/tmp/conch-sftp-tree-test";
        // tolerate a dirty rerun that left the dir behind
        sftp.create_dir(dir.to_string()).ok();
        sftp.write(format!("{dir}/a.txt"), b"hello sftp tree".to_vec())
            .expect("write must create the file");
        assert_eq!(
            sftp.read(format!("{dir}/a.txt")).expect("read back"),
            b"hello sftp tree"
        );
        // truncate semantics: a shorter write leaves no trailing bytes
        sftp.write(format!("{dir}/a.txt"), b"tiny".to_vec())
            .expect("overwrite");
        assert_eq!(
            sftp.read(format!("{dir}/a.txt")).expect("read again"),
            b"tiny"
        );

        // metadata reflects the written size and a regular file
        let meta = sftp.metadata(format!("{dir}/a.txt")).expect("stat");
        assert_eq!(meta.size, 4);
        assert!(meta.is_file && !meta.is_dir && !meta.is_symlink);

        // rename, then the old path is gone and the new path reads
        sftp.rename(format!("{dir}/a.txt"), format!("{dir}/b.txt"))
            .expect("rename");
        assert!(sftp.read(format!("{dir}/a.txt")).is_err());
        assert_eq!(sftp.read(format!("{dir}/b.txt")).expect("renamed"), b"tiny");

        // directory tree: create, list, rmdir
        sftp.create_dir(format!("{dir}/sub")).expect("mkdir");
        let names: Vec<String> = sftp
            .read_dir(dir.to_string())
            .expect("ls")
            .into_iter()
            .map(|e| e.file_name)
            .collect();
        assert!(
            names.contains(&"sub".to_string()),
            "ls must list sub: {names:?}"
        );
        sftp.remove_file(format!("{dir}/b.txt")).expect("rm");
        sftp.remove_dir(format!("{dir}/sub")).expect("rmdir");
        sftp.remove_dir(dir.to_string()).ok(); // pre-existing dir on a dirty matrix is fine
        session.disconnect();
    }

    #[test]
    fn sftp_canonicalizes_absolute_paths() {
        if !matrix_ready(PW_PORT) {
            eprintln!("sshd matrix down — skipping");
            return;
        }
        let session = connect_shell(
            Box::new(AcceptVerifier::default()),
            Box::new(Collector::default()),
        )
        .expect("connect");
        let sftp = session.sftp().expect("sftp open");
        let dir = "/tmp/conch-sftp-realpath-test";
        sftp.create_dir(dir.to_string()).ok();
        let canonical = sftp.canonicalize(dir.to_string()).expect("realpath");
        assert_eq!(
            canonical, dir,
            "an absolute path must canonicalize to itself"
        );
        sftp.remove_dir(dir.to_string()).ok();
        session.disconnect();
    }

    /// Two-hop chain: the target is the password sshd seen from INSIDE the
    /// container network (127.0.0.1:2223), reachable only through the
    /// forwarding instance's direct-tcpip. Verifies that each hop's key is
    /// checked against ITS OWN endpoint (advisor pitfall) and that shell
    /// traffic flows end to end.
    /// The -L / SOCKS primitive: a direct-tcpip channel object the foreign
    /// side pumps byte-wise. Verified against the matrix's inner sshd
    /// banner (same probe as direct_tcpip_banner, but as a live pipe).
    #[test]
    fn direct_tcpip_channel_object_pipes_bytes() {
        if !matrix_ready(FWD_PORT) {
            eprintln!("sshd matrix down — skipping");
            return;
        }
        let events = Collector::default();
        let session = SshSpikeSession::connect(
            SshSpikeConnectParams {
                host: HOST.to_string(),
                port: FWD_PORT,
                username: USER.to_string(),
                auth: password_auth(),
                cols: 80,
                rows: 24,
                via: Vec::new(),
                keep_alive_seconds: 15,
            },
            Box::new(events),
            Box::new(AcceptVerifier::default()),
            Box::new(NullForwardSink),
        )
        .expect("connect to fwd instance");
        let channel = session
            .open_direct_tcpip("127.0.0.1".to_string(), u32::from(INNER_SSHD_PORT))
            .expect("direct-tcpip channel");
        let banner = channel.read().expect("read banner");
        assert!(
            String::from_utf8_lossy(&banner).starts_with("SSH-2.0-OpenSSH"),
            "expected the inner sshd banner, got {:?}",
            String::from_utf8_lossy(&banner)
        );
        channel.disconnect();
        session.disconnect();
    }

    /// The -R primitive, end to end: A requests the forward (server picks
    /// the port); B — a second connection to the same server — dials
    /// direct-tcpip at the bound port; the server forwards B's connection
    /// BACK to A through a forwarded-tcpip channel; the sink receives it
    /// and the two pipes echo. Cancel closes the loop (tolerates in-flight
    /// arrivals per the advisor's rule).
    #[test]
    fn remote_forward_round_trip_reaches_the_sink() {
        if !matrix_ready(FWD_PORT) {
            eprintln!("sshd matrix down — skipping");
            return;
        }
        use std::sync::Arc as StdArc;
        use std::sync::Mutex as StdMutex;

        type Arrival = (String, u32, StdArc<SshSpikeChannel>);

        #[derive(Clone)]
        struct CollectingSink(StdArc<StdMutex<Vec<Arrival>>>);
        impl SshSpikeForwardSink for CollectingSink {
            fn on_connection(&self, host: String, port: u32, channel: StdArc<SshSpikeChannel>) {
                self.0.lock().unwrap().push((host, port, channel));
            }
        }

        let arrivals: StdArc<StdMutex<Vec<Arrival>>> = StdArc::default();
        let session_a = {
            let events = Collector::default();
            SshSpikeSession::connect(
                SshSpikeConnectParams {
                    host: HOST.to_string(),
                    port: FWD_PORT,
                    username: USER.to_string(),
                    auth: password_auth(),
                    cols: 80,
                    rows: 24,
                    via: Vec::new(),
                    keep_alive_seconds: 15,
                },
                Box::new(events),
                Box::new(AcceptVerifier::default()),
                Box::new(CollectingSink(StdArc::clone(&arrivals))),
            )
            .expect("connect A")
        };
        let bound = session_a
            .request_remote_forward("127.0.0.1".to_string(), 0)
            .expect("tcpip-forward");
        assert!(bound > 0, "the server must report the assigned port");

        // B dials the bound port as seen from the SERVER; the server
        // forwards the connection back to A, whose sink receives it
        let session_b = {
            let events = Collector::default();
            SshSpikeSession::connect(
                SshSpikeConnectParams {
                    host: HOST.to_string(),
                    port: FWD_PORT,
                    username: USER.to_string(),
                    auth: password_auth(),
                    cols: 80,
                    rows: 24,
                    via: Vec::new(),
                    keep_alive_seconds: 15,
                },
                Box::new(events),
                Box::new(AcceptVerifier::default()),
                Box::new(NullForwardSink),
            )
            .expect("connect B")
        };
        let channel_b = session_b
            .open_direct_tcpip("127.0.0.1".to_string(), bound)
            .expect("dial the bound port");
        channel_b
            .write(b"ping-through-forward".to_vec())
            .expect("write");

        // wait for the arrival on A's sink
        let (host, port, channel_a) = {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                assert!(std::time::Instant::now() < deadline, "no forwarded arrival");
                let arrival = arrivals.lock().unwrap().pop();
                if let Some(a) = arrival {
                    break a;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, bound);
        let got = channel_a.read().expect("read forwarded bytes");
        assert_eq!(got, b"ping-through-forward");
        channel_a.write(b"pong-back".to_vec()).expect("reply");
        let reply = channel_b.read().expect("read reply");
        assert_eq!(reply, b"pong-back");
        channel_b.disconnect();
        channel_a.disconnect();

        // cancel: the forward goes away (in-flight arrivals tolerated)
        session_a
            .cancel_remote_forward("127.0.0.1".to_string(), bound)
            .expect("cancel");
        session_a.disconnect();
        session_b.disconnect();
    }

    /// A chain's auth failure must name WHICH hop rejected the credential
    /// (per-hop attribution parity with the sshj path's attributing()); the
    /// target's own failure keeps the plain wording.
    #[test]
    fn jump_chain_auth_failure_names_the_failing_hop() {
        if !matrix_ready(FWD_PORT) {
            eprintln!("sshd matrix down — skipping");
            return;
        }
        let err = SshSpikeSession::connect(
            SshSpikeConnectParams {
                host: HOST.to_string(),
                port: INNER_SSHD_PORT,
                username: USER.to_string(),
                auth: password_auth(),
                cols: 80,
                rows: 24,
                via: vec![SshSpikeJump {
                    host: HOST.to_string(),
                    port: FWD_PORT,
                    username: USER.to_string(),
                    auth: SshSpikeAuth::Password {
                        password: "wrong-hop-password".to_string(),
                    },
                }],
                keep_alive_seconds: 15,
            },
            Box::new(Collector::default()),
            Box::new(AcceptVerifier::default()),
            Box::new(NullForwardSink),
        )
        .err()
        .expect("the hop's wrong password must fail the dial");
        match err {
            SshSpikeError::Auth(detail) => {
                assert!(
                    detail.starts_with("jump to 127.0.0.1:2235"),
                    "the failure must name the failing hop, got: {detail}"
                );
            }
            other => panic!("expected Auth, got {other:?}"),
        }
    }

    #[test]
    fn jump_chain_reaches_a_target_that_has_no_direct_route() {
        if !matrix_ready(FWD_PORT) || !matrix_ready(PW_PORT) {
            eprintln!("sshd matrix down — skipping");
            return;
        }
        let verifier = AcceptVerifier::default();
        let events = Collector::default();
        let session = SshSpikeSession::connect(
            SshSpikeConnectParams {
                // the target: the password sshd on the CONTAINER's network
                host: HOST.to_string(),
                port: INNER_SSHD_PORT,
                username: USER.to_string(),
                auth: password_auth(),
                cols: 80,
                rows: 24,
                via: vec![SshSpikeJump {
                    host: HOST.to_string(),
                    port: FWD_PORT,
                    username: USER.to_string(),
                    auth: password_auth(),
                }],
                keep_alive_seconds: 15,
            },
            Box::new(events.clone()),
            Box::new(verifier.clone()),
            Box::new(NullForwardSink),
        )
        .expect("2-hop connect");
        session
            .write(b"echo ok-jump\r\n".to_vec())
            .expect("write through the chain");
        assert!(events
            .wait_for(
                |e| matches!(e, SshSpikeEvent::Data { data }
                    if data.windows(7).any(|w| w == b"ok-jump")),
                "shell output through the jump chain"
            )
            .is_some());
        // one exec over the target connection through the chain
        assert_eq!(
            session
                .exec("echo jump-exec".to_string())
                .expect("exec")
                .trim(),
            "jump-exec"
        );
        // the verifier saw BOTH endpoints: the hop's (2235) and the
        // target's container-side (2223) — never the host-mapped 2233
        let seen = verifier.0.lock().unwrap();
        let endpoints: Vec<&String> = seen.iter().map(|(e, _, _)| e).collect();
        assert!(
            endpoints.contains(&&format!("{HOST}:{FWD_PORT}")),
            "hop key must be verified against the hop endpoint: {endpoints:?}"
        );
        assert!(
            endpoints.contains(&&format!("{HOST}:{INNER_SSHD_PORT}")),
            "target key must be verified against the target endpoint: {endpoints:?}"
        );
        drop(seen);
        session.disconnect();
    }

    /// The TransferQueue contract: chunked reads/writes for large files.
    #[test]
    fn sftp_streaming_handles_read_and_write_in_chunks() {
        if !matrix_ready(PW_PORT) {
            eprintln!("sshd matrix down — skipping");
            return;
        }
        let session = connect_shell(
            Box::new(AcceptVerifier::default()),
            Box::new(Collector::default()),
        )
        .expect("connect");
        let sftp = session.sftp().expect("sftp open");
        let path = "/tmp/conch-sftp-stream-test";
        sftp.create_dir(path.to_string()).ok();

        // write three chunks through a write handle
        let wh = sftp
            .open_write(format!("{path}/blob.bin"))
            .expect("open write");
        for chunk in [vec![7u8; 1000], vec![8u8; 1000], vec![9u8; 500]] {
            wh.write(chunk).expect("chunk write");
        }
        wh.disconnect();

        // metadata reflects the full size
        let meta = sftp.metadata(format!("{path}/blob.bin")).expect("stat");
        assert_eq!(meta.size, 2500);

        // read back chunked until EOF
        let rh = sftp
            .open_read(format!("{path}/blob.bin"))
            .expect("open read");
        let mut total = Vec::new();
        loop {
            let chunk = rh.read(700).expect("chunk read");
            if chunk.is_empty() {
                break; // EOF
            }
            total.extend(chunk);
        }
        rh.disconnect();
        assert_eq!(total.len(), 2500);
        assert!(total[..1000].iter().all(|&b| b == 7));
        assert!(total[1000..2000].iter().all(|&b| b == 8));
        assert!(total[2000..].iter().all(|&b| b == 9));

        sftp.remove_file(format!("{path}/blob.bin")).expect("rm");
        sftp.remove_dir(path.to_string()).expect("rmdir");
        session.disconnect();
    }

    /// Multi-megabyte round trip (soak insurance): disconnect() is
    /// fire-and-forget, so a drop-without-flush loss would only show at a
    /// size larger than every internal buffer.
    #[test]
    fn sftp_streaming_survives_multi_megabyte_round_trips() {
        if !matrix_ready(PW_PORT) {
            eprintln!("sshd matrix down — skipping");
            return;
        }
        let session = connect_shell(
            Box::new(AcceptVerifier::default()),
            Box::new(Collector::default()),
        )
        .expect("connect");
        let sftp = session.sftp().expect("sftp open");
        let path = "/tmp/conch-sftp-big-test";
        sftp.create_dir(path.to_string()).ok();

        let mut payload = Vec::with_capacity(4 << 20);
        let mut byte = 0u8;
        for _ in 0..(4 << 20) {
            payload.push(byte);
            byte = byte.wrapping_add(1);
        }

        let wh = sftp
            .open_write(format!("{path}/big.bin"))
            .expect("open write");
        for chunk in payload.chunks(256 * 1024) {
            wh.write(chunk.to_vec()).expect("chunk write");
        }
        wh.disconnect();

        let meta = sftp.metadata(format!("{path}/big.bin")).expect("stat");
        assert_eq!(meta.size, payload.len() as u64);

        let rh = sftp
            .open_read(format!("{path}/big.bin"))
            .expect("open read");
        let mut read_back = Vec::with_capacity(payload.len());
        loop {
            let chunk = rh.read(256 * 1024).expect("chunk read");
            if chunk.is_empty() {
                break;
            }
            read_back.extend(chunk);
        }
        rh.disconnect();
        assert_eq!(read_back, payload, "4 MB round trip must be byte-exact");

        sftp.remove_file(format!("{path}/big.bin")).expect("rm");
        sftp.remove_dir(path.to_string()).expect("rmdir");
        session.disconnect();
    }

    #[test]
    fn sftp_reads_a_file() {
        if !matrix_ready(PW_PORT) {
            eprintln!("sshd matrix down — skipping");
            return;
        }
        let session = connect_shell(
            Box::new(AcceptVerifier::default()),
            Box::new(Collector::default()),
        )
        .expect("connect");
        let data = session
            .sftp_read("/etc/hostname".to_string())
            .expect("sftp read");
        assert!(!data.is_empty(), "hostname file must not be empty");
        session.disconnect();
    }

    /// Records inbound -R connections and echoes ONE payload back, then
    /// half-closes — so the dialing side can assert a full round trip AND
    /// the strict-proxy FIN propagation through the sink.
    #[derive(Clone, Default)]
    struct EchoForwardSink(Arc<Mutex<Vec<(String, u32)>>>);

    impl SshSpikeForwardSink for EchoForwardSink {
        fn on_connection(
            &self,
            bind_host: String,
            bind_port: u32,
            channel: std::sync::Arc<SshSpikeChannel>,
        ) {
            self.0.lock().unwrap().push((bind_host, bind_port));
            std::thread::spawn(move || {
                // one round trip, then half-close: the sink is the far end
                // of the bridge the facades build
                if let Ok(chunk) = channel.read() {
                    if !chunk.is_empty() {
                        let _ = channel.write(chunk);
                    }
                }
                let _ = channel.eof();
            });
        }
    }

    #[test]
    fn sftp_offset_read_returns_only_the_tail() {
        if !matrix_ready(FWD_PORT) {
            eprintln!("sshd matrix down — skipping");
            return;
        }
        let session = SshSpikeSession::connect(
            SshSpikeConnectParams {
                host: HOST.to_string(),
                port: FWD_PORT,
                username: USER.to_string(),
                auth: password_auth(),
                cols: 80,
                rows: 24,
                via: Vec::new(),
                keep_alive_seconds: 15,
            },
            Box::new(Collector::default()),
            Box::new(AcceptVerifier::default()),
            Box::new(NullForwardSink),
        )
        .expect("connect");
        let sftp = session.sftp().expect("sftp open");
        let path = "/tmp/conch-sftp-offset-test";
        let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let wh = sftp.open_write(path.to_string()).expect("open write");
        wh.write(payload.clone()).expect("write");
        wh.disconnect();

        // resume semantics: a read opened at an offset returns ONLY the tail
        let rh = sftp
            .open_read_at(path.to_string(), 40_000)
            .expect("open read at");
        let mut tail = Vec::new();
        loop {
            let chunk = rh.read(64 * 1024).expect("chunk read");
            if chunk.is_empty() {
                break;
            }
            tail.extend(chunk);
        }
        rh.disconnect();
        assert_eq!(tail, payload[40_000..], "offset read must return the tail");
        sftp.remove_file(path.to_string()).expect("rm");
        session.disconnect();
    }

    #[test]
    fn remote_forward_sink_receives_server_side_connections() {
        if !matrix_ready(FWD_PORT) {
            eprintln!("sshd matrix down — skipping");
            return;
        }
        let sink = EchoForwardSink::default();
        let session = SshSpikeSession::connect(
            SshSpikeConnectParams {
                host: HOST.to_string(),
                port: FWD_PORT,
                username: USER.to_string(),
                auth: password_auth(),
                cols: 80,
                rows: 24,
                via: Vec::new(),
                keep_alive_seconds: 15,
            },
            Box::new(Collector::default()),
            Box::new(AcceptVerifier::default()),
            Box::new(sink.clone()),
        )
        .expect("connect to fwd instance");
        // port 0 = the server picks the bound port
        let bound = session
            .request_remote_forward("127.0.0.1".to_string(), 0)
            .expect("tcpip-forward");
        assert!(bound > 0, "server must report the bound port");
        // Dial the -R port FROM THE SERVER's view (direct-tcpip): the
        // server then opens a forwarded-tcpip channel back to us, the
        // router must hand it to the sink, and the sink's echo must come
        // back through the dialing channel — the whole -R chain in one
        // round trip.
        let dial = session
            .open_direct_tcpip("127.0.0.1".to_string(), bound)
            .expect("dial the -R port server-side");
        dial.write(b"ping-through-r".to_vec()).expect("write");
        dial.eof().expect("half-close after the payload");
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let echoed = loop {
            if std::time::Instant::now() > deadline {
                break None;
            }
            let chunk = dial.read().expect("read");
            if !chunk.is_empty() {
                break Some(chunk);
            }
        };
        assert_eq!(
            echoed.as_deref(),
            Some(&b"ping-through-r"[..]),
            "payload must round-trip through the -R sink"
        );
        // the sink half-closed after echoing: that FIN must surface as EOF,
        // not be swallowed by the read loop
        let fin = dial.read().expect("read after the sink's EOF");
        assert!(
            fin.is_empty(),
            "expected EOF after the sink half-closed, got {fin:?}"
        );
        dial.disconnect();
        let seen = sink.0.lock().unwrap().clone();
        assert!(
            seen.iter().any(|(h, p)| h == "127.0.0.1" && *p == bound),
            "sink must see the inbound connection on {bound}, saw {seen:?}"
        );
        session.disconnect();
    }
}
