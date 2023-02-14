use crate::crypto::boring::alpn::AlpnProtocols;
use crate::crypto::boring::bffi_ext::QuicSslContext;
use crate::crypto::boring::error::{map_result, Result};
use crate::crypto::boring::session_state::SessionState;
use crate::crypto::boring::version::QuicVersion;
use crate::crypto::boring::{
    param_util, Entry, HandshakeData, QuicSsl, QuicSslSession, SessionCache, SimpleCache,
};
use crate::transport_parameters::TransportParameters;
use crate::{crypto, ConnectError, ConnectionId, Side};
use boring::ssl::{
    NameType, Ssl, SslContext, SslContextBuilder, SslMethod, SslSession, SslVerifyMode, SslVersion,
};
use boring_sys as bffi;
use bytes::Bytes;
use foreign_types_shared::ForeignType;
use lazy_static::lazy_static;
use std::any::Any;
use std::ffi::c_int;
use std::io::Cursor;
use std::result::Result as StdResult;
use std::sync::Arc;
use tracing::{trace, warn};

/// Configuration for a client-side QUIC. Wraps around a BoringSSL [SslContextBuilder].
pub struct Config {
    pub ctx: SslContext,
    pub session_cache: Arc<dyn SessionCache>,
}

impl Config {
    pub fn new() -> Result<Self> {
        let mut builder = SslContextBuilder::new(SslMethod::tls())?;

        // QUIC requires TLS 1.3.
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

        builder.set_default_verify_paths()?;

        // We build the context early, since we are not allowed to further mutate the context
        // in start_session.
        let mut ctx = builder.build();

        // Set the callbacks for the SessionState.
        SessionState::set_callbacks(&mut ctx)?;

        // By default, enable early data (used for 0-RTT).
        ctx.enable_early_data(true);

        // Set the default ALPN protocols offered by the client. QUIC requires ALPN be configured
        // (see https://www.rfc-editor.org/rfc/rfc9001.html#section-8.1).
        ctx.set_alpn_protos(&AlpnProtocols::default().encode())?;

        // Configure session caching.
        ctx.set_session_cache_mode(bffi::SSL_SESS_CACHE_CLIENT | bffi::SSL_SESS_CACHE_NO_INTERNAL);
        ctx.set_new_session_callback(Some(Session::new_session_callback));

        Ok(Self {
            ctx,
            session_cache: Arc::new(SimpleCache::new(256)),
        })
    }

    /// Sets the ALPN protocols supported by this side. QUIC requires that
    /// ALPN be used (see https://www.rfc-editor.org/rfc/rfc9001.html#section-8.1).
    /// This method should be called, rather than setting on the underlying
    /// [SslContextBuilder] directly. If this method is not called, or an empty list
    /// is provided, the client will default to offering "h3".
    pub fn set_alpn_protos(&mut self, protos: &[Vec<u8>]) -> Result<()> {
        self.ctx
            .set_alpn_protos(&AlpnProtocols::from(protos).encode())?;
        Ok(())
    }
}

impl crypto::ClientConfig for Config {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> StdResult<Box<dyn crypto::Session>, ConnectError> {
        let version = QuicVersion::parse(version).unwrap();

        Ok(Session::new(self.clone(), version, server_name, params)
            .map_err(|_| ConnectError::EndpointStopping)?)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

lazy_static! {
    static ref SESSION_INDEX: c_int = unsafe {
        bffi::SSL_get_ex_new_index(0, std::ptr::null_mut(), std::ptr::null_mut(), None, None)
    };
}

/// The [crypto::Session] implementation for BoringSSL.
struct Session {
    state: SessionState,
    server_name: Bytes,
    session_cache: Arc<dyn SessionCache>,
    zero_rtt_peer_params: Option<TransportParameters>,
    handshake_data_available: bool,
    handshake_data_sent: bool,
}

impl Session {
    fn new(
        cfg: Arc<Config>,
        version: QuicVersion,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<Self>> {
        let session_cache = cfg.session_cache.clone();
        let mut ssl = Ssl::new(&cfg.ctx).unwrap();

        // Configure the TLS extension based on the QUIC version used.
        ssl.set_quic_use_legacy_codepoint(version.uses_legacy_extension());

        // Configure the SSL to be a client.
        ssl.set_connect_state();

        // Configure verification for the server hostname.
        ssl.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        ssl.set_verify_hostname(server_name)
            .map_err(|_| ConnectError::InvalidDnsName(server_name.into()))?;

        // Set the SNI hostname.
        // TODO: should we validate the hostname?
        ssl.set_hostname(server_name)
            .map_err(|_| ConnectError::InvalidDnsName(server_name.into()))?;

        // Set the transport parameters.
        ssl.set_quic_transport_params(&param_util::encode_params(params))
            .map_err(|_| ConnectError::EndpointStopping)?;

        let server_name_bytes = Bytes::copy_from_slice(server_name.as_bytes());

        // If we have a cached session, use it.
        let mut zero_rtt_peer_params = None;
        if let Some(entry) = session_cache.get(server_name_bytes.clone()) {
            match Entry::decode(ssl.ssl_context(), &mut entry.clone()) {
                Ok(entry) => {
                    zero_rtt_peer_params = Some(entry.params);
                    match unsafe { ssl.set_session(entry.session.as_ref()) } {
                        Ok(()) => {
                            trace!("attempting resumption (0-RTT) for server: {}.", server_name);
                        }
                        Err(e) => {
                            warn!(
                                "failed setting cached session for server {}: {:?}",
                                server_name, e
                            )
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "failed decoding session entry for server {}: {:?}",
                        server_name, e
                    )
                }
            }
        } else {
            trace!(
                "no cached session found for server: {}. Will continue with 1-RTT.",
                server_name
            );
        }

        let mut session = Box::new(Self {
            state: SessionState::new(ssl, Side::Client, version)?,
            server_name: server_name_bytes,
            session_cache,
            zero_rtt_peer_params,
            handshake_data_available: false,
            handshake_data_sent: false,
        });

        // Register the state instance for callbacks.
        session.state.set_ex_data()?;

        // Register the instance in SSL ex_data. This allows the static callbacks to
        // reference the instance.
        unsafe {
            map_result(bffi::SSL_set_ex_data(
                session.state.ssl.as_ptr(),
                *SESSION_INDEX,
                &mut *session as *mut Self as *mut _,
            ))?;
        }

        // Start the handshake in order to emit the Client Hello on the first
        // call to write_handshake.
        session.state.advance_handshake()?;

        Ok(session)
    }

    /// Handler for the rejection of a 0-RTT attempt. Will continue with 1-RTT.
    fn on_zero_rtt_rejected(&mut self) {
        trace!(
            "0-RTT handshake attempted but was rejected by the server: {}",
            Ssl::early_data_reason_string(self.state.ssl.get_early_data_reason())
        );

        self.zero_rtt_peer_params = None;

        // Removed the failed cache entry.
        self.session_cache.remove(self.server_name.clone());

        // Now retry advancing the handshake, this time in 1-RTT mode.
        if let Err(e) = self.state.advance_handshake() {
            warn!("failed advancing 1-RTT handshake: {:?}", e)
        }
    }

    /// Client-side only callback from BoringSSL to allow caching of a new session.
    fn on_new_session(&mut self, session: SslSession) {
        println!("NM[{:?}]:     on_new_session", Side::Client);

        if !session.early_data_capable() {
            warn!("failed caching session: not early data capable");
            return;
        }

        // Get the server transport parameters.
        let params = match self.state.ssl.get_peer_quic_transport_params() {
            Some(params) => {
                match TransportParameters::read(Side::Client, &mut Cursor::new(&params)) {
                    Ok(params) => params,
                    Err(e) => {
                        warn!("failed parsing server transport parameters: {:?}", e);
                        return;
                    }
                }
            }
            None => {
                warn!("failed caching session: server transport parameters are not available");
                return;
            }
        };

        // Encode the session cache entry, including both the session and the server params.
        let entry = Entry { session, params };
        match entry.encode() {
            Ok(value) => {
                // Cache the session.
                self.session_cache.put(self.server_name.clone(), value)
            }
            Err(e) => {
                warn!("failed caching session: unable to encode entry: {:?}", e);
            }
        }
    }

    /// Called by the static callbacks to retrieve the instance pointer.
    #[inline]
    fn get_instance(ssl: *const bffi::SSL) -> &'static mut Session {
        unsafe {
            let data = bffi::SSL_get_ex_data(ssl, *SESSION_INDEX);
            if data.is_null() {
                panic!("BUG: Session instance missing")
            }
            &mut *(data as *mut Session)
        }
    }

    /// Raw callback from BoringSSL.
    extern "C" fn new_session_callback(
        ssl: *mut bffi::SSL,
        session: *mut bffi::SSL_SESSION,
    ) -> c_int {
        let inst = Self::get_instance(ssl);
        let session = unsafe { SslSession::from_ptr(session) };
        inst.on_new_session(session);

        // Return 1 to indicate we've taken ownership of the session.
        1
    }
}

impl crypto::Session for Session {
    #[inline]
    fn initial_keys(&self, dcid: &ConnectionId, side: Side) -> crypto::Keys {
        self.state.initial_keys(dcid, side)
    }

    #[inline]
    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        println!("NM[{:?}]: handshake_data", Side::Client);
        if self.handshake_data_available {
            let sni_name = match self.state.ssl.servername(NameType::HOST_NAME) {
                Some(server_name) => Some(server_name.to_string()),
                None => None,
            };
            let alpn_protocol = match self.state.ssl.selected_alpn_protocol() {
                Some(protocol) => Some(Vec::from(protocol)),
                None => None,
            };
            return Some(Box::new(HandshakeData {
                protocol: alpn_protocol,
                server_name: sni_name,
            }));
        }

        None
    }

    #[inline]
    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.state.peer_identity()
    }

    #[inline]
    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        self.state.early_crypto()
    }

    #[inline]
    fn early_data_accepted(&self) -> Option<bool> {
        println!("NM[{:?}]: early_data_accepted", Side::Client);
        Some(self.state.ssl.early_data_accepted())
    }

    #[inline]
    fn is_handshaking(&self) -> bool {
        self.state.is_handshaking()
    }

    #[inline]
    fn read_handshake(&mut self, plaintext: &[u8]) -> StdResult<bool, crypto::TransportError> {
        println!("NM[{:?}]: read_handshake", Side::Client);
        self.state.read_handshake(plaintext)?;

        if self.state.early_data_rejected {
            self.on_zero_rtt_rejected();
        }

        // Only indicate that handshake data is available once.
        // On the client side there is no ALPN callback, so we need to manually check
        // if the ALPN protocol has been selected.
        if !self.handshake_data_sent {
            if self.state.ssl.selected_alpn_protocol().is_some() {
                self.handshake_data_available = true;
            }

            if self.handshake_data_available {
                self.handshake_data_sent = true;
                return Ok(true);
            }
        }

        Ok(false)
    }

    #[inline]
    fn transport_parameters(
        &self,
    ) -> StdResult<Option<TransportParameters>, crypto::TransportError> {
        match self.state.transport_parameters()? {
            Some(params) => Ok(Some(params)),
            None => {
                if self.state.ssl.in_early_data() {
                    println!(
                        "NM[{:?}]: transport_parameters (0-RTT)={:?}",
                        Side::Client,
                        self.zero_rtt_peer_params
                    );
                    Ok(self.zero_rtt_peer_params)
                } else {
                    Ok(None)
                }
            }
        }
    }

    #[inline]
    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<crypto::Keys> {
        self.state.write_handshake(buf)
    }

    #[inline]
    fn next_1rtt_keys(&mut self) -> Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>> {
        self.state.next_1rtt_keys()
    }

    #[inline]
    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.state.is_valid_retry(orig_dst_cid, header, payload)
    }

    #[inline]
    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> StdResult<(), crypto::ExportKeyingMaterialError> {
        self.state.export_keying_material(output, label, context)
    }
}
