use crate::crypto::boring::alpn::AlpnProtocols;
use crate::crypto::boring::bffi_ext::{Level, QuicSsl};
use crate::crypto::boring::error::{map_result, Result};
use crate::crypto::boring::key::{AeadKey, HeaderKey, Key, Nonce, PacketKey};
use crate::crypto::boring::secret::{Secret, Secrets};
use crate::crypto::boring::session_state::SessionState;
use crate::crypto::boring::suite::CipherSuite;
use crate::crypto::boring::version::QuicVersion;
use crate::crypto::boring::{param_util, HandshakeData, QuicSslContext};
use crate::transport_parameters::TransportParameters;
use crate::{crypto, ConnectionId, Side};
use boring::ssl::{
    NameType, Ssl, SslContext, SslContextBuilder, SslMethod, SslVerifyMode, SslVersion,
};
use boring_sys as bffi;
use foreign_types_shared::ForeignType;
use lazy_static::lazy_static;
use std::any::Any;
use std::ffi::{c_char, c_int, c_uint, c_void, CStr};
use std::result::Result as StdResult;
use std::slice;
use std::sync::Arc;

/// Configuration for a server-side QUIC. Wraps around a BoringSSL [SslContextBuilder].
pub struct Config {
    pub ctx: SslContext,
    pub alpn_protos: AlpnProtocols,
    pub enable_client_auth: bool,

    /// State for the application-level protocol. For HTTP/3, this should be the serialized server
    /// SETTINGS frame.
    ///
    /// This is used internally to set the early data context.
    /// See https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_set_quic_early_data_context
    pub application_state: Option<Vec<u8>>,
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

        // Configure default ALPN protocols accepted by the server.QUIC requires ALPN be
        // configured (see https://www.rfc-editor.org/rfc/rfc9001.html#section-8.1).
        ctx.set_alpn_select_cb(Some(Session::alpn_select_callback));

        // Set the callback for receipt of the Server Name Indication (SNI) extension.
        ctx.set_server_name_cb(Some(Session::server_name_callback));

        // Set the callback for handling keylog events. This is required on the server-side
        // in order to get access to the early client traffic secret.
        ctx.set_keylog_callback(Some(Session::keylog_callback));

        ctx.set_options(bffi::SSL_OP_CIPHER_SERVER_PREFERENCE as u32);

        Ok(Self {
            ctx,
            alpn_protos: AlpnProtocols::default(),
            enable_client_auth: false,
            application_state: None,
        })
    }

    /// Sets the ALPN protocols that will be accepted by the server. QUIC requires that
    /// ALPN be used (see https://www.rfc-editor.org/rfc/rfc9001.html#section-8.1).
    ///
    /// If this method is not called, or an empty list is provided, the server will
    /// default to accepting "h3".
    pub fn set_alpn_protos(&mut self, protos: &[Vec<u8>]) {
        self.alpn_protos = AlpnProtocols::from(protos)
    }
}

impl crypto::ServerConfig for Config {
    fn initial_keys(
        &self,
        version: u32,
        dcid: &ConnectionId,
        side: Side,
    ) -> StdResult<crypto::Keys, crypto::UnsupportedVersion> {
        let version = QuicVersion::parse(version)?;
        let secrets = Secrets::initial(version, dcid, side).unwrap();
        Ok(secrets.keys().unwrap().as_crypto().unwrap())
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        let version = QuicVersion::parse(version).unwrap();
        let suite = CipherSuite::aes128_gcm_sha256();
        let key = Key::from(version.retry_integrity_key());
        let nonce = Nonce::from(version.retry_integrity_nonce());
        let key = AeadKey::new(suite, &key, suite.aead.zero_nonce.clone()).unwrap();

        let mut pseudo_packet = Vec::with_capacity(packet.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(packet);

        // Encrypt using the packet as additional data.
        let mut encrypted = Vec::from(&[0; 16][..]);
        key.seal_in_place(&nonce, &pseudo_packet, &mut encrypted)
            .unwrap();
        let tag_start = encrypted.len() - 16;

        // Now extract the tag that was written.
        let mut tag = [0; 16];
        tag.copy_from_slice(&encrypted[tag_start..]);
        tag
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        let version = QuicVersion::parse(version).unwrap();
        Session::new(self.clone(), version, params).unwrap()
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
    alpn: AlpnProtocols,
    handshake_data_available: bool,
    handshake_data_sent: bool,
    handshaking: bool,
}

impl Session {
    fn new(
        cfg: Arc<Config>,
        version: QuicVersion,
        params: &TransportParameters,
    ) -> Result<Box<Self>> {
        let mut ssl = Ssl::new(&cfg.ctx).unwrap();

        // Configure the TLS extension based on the QUIC version used.
        ssl.set_quic_use_legacy_codepoint(version.uses_legacy_extension());

        // Configure the SSL to be a server.
        ssl.set_accept_state();

        if cfg.enable_client_auth {
            ssl.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        } else {
            ssl.set_verify(SslVerifyMode::NONE);
        }

        // Set the transport parameters.
        ssl.set_quic_transport_params(&param_util::encode_params(params))
            .unwrap();

        ssl.set_quic_early_data_context(&param_util::encode_early_data_context(
            params,
            &cfg.application_state,
        ))
        .unwrap();

        let mut session = Box::new(Self {
            state: SessionState::new(ssl, Side::Server, version)?,
            alpn: cfg.alpn_protos.clone(),
            handshake_data_available: false,
            handshake_data_sent: false,
            handshaking: true,
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

        Ok(session)
    }

    fn on_keylog(&mut self, line: &str) {
        // Hack to access the early client application secret. It is generated internally within
        // BoringSSL during the generation of the Server Hello, but is not made available
        // until the second client flight is processed. The QUIC layer needs both application-level
        // secrets immediately after writing the Server Hello, however. This appears to be the
        // only way available to get access to the secret.

        // The log line is in the form: <label>(sp)<random>(sp)<secret>.
        let parts: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(parts.len(), 3);
        let label = parts[0];
        //let random = parts[1];
        let secret = parts[2];

        if label == "CLIENT_TRAFFIC_SECRET_0" {
            // Set the early client application-level secret.
            let secret = Secret::parse_hex_string(secret).unwrap();
            let suite = CipherSuite::aes256_gcm_sha384();
            println!(
                "NM[{:?}]:     on_keylog: forcing early Application read secret: suite={:?}, secret={:?}, header_key={:?}, packet_key={:?}",
                Side::Server,
                suite,
                &secret,
                HeaderKey::new(self.state.version, suite, &secret).unwrap(),
                PacketKey::new(self.state.version, suite, &secret).unwrap(),
            );

            self.state.level_state_mut(Level::Application)
                .builder
                .set_remote_secret(secret);
        }
    }

    /// Server-side only callback from BoringSSL to select the ALPN protocol.
    #[inline]
    fn on_alpn_select<'a>(&mut self, offered: &'a [u8]) -> Result<&'a [u8]> {
        println!("NM[{:?}]:     on_alpn_select", Side::Server);
        // Indicate that we now have handshake data available.
        self.handshake_data_available = true;

        self.alpn.select_from(offered)
    }

    /// Server-side only callback from BoringSSL indicating that the Server Name Indication (SNI)
    /// extension in the client hello was successfully parsed.
    #[inline]
    fn on_server_name(&mut self, _: *mut c_int) -> c_int {
        println!("NM[{:?}]:     on_server_name", Side::Server);
        // Indicate that we now have handshake data available.
        self.handshake_data_available = true;

        // SSL_TLSEXT_ERR_OK causes the server_name extension to be acked in
        // ServerHello.
        return bffi::SSL_TLSEXT_ERR_OK;
    }
}

// Raw callbacks from BoringSSL
impl Session {
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

    extern "C" fn keylog_callback(ssl: *const bffi::SSL, line: *const c_char) {
        let inst = Self::get_instance(ssl);
        let line = unsafe { CStr::from_ptr(line).to_str().unwrap() };
        inst.on_keylog(line);
    }

    extern "C" fn alpn_select_callback(
        ssl: *mut bffi::SSL,
        out: *mut *const u8,
        out_len: *mut u8,
        in_: *const u8,
        in_len: c_uint,
        _: *mut c_void,
    ) -> c_int {
        let inst = Self::get_instance(ssl);

        unsafe {
            let protos = slice::from_raw_parts(in_, in_len as _);
            match inst.on_alpn_select(protos) {
                Ok(proto) => {
                    *out = proto.as_ptr() as _;
                    *out_len = proto.len() as _;
                    bffi::SSL_TLSEXT_ERR_OK
                }
                Err(_) => bffi::SSL_TLSEXT_ERR_ALERT_FATAL,
            }
        }
    }

    extern "C" fn server_name_callback(
        ssl: *mut bffi::SSL,
        out_alert: *mut c_int,
        _: *mut c_void,
    ) -> c_int {
        let inst = Self::get_instance(ssl);
        inst.on_server_name(out_alert)
    }
}

impl crypto::Session for Session {
    #[inline]
    fn initial_keys(&self, dcid: &ConnectionId, side: Side) -> crypto::Keys {
        self.state.initial_keys(dcid, side)
    }

    #[inline]
    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        println!("NM[{:?}]: handshake_data", Side::Server);
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
        None
    }

    #[inline]
    fn is_handshaking(&self) -> bool {
        self.state.is_handshaking()
    }

    #[inline]
    fn read_handshake(&mut self, plaintext: &[u8]) -> StdResult<bool, crypto::TransportError> {
        self.state.read_handshake(plaintext)?;

        // Only indicate that handshake data is available once.
        if !self.handshake_data_sent && self.handshake_data_available {
            self.handshake_data_sent = true;
            return Ok(true);
        }

        Ok(false)
    }

    #[inline]
    fn transport_parameters(
        &self,
    ) -> StdResult<Option<TransportParameters>, crypto::TransportError> {
        self.state.transport_parameters()
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
