use std::any::Any;
use std::{
    cmp,
    collections::{HashMap, VecDeque},
    env,
    io::{self, Write},
    mem,
    net::{Ipv6Addr, SocketAddr, UdpSocket},
    ops::RangeFrom,
    str,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::crypto::boring::QuicSslContext;
use crate::crypto::HmacKey;
use assert_matches::assert_matches;
use boring::pkey::PKey;
use boring::x509::X509;
use lazy_static::lazy_static;
use rand::RngCore;
use rcgen::{BasicConstraints, CertificateParams, IsCa};
use ring::hmac;
use rustls::{Certificate, KeyLogFile, PrivateKey};
use tracing::{info_span, trace};

use super::*;

pub struct Pair {
    pub server: TestEndpoint,
    pub client: TestEndpoint,
    pub time: Instant,
    // One-way
    pub latency: Duration,
    /// Number of spin bit flips
    pub spins: u64,
    last_spin: bool,
}

impl Pair {
    pub fn new(endpoint_config: Arc<EndpointConfig>, server_config: Arc<ServerConfig>) -> Self {
        let server = Endpoint::new(endpoint_config.clone(), Some(server_config));
        let client = Endpoint::new(endpoint_config, None);

        Pair::new_from_endpoint(client, server)
    }

    pub fn for_provider(p: Provider) -> Self {
        Pair::new(Default::default(), Arc::new(p.server_config()))
    }

    pub fn new_from_endpoint(client: Endpoint, server: Endpoint) -> Self {
        let server_addr = SocketAddr::new(
            Ipv6Addr::LOCALHOST.into(),
            SERVER_PORTS.lock().unwrap().next().unwrap(),
        );
        let client_addr = SocketAddr::new(
            Ipv6Addr::LOCALHOST.into(),
            CLIENT_PORTS.lock().unwrap().next().unwrap(),
        );
        Self {
            server: TestEndpoint::new(server, server_addr),
            client: TestEndpoint::new(client, client_addr),
            time: Instant::now(),
            latency: Duration::new(0, 0),
            spins: 0,
            last_spin: false,
        }
    }

    /// Returns whether the connection is not idle
    pub fn step(&mut self) -> bool {
        self.drive_client();
        self.drive_server();
        if self.client.is_idle() && self.server.is_idle() {
            return false;
        }

        let client_t = self.client.next_wakeup();
        let server_t = self.server.next_wakeup();
        match min_opt(client_t, server_t) {
            Some(t) if Some(t) == client_t => {
                if t != self.time {
                    self.time = self.time.max(t);
                    trace!("advancing to {:?} for client", self.time);
                }
                true
            }
            Some(t) if Some(t) == server_t => {
                if t != self.time {
                    self.time = self.time.max(t);
                    trace!("advancing to {:?} for server", self.time);
                }
                true
            }
            Some(_) => unreachable!(),
            None => false,
        }
    }

    /// Advance time until both connections are idle
    pub fn drive(&mut self) {
        while self.step() {}
    }

    pub fn drive_client(&mut self) {
        let span = info_span!("client");
        let _guard = span.enter();
        self.client.drive(self.time, self.server.addr);
        for x in self.client.outbound.drain(..) {
            if x.contents[0] & packet::LONG_HEADER_FORM == 0 {
                let spin = x.contents[0] & packet::SPIN_BIT != 0;
                self.spins += (spin == self.last_spin) as u64;
                self.last_spin = spin;
            }
            if let Some(ref socket) = self.client.socket {
                socket.send_to(&x.contents, x.destination).unwrap();
            }
            if self.server.addr == x.destination {
                self.server
                    .inbound
                    .push_back((self.time + self.latency, x.ecn, x.contents));
            }
        }
    }

    pub fn drive_server(&mut self) {
        let span = info_span!("server");
        let _guard = span.enter();
        self.server.drive(self.time, self.client.addr);
        for x in self.server.outbound.drain(..) {
            if let Some(ref socket) = self.server.socket {
                socket.send_to(&x.contents, x.destination).unwrap();
            }
            if self.client.addr == x.destination {
                self.client
                    .inbound
                    .push_back((self.time + self.latency, x.ecn, x.contents));
            }
        }
    }

    pub fn connect(&mut self, p: Provider) -> (ConnectionHandle, ConnectionHandle) {
        self.connect_with(p.client_config())
    }

    pub fn connect_with(&mut self, config: ClientConfig) -> (ConnectionHandle, ConnectionHandle) {
        info!("connecting");
        let client_ch = self.begin_connect(config);
        self.drive();
        let server_ch = self.server.assert_accept();
        self.finish_connect(client_ch, server_ch);
        (client_ch, server_ch)
    }

    /// Just start connecting the client
    pub fn begin_connect(&mut self, config: ClientConfig) -> ConnectionHandle {
        let span = info_span!("client");
        let _guard = span.enter();
        let (client_ch, client_conn) = self
            .client
            .connect(config, self.server.addr, "localhost")
            .unwrap();
        self.client.connections.insert(client_ch, client_conn);
        client_ch
    }

    fn finish_connect(&mut self, client_ch: ConnectionHandle, server_ch: ConnectionHandle) {
        assert_matches!(
            self.client_conn_mut(client_ch).poll(),
            Some(Event::HandshakeDataReady)
        );
        assert_matches!(
            self.client_conn_mut(client_ch).poll(),
            Some(Event::Connected { .. })
        );
        assert_matches!(
            self.server_conn_mut(server_ch).poll(),
            Some(Event::HandshakeDataReady)
        );
        assert_matches!(
            self.server_conn_mut(server_ch).poll(),
            Some(Event::Connected { .. })
        );
    }

    pub fn client_conn_mut(&mut self, ch: ConnectionHandle) -> &mut Connection {
        self.client.connections.get_mut(&ch).unwrap()
    }

    pub fn client_streams(&mut self, ch: ConnectionHandle) -> Streams<'_> {
        self.client_conn_mut(ch).streams()
    }

    pub fn client_send(&mut self, ch: ConnectionHandle, s: StreamId) -> SendStream<'_> {
        self.client_conn_mut(ch).send_stream(s)
    }

    pub fn client_recv(&mut self, ch: ConnectionHandle, s: StreamId) -> RecvStream<'_> {
        self.client_conn_mut(ch).recv_stream(s)
    }

    pub fn client_datagrams(&mut self, ch: ConnectionHandle) -> Datagrams<'_> {
        self.client_conn_mut(ch).datagrams()
    }

    pub fn server_conn_mut(&mut self, ch: ConnectionHandle) -> &mut Connection {
        self.server.connections.get_mut(&ch).unwrap()
    }

    pub fn server_streams(&mut self, ch: ConnectionHandle) -> Streams<'_> {
        self.server_conn_mut(ch).streams()
    }

    pub fn server_send(&mut self, ch: ConnectionHandle, s: StreamId) -> SendStream<'_> {
        self.server_conn_mut(ch).send_stream(s)
    }

    pub fn server_recv(&mut self, ch: ConnectionHandle, s: StreamId) -> RecvStream<'_> {
        self.server_conn_mut(ch).recv_stream(s)
    }

    pub fn server_datagrams(&mut self, ch: ConnectionHandle) -> Datagrams<'_> {
        self.server_conn_mut(ch).datagrams()
    }
}

pub struct TestEndpoint {
    pub endpoint: Endpoint,
    pub addr: SocketAddr,
    socket: Option<UdpSocket>,
    timeout: Option<Instant>,
    pub outbound: VecDeque<Transmit>,
    delayed: VecDeque<Transmit>,
    pub inbound: VecDeque<(Instant, Option<EcnCodepoint>, Vec<u8>)>,
    accepted: Option<ConnectionHandle>,
    pub connections: HashMap<ConnectionHandle, Connection>,
    conn_events: HashMap<ConnectionHandle, VecDeque<ConnectionEvent>>,
}

impl TestEndpoint {
    fn new(endpoint: Endpoint, addr: SocketAddr) -> Self {
        let socket = if env::var_os("SSLKEYLOGFILE").is_some() {
            let socket = UdpSocket::bind(addr).expect("failed to bind UDP socket");
            socket
                .set_read_timeout(Some(Duration::new(0, 10_000_000)))
                .unwrap();
            Some(socket)
        } else {
            None
        };
        Self {
            endpoint,
            addr,
            socket,
            timeout: None,
            outbound: VecDeque::new(),
            delayed: VecDeque::new(),
            inbound: VecDeque::new(),
            accepted: None,
            connections: HashMap::default(),
            conn_events: HashMap::default(),
        }
    }

    pub fn drive(&mut self, now: Instant, remote: SocketAddr) {
        if let Some(ref socket) = self.socket {
            loop {
                let mut buf = [0; 8192];
                if socket.recv_from(&mut buf).is_err() {
                    break;
                }
            }
        }

        while self.inbound.front().map_or(false, |x| x.0 <= now) {
            let (recv_time, ecn, packet) = self.inbound.pop_front().unwrap();
            if let Some((ch, event)) =
                self.endpoint
                    .handle(recv_time, remote, None, ecn, packet.as_slice().into())
            {
                match event {
                    DatagramEvent::NewConnection(conn) => {
                        self.connections.insert(ch, conn);
                        self.accepted = Some(ch);
                    }
                    DatagramEvent::ConnectionEvent(event) => {
                        self.conn_events
                            .entry(ch)
                            .or_insert_with(VecDeque::new)
                            .push_back(event);
                    }
                }
            }
        }

        while let Some(x) = self.poll_transmit() {
            self.outbound.extend(split_transmit(x));
        }

        let mut endpoint_events: Vec<(ConnectionHandle, EndpointEvent)> = vec![];
        for (ch, conn) in self.connections.iter_mut() {
            if self.timeout.map_or(false, |x| x <= now) {
                self.timeout = None;
                conn.handle_timeout(now);
            }

            for (_, mut events) in self.conn_events.drain() {
                for event in events.drain(..) {
                    conn.handle_event(event);
                }
            }

            while let Some(event) = conn.poll_endpoint_events() {
                endpoint_events.push((*ch, event));
            }

            while let Some(x) = conn.poll_transmit(now, MAX_DATAGRAMS) {
                self.outbound.extend(split_transmit(x));
            }
            self.timeout = conn.poll_timeout();
        }

        for (ch, event) in endpoint_events {
            if let Some(event) = self.handle_event(ch, event) {
                if let Some(conn) = self.connections.get_mut(&ch) {
                    conn.handle_event(event);
                }
            }
        }
    }

    pub fn next_wakeup(&self) -> Option<Instant> {
        let next_inbound = self.inbound.front().map(|x| x.0);
        min_opt(self.timeout, next_inbound)
    }

    fn is_idle(&self) -> bool {
        self.connections.values().all(|x| x.is_idle())
    }

    pub fn delay_outbound(&mut self) {
        assert!(self.delayed.is_empty());
        mem::swap(&mut self.delayed, &mut self.outbound);
    }

    pub fn finish_delay(&mut self) {
        self.outbound.extend(self.delayed.drain(..));
    }

    pub fn assert_accept(&mut self) -> ConnectionHandle {
        self.accepted.take().expect("server didn't connect")
    }
}

impl ops::Deref for TestEndpoint {
    type Target = Endpoint;
    fn deref(&self) -> &Endpoint {
        &self.endpoint
    }
}

impl ops::DerefMut for TestEndpoint {
    fn deref_mut(&mut self) -> &mut Endpoint {
        &mut self.endpoint
    }
}

pub fn subscribe() -> tracing::subscriber::DefaultGuard {
    let sub = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(|| TestWriter)
        .finish();
    tracing::subscriber::set_default(sub)
}

struct TestWriter;

impl Write for TestWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        print!(
            "{}",
            str::from_utf8(buf).expect("tried to log invalid UTF-8")
        );
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()
    }
}

pub struct ClientParams {
    /// If true, the client will present its certificate to the server.
    pub enable_client_auth: bool,
    pub cert_chain: Vec<Vec<u8>>,
    pub key: Vec<u8>,
    pub allowed_server_cert_chain: Vec<Vec<u8>>,
    pub alpn_protocols: Vec<Vec<u8>>,
}

impl ClientParams {
    pub fn new() -> Self {
        Self {
            enable_client_auth: false,
            cert_chain: Vec::new(),
            key: Vec::new(),
            allowed_server_cert_chain: Vec::new(),
            alpn_protocols: Vec::new(),
        }
    }
}

fn default_alpn() -> Vec<Vec<u8>> {
    // Boring requires that ALPN be set.
    vec!["foo".into()]
}

impl Default for ClientParams {
    fn default() -> Self {
        Self {
            enable_client_auth: false,
            cert_chain: CLIENT_CERT.cert_chain(),
            key: CLIENT_CERT.key(),
            allowed_server_cert_chain: SERVER_CERT.cert_chain(),
            alpn_protocols: default_alpn(),
        }
    }
}

pub struct ServerParams {
    pub cert_chain: Vec<Vec<u8>>,
    pub key: Vec<u8>,

    /// If true, the server will verify the certificate presented by the client against
    /// the value in [allowed_client_cert].
    pub enable_client_auth: bool,

    /// The allowed cert chain for the client used if [enable_client_auth] is `true`.
    pub allowed_client_cert_chain: Vec<Vec<u8>>,

    pub alpn_protocols: Vec<Vec<u8>>,
}

impl ServerParams {
    pub fn new() -> Self {
        Self {
            cert_chain: Vec::new(),
            key: Vec::new(),
            enable_client_auth: false,
            allowed_client_cert_chain: Vec::new(),
            alpn_protocols: default_alpn(),
        }
    }
}

impl Default for ServerParams {
    fn default() -> Self {
        Self {
            cert_chain: SERVER_CERT.cert_chain(),
            key: SERVER_CERT.key(),
            enable_client_auth: false,
            allowed_client_cert_chain: CLIENT_CERT.cert_chain(),
            alpn_protocols: default_alpn(),
        }
    }
}

/// Crypto provider for tests.
#[derive(Clone, Copy, Debug)]
pub enum Provider {
    Rustls,
    Boring,
}

impl Provider {
    pub fn client_crypto(&self, params: ClientParams) -> Box<dyn crypto::ClientConfig> {
        match self {
            Self::Rustls => Box::new(client_crypto_rustls(params)),
            Self::Boring => Box::new(client_crypto_boring(params)),
        }
    }

    pub fn client_crypto_reuse_session(
        &self,
        params: ClientParams,
        prev: &Box<dyn crypto::ClientConfig>,
    ) -> Box<dyn crypto::ClientConfig> {
        match self {
            Self::Rustls => {
                let prev = prev
                    .as_any()
                    .downcast_ref::<rustls::ClientConfig>()
                    .unwrap();
                let mut out = client_crypto_rustls(params);
                out.session_storage = prev.session_storage.clone();
                Box::new(out)
            }
            Self::Boring => {
                let prev = prev
                    .as_any()
                    .downcast_ref::<crypto::boring::ClientConfig>()
                    .unwrap();
                let mut out = client_crypto_boring(params);
                out.session_cache = prev.session_cache.clone();
                Box::new(out)
            }
        }
    }

    pub fn server_crypto(&self, params: ServerParams) -> Box<dyn crypto::ServerConfig> {
        match self {
            Self::Rustls => Box::new(server_crypto_rustls(params)),
            Self::Boring => Box::new(server_crypto_boring(params)),
        }
    }

    pub fn hmac_key(&self) -> Arc<dyn HmacKey> {
        match self {
            Self::Rustls => Arc::new(hmac_key_rustls()),
            Self::Boring => Arc::new(hmac_key_boring()),
        }
    }

    pub fn get_selected_alpn_protocol(&self, handshake_data: Option<Box<dyn Any>>) -> Vec<u8> {
        match self {
            Self::Rustls => get_selected_alpn_protocol_rustls(handshake_data),
            Self::Boring => get_selected_alpn_protocol_boring(handshake_data),
        }
    }

    pub fn server_config(&self) -> ServerConfig {
        ServerConfig::with_crypto(Arc::from(self.server_crypto(ServerParams::default())))
    }

    pub fn server_config_with_cert(&self, cert_and_key: &CertAndKey) -> ServerConfig {
        ServerConfig::with_crypto(Arc::from(self.server_crypto(ServerParams {
            cert_chain: cert_and_key.cert_chain(),
            key: cert_and_key.key(),
            ..ServerParams::default()
        })))
    }

    pub fn server_config_with_alpn_protocols(&self, alpn_protocols: Vec<Vec<u8>>) -> ServerConfig {
        ServerConfig::with_crypto(Arc::from(self.server_crypto(ServerParams {
            alpn_protocols,
            ..ServerParams::default()
        })))
    }

    pub fn client_config(&self) -> ClientConfig {
        ClientConfig::new(Arc::from(self.client_crypto(ClientParams::default())))
    }

    pub fn client_config_with_cert(&self, chain: Vec<Vec<u8>>) -> ClientConfig {
        ClientConfig::new(Arc::from(self.client_crypto(ClientParams {
            allowed_server_cert_chain: chain,
            ..ClientParams::default()
        })))
    }

    pub fn client_config_with_alpn_protocols(&self, alpn_protocols: Vec<Vec<u8>>) -> ClientConfig {
        ClientConfig::new(Arc::from(self.client_crypto(ClientParams {
            alpn_protocols,
            ..ClientParams::default()
        })))
    }
}

pub fn client_crypto_rustls(params: ClientParams) -> rustls::ClientConfig {
    // Create the cert store containing the server certs.
    let mut server_certs = rustls::RootCertStore::empty();
    for cert in params.allowed_server_cert_chain {
        server_certs.add(&Certificate(cert)).unwrap();
    }

    let config = rustls::ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(server_certs);

    let mut config = if params.enable_client_auth {
        let key = PrivateKey(params.key);
        let mut certs = Vec::new();
        for cert in params.cert_chain {
            certs.push(Certificate(cert));
        }
        config.with_single_cert(certs, key).unwrap()
    } else {
        config.with_no_client_auth()
    };

    config.key_log = Arc::new(KeyLogFile::new());
    config.alpn_protocols = params.alpn_protocols;
    config.enable_early_data = true;
    config
}

pub fn server_crypto_rustls(params: ServerParams) -> rustls::ServerConfig {
    let key = PrivateKey(params.key);
    let mut certs = Vec::new();
    for cert in params.cert_chain {
        certs.push(Certificate(cert));
    }
    let mut cfg = if params.enable_client_auth {
        rustls::ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier({
                let mut store = rustls::RootCertStore::empty();
                for client_cert in params.allowed_client_cert_chain {
                    store.add(&Certificate(client_cert)).unwrap();
                }

                rustls::server::AllowAnyAuthenticatedClient::new(store)
            })
            .with_single_cert(certs, key)
            .unwrap()
    } else {
        // Client auth is disabled: allow all clients.
        crypto::rustls::server_config(certs, key).unwrap()
    };
    cfg.alpn_protocols = params.alpn_protocols;
    cfg
}

pub fn hmac_key_rustls() -> hmac::Key {
    let mut reset_key = vec![0; 64];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut reset_key);
    hmac::Key::new(hmac::HMAC_SHA256, &reset_key)
}

pub fn get_selected_alpn_protocol_rustls(handshake_data: Option<Box<dyn Any>>) -> Vec<u8> {
    handshake_data
        .unwrap()
        .downcast::<crypto::rustls::HandshakeData>()
        .unwrap()
        .protocol
        .unwrap()
}

pub fn client_crypto_boring(params: ClientParams) -> crypto::boring::ClientConfig {
    let mut cfg = crypto::boring::ClientConfig::new().unwrap();
    cfg.set_alpn_protos(&params.alpn_protocols).unwrap();

    // Configure client certs.
    if params.enable_client_auth {
        for (i, cert) in params.cert_chain.iter().enumerate() {
            let cert = X509::from_der(cert).unwrap();
            if i == 0 {
                // The leaf certificate.
                cfg.ctx.set_certificate(cert.as_ref()).unwrap();
            } else {
                cfg.ctx.add_extra_chain_cert(cert).unwrap();
            }
        }
        cfg.ctx
            .set_private_key(PKey::private_key_from_der(&params.key).as_ref().unwrap())
            .unwrap();
        cfg.ctx.check_private_key().unwrap();
    }

    // Configure server cert verification.
    let store = cfg.ctx.cert_store_mut();
    for server_cert in params.allowed_server_cert_chain {
        store
            .add_cert(X509::from_der(&server_cert).unwrap())
            .unwrap();
    }

    cfg
}

pub fn server_crypto_boring(params: ServerParams) -> crypto::boring::ServerConfig {
    let mut cfg = crypto::boring::ServerConfig::new().unwrap();
    cfg.set_alpn_protos(&params.alpn_protocols);

    // Configure certs.
    for (i, cert) in params.cert_chain.iter().enumerate() {
        let cert = X509::from_der(cert).unwrap();
        if i == 0 {
            // The leaf certificate.
            cfg.ctx.set_certificate(cert.as_ref()).unwrap();
        } else {
            cfg.ctx.add_extra_chain_cert(cert).unwrap();
        }
    }
    cfg.ctx
        .set_private_key(PKey::private_key_from_der(&params.key).as_ref().unwrap())
        .unwrap();
    cfg.ctx.check_private_key().unwrap();

    // Configure client auth.
    cfg.enable_client_auth = params.enable_client_auth;
    if params.enable_client_auth {
        let store = cfg.ctx.cert_store_mut();
        for client_cert in params.allowed_client_cert_chain {
            store
                .add_cert(X509::from_der(&client_cert).unwrap())
                .unwrap();
        }
    }
    cfg
}

pub fn hmac_key_boring() -> crypto::boring::HmacKey {
    crypto::boring::HmacKey::sha256()
}

pub fn get_selected_alpn_protocol_boring(handshake_data: Option<Box<dyn Any>>) -> Vec<u8> {
    handshake_data
        .unwrap()
        .downcast::<crypto::boring::HandshakeData>()
        .unwrap()
        .protocol
        .unwrap()
}

pub fn min_opt<T: Ord>(x: Option<T>, y: Option<T>) -> Option<T> {
    match (x, y) {
        (Some(x), Some(y)) => Some(cmp::min(x, y)),
        (Some(x), _) => Some(x),
        (_, Some(y)) => Some(y),
        _ => None,
    }
}

/// The maximum of datagrams TestEndpoint will produce via `poll_transmit`
const MAX_DATAGRAMS: usize = 10;

fn split_transmit(transmit: Transmit) -> Vec<Transmit> {
    let segment_size = match transmit.segment_size {
        Some(segment_size) => segment_size,
        _ => return vec![transmit],
    };

    let mut offset = 0;
    let mut transmits = Vec::new();
    while offset < transmit.contents.len() {
        let end = (offset + segment_size).min(transmit.contents.len());

        let contents = transmit.contents[offset..end].to_vec();
        transmits.push(Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents,
            segment_size: None,
            src_ip: transmit.src_ip,
        });

        offset = end;
    }

    transmits
}

pub struct CertAndKey(Vec<u8>, Vec<u8>);

impl CertAndKey {
    pub fn cert(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn cert_chain(&self) -> Vec<Vec<u8>> {
        let mut certs = Vec::new();
        certs.push(self.cert());
        certs.push(CA.serialize_der().unwrap());
        certs
    }

    pub fn key(&self) -> Vec<u8> {
        self.1.clone()
    }
}

pub(crate) fn gen_cert(
    subject_alt_names: impl Into<Vec<String>>,
    ca: &rcgen::Certificate,
) -> CertAndKey {
    let cert = rcgen::generate_simple_self_signed(subject_alt_names).unwrap();
    let key = cert.serialize_private_key_der();
    let cert = cert.serialize_der_with_signer(ca).unwrap();
    CertAndKey(cert, key)
}

fn gen_ca() -> rcgen::Certificate {
    let mut params = CertificateParams::new(&[] as &[String]);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    rcgen::Certificate::from_params(params).unwrap()
}

lazy_static! {
    pub static ref SERVER_PORTS: Mutex<RangeFrom<u16>> = Mutex::new(4433..);
    pub static ref CLIENT_PORTS: Mutex<RangeFrom<u16>> = Mutex::new(44433..);
    pub(crate) static ref CA: rcgen::Certificate = gen_ca();
    pub(crate) static ref SERVER_CERT: CertAndKey = gen_cert(vec!["localhost".into()], &CA);
    pub(crate) static ref CLIENT_CERT: CertAndKey = gen_cert(vec!["client.com".into()], &CA);
    pub(crate) static ref UNTRUSTED_CA: rcgen::Certificate = gen_ca();
    pub(crate) static ref UNTRUSTED_CERT: CertAndKey =
        gen_cert(vec!["evil.com".into()], &UNTRUSTED_CA);
}
