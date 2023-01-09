use std::{
    convert::TryInto,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use assert_matches::assert_matches;
use bytes::Bytes;
use hex_literal::hex;
use rustls::internal::msgs::enums::AlertDescription;
use tracing::info;

use super::*;
use crate::{
    cid_generator::{ConnectionIdGenerator, RandomConnectionIdGenerator},
    frame::FrameStruct,
};
mod util;
use util::*;
use yare::parameterized;

#[test]
fn ide_marker_() {}

#[parameterized(
    rustls = { Provider::Rustls },
    boring = { Provider::Boring },
)]
fn version_negotiate_server(sprovider: Provider) {
    let _guard = subscribe();
    let client_addr = "[::2]:7890".parse().unwrap();

    let server_config = sprovider.server_config();
    //let server_config = ServerConfig::with_crypto(sprovider.server_crypto(ServerParams::default()));
    let mut server = Endpoint::new(Default::default(), Some(Arc::new(server_config)));
    let now = Instant::now();
    let event = server.handle(
        now,
        client_addr,
        None,
        None,
        // Long-header packet with reserved version number
        hex!("80 0a1a2a3a 04 00000000 04 00000000 00")[..].into(),
    );
    assert!(event.is_none());

    let io = server.poll_transmit();
    assert!(io.is_some());
    if let Some(Transmit { contents, .. }) = io {
        assert_ne!(contents[0] & 0x80, 0);
        assert_eq!(&contents[1..15], hex!("00000000 04 00000000 04 00000000"));
        assert!(contents[15..].chunks(4).any(|x| {
            DEFAULT_SUPPORTED_VERSIONS.contains(&u32::from_be_bytes(x.try_into().unwrap()))
        }));
    }
    assert_matches!(server.poll_transmit(), None);
}

#[parameterized(
    rustls = { Provider::Rustls },
    boring = { Provider::Boring },
)]
fn version_negotiate_client() {
    let cprovider = Provider::Boring;
    let _guard = subscribe();
    let server_addr = "[::2]:7890".parse().unwrap();
    let cid_generator_factory: fn() -> Box<dyn ConnectionIdGenerator> =
        || Box::new(RandomConnectionIdGenerator::new(0));
    let mut client = Endpoint::new(
        Arc::new(EndpointConfig {
            connection_id_generator_factory: Arc::new(cid_generator_factory),
            ..Default::default()
        }),
        None,
    );
    let client_config = cprovider.client_config();
    //let client_config = ClientConfig::new(cprovider.client_crypto(ClientParams::default()));
    let (_, mut client_ch) = client
        .connect(client_config, server_addr, "localhost")
        .unwrap();
    let now = Instant::now();
    let opt_event = client.handle(
        now,
        server_addr,
        None,
        None,
        // Version negotiation packet for reserved version
        hex!(
            "80 00000000 04 00000000 04 00000000
             0a1a2a3a"
        )[..]
            .into(),
    );
    if let Some((_, DatagramEvent::ConnectionEvent(event))) = opt_event {
        client_ch.handle_event(event);
    }
    assert_matches!(
        client_ch.poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::VersionMismatch,
        })
    );
}

#[parameterized(
    rustls = { Provider::Rustls, Provider::Rustls },
    boring = { Provider::Boring, Provider::Boring },
    rustls_to_boring = { Provider::Rustls, Provider::Boring },
    boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn lifecycle(cprovider: Provider, sprovider: Provider) {
    // let cprovider = Provider::Boring;
    // let sprovider = Provider::Rustls;
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let (client_ch, server_ch) = pair.connect(cprovider);
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    assert!(pair.client_conn_mut(client_ch).using_ecn());
    assert!(pair.server_conn_mut(server_ch).using_ecn());

    const REASON: &[u8] = b"whee";
    info!("closing");
    pair.client.connections.get_mut(&client_ch).unwrap().close(
        pair.time,
        VarInt(42),
        REASON.into(),
    );
    pair.drive();
    assert_matches!(pair.server_conn_mut(server_ch).poll(),
                    Some(Event::ConnectionLost { reason: ConnectionError::ApplicationClosed(
                        ApplicationClose { error_code: VarInt(42), ref reason }
                    )}) if reason == REASON);
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);
}

#[parameterized(
    rustls = { Provider::Rustls, Provider::Rustls },
    boring = { Provider::Boring, Provider::Boring },
    rustls_to_boring = { Provider::Rustls, Provider::Boring },
    boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn draft_version_compat(cprovider: Provider, sprovider: Provider) {
    // let cprovider = Provider::Boring;
    // let sprovider = Provider::Boring;
    let _guard = subscribe();
    let mut client_config = cprovider.client_config();
    //let mut client_config = ClientConfig::new(cprovider.client_crypto(ClientParams::default()));
    client_config.version(0xff00_0020);

    let mut pair = Pair::for_provider(sprovider);
    let (client_ch, server_ch) = pair.connect_with(client_config);

    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    assert!(pair.client_conn_mut(client_ch).using_ecn());
    assert!(pair.server_conn_mut(server_ch).using_ecn());

    const REASON: &[u8] = b"whee";
    info!("closing");
    pair.client.connections.get_mut(&client_ch).unwrap().close(
        pair.time,
        VarInt(42),
        REASON.into(),
    );
    pair.drive();
    assert_matches!(pair.server_conn_mut(server_ch).poll(),
                    Some(Event::ConnectionLost { reason: ConnectionError::ApplicationClosed(
                        ApplicationClose { error_code: VarInt(42), ref reason }
                    )}) if reason == REASON);
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn stateless_retry(cprovider: Provider, sprovider: Provider) {
    // let cprovider = Provider::Boring;
    // let sprovider = Provider::Boring;
    let _guard = subscribe();
    let mut pair = Pair::new(
        Default::default(),
        Arc::new(ServerConfig {
            use_retry: true,
            ..sprovider.server_config()
        }),
    );
    pair.connect(cprovider);
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn server_stateless_reset(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();

    let endpoint_config = Arc::new(EndpointConfig::new(sprovider.hmac_key()));

    let mut pair = Pair::new(endpoint_config.clone(), Arc::new(sprovider.server_config()));
    let (client_ch, _) = pair.connect(cprovider);
    pair.drive(); // Flush any post-handshake frames
    pair.server.endpoint =
        Endpoint::new(endpoint_config, Some(Arc::new(sprovider.server_config())));
    // Force the server to generate the smallest possible stateless reset
    pair.client.connections.get_mut(&client_ch).unwrap().ping();
    info!("resetting");
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::Reset
        })
    );
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn client_stateless_reset(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();

    let endpoint_config = Arc::new(EndpointConfig::new(sprovider.hmac_key()));

    let mut pair = Pair::new(endpoint_config.clone(), Arc::new(sprovider.server_config()));
    let (_, server_ch) = pair.connect(cprovider);
    pair.client.endpoint =
        Endpoint::new(endpoint_config, Some(Arc::new(sprovider.server_config())));
    // Send something big enough to allow room for a smaller stateless reset.
    pair.server.connections.get_mut(&server_ch).unwrap().close(
        pair.time,
        VarInt(42),
        (&[0xab; 128][..]).into(),
    );
    info!("resetting");
    pair.drive();
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::Reset
        })
    );
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
)]
fn export_keying_material(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let (client_ch, server_ch) = pair.connect(cprovider);

    const LABEL: &[u8] = b"test_label";
    const CONTEXT: &[u8] = b"test_context";

    // client keying material
    let mut client_buf = [0u8; 64];
    pair.client_conn_mut(client_ch)
        .crypto_session()
        .export_keying_material(&mut client_buf, LABEL, CONTEXT)
        .unwrap();

    // server keying material
    let mut server_buf = [0u8; 64];
    pair.server_conn_mut(server_ch)
        .crypto_session()
        .export_keying_material(&mut server_buf, LABEL, CONTEXT)
        .unwrap();

    assert_eq!(&client_buf[..], &server_buf[..]);
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn finish_stream_simple(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let (client_ch, server_ch) = pair.connect(cprovider);

    let s = pair.client_streams(client_ch).open(Dir::Uni).unwrap();

    const MSG: &[u8] = b"hello";
    pair.client_send(client_ch, s).write(MSG).unwrap();
    assert_eq!(pair.client_streams(client_ch).send_streams(), 1);
    pair.client_send(client_ch, s).finish().unwrap();
    pair.drive();

    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Stream(StreamEvent::Finished { id })) if id == s
    );
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    assert_eq!(pair.client_streams(client_ch).send_streams(), 0);
    assert_eq!(pair.server_conn_mut(client_ch).streams().send_streams(), 0);
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );
    // Receive-only streams do not get `StreamFinished` events
    assert_eq!(pair.server_conn_mut(client_ch).streams().send_streams(), 0);
    assert_matches!(pair.server_streams(server_ch).accept(Dir::Uni), Some(stream) if stream == s);
    assert_matches!(pair.server_conn_mut(server_ch).poll(), None);

    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(
        chunks.next(usize::MAX),
        Ok(Some(chunk)) if chunk.offset == 0 && chunk.bytes == MSG
    );
    assert_matches!(chunks.next(usize::MAX), Ok(None));
    let _ = chunks.finalize();
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn reset_stream(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let (client_ch, server_ch) = pair.connect(cprovider);

    let s = pair.client_streams(client_ch).open(Dir::Uni).unwrap();

    const MSG: &[u8] = b"hello";
    pair.client_send(client_ch, s).write(MSG).unwrap();
    pair.drive();

    info!("resetting stream");
    const ERROR: VarInt = VarInt(42);
    pair.client_send(client_ch, s).reset(ERROR).unwrap();
    pair.drive();

    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );
    assert_matches!(pair.server_streams(server_ch).accept(Dir::Uni), Some(stream) if stream == s);
    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(chunks.next(usize::MAX), Err(ReadError::Reset(ERROR)));
    let _ = chunks.finalize();
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn stop_stream(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let (client_ch, server_ch) = pair.connect(cprovider);

    let s = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    const MSG: &[u8] = b"hello";
    pair.client_send(client_ch, s).write(MSG).unwrap();
    pair.drive();

    info!("stopping stream");
    const ERROR: VarInt = VarInt(42);
    pair.server_recv(server_ch, s).stop(ERROR).unwrap();
    pair.drive();

    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );
    assert_matches!(pair.server_streams(server_ch).accept(Dir::Uni), Some(stream) if stream == s);

    assert_matches!(
        pair.client_send(client_ch, s).write(b"foo"),
        Err(WriteError::Stopped(ERROR))
    );
    assert_matches!(
        pair.client_send(client_ch, s).finish(),
        Err(FinishError::Stopped(ERROR))
    );
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn reject_self_signed_server_cert(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    info!("connecting");
    let client_ch = pair.begin_connect(cprovider.client_config_with_cert(vec![]));
    pair.drive();
    assert_matches!(pair.client_conn_mut(client_ch).poll(),
                Some(Event::ConnectionLost { reason: ConnectionError::TransportError(ref error)}) => {
        assert!(
            // Boring and Rustls return different values here.
            error.code == TransportErrorCode::crypto(AlertDescription::BadCertificate.get_u8()) ||
            error.code == TransportErrorCode::crypto(AlertDescription::UnknownCA.get_u8())
            );
    });
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn client_auth(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();

    let client_config = ClientConfig::new(Arc::from(cprovider.client_crypto(ClientParams {
        // Don't present the client certificate to the server.
        enable_client_auth: true,
        ..ClientParams::default()
    })));
    let server_config = ServerConfig::with_crypto(Arc::from(sprovider.server_crypto(ServerParams {
        // Require that a client certificate be present and valid.
        enable_client_auth: true,
        ..ServerParams::default()
    })));

    let mut pair = Pair::new(Default::default(), Arc::new(server_config));
    let (client_ch, server_ch) = pair.connect_with(client_config);
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    assert!(pair.client_conn_mut(client_ch).using_ecn());
    assert!(pair.server_conn_mut(server_ch).using_ecn());

    const REASON: &[u8] = b"whee";
    info!("closing");
    pair.client.connections.get_mut(&client_ch).unwrap().close(
        pair.time,
        VarInt(42),
        REASON.into(),
    );
    pair.drive();
    assert_matches!(pair.server_conn_mut(server_ch).poll(),
                    Some(Event::ConnectionLost { reason: ConnectionError::ApplicationClosed(
                        ApplicationClose { error_code: VarInt(42), ref reason }
                    )}) if reason == REASON);
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn reject_missing_client_cert(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();

    let client_config = ClientConfig::new(Arc::from(cprovider.client_crypto(ClientParams {
        // Don't present the client certificate to the server.
        enable_client_auth: false,
        ..ClientParams::default()
    })));
    let server_config = ServerConfig::with_crypto(Arc::from(sprovider.server_crypto(ServerParams {
        // Require that a client certificate be present and valid.
        enable_client_auth: true,
        ..ServerParams::default()
    })));

    let mut pair = Pair::new(Default::default(), Arc::new(server_config));

    info!("connecting");
    let client_ch = pair.begin_connect(client_config);
    pair.drive();

    // The client completes the connection, but finds it immediately closed
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Connected)
    );
    assert_matches!(pair.client_conn_mut(client_ch).poll(),
                    Some(Event::ConnectionLost { reason: ConnectionError::ConnectionClosed(ref close)})
                    if close.error_code == TransportErrorCode::crypto(AlertDescription::CertificateRequired.get_u8()));

    // The server never completes the connection
    let server_ch = pair.server.assert_accept();
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(pair.server_conn_mut(server_ch).poll(),
                    Some(Event::ConnectionLost { reason: ConnectionError::TransportError(ref error)})
                    if error.code == TransportErrorCode::crypto(AlertDescription::CertificateRequired.get_u8()));
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn reject_unknown_client_cert(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();

    let client_config = ClientConfig::new(Arc::from(cprovider.client_crypto(ClientParams {
        // Don't present the client certificate to the server.
        enable_client_auth: true,
        cert_chain: UNTRUSTED_CERT.cert_chain(),
        key: UNTRUSTED_CERT.key(),
        ..ClientParams::default()
    })));
    let server_config = ServerConfig::with_crypto(Arc::from(sprovider.server_crypto(ServerParams {
        // Require that a client certificate be present and valid.
        enable_client_auth: true,
        ..ServerParams::default()
    })));

    let mut pair = Pair::new(Default::default(), Arc::new(server_config));

    info!("connecting");
    let client_ch = pair.begin_connect(client_config);
    pair.drive();

    // The client completes the connection, but finds it immediately closed
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Connected)
    );
    assert_matches!(pair.client_conn_mut(client_ch).poll(),
                    Some(Event::ConnectionLost { reason: ConnectionError::ConnectionClosed(ref close)}) => {
            println!("NM: client closed with code={}, reason={:?}", close.error_code, close.reason);
            assert!(
                // BoringSSL behavior.
                close.error_code == TransportErrorCode::crypto(AlertDescription::UnknownCA.get_u8()) ||

                // Rustls behavior.
                (close.error_code == TransportErrorCode::crypto(AlertDescription::HandshakeFailure.get_u8())
                    && String::from_utf8(close.reason.to_vec()).unwrap().contains("UnknownIssuer"))
            );

    });

    // The server never completes the connection
    let server_ch = pair.server.assert_accept();
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(pair.server_conn_mut(server_ch).poll(),
                    Some(Event::ConnectionLost { reason: ConnectionError::TransportError(ref error)}) => {
            println!("NM: server closed with code={}, reason={:?}", error.code, error.reason);
            assert!(
                // BoringSSL behavior.
                error.code == TransportErrorCode::crypto(AlertDescription::UnknownCA.get_u8()) ||

                // Rustls behavior.
                (error.code == TransportErrorCode::crypto(AlertDescription::HandshakeFailure.get_u8())
                    && error.reason.contains("UnknownIssuer"))
            );
    });
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn congestion(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let (client_ch, _) = pair.connect(cprovider);

    const TARGET: u64 = 2048;
    assert!(pair.client_conn_mut(client_ch).congestion_window() > TARGET);
    let s = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    // Send data without receiving ACKs until the congestion state falls below target
    while pair.client_conn_mut(client_ch).congestion_window() > TARGET {
        let n = pair.client_send(client_ch, s).write(&[42; 1024]).unwrap();
        assert_eq!(n, 1024);
        pair.drive_client();
    }
    // Ensure that the congestion state recovers after receiving the ACKs
    pair.drive();
    assert!(pair.client_conn_mut(client_ch).congestion_window() >= TARGET);
    pair.client_send(client_ch, s).write(&[42; 1024]).unwrap();
}

#[allow(clippy::field_reassign_with_default)] // https://github.com/rust-lang/rust-clippy/issues/6527
#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn high_latency_handshake(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    pair.latency = Duration::from_micros(200 * 1000);
    let (client_ch, server_ch) = pair.connect(cprovider);
    assert_eq!(pair.client_conn_mut(client_ch).bytes_in_flight(), 0);
    assert_eq!(pair.server_conn_mut(server_ch).bytes_in_flight(), 0);
    assert!(pair.client_conn_mut(client_ch).using_ecn());
    assert!(pair.server_conn_mut(server_ch).using_ecn());
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn zero_rtt_happypath(cprovider: Provider, sprovider: Provider) {
    // let cprovider = Provider::Boring;
    // let sprovider = Provider::Rustls;
    let _guard = subscribe();
    let mut pair = Pair::new(
        Default::default(),
        Arc::new(ServerConfig {
            use_retry: true,
            ..sprovider.server_config()
        }),
    );
    let crypto_config = cprovider.client_crypto(ClientParams::default());
    let crypto_config2 = cprovider.client_crypto_reuse_session(ClientParams::default(), &crypto_config);
    let config = ClientConfig::new(Arc::from(crypto_config));
    let config2 = ClientConfig::new(Arc::from(crypto_config2));
    //let config = cprovider.client_config();

    // Establish normal connection
    let client_ch = pair.begin_connect(config.clone());
    pair.drive();
    pair.server.assert_accept();
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(0), [][..].into());
    pair.drive();

    pair.client.addr = SocketAddr::new(
        Ipv6Addr::LOCALHOST.into(),
        CLIENT_PORTS.lock().unwrap().next().unwrap(),
    );
    info!("resuming session");
    let client_ch = pair.begin_connect(config2);
    assert!(pair.client_conn_mut(client_ch).has_0rtt());
    let s = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    const MSG: &[u8] = b"Hello, 0-RTT!";
    pair.client_send(client_ch, s).write(MSG).unwrap();
    pair.drive();

    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Connected)
    );

    assert!(pair.client_conn_mut(client_ch).accepted_0rtt());
    let server_ch = pair.server.assert_accept();

    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    // We don't currently preserve stream event order wrt. connection events
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Connected)
    );
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );

    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(
        chunks.next(usize::MAX),
        Ok(Some(chunk)) if chunk.offset == 0 && chunk.bytes == MSG
    );
    let _ = chunks.finalize();
    assert_eq!(pair.client_conn_mut(client_ch).lost_packets(), 0);
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn zero_rtt_rejection(cprovider: Provider, sprovider: Provider) {
    // let cprovider = Provider::Boring;
    // let sprovider = Provider::Rustls;
    let _guard = subscribe();

    // Share the client-side session cache across the 1st and resumed connections.
    let client_crypto = cprovider.client_crypto(ClientParams::default());
    let client_crypto_resumed = cprovider.client_crypto_reuse_session(ClientParams::default(), &client_crypto);
    let client_config = ClientConfig::new(Arc::from(client_crypto));
    let client_config_resumed = ClientConfig::new(Arc::from(client_crypto_resumed));

    // Use separate servers for the 1st and resumed connections so that the resumed server will not
    // have any cached sessions. This will cause the 0-RTT attempt to be rejected.
    let server_config = sprovider.server_config();
    let server_config_resumed = sprovider.server_config();

    // let mut server_crypto = sprovider.server_crypto(ServerParams::default());
    // let mut server_crypto_resumed = sprovider.server_crypto(ServerParams::default());
    //let mut server_crypto_resumed = sprovider.server_crypto_reuse_session(ServerParams::default(), &server_crypto);
    // let mut server_config = Arc::new(sprovider.server_config());
    // let mut server_config_resumed = Arc::new(sprovider.server_config());
    // let mut server_config = Arc::new(ServerConfig::with_crypto(Arc::from(server_crypto)));
    // let mut server_config_resumed = Arc::new(ServerConfig::with_crypto(Arc::from(server_crypto_resumed)));
    let mut pair = Pair::new(Arc::new(EndpointConfig::default()), Arc::new(server_config));

    // let client_crypto = cprovider.client_crypto(ClientParams {
    //     //alpn_protocols: vec!["foo".into()],
    //     ..ClientParams::default()
    // });
    // let mut client_crypto_resumed = cprovider.client_crypto_reuse_session(ClientParams {
    //     //alpn_protocols: vec!["bar".into()],
    //     ..ClientParams::default()
    // }, &client_crypto);
    //cprovider.set_alpn_protocols(&mut client_crypto_resumed, vec!["bar".into()]);

    // let mut client_crypto = client_crypto_rustls(ClientParams {
    //     alpn_protocols: vec!["foo".into()],
    //     ..ClientParams::default()
    // });
    // let client_config = ClientConfig::new(Arc::from(client_crypto));
    // let client_config_resumed = ClientConfig::new(Arc::from(client_crypto_resumed));
    // let client_config = cprovider.client_config();
    // let client_config_resumed = client_config.clone();

    // Establish normal connection
    let client_ch = pair.begin_connect(client_config);
    pair.drive();
    let server_ch = pair.server.assert_accept();
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Connected)
    );
    assert_matches!(pair.server_conn_mut(server_ch).poll(), None);
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(0), [][..].into());
    pair.drive();
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::ConnectionLost { .. })
    );
    assert_matches!(pair.server_conn_mut(server_ch).poll(), None);
    pair.client.connections.clear();
    pair.server.connections.clear();

    info!("resuming session");
    //sprovider.clear_session_cache(server_config.crypto.clone());
    //sprovider.clear_session_cache(server_config.crypto.clone());
    // Changing protocols invalidates 0-RTT
    //cprovider.set_alpn_protocols(&mut client_crypto_resumed, vec!["bar".into()]);

    //let mut server_config_resumed = sprovider.server_config();
    // let mut transport = TransportConfig::default();
    // transport.max_concurrent_bidi_streams.0 = 1;
    // server_config_resumed.transport = Arc::new(transport);

    //let server_config = sprovider.server_config();
    let mut pair = Pair::new(Arc::new(EndpointConfig::default()), Arc::new(server_config_resumed));

    //client_crypto_resumed.alpn_protocols = vec!["bar".into()];
    //let client_config_resumed = ClientConfig::new(Arc::from(client_crypto_resumed));
    //let client_config = Arc::from(client_config.clone());

    let client_ch = pair.begin_connect(client_config_resumed);
    assert!(pair.client_conn_mut(client_ch).has_0rtt());
    let s = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    const MSG: &[u8] = b"Hello, 0-RTT!";
    pair.client_send(client_ch, s).write(MSG).unwrap();
    pair.drive();
    assert!(!pair.client_conn_mut(client_ch).accepted_0rtt());
    let server_ch = pair.server.assert_accept();
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Connected)
    );
    assert_matches!(pair.server_conn_mut(server_ch).poll(), None);
    let s2 = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    assert_eq!(s, s2);

    let mut recv = pair.server_recv(server_ch, s2);
    let mut chunks = recv.read(false).unwrap();
    assert_eq!(chunks.next(usize::MAX), Err(ReadError::Blocked));
    let _ = chunks.finalize();
    assert_eq!(pair.client_conn_mut(client_ch).lost_packets(), 0);
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn alpn_success(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let server_config =
        sprovider.server_config_with_alpn_protocols(vec!["foo".into(), "bar".into(), "baz".into()]);
    let client_config = cprovider.client_config_with_alpn_protocols(vec![
        "bar".into(),
        "quux".into(),
        "corge".into(),
    ]);
    let mut pair = Pair::new(Arc::new(EndpointConfig::default()), Arc::new(server_config));

    // Establish normal connection
    let client_ch = pair.begin_connect(client_config);
    pair.drive();
    let server_ch = pair.server.assert_accept();
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Connected)
    );

    let protocol = cprovider.get_selected_alpn_protocol(
        pair.client_conn_mut(client_ch)
            .crypto_session()
            .handshake_data(),
    );
    assert_eq!(protocol, &b"bar"[..]);
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn server_alpn_unset(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::new(
        Arc::new(EndpointConfig::default()),
        Arc::new(sprovider.server_config_with_alpn_protocols(vec![])),
    );

    let client_config = cprovider.client_config_with_alpn_protocols(vec!["foo".into()]);

    let client_ch = pair.begin_connect(client_config);
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::ConnectionLost { reason: ConnectionError::ConnectionClosed(err) }) if err.error_code == TransportErrorCode::crypto(0x78)
    );
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
)]
fn client_alpn_unset(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let server_config =
        sprovider.server_config_with_alpn_protocols(vec!["foo".into()]);
    let mut pair = Pair::new(Arc::new(EndpointConfig::default()), Arc::new(server_config));

    let client_ch = pair.begin_connect(cprovider.client_config_with_alpn_protocols(vec![]));
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::ConnectionLost { reason: ConnectionError::ConnectionClosed(err) }) if err.error_code == TransportErrorCode::crypto(0x78)
    );
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn alpn_mismatch(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let server_config =
        sprovider.server_config_with_alpn_protocols(vec!["foo".into(), "bar".into(), "baz".into()]);
    let mut pair = Pair::new(Arc::new(EndpointConfig::default()), Arc::new(server_config));

    let client_config =
        cprovider.client_config_with_alpn_protocols(vec!["quux".into(), "corge".into()]);

    let client_ch = pair.begin_connect(client_config);
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::ConnectionLost { reason: ConnectionError::ConnectionClosed(err) }) if err.error_code == TransportErrorCode::crypto(0x78)
    );
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn stream_id_limit(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let server = ServerConfig {
        transport: Arc::new(TransportConfig {
            max_concurrent_uni_streams: 1u32.into(),
            ..TransportConfig::default()
        }),
        ..sprovider.server_config()
    };
    let mut pair = Pair::new(Default::default(), Arc::new(server));
    let (client_ch, server_ch) = pair.connect(cprovider);

    let s = pair
        .client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .streams()
        .open(Dir::Uni)
        .expect("couldn't open first stream");
    assert_eq!(
        pair.client_streams(client_ch).open(Dir::Uni),
        None,
        "only one stream is permitted at a time"
    );
    // Generate some activity to allow the server to see the stream
    const MSG: &[u8] = b"hello";
    pair.client_send(client_ch, s).write(MSG).unwrap();
    pair.client_send(client_ch, s).finish().unwrap();
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Stream(StreamEvent::Finished { id })) if id == s
    );
    assert_eq!(
        pair.client_streams(client_ch).open(Dir::Uni),
        None,
        "server does not immediately grant additional credit"
    );
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );
    assert_matches!(pair.server_streams(server_ch).accept(Dir::Uni), Some(stream) if stream == s);

    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(
        chunks.next(usize::MAX),
        Ok(Some(chunk)) if chunk.offset == 0 && chunk.bytes == MSG
    );
    assert_eq!(chunks.next(usize::MAX), Ok(None));
    let _ = chunks.finalize();

    // Server will only send MAX_STREAM_ID now that the application's been notified
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Stream(StreamEvent::Available { dir: Dir::Uni }))
    );
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);

    // Try opening the second stream again, now that we've made room
    let s = pair
        .client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .streams()
        .open(Dir::Uni)
        .expect("didn't get stream id budget");
    pair.client_send(client_ch, s).finish().unwrap();
    pair.drive();
    // Make sure the server actually processes data on the newly-available stream
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );
    assert_matches!(pair.server_streams(server_ch).accept(Dir::Uni), Some(stream) if stream == s);
    assert_matches!(pair.server_conn_mut(server_ch).poll(), None);

    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(chunks.next(usize::MAX), Ok(None));
    let _ = chunks.finalize();
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn key_update_simple(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let (client_ch, server_ch) = pair.connect(cprovider);
    let s = pair
        .client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .streams()
        .open(Dir::Bi)
        .expect("couldn't open first stream");

    const MSG1: &[u8] = b"hello1";
    pair.client_send(client_ch, s).write(MSG1).unwrap();
    pair.drive();

    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Bi }))
    );
    assert_matches!(pair.server_streams(server_ch).accept(Dir::Bi), Some(stream) if stream == s);
    assert_matches!(pair.server_conn_mut(server_ch).poll(), None);
    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(
        chunks.next(usize::MAX),
        Ok(Some(chunk)) if chunk.offset == 0 && chunk.bytes == MSG1
    );
    let _ = chunks.finalize();

    info!("initiating key update");
    pair.client_conn_mut(client_ch).initiate_key_update();

    const MSG2: &[u8] = b"hello2";
    pair.client_send(client_ch, s).write(MSG2).unwrap();
    pair.drive();

    assert_matches!(pair.server_conn_mut(server_ch).poll(), Some(Event::Stream(StreamEvent::Readable { id })) if id == s);
    assert_matches!(pair.server_conn_mut(server_ch).poll(), None);
    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(
        chunks.next(usize::MAX),
        Ok(Some(chunk)) if chunk.offset == 6 && chunk.bytes == MSG2
    );
    let _ = chunks.finalize();

    assert_eq!(pair.client_conn_mut(client_ch).lost_packets(), 0);
    assert_eq!(pair.server_conn_mut(server_ch).lost_packets(), 0);
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn key_update_reordered(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let (client_ch, server_ch) = pair.connect(cprovider);
    let s = pair
        .client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .streams()
        .open(Dir::Bi)
        .expect("couldn't open first stream");

    const MSG1: &[u8] = b"1";
    pair.client_send(client_ch, s).write(MSG1).unwrap();
    pair.client.drive(pair.time, pair.server.addr);
    assert!(!pair.client.outbound.is_empty());
    pair.client.delay_outbound();

    pair.client_conn_mut(client_ch).initiate_key_update();
    info!("updated keys");

    const MSG2: &[u8] = b"two";
    pair.client_send(client_ch, s).write(MSG2).unwrap();
    pair.client.drive(pair.time, pair.server.addr);
    pair.client.finish_delay();
    pair.drive();

    assert_eq!(pair.client_conn_mut(client_ch).lost_packets(), 0);
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Bi }))
    );
    assert_matches!(pair.server_streams(server_ch).accept(Dir::Bi), Some(stream) if stream == s);

    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(true).unwrap();
    let buf1 = chunks.next(usize::MAX).unwrap().unwrap();
    assert_matches!(&*buf1.bytes, MSG1);
    let buf2 = chunks.next(usize::MAX).unwrap().unwrap();
    assert_eq!(buf2.bytes, MSG2);
    let _ = chunks.finalize();

    assert_eq!(pair.client_conn_mut(client_ch).lost_packets(), 0);
    assert_eq!(pair.server_conn_mut(server_ch).lost_packets(), 0);
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn initial_retransmit(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let client_ch = pair.begin_connect(cprovider.client_config());
    pair.client.drive(pair.time, pair.server.addr);
    pair.client.outbound.clear(); // Drop initial
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Connected { .. })
    );
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
//#[test]
fn instant_close_1(cprovider: Provider, sprovider: Provider) {
    // let cprovider = Provider::Boring;
    // let sprovider = Provider::Boring;
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    info!("connecting");
    let client_ch = pair.begin_connect(cprovider.client_config());
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(0), Bytes::new());
    pair.drive();
    let server_ch = pair.server.assert_accept();
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::ConnectionClosed(ConnectionClose {
                error_code: TransportErrorCode::APPLICATION_ERROR,
                ..
            }),
        })
    );
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn instant_close_2(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    info!("connecting");
    let client_ch = pair.begin_connect(cprovider.client_config());
    // Unlike `instant_close`, the server sees a valid Initial packet first.
    pair.drive_client();
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    let server_ch = pair.server.assert_accept();
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::ConnectionClosed(ConnectionClose {
                error_code: TransportErrorCode::APPLICATION_ERROR,
                ..
            }),
        })
    );
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn idle_timeout(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    const IDLE_TIMEOUT: u64 = 100;
    let server = ServerConfig {
        transport: Arc::new(TransportConfig {
            max_idle_timeout: Some(VarInt(IDLE_TIMEOUT)),
            ..TransportConfig::default()
        }),
        ..sprovider.server_config()
    };
    let mut pair = Pair::new(Default::default(), Arc::new(server));
    let (client_ch, server_ch) = pair.connect(cprovider);
    pair.client_conn_mut(client_ch).ping();
    let start = pair.time;

    while !pair.client_conn_mut(client_ch).is_closed()
        || !pair.server_conn_mut(server_ch).is_closed()
    {
        if !pair.step() {
            if let Some(t) = min_opt(pair.client.next_wakeup(), pair.server.next_wakeup()) {
                pair.time = t;
            }
        }
        pair.client.inbound.clear(); // Simulate total S->C packet loss
    }

    assert!(pair.time - start < Duration::from_millis(2 * IDLE_TIMEOUT));
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::TimedOut,
        })
    );
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::TimedOut,
        })
    );
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn connection_close_sends_acks(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let (client_ch, _server_ch) = pair.connect(cprovider);

    let client_acks = pair.client_conn_mut(client_ch).stats().frame_rx.acks;

    pair.client_conn_mut(client_ch).ping();
    pair.drive_client();

    let time = pair.time;
    pair.server_conn_mut(client_ch)
        .close(time, VarInt(42), Bytes::new());

    pair.drive();

    let client_acks_2 = pair.client_conn_mut(client_ch).stats().frame_rx.acks;
    assert!(
        client_acks_2 > client_acks,
        "Connection close should send pending ACKs"
    );
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn concurrent_connections_full(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::new(
        Default::default(),
        Arc::new(ServerConfig {
            concurrent_connections: 0,
            ..sprovider.server_config()
        }),
    );
    let client_ch = pair.begin_connect(cprovider.client_config());
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::ConnectionClosed(frame::ConnectionClose {
                error_code: TransportErrorCode::CONNECTION_REFUSED,
                ..
            }),
        })
    );
    assert_eq!(pair.server.connections.len(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn server_hs_retransmit(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let client_ch = pair.begin_connect(cprovider.client_config());
    pair.step();
    assert!(!pair.client.inbound.is_empty()); // Initial + Handshakes
    pair.client.inbound.clear();
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Connected { .. })
    );
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn migration(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let (client_ch, server_ch) = pair.connect(cprovider);
    pair.client.addr = SocketAddr::new(
        Ipv4Addr::new(127, 0, 0, 1).into(),
        CLIENT_PORTS.lock().unwrap().next().unwrap(),
    );
    pair.client_conn_mut(client_ch).ping();

    // Assert that just receiving the ping message is accounted into the servers
    // anti-amplification budget
    pair.drive_client();
    pair.drive_server();
    assert_ne!(pair.server_conn_mut(server_ch).total_recvd(), 0);

    pair.drive();
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    assert_eq!(
        pair.server_conn_mut(server_ch).remote_address(),
        pair.client.addr
    );
}

fn test_flow_control(
    cprovider: Provider,
    sprovider: Provider,
    config: TransportConfig,
    window_size: usize,
) {
    let _guard = subscribe();
    let mut pair = Pair::new(
        Default::default(),
        Arc::new(ServerConfig {
            transport: Arc::new(config),
            ..sprovider.server_config()
        }),
    );
    let (client_ch, server_ch) = pair.connect(cprovider);
    let msg = vec![0xAB; window_size + 10];

    // Stream reset before read
    let s = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    info!("writing");
    assert_eq!(pair.client_send(client_ch, s).write(&msg), Ok(window_size));
    assert_eq!(
        pair.client_send(client_ch, s).write(&msg[window_size..]),
        Err(WriteError::Blocked)
    );
    pair.drive();
    info!("resetting");
    pair.client_send(client_ch, s).reset(VarInt(42)).unwrap();
    pair.drive();

    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(true).unwrap();
    assert_eq!(
        chunks.next(usize::MAX).err(),
        Some(ReadError::Reset(VarInt(42)))
    );
    let _ = chunks.finalize();

    // Happy path
    info!("writing");
    let s = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    assert_eq!(pair.client_send(client_ch, s).write(&msg), Ok(window_size));
    assert_eq!(
        pair.client_send(client_ch, s).write(&msg[window_size..]),
        Err(WriteError::Blocked)
    );

    pair.drive();
    let mut cursor = 0;
    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(true).unwrap();
    loop {
        match chunks.next(usize::MAX) {
            Ok(Some(chunk)) => {
                cursor += chunk.bytes.len();
            }
            Ok(None) => {
                panic!("end of stream");
            }
            Err(ReadError::Blocked) => {
                break;
            }
            Err(e) => {
                panic!("{}", e);
            }
        }
    }
    let _ = chunks.finalize();

    info!("finished reading");
    assert_eq!(cursor, window_size);
    pair.drive();
    info!("writing");
    assert_eq!(pair.client_send(client_ch, s).write(&msg), Ok(window_size));
    assert_eq!(
        pair.client_send(client_ch, s).write(&msg[window_size..]),
        Err(WriteError::Blocked)
    );

    pair.drive();
    let mut cursor = 0;
    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(true).unwrap();
    loop {
        match chunks.next(usize::MAX) {
            Ok(Some(chunk)) => {
                cursor += chunk.bytes.len();
            }
            Ok(None) => {
                panic!("end of stream");
            }
            Err(ReadError::Blocked) => {
                break;
            }
            Err(e) => {
                panic!("{}", e);
            }
        }
    }
    assert_eq!(cursor, window_size);
    let _ = chunks.finalize();
    info!("finished reading");
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn stream_flow_control(cprovider: Provider, sprovider: Provider) {
    test_flow_control(
        cprovider,
        sprovider,
        TransportConfig {
            stream_receive_window: 2000u32.into(),
            ..TransportConfig::default()
        },
        2000,
    );
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn conn_flow_control(cprovider: Provider, sprovider: Provider) {
    test_flow_control(
        cprovider,
        sprovider,
        TransportConfig {
            receive_window: 2000u32.into(),
            ..TransportConfig::default()
        },
        2000,
    );
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn stop_opens_bidi(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let (client_ch, server_ch) = pair.connect(cprovider);
    assert_eq!(pair.client_streams(client_ch).send_streams(), 0);
    let s = pair.client_streams(client_ch).open(Dir::Bi).unwrap();
    assert_eq!(pair.client_streams(client_ch).send_streams(), 1);
    const ERROR: VarInt = VarInt(42);
    pair.client
        .connections
        .get_mut(&server_ch)
        .unwrap()
        .recv_stream(s)
        .stop(ERROR)
        .unwrap();
    pair.drive();

    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Bi }))
    );
    assert_eq!(pair.server_conn_mut(client_ch).streams().send_streams(), 0);
    assert_matches!(pair.server_streams(server_ch).accept(Dir::Bi), Some(stream) if stream == s);
    assert_eq!(pair.server_conn_mut(client_ch).streams().send_streams(), 1);

    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(chunks.next(usize::MAX), Err(ReadError::Blocked));
    let _ = chunks.finalize();

    assert_matches!(
        pair.server_send(server_ch, s).write(b"foo"),
        Err(WriteError::Stopped(ERROR))
    );
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Stopped {
            id: _,
            error_code: ERROR
        }))
    );
    assert_matches!(pair.server_conn_mut(server_ch).poll(), None);
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn implicit_open(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let (client_ch, server_ch) = pair.connect(cprovider);
    let s1 = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    let s2 = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    pair.client_send(client_ch, s2).write(b"hello").unwrap();
    pair.drive();
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );
    assert_eq!(pair.server_streams(server_ch).accept(Dir::Uni), Some(s1));
    assert_eq!(pair.server_streams(server_ch).accept(Dir::Uni), Some(s2));
    assert_eq!(pair.server_streams(server_ch).accept(Dir::Uni), None);
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn zero_length_cid(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let cid_generator_factory: fn() -> Box<dyn ConnectionIdGenerator> =
        || Box::new(RandomConnectionIdGenerator::new(0));
    let mut pair = Pair::new(
        Arc::new(EndpointConfig {
            connection_id_generator_factory: Arc::new(cid_generator_factory),
            ..EndpointConfig::default()
        }),
        Arc::new(sprovider.server_config()),
    );
    let (client_ch, server_ch) = pair.connect(cprovider);
    // Ensure we can reconnect after a previous connection is cleaned up
    info!("closing");
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    pair.server
        .connections
        .get_mut(&server_ch)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.connect(cprovider);
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn keep_alive(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    const IDLE_TIMEOUT: u64 = 10;
    let server = ServerConfig {
        transport: Arc::new(TransportConfig {
            keep_alive_interval: Some(Duration::from_millis(IDLE_TIMEOUT / 2)),
            max_idle_timeout: Some(VarInt(IDLE_TIMEOUT)),
            ..TransportConfig::default()
        }),
        ..sprovider.server_config()
    };
    let mut pair = Pair::new(Default::default(), Arc::new(server));
    let (client_ch, server_ch) = pair.connect(cprovider);
    // Run a good while longer than the idle timeout
    let end = pair.time + Duration::from_millis(20 * IDLE_TIMEOUT);
    while pair.time < end {
        if !pair.step() {
            if let Some(time) = min_opt(pair.client.next_wakeup(), pair.server.next_wakeup()) {
                pair.time = time;
            }
        }
        assert!(!pair.client_conn_mut(client_ch).is_closed());
        assert!(!pair.server_conn_mut(server_ch).is_closed());
    }
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn cid_rotation(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    const CID_TIMEOUT: Duration = Duration::from_secs(2);

    let cid_generator_factory: fn() -> Box<dyn ConnectionIdGenerator> =
        || Box::new(*RandomConnectionIdGenerator::new(8).set_lifetime(CID_TIMEOUT));

    // Only test cid rotation on server side to have a clear output trace
    let server = Endpoint::new(
        Arc::new(EndpointConfig {
            connection_id_generator_factory: Arc::new(cid_generator_factory),
            ..EndpointConfig::default()
        }),
        Some(Arc::new(sprovider.server_config())),
    );
    let client = Endpoint::new(Arc::new(EndpointConfig::default()), None);

    let mut pair = Pair::new_from_endpoint(client, server);
    let (_, server_ch) = pair.connect(cprovider);

    let mut round: u64 = 1;
    let mut stop = pair.time;
    let end = pair.time + 5 * CID_TIMEOUT;

    use crate::cid_queue::CidQueue;
    use crate::LOC_CID_COUNT;
    let mut active_cid_num = CidQueue::LEN as u64 + 1;
    active_cid_num = active_cid_num.min(LOC_CID_COUNT);
    let mut left_bound = 0;
    let mut right_bound = active_cid_num - 1;

    while pair.time < end {
        stop += CID_TIMEOUT;
        // Run a while until PushNewCID timer fires
        while pair.time < stop {
            if !pair.step() {
                if let Some(time) = min_opt(pair.client.next_wakeup(), pair.server.next_wakeup()) {
                    pair.time = time;
                }
            }
        }
        info!(
            "Checking active cid sequence range before {:?} seconds",
            round * CID_TIMEOUT.as_secs()
        );
        let _bound = (left_bound, right_bound);
        assert_matches!(
            pair.server_conn_mut(server_ch).active_local_cid_seq(),
            _bound
        );
        round += 1;
        left_bound += active_cid_num;
        right_bound += active_cid_num;
        pair.drive_server();
    }
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn cid_retirement(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let (client_ch, server_ch) = pair.connect(cprovider);

    // Server retires current active remote CIDs
    pair.server_conn_mut(server_ch)
        .rotate_local_cid(1, Instant::now());
    pair.drive();
    // Any unexpected behavior may trigger TransportError::CONNECTION_ID_LIMIT_ERROR
    assert!(!pair.client_conn_mut(client_ch).is_closed());
    assert!(!pair.server_conn_mut(server_ch).is_closed());
    assert_matches!(pair.client_conn_mut(client_ch).active_rem_cid_seq(), 1);

    use crate::cid_queue::CidQueue;
    use crate::LOC_CID_COUNT;
    let mut active_cid_num = CidQueue::LEN as u64;
    active_cid_num = active_cid_num.min(LOC_CID_COUNT);

    let next_retire_prior_to = active_cid_num + 1;
    pair.client_conn_mut(client_ch).ping();
    // Server retires all valid remote CIDs
    pair.server_conn_mut(server_ch)
        .rotate_local_cid(next_retire_prior_to, Instant::now());
    pair.drive();
    assert!(!pair.client_conn_mut(client_ch).is_closed());
    assert!(!pair.server_conn_mut(server_ch).is_closed());
    assert_matches!(
        pair.client_conn_mut(client_ch).active_rem_cid_seq(),
        _next_retire_prior_to
    );
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn finish_stream_flow_control_reordered(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let (client_ch, server_ch) = pair.connect(cprovider);

    let s = pair.client_streams(client_ch).open(Dir::Uni).unwrap();

    const MSG: &[u8] = b"hello";
    pair.client_send(client_ch, s).write(MSG).unwrap();
    pair.drive_client(); // Send stream data
    pair.server.drive(pair.time, pair.client.addr); // Receive

    // Issue flow control credit
    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(
        chunks.next(usize::MAX),
        Ok(Some(chunk)) if chunk.offset == 0 && chunk.bytes == MSG
    );
    let _ = chunks.finalize();

    pair.server.drive(pair.time, pair.client.addr);
    pair.server.delay_outbound(); // Delay it

    pair.client_send(client_ch, s).finish().unwrap();
    pair.drive_client(); // Send FIN
    pair.server.drive(pair.time, pair.client.addr); // Acknowledge
    pair.server.finish_delay(); // Add flow control packets after
    pair.drive();

    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Stream(StreamEvent::Finished { id })) if id == s
    );
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );
    assert_matches!(pair.server_streams(server_ch).accept(Dir::Uni), Some(stream) if stream == s);

    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(chunks.next(usize::MAX), Ok(None));
    let _ = chunks.finalize();
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn handshake_1rtt_handling(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let client_ch = pair.begin_connect(cprovider.client_config());
    pair.drive_client();
    pair.drive_server();
    let server_ch = pair.server.assert_accept();
    // Server now has 1-RTT keys, but remains in Handshake state until the TLS CFIN has
    // authenticated the client. Delay the final client handshake flight so that doesn't happen yet.
    pair.client.drive(pair.time, pair.server.addr);
    pair.client.delay_outbound();

    // Send some 1-RTT data which will be received first.
    let s = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    const MSG: &[u8] = b"hello";
    pair.client_send(client_ch, s).write(MSG).unwrap();
    pair.client_send(client_ch, s).finish().unwrap();
    pair.client.drive(pair.time, pair.server.addr);

    // Add the handshake flight back on.
    pair.client.finish_delay();

    pair.drive();

    assert!(pair.client_conn_mut(client_ch).lost_packets() != 0);
    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(
        chunks.next(usize::MAX),
        Ok(Some(chunk)) if chunk.offset == 0 && chunk.bytes == MSG
    );
    let _ = chunks.finalize();
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn stop_before_finish(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let (client_ch, server_ch) = pair.connect(cprovider);

    let s = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    const MSG: &[u8] = b"hello";
    pair.client_send(client_ch, s).write(MSG).unwrap();
    pair.drive();

    info!("stopping stream");
    const ERROR: VarInt = VarInt(42);
    pair.server_recv(server_ch, s).stop(ERROR).unwrap();
    pair.drive();

    assert_matches!(
        pair.client_send(client_ch, s).finish(),
        Err(FinishError::Stopped(ERROR))
    );
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn stop_during_finish(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let (client_ch, server_ch) = pair.connect(cprovider);

    let s = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    const MSG: &[u8] = b"hello";
    pair.client_send(client_ch, s).write(MSG).unwrap();
    pair.drive();

    assert_matches!(pair.server_streams(server_ch).accept(Dir::Uni), Some(stream) if stream == s);
    info!("stopping and finishing stream");
    const ERROR: VarInt = VarInt(42);
    pair.server_recv(server_ch, s).stop(ERROR).unwrap();
    pair.drive_server();
    pair.client_send(client_ch, s).finish().unwrap();
    pair.drive_client();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Stream(StreamEvent::Stopped { id, error_code: ERROR })) if id == s
    );
}

// Ensure we can recover from loss of tail packets when the congestion window is full
#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn congested_tail_loss(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let (client_ch, _) = pair.connect(cprovider);

    const TARGET: u64 = 2048;
    assert!(pair.client_conn_mut(client_ch).congestion_window() > TARGET);
    let s = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    // Send data without receiving ACKs until the congestion state falls below target
    while pair.client_conn_mut(client_ch).congestion_window() > TARGET {
        let n = pair.client_send(client_ch, s).write(&[42; 1024]).unwrap();
        assert_eq!(n, 1024);
        pair.drive_client();
    }
    assert!(!pair.server.inbound.is_empty());
    pair.server.inbound.clear();
    // Ensure that the congestion state recovers after retransmits occur and are ACKed
    info!("recovering");
    pair.drive();
    assert!(pair.client_conn_mut(client_ch).congestion_window() > TARGET);
    pair.client_send(client_ch, s).write(&[42; 1024]).unwrap();
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn datagram_send_recv(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let (client_ch, server_ch) = pair.connect(cprovider);
    assert_matches!(pair.server_conn_mut(server_ch).poll(), None);
    assert_matches!(pair.client_datagrams(client_ch).max_size(), Some(x) if x > 0);

    const DATA: &[u8] = b"whee";
    pair.client_datagrams(client_ch).send(DATA.into()).unwrap();
    pair.drive();
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::DatagramReceived)
    );
    assert_eq!(pair.server_datagrams(server_ch).recv().unwrap(), DATA);
    assert_matches!(pair.server_datagrams(server_ch).recv(), None);
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn datagram_recv_buffer_overflow(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    const WINDOW: usize = 100;
    let server = ServerConfig {
        transport: Arc::new(TransportConfig {
            datagram_receive_buffer_size: Some(WINDOW),
            ..TransportConfig::default()
        }),
        ..sprovider.server_config()
    };
    let mut pair = Pair::new(Default::default(), Arc::new(server));
    let (client_ch, server_ch) = pair.connect(cprovider);
    assert_matches!(pair.server_conn_mut(server_ch).poll(), None);
    assert_eq!(
        pair.client_conn_mut(client_ch).datagrams().max_size(),
        Some(WINDOW - Datagram::SIZE_BOUND)
    );

    const DATA1: &[u8] = &[0xAB; (WINDOW / 3) + 1];
    const DATA2: &[u8] = &[0xBC; (WINDOW / 3) + 1];
    const DATA3: &[u8] = &[0xCD; (WINDOW / 3) + 1];
    pair.client_datagrams(client_ch).send(DATA1.into()).unwrap();
    pair.client_datagrams(client_ch).send(DATA2.into()).unwrap();
    pair.client_datagrams(client_ch).send(DATA3.into()).unwrap();
    pair.drive();
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::DatagramReceived)
    );
    assert_eq!(pair.server_datagrams(server_ch).recv().unwrap(), DATA2);
    assert_eq!(pair.server_datagrams(server_ch).recv().unwrap(), DATA3);
    assert_matches!(pair.server_datagrams(server_ch).recv(), None);

    pair.client_datagrams(client_ch).send(DATA1.into()).unwrap();
    pair.drive();
    assert_eq!(pair.server_datagrams(server_ch).recv().unwrap(), DATA1);
    assert_matches!(pair.server_datagrams(server_ch).recv(), None);
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn datagram_unsupported(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let server = ServerConfig {
        transport: Arc::new(TransportConfig {
            datagram_receive_buffer_size: None,
            ..TransportConfig::default()
        }),
        ..sprovider.server_config()
    };
    let mut pair = Pair::new(Default::default(), Arc::new(server));
    let (client_ch, server_ch) = pair.connect(cprovider);
    assert_matches!(pair.server_conn_mut(server_ch).poll(), None);
    assert_matches!(pair.client_datagrams(client_ch).max_size(), None);

    match pair.client_datagrams(client_ch).send(Bytes::new()) {
        Err(SendDatagramError::UnsupportedByPeer) => {}
        Err(e) => panic!("unexpected error: {}", e),
        Ok(_) => panic!("unexpected success"),
    }
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn large_initial(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let server_config = sprovider.server_config_with_alpn_protocols(vec![vec![0, 0, 0, 42]]);

    let mut pair = Pair::new(Arc::new(EndpointConfig::default()), Arc::new(server_config));
    let protocols = (0..1000u32)
        .map(|x| x.to_be_bytes().to_vec())
        .collect::<Vec<_>>();
    let cfg = cprovider.client_config_with_alpn_protocols(protocols);
    let client_ch = pair.begin_connect(cfg);
    pair.drive();
    let server_ch = pair.server.assert_accept();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Connected { .. })
    );
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Connected { .. })
    );
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
/// Ensure that we don't yield a finish event before the actual FIN is acked so the peer isn't left
/// hanging
fn finish_acked(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let (client_ch, server_ch) = pair.connect(cprovider);

    let s = pair.client_streams(client_ch).open(Dir::Uni).unwrap();

    const MSG: &[u8] = b"hello";
    pair.client_send(client_ch, s).write(MSG).unwrap();
    info!("client sends data to server");
    pair.drive_client(); // send data to server
    info!("server acknowledges data");
    pair.drive_server(); // process data and send data ack

    // Receive data
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );
    assert_matches!(pair.server_conn_mut(server_ch).poll(), None);

    assert_matches!(pair.server_streams(server_ch).accept(Dir::Uni), Some(stream) if stream == s);

    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(
        chunks.next(usize::MAX),
        Ok(Some(chunk)) if chunk.offset == 0 && chunk.bytes == MSG
    );
    assert_matches!(chunks.next(usize::MAX), Err(ReadError::Blocked));
    let _ = chunks.finalize();

    // Finish before receiving data ack
    pair.client_send(client_ch, s).finish().unwrap();
    // Send FIN, receive data ack
    info!("client receives ACK, sends FIN");
    pair.drive_client();
    // Check for premature finish from data ack
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    // Process FIN ack
    info!("server ACKs FIN");
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Stream(StreamEvent::Finished { id })) if id == s
    );

    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(chunks.next(usize::MAX), Ok(None));
    let _ = chunks.finalize();
}

#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
/// Ensure that we don't yield a finish event while there's still unacknowledged data
fn finish_retransmit(cprovider: Provider, sprovider: Provider) {
    let _guard = subscribe();
    let mut pair = Pair::for_provider(sprovider);
    let (client_ch, server_ch) = pair.connect(cprovider);

    let s = pair.client_streams(client_ch).open(Dir::Uni).unwrap();

    const MSG: &[u8] = b"hello";
    pair.client_send(client_ch, s).write(MSG).unwrap();
    pair.drive_client(); // send data to server
    pair.server.inbound.clear(); // Lose it

    // Send FIN
    pair.client_send(client_ch, s).finish().unwrap();
    pair.drive_client();
    // Process FIN
    pair.drive_server();
    // Receive FIN ack, but no data ack
    pair.drive_client();
    // Check for premature finish from FIN ack
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    // Recover
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Stream(StreamEvent::Finished { id })) if id == s
    );

    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );

    assert_matches!(pair.server_streams(server_ch).accept(Dir::Uni), Some(stream) if stream == s);

    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(
        chunks.next(usize::MAX),
        Ok(Some(chunk)) if chunk.offset == 0 && chunk.bytes == MSG
    );
    assert_matches!(chunks.next(usize::MAX), Ok(None));
    let _ = chunks.finalize();
}

/// Ensures that exchanging data on a client-initiated bidirectional stream works past the initial
/// stream window.
#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn repeated_request_response(cprovider: Provider, sprovider: Provider) {
    // let cprovider = Provider::Boring;
    // let sprovider = Provider::Boring;
    let _guard = subscribe();
    let server = ServerConfig {
        transport: Arc::new(TransportConfig {
            max_concurrent_bidi_streams: 1u32.into(),
            ..TransportConfig::default()
        }),
        ..sprovider.server_config()
    };
    let mut pair = Pair::new(Default::default(), Arc::new(server));
    let (client_ch, server_ch) = pair.connect(cprovider);
    const REQUEST: &[u8] = b"hello";
    const RESPONSE: &[u8] = b"world";
    for _ in 0..3 {
        let s = pair.client_streams(client_ch).open(Dir::Bi).unwrap();

        pair.client_send(client_ch, s).write(REQUEST).unwrap();
        pair.client_send(client_ch, s).finish().unwrap();

        pair.drive();

        assert_eq!(pair.server_streams(server_ch).accept(Dir::Bi), Some(s));
        let mut recv = pair.server_recv(server_ch, s);
        let mut chunks = recv.read(false).unwrap();
        assert_matches!(
            chunks.next(usize::MAX),
            Ok(Some(chunk)) if chunk.offset == 0 && chunk.bytes == REQUEST
        );

        assert_matches!(chunks.next(usize::MAX), Ok(None));
        let _ = chunks.finalize();
        pair.server_send(server_ch, s).write(RESPONSE).unwrap();
        pair.server_send(server_ch, s).finish().unwrap();

        pair.drive();

        let mut recv = pair.client_recv(client_ch, s);
        let mut chunks = recv.read(false).unwrap();
        assert_matches!(
            chunks.next(usize::MAX),
            Ok(Some(chunk)) if chunk.offset == 0 && chunk.bytes == RESPONSE
        );
        assert_matches!(chunks.next(usize::MAX), Ok(None));
        let _ = chunks.finalize();
    }
}

/// Ensures that the client sends an anti-deadlock probe after an incomplete server's first flight
#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn handshake_anti_deadlock_probe(cprovider: Provider, sprovider: Provider) {
    // let cprovider = Provider::Boring;
    // let sprovider = Provider::Boring;
    let _guard = subscribe();

    let cert_and_key = big_cert_and_key();
    let server = sprovider.server_config_with_cert(&cert_and_key);
    let client = cprovider.client_config_with_cert(cert_and_key.cert_chain());
    let mut pair = Pair::new(Default::default(), Arc::new(server));

    let client_ch = pair.begin_connect(client);
    // Client sends initial
    pair.drive_client();
    // Server sends first flight, gets blocked on anti-amplification
    pair.drive_server();
    // Client acks...
    pair.drive_client();
    // ...but it's lost, so the server doesn't get anti-amplification credit from it
    pair.server.inbound.clear();
    // Client sends an anti-deadlock probe, and the handshake completes as usual.
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Connected { .. })
    );
}

/// Ensures that the server can respond with 3 initial packets during the handshake
/// before the anti-amplification limit kicks in when MTUs are similar.
#[parameterized(
rustls = { Provider::Rustls, Provider::Rustls },
boring = { Provider::Boring, Provider::Boring },
rustls_to_boring = { Provider::Rustls, Provider::Boring },
boring_to_rustls = { Provider::Boring, Provider::Rustls },
)]
fn server_can_send_3_inital_packets(cprovider: Provider, sprovider: Provider) {
    // let cprovider = Provider::Boring;
    // let sprovider = Provider::Boring;
    let _guard = subscribe();

    let cert_and_key = big_cert_and_key();
    let server = sprovider.server_config_with_cert(&cert_and_key);
    let client = cprovider.client_config_with_cert(cert_and_key.cert_chain());
    let mut pair = Pair::new(Default::default(), Arc::new(server));

    let client_ch = pair.begin_connect(client);
    // Client sends initial
    pair.drive_client();
    // Server sends first flight, gets blocked on anti-amplification
    pair.drive_server();
    // Server should have queued 3 packets at this time
    assert_eq!(pair.client.inbound.len(), 3);

    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Connected { .. })
    );
}

/// Generate a big fat certificate that can't fit inside the initial anti-amplification limit
fn big_cert_and_key() -> CertAndKey {
    gen_cert(
        Some("localhost".into())
            .into_iter()
            .chain((0..1000).map(|x| format!("foo_{}", x)))
            .collect::<Vec<_>>(),
        &CA,
    )
}

#[parameterized(
rustls = { Provider::Rustls },
boring = { Provider::Boring },
)]
fn malformed_token_len(sprovider: Provider) {
    // let cprovider = Provider::Boring;
    // let sprovider = Provider::Boring;
    let _guard = subscribe();
    let client_addr = "[::2]:7890".parse().unwrap();
    let mut server = Endpoint::new(
        Default::default(),
        Some(Arc::new(sprovider.server_config())),
    );
    server.handle(
        Instant::now(),
        client_addr,
        None,
        None,
        hex!("8900 0000 0101 0000 1b1b 841b 0000 0000 3f00")[..].into(),
    );
}
