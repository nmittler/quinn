mod aead;
mod alert;
mod alpn;
mod bffi_ext;
mod client;
mod error;
mod handshake_token;
mod hkdf;
mod hmac;
mod key;
mod macros;
mod param_util;
mod secret;
mod server;
mod session_cache;
mod session_state;
mod suite;
mod version;

// Export the public interface.
pub use alpn::*;
pub use bffi_ext::*;
pub use client::Config as ClientConfig;
pub use error::{Error, Result};
pub use handshake_token::HandshakeTokenKey;
pub use hmac::HmacKey;
pub use server::Config as ServerConfig;
pub use session_cache::*;
pub use version::QuicVersion;

/// Information available from [Session::handshake_data] once the handshake has completed.
pub struct HandshakeData {
    /// The negotiated application protocol, if ALPN is in use
    ///
    /// Guaranteed to be set if a nonempty list of protocols was specified for this connection.
    pub protocol: Option<Vec<u8>>,

    /// The server name specified by the client, if any
    ///
    /// Always `None` for outgoing connections
    pub server_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::boring::aead::TAG_LEN;
    use crate::crypto::boring::error::Result;
    use crate::crypto::boring::secret::{Secret, Secrets};
    use crate::crypto::boring::suite::CipherSuite;
    use crate::crypto::{ClientConfig, ServerConfig};
    use crate::transport_parameters::{PreferredAddress, TransportParameters};
    use crate::{crypto, ConnectionId, Side, RESET_TOKEN_SIZE};
    use boring::pkey::{PKey, Private};
    use boring::x509::X509;
    use bytes::BytesMut;
    use hex_literal::hex;
    use lazy_static::lazy_static;
    use rustls::{Certificate, KeyLogFile, PrivateKey};
    use std::any::Any;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::Arc;

    lazy_static! {
        static ref CERTIFICATE: rcgen::Certificate =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    }

    const KEY: &[u8] = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIK0xIG5qmZXWK/OLeTVAOy1VUSmHrH8odqpiHElMyZkAoAoGCCqGSM49
AwEHoUQDQgAEiO1xBD+48t24IozQ0K/yTObhW6d50pdUFM/o1OZE/osJ9WPOIYWd
V0MBboh2u37robtHCFu32OO2hkgGsWc7Dw==
-----END EC PRIVATE KEY-----
"
    .as_bytes();

    const CA_CERT: &[u8] = "-----BEGIN CERTIFICATE-----
MIIBhzCCAS2gAwIBAgIUfnPH7banyhkPDHCBmVeisk3KFKkwCgYIKoZIzj0EAwIw
GDEWMBQGA1UECgwNY2x1c3Rlci5sb2NhbDAgFw0yMjExMTgxNjU4MjZaGA8yMjk2
MDkwMjE2NTgyNlowGDEWMBQGA1UECgwNY2x1c3Rlci5sb2NhbDBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABGL6BaS2jW+GznxrHnnDvDCBBKvuHHg35yc18H61NKjt
ljQ06qOGiyWH219gugr0nhDn43uSmx4vHkJhlU1nc0ujUzBRMB0GA1UdDgQWBBRK
OHn6jPW+rM/MgqLTEsSKDXgXdzAfBgNVHSMEGDAWgBRKOHn6jPW+rM/MgqLTEsSK
DXgXdzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCntPleHc4+
RpmW4D5xQszUsMOVrxzPmVBKDzMDl5NgUwIgYtRpO9TDgQxgP6DW3jj6IQ5lv2xR
X6IfsJZgMU3EKwU=
-----END CERTIFICATE-----
"
    .as_bytes();

    const CA_KEY: &[u8] = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHuydKTawUXQLhAltF2JGRdP8453ghPiE4a4VhSlGBa1oAoGCCqGSM49
AwEHoUQDQgAEYvoFpLaNb4bOfGseecO8MIEEq+4ceDfnJzXwfrU0qO2WNDTqo4aL
JYfbX2C6CvSeEOfje5KbHi8eQmGVTWdzSw==
-----END EC PRIVATE KEY-----
"
    .as_bytes();

    fn cert_and_key() -> (Vec<u8>, Vec<u8>) {
        (
            CERTIFICATE.serialize_der().unwrap(),
            CERTIFICATE.serialize_private_key_der(),
        )
    }

    fn cert_and_key_boring() -> (X509, PKey<Private>) {
        let (cert, key) = cert_and_key();
        (
            X509::from_der(&cert).unwrap(),
            PKey::private_key_from_der(&key).unwrap(),
        )
    }

    fn cert_and_key_rustls() -> (Certificate, PrivateKey) {
        let (cert, key) = cert_and_key();
        (Certificate(cert), PrivateKey(key))
    }

    // struct Certs {
    //     cert: X509,
    //     key: PKey<Private>,
    //     chain: Vec<X509>,
    // }
    //
    // fn certs(subject_alt_name: &str) -> StdResult<Certs, ErrorStack> {
    //     let key = PKey::private_key_from_pem(KEY)?;
    //     let ca_key = PKey::private_key_from_pem(CA_KEY)?;
    //     let ca_cert = X509::from_pem(CA_CERT)?;
    //
    //     let mut builder = X509::builder()?;
    //     builder.set_pubkey(&key)?;
    //
    //     builder.set_version(2)?;
    //     builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    //     builder.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
    //
    //     let serial_number = {
    //         let mut serial = BigNum::new().unwrap();
    //         serial
    //             .rand(159, boring::bn::MsbOption::MAYBE_ZERO, false)
    //             .unwrap();
    //         serial.to_asn1_integer().unwrap()
    //     };
    //     builder.set_serial_number(&serial_number)?;
    //
    //     let mut names = X509NameBuilder::new()?;
    //     names.append_entry_by_text("O", "cluster.local")?;
    //     let names = names.build();
    //     builder.set_issuer_name(&names)?;
    //
    //     builder.append_extension(
    //         KeyUsage::new()
    //             .critical()
    //             .digital_signature()
    //             .key_encipherment()
    //             .build()?,
    //     )?;
    //     builder.append_extension(
    //         ExtendedKeyUsage::new()
    //             .client_auth()
    //             .server_auth()
    //             .build()?,
    //     )?;
    //     builder.append_extension(BasicConstraints::new().critical().build()?)?;
    //     builder.append_extension(
    //         AuthorityKeyIdentifier::new()
    //             .keyid(false)
    //             .issuer(false)
    //             .build(&builder.x509v3_context(Some(&ca_cert), None))?,
    //     )?;
    //     builder.append_extension(
    //         SubjectAlternativeName::new()
    //             .uri(subject_alt_name)
    //             .critical()
    //             .build(&builder.x509v3_context(Some(&ca_cert), None))?,
    //     )?;
    //
    //     // CA signs the cert.
    //     builder.sign(&ca_key, MessageDigest::sha256())?;
    //
    //     let cert = builder.build();
    //     Ok(Certs {
    //         cert: cert.clone(),
    //         key,
    //         chain: vec![cert.clone(), ca_cert],
    //     })
    // }

    /// Copied from quiche.
    #[test]
    fn test_initial_keys_v1() -> Result<()> {
        let dcid: &[u8] = &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08][..];
        let version = QuicVersion::V1;
        let suite = CipherSuite::aes128_gcm_sha256();

        let s = Secrets::initial(version, &ConnectionId::new(dcid), Side::Client)?;

        let expected_enc_key: &[u8] = &[
            0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1,
            0xa2, 0x2d,
        ];
        assert_eq!(
            s.local.packet_key(version, suite)?.key().slice(),
            expected_enc_key
        );
        let expected_enc_iv: &[u8] = &[
            0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c,
        ];
        assert_eq!(
            s.local.packet_key(version, suite)?.iv().slice(),
            expected_enc_iv
        );
        let expected_enc_hdr_key: &[u8] = &[
            0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad,
            0xed, 0xd2,
        ];
        assert_eq!(
            s.local.header_key(version, suite)?.key().slice(),
            expected_enc_hdr_key
        );
        let expected_dec_key: &[u8] = &[
            0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c, 0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06,
            0x7e, 0x37,
        ];
        assert_eq!(
            s.remote.packet_key(version, suite)?.key().slice(),
            expected_dec_key
        );
        let expected_dec_iv: &[u8] = &[
            0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53, 0xb0, 0xbb, 0xa0, 0x3e,
        ];
        assert_eq!(
            s.remote.packet_key(version, suite)?.iv().slice(),
            expected_dec_iv
        );
        let expected_dec_hdr_key: &[u8] = &[
            0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76, 0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea,
            0xa3, 0x14,
        ];
        assert_eq!(
            s.remote.header_key(version, suite)?.key().slice(),
            expected_dec_hdr_key
        );

        Ok(())
    }

    #[test]
    fn test_retry_tag() -> Result<()> {
        let cid = ConnectionId::new(&hex!["8394c8f03e515708"]);
        let version = QuicVersion::V1;
        let packet = hex!(
            "c0000000010806b858ec6f80452b0000402100c8fb7ffd97230e38b70d86e7ff148afdf88fc21c4426c7d1cec79914c8785757"
        );

        let boring_tag = {
            let cfg = crypto::boring::ServerConfig::new()?;
            cfg.retry_tag(version.label(), &cid, &packet)
        };

        let expected = hex!("559c3e639c4684e0068e8e241ba356aa");
        assert_eq!(expected, boring_tag);
        Ok(())
    }

    /// Copied from rustls.
    #[test]
    fn short_packet_header_protection() {
        // https://www.rfc-editor.org/rfc/rfc9001.html#name-chacha20-poly1305-short-hea

        const PN: u64 = 654360564;
        const SECRET: &[u8] = &[
            0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e, 0xbe, 0x69, 0x42, 0x27, 0x48, 0xad,
            0x00, 0xa1, 0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0, 0x7d, 0x60, 0x60, 0xf6, 0x88, 0xf3,
            0x0f, 0x21, 0x63, 0x2b,
        ];

        let version = QuicVersion::V1;
        let suite = CipherSuite::chacha20_poly1305_sha256();

        let secret = Secret::from(SECRET);
        let hpk = secret
            .header_key(version, suite)
            .unwrap()
            .as_crypto()
            .unwrap();
        let packet = secret
            .packet_key(version, suite)
            .unwrap()
            .as_crypto()
            .unwrap();

        const PLAIN: &[u8] = &[0x42, 0x00, 0xbf, 0xf4, b'h', b'e', b'l', b'l', b'o'];

        let mut buf = PLAIN.to_vec();
        // Make space for the output tag.
        buf.extend_from_slice(&[0u8; TAG_LEN]);
        packet.encrypt(PN, &mut buf, 4);

        let pn_offset = 1;
        hpk.encrypt(pn_offset, &mut buf);

        const PROTECTED: &[u8] = &[
            0x59, 0x3b, 0x46, 0x22, 0x0c, 0x4d, 0x50, 0x4a, 0x9f, 0x18, 0x57, 0x79, 0x33, 0x56,
            0x40, 0x0f, 0xc4, 0xa7, 0x84, 0xee, 0x30, 0x9d, 0xff, 0x98, 0xb2,
        ];

        assert_eq!(&buf, PROTECTED);

        hpk.decrypt(pn_offset, &mut buf);

        let (header, payload_tag) = buf.split_at(4);
        let mut payload_tag = BytesMut::from(payload_tag);
        packet.decrypt(PN, header, &mut payload_tag).unwrap();
        let plain = payload_tag.as_ref();
        assert_eq!(plain, &PLAIN[4..]);
    }

    /// Copied from rustls.
    #[test]
    fn key_update_test_vector() {
        let version = QuicVersion::V1;
        let suite = CipherSuite::aes128_gcm_sha256();
        let mut secrets = Secrets {
            version,
            suite,
            local: Secret::from(&[
                0xb8, 0x76, 0x77, 0x08, 0xf8, 0x77, 0x23, 0x58, 0xa6, 0xea, 0x9f, 0xc4, 0x3e, 0x4a,
                0xdd, 0x2c, 0x96, 0x1b, 0x3f, 0x52, 0x87, 0xa6, 0xd1, 0x46, 0x7e, 0xe0, 0xae, 0xab,
                0x33, 0x72, 0x4d, 0xbf,
            ]),
            remote: Secret::from(&[
                0x42, 0xdc, 0x97, 0x21, 0x40, 0xe0, 0xf2, 0xe3, 0x98, 0x45, 0xb7, 0x67, 0x61, 0x34,
                0x39, 0xdc, 0x67, 0x58, 0xca, 0x43, 0x25, 0x9b, 0x87, 0x85, 0x06, 0x82, 0x4e, 0xb1,
                0xe4, 0x38, 0xd8, 0x55,
            ]),
        };
        secrets.update().unwrap();

        let expected = Secrets {
            version,
            suite,
            local: Secret::from(&[
                0x42, 0xca, 0xc8, 0xc9, 0x1c, 0xd5, 0xeb, 0x40, 0x68, 0x2e, 0x43, 0x2e, 0xdf, 0x2d,
                0x2b, 0xe9, 0xf4, 0x1a, 0x52, 0xca, 0x6b, 0x22, 0xd8, 0xe6, 0xcd, 0xb1, 0xe8, 0xac,
                0xa9, 0x6, 0x1f, 0xce,
            ]),
            remote: Secret::from(&[
                0xeb, 0x7f, 0x5e, 0x2a, 0x12, 0x3f, 0x40, 0x7d, 0xb4, 0x99, 0xe3, 0x61, 0xca, 0xe5,
                0x90, 0xd4, 0xd9, 0x92, 0xe1, 0x4b, 0x7a, 0xce, 0x3, 0xc2, 0x44, 0xe0, 0x42, 0x21,
                0x15, 0xb6, 0xd3, 0x8a,
            ]),
        };

        assert_eq!(expected, secrets);
    }

    #[test]
    fn client_encrypt_header() {
        let dcid = ConnectionId::new(&hex!("06b858ec6f80452b"));

        let secrets = Secrets::initial(QuicVersion::V1, &dcid, Side::Client).unwrap();
        let client = secrets.keys().unwrap().as_crypto().unwrap();

        // Client (encrypt)
        let mut packet: [u8; 51] = hex!(
            "c0000000010806b858ec6f80452b0000402100c8fb7ffd97230e38b70d86e7ff148afdf88fc21c4426c7d1cec79914c8785757"
        );
        let packet_number = 0;
        let packet_number_pos = 18;
        let header_len = 19;

        // Encrypt the payload.
        client
            .packet
            .local
            .encrypt(packet_number, &mut packet, header_len);
        let expected_after_packet_encrypt: [u8; 51] = hex!(
            "c0000000010806b858ec6f80452b0000402100f60e77fa2f629f9921fae64125c5632cf769d801a4693af6b949af37c2c45399"
        );
        assert_eq!(packet, expected_after_packet_encrypt);

        // Encrypt the header.
        client.header.local.encrypt(packet_number_pos, &mut packet);
        let expected_after_header_encrypt: [u8; 51] = hex!(
            "cd000000010806b858ec6f80452b000040210bf60e77fa2f629f9921fae64125c5632cf769d801a4693af6b949af37c2c45399"
        );
        assert_eq!(packet, expected_after_header_encrypt);
    }

    #[test]
    fn server_decrypt_header() {
        let dcid = ConnectionId::new(&hex!("06b858ec6f80452b"));
        let secrets = Secrets::initial(QuicVersion::V1, &dcid, Side::Server).unwrap();
        let server = secrets.keys().unwrap().as_crypto().unwrap();

        let mut packet = BytesMut::from(&hex!(
            "c8000000010806b858ec6f80452b00004021be3ef50807b84191a196f760a6dad1e9d1c430c48952cba0148250c21c0a6a70e1"
        )[..]);
        let packet_number = 0;
        let packet_number_pos = 18;
        let header_len = 19;

        // Decrypt the header.
        server.header.remote.decrypt(packet_number_pos, &mut packet);
        let expected_header: [u8; 19] = hex!("c0000000010806b858ec6f80452b0000402100");
        assert_eq!(packet[..header_len], expected_header);

        // Decrypt the payload.
        let mut header = packet;
        let mut packet = header.split_off(header_len);
        server
            .packet
            .remote
            .decrypt(packet_number, &mut header, &mut packet)
            .unwrap();
        assert_eq!(packet[..], [0; 16]);
    }

    pub fn configs_rustls() -> (rustls::ClientConfig, rustls::ServerConfig) {
        let (cert, key) = cert_and_key_rustls();

        // Create the client config with the certs.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(&cert).unwrap();
        let mut client = crypto::rustls::client_config(roots);
        client.alpn_protocols = vec!["h3".into()];
        client.key_log = Arc::new(KeyLogFile::new());

        let mut server = crypto::rustls::server_config(vec![cert], key).unwrap();
        server.alpn_protocols = vec!["h3".into()];

        (client, server)
    }

    pub fn handshake_data_rustls(hd: Option<Box<dyn Any>>) -> Box<crypto::rustls::HandshakeData> {
        hd.unwrap()
            .downcast::<crypto::rustls::HandshakeData>()
            .unwrap()
    }

    pub fn handshake_data_boring(hd: Option<Box<dyn Any>>) -> Box<HandshakeData> {
        hd.unwrap().downcast::<HandshakeData>().unwrap()
    }

    pub fn server_name_rustls(hd: Option<Box<dyn Any>>) -> String {
        handshake_data_rustls(hd).server_name.unwrap()
    }

    pub fn server_name_boring(hd: Option<Box<dyn Any>>) -> String {
        handshake_data_boring(hd).server_name.unwrap()
    }

    pub fn configs_boring() -> (crypto::boring::ClientConfig, crypto::boring::ServerConfig) {
        let (cert, key) = cert_and_key_boring();

        // Create the client config from the certs.
        let mut client = crypto::boring::ClientConfig::new().unwrap();
        client.ctx.cert_store_mut().add_cert(cert.clone()).unwrap();

        let mut server = crypto::boring::ServerConfig::new().unwrap();
        server.ctx.set_certificate(cert.clone().as_ref()).unwrap();
        server.ctx.set_private_key(key.as_ref()).unwrap();
        server.ctx.check_private_key().unwrap();

        (client, server)
    }

    #[test]
    fn handshake_1rtt() {
        let (client_cfg_rustls, server_cfg_rustls) = configs_rustls(); //configs_boring();
        let (client_cfg_boring, server_cfg_boring) = configs_boring(); //configs_boring();
        let client_cfg = client_cfg_rustls;
        let server_cfg = server_cfg_boring;
        let get_server_name = server_name_boring;

        let client_cfg = Arc::new(client_cfg);
        let server_cfg = Arc::new(server_cfg);

        let version = 0x0000_0001;
        let server_name = "fake.com";
        let src_cid = ConnectionId::new(&hex!("01020304"));
        let dest_cid = ConnectionId::new(&hex!("05060708"));
        let params = TransportParameters {
            initial_src_cid: Some(src_cid),
            original_dst_cid: Some(dest_cid),
            initial_max_streams_bidi: 16u32.into(),
            initial_max_streams_uni: 16u32.into(),
            ack_delay_exponent: 2u32.into(),
            max_udp_payload_size: 1200u32.into(),
            preferred_address: Some(PreferredAddress {
                address_v4: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42)),
                address_v6: None,
                connection_id: dest_cid,
                stateless_reset_token: [0xab; RESET_TOKEN_SIZE].into(),
            }),
            grease_quic_bit: true,
            ..TransportParameters::default()
        };

        let mut client = client_cfg
            .start_session(version, server_name, &params)
            .unwrap();
        let mut server = server_cfg.start_session(version, &params);
        assert!(client.is_handshaking());
        assert!(server.is_handshaking());
        assert!(client.handshake_data().is_none());
        assert!(server.handshake_data().is_none());
        assert!(client.next_1rtt_keys().is_none());
        assert!(server.next_1rtt_keys().is_none());

        // Generate the client hello.
        let mut data_from_client = Vec::new();
        let next_client_keys = client.write_handshake(&mut data_from_client);
        assert!(next_client_keys.is_none());
        assert!(client.is_handshaking());
        assert!(client.handshake_data().is_none());
        assert!(client.next_1rtt_keys().is_none());

        // Send the client hello to the server.
        let got_handshake_data = server.read_handshake(&data_from_client).unwrap();
        assert!(got_handshake_data);
        assert!(server.is_handshaking());
        assert_eq!(
            server_name,
            get_server_name(server.handshake_data()).as_str()
        );
        assert!(server.next_1rtt_keys().is_none());

        // Generate the server hello.
        let mut data_from_server = Vec::new();
        let next_server_keys = server.write_handshake(&mut data_from_server);
        assert!(next_server_keys.is_some()); // Handshake keys.
        assert!(server.is_handshaking());
        assert_eq!(
            server_name,
            get_server_name(server.handshake_data()).as_str()
        );
        //assert!(server.next_1rtt_keys().is_none());

        // Send the server hello to the client.
        let got_handshake_data = client.read_handshake(&data_from_server).unwrap();
        assert!(!got_handshake_data);
        assert!(client.is_handshaking());
        assert!(client.handshake_data().is_none());
        assert!(client.next_1rtt_keys().is_none());

        let mut data_from_client = Vec::new();
        let next_client_keys = client.write_handshake(&mut data_from_client);
        assert!(next_client_keys.is_some()); // Handshaking.
        assert!(data_from_client.is_empty()); // No further handshake data to write to the server.
        assert!(client.is_handshaking());
        //assert!(client.next_1rtt_keys().is_none());

        // Send an empty client frame to the server.
        let got_handshake_data = server.read_handshake(&data_from_client).unwrap();
        // assert!(got_handshake_data); // doesn't work for rustls.
        assert!(server.is_handshaking());
        let handshake_data = server.handshake_data();
        assert!(handshake_data.is_some());
        //assert!(server.next_1rtt_keys().is_none());
    }
}
