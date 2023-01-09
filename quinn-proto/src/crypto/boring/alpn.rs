use crate::crypto::boring::error::{Result, Error};

#[derive(Clone, Debug)]
pub struct AlpnProtocol(Vec<u8>);

impl AlpnProtocol {
    pub fn from(val: Vec<u8>) -> Self {
        AlpnProtocol(val)
    }

    #[inline]
    pub fn encode_to(&self, out: &mut Vec<u8>) {
        out.push(self.0.len() as u8);
        out.extend_from_slice(&self.0);
    }

    #[inline]
    pub fn decode_from(encoded: &[u8]) -> (&[u8], AlpnProtocol) {
        assert!(encoded.len() > 0);

        // Read the length of the next protocol.
        let len = encoded[0] as usize;
        assert!(1 + len <= encoded.len());

        // Get the protocol.
        let alpn = AlpnProtocol(Vec::from(&encoded[1..1 + len]));
        (&encoded[1 + len..], alpn)
    }
}

#[derive(Clone, Debug)]
pub struct AlpnProtocols(Vec<AlpnProtocol>);

impl AlpnProtocols {
    pub const H3: &'static [u8; 2] = b"h3";

    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Performs the server-side ALPN protocol selection.
    pub fn select_from<'a>(&self, offered: &'a [u8]) -> Result<&'a [u8]> {
        for server_proto in &self.0 {
            let mut i = 0;
            while i < offered.len() {
                let len = offered[i] as usize;
                i += 1;

                let client_proto = &offered[i..i + len];
                if server_proto.0 == client_proto {
                    return Ok(client_proto);
                }
                i += len;
            }
        }
        Err(Error::other("ALPN selection failed".into()))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        for proto in &self.0 {
            proto.encode_to(&mut out);
        }
        out
    }

    pub fn decode(mut encoded: &[u8]) -> AlpnProtocols {
        let mut out = Vec::new();
        while encoded.len() > 0 {
            let (new_slice, alpn) = AlpnProtocol::decode_from(encoded);
            out.push(alpn);
            encoded = new_slice;
        }
        AlpnProtocols(out)
    }

    pub fn from(protos: &[Vec<u8>]) -> AlpnProtocols {
        let mut out = Vec::with_capacity(protos.len());
        for proto in protos {
            out.push(AlpnProtocol(proto.clone()))
        }
        AlpnProtocols(out)
    }
}

impl Default for AlpnProtocols {
    fn default() -> Self {
        Self::from(&[Self::H3.to_vec()])
    }
}
