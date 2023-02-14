use crate::crypto::boring::error::{map_result, Error, Result};
use boring::hash::MessageDigest;
use boring_sys as bffi;
use bytes::{BufMut, BytesMut};
use lazy_static::lazy_static;

/// The maximum digest size used by the supported digest algorithms (SHA256=32, SHA384=48).
pub(super) const MAX_DIGEST_LEN: usize = 48;

/// Implementation of [HKDF](https://www.rfc-editor.org/rfc/rfc5869)) used for
/// creating the initial secrets for
/// [QUIC](https://www.rfc-editor.org/rfc/rfc9001#section-5.2) and
/// [TLS_1.3](https://datatracker.ietf.org/doc/html/rfc9001#name-initial-secrets).
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Hkdf(MessageDigest);

lazy_static! {
    static ref SHA256: Hkdf = Hkdf(MessageDigest::sha256());
    static ref SHA384: Hkdf = Hkdf(MessageDigest::sha384());
}

impl Hkdf {
    pub(super) fn sha256() -> Hkdf {
        *SHA256
    }

    pub(super) fn sha384() -> Hkdf {
        *SHA384
    }

    /// The digest hash used for this HKDF instance.
    #[inline]
    pub(super) fn digest(self) -> MessageDigest {
        self.0
    }

    /// The size of the digest in bytes.
    #[inline]
    pub(super) fn digest_size(self) -> usize {
        self.0.size()
    }

    /// Performs an HKDF extract (https://tools.ietf.org/html/rfc5869#section-2.2),
    /// given the salt and the initial key material (IKM). Returns the slice of the [out]
    /// array containing the generated pseudorandom key (PRK).
    #[inline]
    pub(super) fn extract<'a>(
        self,
        salt: &[u8],
        ikm: &[u8],
        out: &'a mut [u8],
    ) -> Result<usize> {
        if out.len() < self.digest_size() {
            return Err(Error::invalid_input(
                format!("HKDF extract output array invalid size: {}", out.len()).into(),
            ));
        }

        let mut out_len = out.len();

        unsafe {
            map_result(bffi::HKDF_extract(
                out.as_mut_ptr(),
                &mut out_len,
                self.0.as_ptr(),
                ikm.as_ptr(),
                ikm.len(),
                salt.as_ptr(),
                salt.len(),
            ))?;

            Ok(out_len)
        }
    }

    /// Performs the HKDF-Expand-Label function as defined in the TLS-1.3 spec
    /// (https://datatracker.ietf.org/doc/html/rfc8446#section-7.1). The HKDF-Expand-Label
    /// function (as defined in (https://www.rfc-editor.org/rfc/rfc5869#section-2.3)) takes
    /// 4 explicit arguments (Secret, Label, Context, and Length), as well as implicit PRF
    /// which is the hash function negotiated by TLS.
    ///
    /// Its use in QUIC is only for deriving initial secrets for obfuscation, for calculating
    /// packet protection keys and IVs from the corresponding packet protection secret and
    /// key update in the same quic session. None of these uses need a Context (a zero-length
    /// context is provided), so this argument is omitted here.
    #[inline]
    pub(super) fn expand_label(self, secret: &[u8], label: &[u8], out: &mut [u8]) -> Result<()> {
        // Convert the label to a structure required by HKDF_expand. Doing
        // this inline rather than using the complex openssl Crypto ByteBuilder (CBB).
        let label = {
            const TLS_VERSION_LABEL: &[u8] = b"tls13 ";

            // Initialize the builder for the label structure.
            let label_len = TLS_VERSION_LABEL.len() + label.len();
            let builder_capacity = 2 /* 2-byte total length field */ +
                1 /* 1-byte for the length of the label. */ +
                label_len /* Label length */ +
                1 /* 1-byte for the length of the Context. */ +
                0 /* Quic does not use a Context (i.e. zero-length). */;
            let mut builder = BytesMut::with_capacity(builder_capacity);

            // Add the length of the output key in big-endian byte order.
            builder.put_u16(out.len() as u16);

            // Add a child containing the label.
            builder.put_u8(label_len as u8);
            builder.put(TLS_VERSION_LABEL);
            builder.put(label);

            // Add a child containing a zero hash.
            builder.put_u8(0);
            builder
        };

        self.expand(secret, &label, out)
    }

    #[inline]
    pub(super) fn expand(&self, prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
        unsafe {
            map_result(bffi::HKDF_expand(
                out.as_mut_ptr(),
                out.len(),
                self.0.as_ptr(),
                prk.as_ptr(),
                prk.len(),
                info.as_ptr(),
                info.len(),
            ))?;
        }
        Ok(())
    }
}
