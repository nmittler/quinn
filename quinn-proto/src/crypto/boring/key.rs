use crate::crypto;
use crate::crypto::boring::error::{map_result, map_result_zero_is_success, Result};
use crate::crypto::boring::macros::bounded_array;
use crate::crypto::boring::secret::Secret;
use crate::crypto::boring::suite::{CipherSuite, ID};
use crate::crypto::boring::{Error, QuicVersion};
use boring_sys as bffi;
use bytes::BytesMut;
use std::ffi::c_uint;
use std::mem;
use std::mem::MaybeUninit;
use std::result::Result as StdResult;

const SAMPLE_LEN: usize = 16; // 128-bits.

/// The maximum key size supported by Quic.
const MAX_KEY_LEN: usize = 32;

/// The maximum nonce size supported by Quic.
const MAX_NONCE_LEN: usize = 12;

bounded_array! {
    /// A buffer that can fit the largest key supported by Quic.
    pub(super) struct Key(MAX_KEY_LEN),

    /// A buffer that can fit the largest nonce supported by Quic.
    pub(super) struct Nonce(MAX_NONCE_LEN)
}

/// A pair of keys for bidirectional communication
#[derive(Copy, Clone, Debug)]
pub(super) struct KeyPair<T> {
    /// The key for this side, used for encrypting data.
    pub(super) local: T,

    /// The key for the other side, used for decrypting data.
    pub(super) remote: T,
}

impl KeyPair<HeaderKey> {
    #[inline]
    pub(super) fn as_crypto(&self) -> Result<crypto::KeyPair<Box<dyn crypto::HeaderKey>>> {
        Ok(crypto::KeyPair {
            local: self.local.as_crypto()?,
            remote: self.remote.as_crypto()?,
        })
    }
}

impl KeyPair<PacketKey> {
    #[inline]
    pub(super) fn as_crypto(&self) -> Result<crypto::KeyPair<Box<dyn crypto::PacketKey>>> {
        Ok(crypto::KeyPair {
            local: self.local.as_crypto()?,
            remote: self.remote.as_crypto()?,
        })
    }
}

/// A complete set of keys for a certain encryption level.
#[derive(Copy, Clone, Debug)]
pub(super) struct Keys {
    /// Header protection keys
    pub(super) header: KeyPair<HeaderKey>,
    /// Packet protection keys
    pub(super) packet: KeyPair<PacketKey>,
}

impl Keys {
    pub(super) fn as_crypto(&self) -> Result<crypto::Keys> {
        Ok(crypto::Keys {
            header: self.header.as_crypto()?,
            packet: self.packet.as_crypto()?,
        })
    }
}

/// Internal header key representation. Supports conversion to [crypto::HeaderKey]
#[derive(Copy, Clone, Debug)]
pub(super) struct HeaderKey {
    suite: &'static CipherSuite,
    key: Key,
}

impl HeaderKey {
    pub(super) fn new(
        version: QuicVersion,
        suite: &'static CipherSuite,
        secret: &Secret,
    ) -> Result<Self> {
        let mut key = suite.aead.new_key();
        suite
            .hkdf
            .expand_label(secret.slice(), version.header_key_label(), key.slice_mut())?;

        Ok(Self { suite, key })
    }

    #[inline]
    pub(super) fn key(&self) -> &Key {
        &self.key
    }

    /// Converts to a crypto HeaderKey.
    #[inline]
    pub(super) fn as_crypto(&self) -> Result<Box<dyn crypto::HeaderKey>> {
        match self.suite.id {
            ID::Aes128GcmSha256 | ID::Aes256GcmSha384 => {
                Ok(Box::new(AesHeaderKey::new(&self.key())?))
            }
            ID::Chacha20Poly1305Sha256 => Ok(Box::new(ChaChaHeaderKey::new(self.key().clone())?)),
        }
    }
}

/// Base trait for a crypto header protection keys. Implementation copied from rustls.
trait CryptoHeaderKey: crypto::HeaderKey {
    fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5]>;

    #[inline]
    fn sample_len(&self) -> usize {
        SAMPLE_LEN
    }

    #[inline]
    fn decrypt_in_place(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.xor_in_place(
            &sample[..self.sample_len()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
            true,
        )
        .unwrap();
    }

    #[inline]
    fn encrypt_in_place(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.xor_in_place(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
            false,
        )
        .unwrap();
    }

    #[inline]
    fn xor_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        masked: bool,
    ) -> Result<()> {
        // This implements [Header Protection Application] almost verbatim.

        let mask = self.new_mask(sample).unwrap();

        // The `unwrap()` will not panic because `new_mask` returns a
        // non-empty result.
        let (first_mask, pn_mask) = mask.split_first().unwrap();

        // It is OK for the `mask` to be longer than `packet_number`,
        // but a valid `packet_number` will never be longer than `mask`.
        if packet_number.len() > pn_mask.len() {
            return Err(Error::other(
                format!("packet number too long: {}", packet_number.len()).into(),
            ));
        }

        // Infallible from this point on. Before this point, `first` and
        // `packet_number` are unchanged.

        const LONG_HEADER_FORM: u8 = 0x80;
        let bits = match *first & LONG_HEADER_FORM == LONG_HEADER_FORM {
            true => 0x0f,  // Long header: 4 bits masked
            false => 0x1f, // Short header: 5 bits masked
        };

        let first_plain = match masked {
            // When unmasking, use the packet length bits after unmasking
            true => *first ^ (first_mask & bits),
            // When masking, use the packet length bits before masking
            false => *first,
        };
        let pn_len = (first_plain & 0x03) as usize + 1;

        *first ^= first_mask & bits;
        for (dst, m) in packet_number.iter_mut().zip(pn_mask).take(pn_len) {
            *dst ^= m;
        }

        Ok(())
    }
}

/// A [CryptoHeaderKey] for AES ciphers.
struct AesHeaderKey(bffi::AES_KEY);

impl AesHeaderKey {
    fn new(key: &Key) -> Result<AesHeaderKey> {
        let hpk = unsafe {
            let mut hpk = MaybeUninit::uninit();

            // NOTE: this function breaks the usual return value convention.
            map_result_zero_is_success(bffi::AES_set_encrypt_key(
                key.as_ptr(),
                (key.len() * 8) as c_uint,
                hpk.as_mut_ptr(),
            ))?;

            hpk.assume_init()
        };
        Ok(Self(hpk))
    }
}

impl CryptoHeaderKey for AesHeaderKey {
    #[inline]
    fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        if sample.len() != SAMPLE_LEN {
            return Err(Error::invalid_input(
                format!("invalid sample length: {}", sample.len()).into(),
            ));
        }

        let mut encrypted: [u8; SAMPLE_LEN] = [0; SAMPLE_LEN];
        unsafe {
            bffi::AES_encrypt(sample.as_ptr(), encrypted.as_mut_ptr(), &self.0);
        }

        let mut out: [u8; 5] = [0; 5];
        out.copy_from_slice(&encrypted[..5]);
        Ok(out)
    }
}

impl crypto::HeaderKey for AesHeaderKey {
    #[inline]
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.decrypt_in_place(pn_offset, packet)
    }

    #[inline]
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.encrypt_in_place(pn_offset, packet)
    }

    #[inline]
    fn sample_size(&self) -> usize {
        self.sample_len()
    }
}

/// A [CryptoHeaderKey] for ChaCha ciphers.
struct ChaChaHeaderKey(Key);

impl ChaChaHeaderKey {
    const ZEROS: [u8; 5] = [0; 5];

    fn new(key: Key) -> Result<ChaChaHeaderKey> {
        Ok(Self(key))
    }
}

impl CryptoHeaderKey for ChaChaHeaderKey {
    #[inline]
    fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        if sample.len() != SAMPLE_LEN {
            return Err(Error::invalid_input(
                format!("sample len invalid: {}", sample.len()).into(),
            ));
        }

        // Extract the counter and the nonce from the sample.
        let (counter, nonce) = sample.split_at(mem::size_of::<u32>());
        let counter = u32::from_ne_bytes(counter.try_into().unwrap());

        let mut out: [u8; 5] = [0; 5];
        unsafe {
            bffi::CRYPTO_chacha_20(
                out.as_mut_ptr(),
                Self::ZEROS.as_ptr(),
                Self::ZEROS.len(),
                self.0.as_ptr(),
                nonce.as_ptr(),
                counter,
            );
        }

        Ok(out)
    }
}

impl crypto::HeaderKey for ChaChaHeaderKey {
    #[inline]
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.decrypt_in_place(pn_offset, packet)
    }

    #[inline]
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.encrypt_in_place(pn_offset, packet)
    }

    #[inline]
    fn sample_size(&self) -> usize {
        self.sample_len()
    }
}

/// Internal key representation.
#[derive(Copy, Clone, Debug)]
pub(super) struct PacketKey {
    suite: &'static CipherSuite,
    key: Key,
    iv: Nonce,
}

impl PacketKey {
    #[inline]
    pub(super) fn new(
        version: QuicVersion,
        suite: &'static CipherSuite,
        secret: &Secret,
    ) -> Result<Self> {
        let mut key = suite.aead.new_key();
        suite
            .hkdf
            .expand_label(secret.slice(), version.key_label(), key.slice_mut())?;

        let mut iv = suite.aead.new_nonce();
        suite
            .hkdf
            .expand_label(secret.slice(), version.iv_label(), iv.slice_mut())?;

        Ok(Self { suite, key, iv })
    }

    #[inline]
    pub(super) fn key(&self) -> &Key {
        &self.key
    }

    #[inline]
    pub(super) fn iv(&self) -> &Nonce {
        &self.iv
    }

    /// Converts to a crypto PacketKey.
    #[inline]
    pub(super) fn as_crypto(&self) -> Result<Box<dyn crypto::PacketKey>> {
        AeadKey::new_packet_key(self.suite, self.key(), self.iv().clone())
    }
}

/// A [crypto::PacketKey] that is based on a BoringSSL [EVP_AEAD_CTX].
pub(super) struct AeadKey {
    suite: &'static CipherSuite,
    ctx: bffi::EVP_AEAD_CTX,
    iv: Nonce,
}

unsafe impl Send for AeadKey {}

impl AeadKey {
    #[inline]
    pub(super) fn new(suite: &'static CipherSuite, key: &Key, iv: Nonce) -> Result<Self> {
        Ok(Self {
            suite,
            ctx: suite.aead.new_aead_ctx(key)?,
            iv,
        })
    }

    #[inline]
    fn new_packet_key(
        suite: &'static CipherSuite,
        key: &Key,
        iv: Nonce,
    ) -> Result<Box<dyn crypto::PacketKey>> {
        Ok(Box::new(Self::new(suite, key, iv)?))
    }

    #[inline]
    fn nonce_for_packet(&self, packet_number: u64) -> Nonce {
        let mut nonce = self.suite.aead.new_nonce();
        let slice = nonce.slice_mut();
        slice[4..].copy_from_slice(&packet_number.to_be_bytes());
        for (out, inp) in slice.iter_mut().zip(self.iv.slice().iter()) {
            *out ^= inp;
        }
        nonce
    }

    #[inline]
    pub(super) fn seal_in_place(&self, nonce: &Nonce, additional_data: &[u8], data: &mut [u8]) -> Result<()> {
        let mut out_len = data.len() - self.suite.aead.tag_len;
        unsafe {
            map_result(bffi::EVP_AEAD_CTX_seal(
                &self.ctx,
                data.as_mut_ptr(),
                &mut out_len,
                data.len(),
                nonce.as_ptr(),
                nonce.len(),
                data.as_ptr(),
                out_len,
                additional_data.as_ptr(),
                additional_data.len(),
            ))?;
        }
        Ok(())
    }

    #[inline]
    pub(super) fn open_in_place<'a>(
        &self,
        nonce: &Nonce,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> StdResult<usize, crypto::CryptoError> {
        let mut out_len = match data.len().checked_sub(self.suite.aead.tag_len) {
            Some(n) => n,
            None => return Err(crypto::CryptoError {}),
        };

        unsafe {
            map_result(bffi::EVP_AEAD_CTX_open(
                &self.ctx,
                data.as_mut_ptr(),
                &mut out_len,
                out_len,
                nonce.as_ptr(),
                nonce.len(),
                data.as_ptr(),
                data.len(),
                additional_data.as_ptr(),
                additional_data.len(),
            ))?;
        }
        Ok(out_len)
    }
}

impl crypto::AeadKey for AeadKey {
    #[inline]
    fn seal(
        &self,
        data: &mut Vec<u8>,
        additional_data: &[u8],
    ) -> StdResult<(), crypto::CryptoError> {
        self.seal_in_place(&self.suite.aead.zero_nonce, additional_data, data)?;
        Ok(())
    }

    #[inline]
    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> StdResult<&'a mut [u8], crypto::CryptoError> {
        let plain_len = self.open_in_place(&self.suite.aead.zero_nonce, data, additional_data)?;
        Ok(&mut data[..plain_len])
    }
}

impl crypto::PacketKey for AeadKey {
    /// Encrypt a QUIC packet in-place.
    fn encrypt(&self, packet_number: u64, buf: &mut [u8], header_len: usize) {
        let (header, mut payload_tag) = buf.split_at_mut(header_len);

        let nonce = self.nonce_for_packet(packet_number);

        self.seal_in_place(&nonce, &header, &mut payload_tag)
            .unwrap();
    }

    /// Decrypt a QUIC packet in-place.
    fn decrypt(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> StdResult<(), crypto::CryptoError> {
        let nonce = self.nonce_for_packet(packet_number);

        let plain_len = self.open_in_place(&nonce, payload.as_mut(), header)?;
        payload.truncate(plain_len);
        Ok(())
    }

    #[inline]
    fn tag_len(&self) -> usize {
        self.suite.aead.tag_len
    }

    #[inline]
    fn confidentiality_limit(&self) -> u64 {
        self.suite.confidentiality_limit
    }

    #[inline]
    fn integrity_limit(&self) -> u64 {
        self.suite.integrity_limit
    }
}
