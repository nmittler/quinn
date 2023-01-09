use crate::crypto;
use crate::crypto::boring::error::Result;
use crate::crypto::boring::hkdf::Hkdf;
use crate::crypto::boring::key::{AeadKey, Key, Nonce};
use crate::crypto::boring::secret::Secret;
use crate::crypto::boring::suite::CipherSuite;

// TODO: Test me.
pub struct HandshakeTokenKey(Key);

impl HandshakeTokenKey {
    /// Creates a new randomized HandshakeTokenKey.
    pub fn new() -> Result<HandshakeTokenKey> {
        // Create a random secret.
        let secret = Secret::random();

        // Extract the key.
        let mut key = [0u8; Key::MAX_LEN];
        let len = Hkdf::sha256().extract(&[], secret.slice(), &mut key)?;
        Ok(Self(Key::new(key, len)))
    }

    fn key(&self) -> &[u8] {
        return self.0.slice();
    }
}

impl crypto::HandshakeTokenKey for HandshakeTokenKey {
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn crypto::AeadKey> {
        let suite = CipherSuite::aes256_gcm_sha384();
        let mut key = suite.aead.new_key();
        Hkdf::sha256()
            .expand(&self.key(), random_bytes, key.slice_mut())
            .unwrap();

        Box::new(AeadKey::new(suite, &key, Nonce::with_len(0)).unwrap())
    }
}
