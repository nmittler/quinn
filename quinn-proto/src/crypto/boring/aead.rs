use crate::crypto::boring::error::{map_result, Error, Result};
use crate::crypto::boring::key::{Key, Nonce};
use crate::crypto::boring::suite::CipherSuite;
use boring_sys as bffi;
use lazy_static::lazy_static;
use std::mem::MaybeUninit;

const AES_128_GCM_KEY_LEN: usize = 16;
const AES_256_GCM_KEY_LEN: usize = 32;
const CHACHA20_POLY1305_KEY_LEN: usize = 32;

const AES_GCM_NONCE_LEN: usize = 12;
const POLY1305_NONCE_LEN: usize = 12;

pub(super) const TAG_LEN: usize = 16;
const AES_GCM_TAG_LEN: usize = 16;
const POLY1305_TAG_LEN: usize = 16;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum ID {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

/// Wrapper around a raw BoringSSL EVP_AEAD.
#[derive(Copy, Clone, PartialEq, Eq)]
struct AeadPtr(*const bffi::EVP_AEAD);

unsafe impl Send for AeadPtr {}
unsafe impl Sync for AeadPtr {}

impl AeadPtr {
    fn aes128_gcm() -> Self {
        unsafe { Self(bffi::EVP_aead_aes_128_gcm()) }
    }

    fn aes256_gcm() -> Self {
        unsafe { Self(bffi::EVP_aead_aes_256_gcm()) }
    }

    fn chacha20_poly1305() -> Self {
        unsafe { Self(bffi::EVP_aead_chacha20_poly1305()) }
    }
}

/// Wrapper around an BoringSSL EVP_AEAD.
pub(super) struct Aead {
    ptr: AeadPtr,
    pub(super) id: ID,
    pub(super) key_len: usize,
    pub(super) tag_len: usize,
    pub(super) nonce_len: usize,
    pub(super) zero_nonce: Nonce,
}

impl PartialEq for Aead {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }

    #[inline]
    fn ne(&self, other: &Self) -> bool {
        self.id != other.id
    }
}

impl Eq for Aead {}

lazy_static! {
    static ref AES128_GCM: Aead = Aead {
        ptr: AeadPtr::aes128_gcm(),
        id: ID::Aes128Gcm,
        key_len: AES_128_GCM_KEY_LEN,
        tag_len: AES_GCM_TAG_LEN,
        nonce_len: AES_GCM_NONCE_LEN,
        zero_nonce: Nonce::new([0u8; Nonce::MAX_LEN], AES_GCM_NONCE_LEN),
    };
    static ref AES256_GCM: Aead = Aead {
        ptr: AeadPtr::aes256_gcm(),
        id: ID::Aes256Gcm,
        key_len: AES_256_GCM_KEY_LEN,
        tag_len: AES_GCM_TAG_LEN,
        nonce_len: AES_GCM_NONCE_LEN,
        zero_nonce: Nonce::new([0u8; Nonce::MAX_LEN], AES_GCM_NONCE_LEN),
    };
    static ref CHACHA20_POLY1305: Aead = Aead {
        ptr: AeadPtr::chacha20_poly1305(),
        id: ID::Chacha20Poly1305,
        key_len: CHACHA20_POLY1305_KEY_LEN,
        tag_len: POLY1305_TAG_LEN,
        nonce_len: POLY1305_NONCE_LEN,
        zero_nonce: Nonce::new([0u8; Nonce::MAX_LEN], POLY1305_NONCE_LEN),
    };
}

impl Aead {
    #[inline]
    pub(super) fn aes128_gcm() -> &'static Self {
        &AES128_GCM
    }

    #[inline]
    pub(super) fn aes256_gcm() -> &'static Self {
        &AES256_GCM
    }

    #[inline]
    pub(super) fn chacha20_poly1305() -> &'static Self {
        &CHACHA20_POLY1305
    }

    #[inline]
    pub(super) fn new_key(&self) -> Key {
        Key::with_len(self.key_len)
    }

    #[inline]
    pub(super) fn new_nonce(&self) -> Nonce {
        Nonce::with_len(self.nonce_len)
    }

    #[inline]
    pub(super) fn as_ptr(&self) -> *const bffi::EVP_AEAD {
        self.ptr.0
    }

    #[inline]
    pub(super) fn suite(&self) -> &'static CipherSuite {
        match self.id {
            ID::Aes128Gcm => CipherSuite::aes128_gcm_sha256(),
            ID::Aes256Gcm => CipherSuite::aes256_gcm_sha384(),
            ID::Chacha20Poly1305 => CipherSuite::chacha20_poly1305_sha256(),
        }
    }

    #[inline]
    pub(super) fn new_aead_ctx(&self, key: &Key) -> Result<bffi::EVP_AEAD_CTX> {
        if key.len() != self.key_len {
            return Err(Error::invalid_input(
                format!("key length invalid for AEAD_CTX: {}", key.len()).into(),
            ));
        }

        let ctx = unsafe {
            let mut ctx = MaybeUninit::uninit();

            map_result(bffi::EVP_AEAD_CTX_init(
                ctx.as_mut_ptr(),
                self.as_ptr(),
                key.as_ptr(),
                key.len(),
                self.tag_len,
                std::ptr::null_mut(),
            ))?;

            ctx.assume_init()
        };

        Ok(ctx)
    }
}
