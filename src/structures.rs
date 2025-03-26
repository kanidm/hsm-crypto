use crypto_glue::{
    aes256::Aes256Key,
    aes256gcm::{Aes256GcmNonce, Aes256GcmTag},
    ecdsa_p256::{EcdsaP256PrivateKey, EcdsaP256PrivateKeyFieldBytes},
    hmac_s256::HmacSha256Key,
    rsa::RS256PrivateKey,
    zeroize::Zeroizing,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadableStorageKey {
    SoftAes256GcmV1 {
        key: Zeroizing<Vec<u8>>,
        tag: [u8; 16],
        iv: [u8; 16],
    },
    SoftAes256GcmV2 {
        enc_key: Aes256Key,
        tag: Aes256GcmTag,
        nonce: Aes256GcmNonce,
    },
}

pub type LoadableMachineKey = LoadableStorageKey;

pub enum StorageKey {
    SoftAes256GcmV2 { key: Aes256Key },
}

pub enum LoadableHmacS256Key {
    SoftSha256V1 {
        key: Zeroizing<Vec<u8>>,
        tag: [u8; 16],
        iv: [u8; 16],
    },
    SoftAes256GcmV2 {
        // This is the encrypted HmacSha256Key
        enc_key: HmacSha256Key,
        tag: Aes256GcmTag,
        nonce: Aes256GcmNonce,
    },
}

pub type LoadableHmacKey = LoadableHmacS256Key;

pub enum HmacS256Key {
    SoftAes256GcmV2 { key: HmacSha256Key },
}

pub enum LoadableES256Key {
    SoftAes256GcmV2 {
        // This is the encrypted EcdsaP256PrivateKey
        enc_key: EcdsaP256PrivateKeyFieldBytes,
        tag: Aes256GcmTag,
        nonce: Aes256GcmNonce,
    },
}

pub enum ES256Key {
    SoftAes256GcmV2 { key: EcdsaP256PrivateKey },
}

pub enum LoadableRS256Key {
    Soft2048V1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
        cek: Vec<u8>,
    },
    SoftAes256GcmV2 {
        enc_key: Zeroizing<Vec<u8>>,
        tag: Aes256GcmTag,
        nonce: Aes256GcmNonce,
        cek_enc: Aes256Key,
        cek_tag: Aes256GcmTag,
        cek_nonce: Aes256GcmNonce,
    },
}

pub type LoadableMsOapxbcRsaKey = LoadableRS256Key;

pub enum RS256Key {
    SoftAes256GcmV2 {
        key: RS256PrivateKey,
        content_encryption_key: Aes256Key,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SealedData {
    // currently needs the parent to have a cek
    SoftV1 {
        data: Zeroizing<Vec<u8>>,
        tag: [u8; 16],
        iv: [u8; 16],
    },
    SoftAes256GcmV2 {
        data: Zeroizing<Vec<u8>>,
        tag: Aes256GcmTag,
        nonce: Aes256GcmNonce,
    },
}

pub type LoadableMsOapxbcSessionKey = SealedData;
