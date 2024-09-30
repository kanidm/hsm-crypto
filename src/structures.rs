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
    SoftAes256GcmV2 {
        enc_key: Aes256Key,
        tag: Aes256GcmTag,
        nonce: Aes256GcmNonce,
    },
}

pub enum StorageKey {
    SoftAes256GcmV2 {
        key: Aes256Key,
        // Other properties?
    },
}

pub enum LoadableHmacS256Key {
    SoftAes256GcmV2 {
        // This is the encrypted HmacSha256Key
        enc_key: HmacSha256Key,
        tag: Aes256GcmTag,
        nonce: Aes256GcmNonce,
    },
}

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
    SoftAes256GcmV2 {
        enc_key: Zeroizing<Vec<u8>>,
        tag: Aes256GcmTag,
        nonce: Aes256GcmNonce,
        cek_enc: Aes256Key,
        cek_tag: Aes256GcmTag,
        cek_nonce: Aes256GcmNonce,
    },
}

pub enum RS256Key {
    SoftAes256GcmV2 {
        key: RS256PrivateKey,
        content_encryption_key: Aes256Key,
    },
}
