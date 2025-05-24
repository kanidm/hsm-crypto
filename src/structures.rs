use crypto_glue::{
    aes256::Aes256Key,
    aes256gcm::{Aes256GcmNonce, Aes256GcmTag},
    ecdsa_p256::{EcdsaP256FieldBytes, EcdsaP256PrivateKey},
    hmac_s256::HmacSha256Key,
    rsa::RS256PrivateKey,
    zeroize::Zeroizing,
};
use serde::{Deserialize, Serialize};

#[cfg(feature = "tpm")]
use tss_esapi::structures as tpm;

#[cfg(feature = "tpm")]
use tss_esapi::utils::TpmsContext;

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
    #[cfg(feature = "tpm")]
    TpmAes128CfbV1 {
        // These are needed to allow direct and indirect storage keys.
        private: Option<tpm::Private>,
        public: Option<tpm::Public>,
        sk_private: tpm::Private,
        sk_public: tpm::Public,
    },
    #[cfg(not(feature = "tpm"))]
    TpmAes128CfbV1 {
        private: (),
        public: (),
        sk_private: (),
        sk_public: (),
    },
}

pub type LoadableMachineKey = LoadableStorageKey;

pub enum StorageKey {
    SoftAes256GcmV2 {
        key: Aes256Key,
    },
    #[cfg(feature = "tpm")]
    Tpm {
        key_context: TpmsContext,
    },
    #[cfg(not(feature = "tpm"))]
    Tpm {
        key_context: (),
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[cfg(feature = "tpm")]
    TpmSha256V1 {
        private: tpm::Private,
        public: tpm::Public,
    },
    #[cfg(not(feature = "tpm"))]
    TpmSha256V1 { private: (), public: () },
}

pub type LoadableHmacKey = LoadableHmacS256Key;

pub enum HmacS256Key {
    SoftAes256GcmV2 {
        key: HmacSha256Key,
    },
    #[cfg(feature = "tpm")]
    Tpm {
        key_context: TpmsContext,
    },
    #[cfg(not(feature = "tpm"))]
    Tpm {
        key_context: (),
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadableES256Key {
    SoftAes256GcmV2 {
        // This is the encrypted EcdsaP256PrivateKey
        enc_key: EcdsaP256FieldBytes,
        tag: Aes256GcmTag,
        nonce: Aes256GcmNonce,
    },
    #[cfg(feature = "tpm")]
    TpmV1 {
        private: tpm::Private,
        public: tpm::Public,
    },
    #[cfg(not(feature = "tpm"))]
    TpmV1 { private: (), public: () },
}

pub enum ES256Key {
    SoftAes256GcmV2 {
        key: EcdsaP256PrivateKey,
    },
    #[cfg(feature = "tpm")]
    Tpm {
        key_context: TpmsContext,
    },
    #[cfg(not(feature = "tpm"))]
    Tpm {
        key_context: (),
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadableRS256Key {
    Soft2048V1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
        cek: Vec<u8>,
    },
    Soft2048V2 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
    },
    SoftAes256GcmV2 {
        enc_key: Zeroizing<Vec<u8>>,
        tag: Aes256GcmTag,
        nonce: Aes256GcmNonce,
    },
    #[cfg(feature = "tpm")]
    TpmV1 {
        private: tpm::Private,
        public: tpm::Public,
    },
    #[cfg(not(feature = "tpm"))]
    TpmV1 { private: (), public: () },
}

pub type LoadableMsOapxbcRsaKey = LoadableRS256Key;

pub enum RS256Key {
    SoftAes256GcmV2 {
        key: Box<RS256PrivateKey>,
    },
    SoftAes256GcmV2Cek {
        key: Box<RS256PrivateKey>,
        content_encryption_key: Aes256Key,
    },
    #[cfg(feature = "tpm")]
    Tpm {
        key_context: TpmsContext,
    },
    #[cfg(not(feature = "tpm"))]
    Tpm {
        key_context: (),
    },
}

pub type MsOapxbcRsaKey = RS256Key;

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
    #[cfg(feature = "tpm")]
    TpmAes256GcmV2 {
        private: tpm::Private,
        public: tpm::Public,
        data: Zeroizing<Vec<u8>>,
        tag: Aes256GcmTag,
        nonce: Aes256GcmNonce,
    },
    #[cfg(not(feature = "tpm"))]
    TpmAes256GcmV2 {
        private: (),
        public: (),
        data: (),
        tag: (),
        nonce: (),
    },
}

pub type LoadableMsOapxbcSessionKey = SealedData;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadableMsHelloKey {
    SoftRsa2048V1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
        // x509: Vec<u8>,
    },
    Rsa2048V1 {
        loadable_storage_key: LoadableStorageKey,
        loadable_rs256_key: LoadableRS256Key,
    },
}

pub struct MsInProgressEnrolment {
    pub(crate) loadable_rs256_key: LoadableRS256Key,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadableMsDeviceEnrolmentKey {
    SoftRsa2048V1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
        x509: Vec<u8>,
    },
    Rsa2048V1 {
        loadable_rs256_key: LoadableRS256Key,
        x509_der: Vec<u8>,
    },
}

pub type MsDeviceEnrolmentKey = RS256Key;

