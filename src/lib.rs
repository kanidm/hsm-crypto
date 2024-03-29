#![deny(warnings)]
#![warn(unused_extern_crates)]
// Enable some groups of clippy lints.
#![deny(clippy::suspicious)]
#![deny(clippy::perf)]
// Specific lints to enforce.
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![deny(clippy::disallowed_types)]
#![deny(clippy::manual_let_else)]
#![allow(clippy::unreachable)]

use argon2::MIN_SALT_LEN;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tracing::error;
pub use zeroize::Zeroizing;

#[cfg(feature = "msextensions")]
use openssl::rsa::Rsa;

pub(crate) const AES256GCM_KEY_LEN: usize = 32;
pub(crate) const AES256GCM_IV_LEN: usize = 16;
pub(crate) const HMAC_KEY_LEN: usize = 32;

pub mod soft;

#[cfg(feature = "tpm")]
pub mod tpm;
// future goal ... once I can afford one ...
// mod yubihsm;

pub(crate) const TPM_PIN_MIN_LEN: u8 = 6;
// TPM's limit the max pin based on algorithm max bytes per the
// size of the largest hash. This means pins max out at 32 bytes
// as that's the size of sha256 output.
pub(crate) const TPM_PIN_MAX_LEN: u8 = 32;

pub struct PinValue {
    value: Zeroizing<Vec<u8>>,
}

#[derive(Debug)]
pub enum TpmPinError {
    TooShort(u8),
    TooLarge(u8),
}

impl PinValue {
    pub fn new(input: &str) -> Result<Self, TpmPinError> {
        if input.len() < TPM_PIN_MIN_LEN as usize {
            return Err(TpmPinError::TooShort(TPM_PIN_MIN_LEN));
        } else if input.len() > TPM_PIN_MAX_LEN as usize {
            return Err(TpmPinError::TooLarge(TPM_PIN_MAX_LEN));
        }

        Ok(PinValue {
            value: input.as_bytes().to_vec().into(),
        })
    }

    pub(crate) fn derive_aes_256_gcm(
        &self,
        parent_key: &[u8],
    ) -> Result<Zeroizing<[u8; AES256GCM_KEY_LEN]>, TpmError> {
        use argon2::{Algorithm, Argon2, Params, Version};

        let mut auth_key = Zeroizing::new([0; AES256GCM_KEY_LEN]);

        // This can't be changed else it will break key derivation for users.
        let argon2id_params =
            Params::new(32_768, 1, 1, Some(auth_key.as_ref().len())).map_err(|argon_err| {
                error!(?argon_err);
                TpmError::AuthValueDerivation
            })?;

        // Want at least 8 bytes salt, 16 bytes pw input.
        if parent_key.len() < 24 {
            return Err(TpmError::AuthValueTooShort);
        }

        let (salt, pepper) = parent_key.split_at(MIN_SALT_LEN);

        let argon =
            Argon2::new_with_secret(pepper, Algorithm::Argon2id, Version::V0x13, argon2id_params)
                .map_err(|argon_err| {
                error!(?argon_err);
                TpmError::AuthValueDerivation
            })?;

        // let now = std::time::SystemTime::now();

        argon
            .hash_password_into(self.value.as_ref(), salt, auth_key.as_mut())
            .map_err(|argon_err| {
                error!(?argon_err);
                TpmError::AuthValueDerivation
            })?;

        // error!(elapsed = ?now.elapsed());

        Ok(auth_key)
    }
}

pub enum AuthValue {
    Key256Bit {
        auth_key: Zeroizing<[u8; AES256GCM_KEY_LEN]>,
    },
}

#[derive(Debug, Copy, Clone)]
pub enum KeyAlgorithm {
    Rsa2048,
    Ecdsa256,
}

impl AuthValue {
    fn random_key() -> Result<Zeroizing<[u8; 24]>, TpmError> {
        let mut auth_key = Zeroizing::new([0; 24]);
        openssl::rand::rand_bytes(auth_key.as_mut()).map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::Entropy
        })?;
        Ok(auth_key)
    }

    pub fn generate() -> Result<String, TpmError> {
        let ak = Self::random_key()?;
        Ok(hex::encode(&ak))
    }

    pub fn ephemeral() -> Result<Self, TpmError> {
        let mut auth_key = Zeroizing::new([0; AES256GCM_KEY_LEN]);
        openssl::rand::rand_bytes(auth_key.as_mut()).map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::Entropy
        })?;

        Ok(AuthValue::Key256Bit { auth_key })
    }

    /// Derive an auth value from input bytes. This value must be at least 24 bytes in length.
    ///
    /// The key derivation is performed with Argon2id.
    pub fn derive_from_bytes(cleartext: &[u8]) -> Result<Self, TpmError> {
        use argon2::{Algorithm, Argon2, Params, Version};

        let mut auth_key = Zeroizing::new([0; AES256GCM_KEY_LEN]);

        // This can't be changed else it will break key derivation for users.
        let argon2id_params =
            Params::new(32_768, 4, 1, Some(auth_key.as_ref().len())).map_err(|argon_err| {
                error!(?argon_err);
                TpmError::AuthValueDerivation
            })?;

        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2id_params);

        // Want at least 8 bytes salt, 16 bytes pw input.
        if cleartext.len() < 24 {
            return Err(TpmError::AuthValueTooShort);
        }

        let (salt, key) = cleartext.split_at(MIN_SALT_LEN);

        argon
            .hash_password_into(key, salt, auth_key.as_mut())
            .map_err(|argon_err| {
                error!(?argon_err);
                TpmError::AuthValueDerivation
            })?;

        Ok(AuthValue::Key256Bit { auth_key })
    }

    /// Derive an auth value from input hex. The input hex string must contain at least
    /// 24 bytes (the string is at least 48 hex chars)
    pub fn derive_from_hex(cleartext: &str) -> Result<Self, TpmError> {
        hex::decode(cleartext)
            .map_err(|_| TpmError::AuthValueInvalidHexInput)
            .and_then(|bytes| Self::derive_from_bytes(bytes.as_slice()))
    }
}

impl TryFrom<&[u8]> for AuthValue {
    type Error = TpmError;

    fn try_from(cleartext: &[u8]) -> Result<Self, Self::Error> {
        Self::derive_from_bytes(cleartext)
    }
}

impl FromStr for AuthValue {
    type Err = TpmError;

    fn from_str(cleartext: &str) -> Result<Self, Self::Err> {
        Self::derive_from_hex(cleartext)
    }
}

#[derive(Debug, Clone)]
pub enum TpmError {
    AuthValueInvalidHexInput,
    AuthValueTooShort,
    AuthValueDerivation,
    Aes256GcmConfig,
    Aes256GcmEncrypt,
    Aes256GcmDecrypt,
    HmacKey,
    HmacSign,
    EcGroup,
    EcKeyGenerate,
    EcKeyPrivateToDer,
    EcKeyFromDer,
    EcKeyToPrivateKey,
    EcdsaPublicFromComponents,
    EcdsaPublicToDer,
    IdentityKeyDigest,
    IdentityKeyPublicToDer,
    IdentityKeyPublicToPem,
    IdentityKeyInvalidForSigning,
    IdentityKeyInvalidForVerification,
    IdentityKeySignature,
    IdentityKeyVerification,
    IdentityKeyX509ToPem,
    IdentityKeyX509ToDer,
    IdentityKeyX509Missing,
    RsaGenerate,
    RsaPrivateToDer,
    RsaKeyFromDer,
    RsaPublicToDer,
    RsaToPrivateKey,
    RsaPublicFromComponents,
    X509FromDer,
    X509PublicKey,
    X509KeyMismatch,
    X509RequestBuilder,
    X509NameBuilder,
    X509NameAppend,
    X509RequestSubjectName,
    X509RequestSign,
    X509RequestToDer,
    X509RequestSetPublic,

    MsOapxbcKeyPublicToDer,
    MsOapxbcKeyOaepOption,
    MsOapxbcKeyOaepDecipher,
    MsOapxbcKeyOaepEncipher,

    TpmTctiNameInvalid,
    TpmAuthSession,
    TpmContextCreate,
    TpmContextFlushObject,
    TpmContextSave,
    TpmContextLoad,
    TpmPrimaryObjectAttributesInvalid,
    TpmPrimaryPublicBuilderInvalid,
    TpmPrimaryCreate,
    TpmEntropy,
    TpmAuthValueInvalid,

    TpmMachineKeyObjectAttributesInvalid,
    TpmMachineKeyBuilderInvalid,
    TpmMachineKeyCreate,
    TpmMachineKeyLoad,
    TpmKeyLoad,

    TpmMsRsaKeyLoad,
    TpmHmacKeyLoad,

    TpmStorageKeyObjectAttributesInvalid,
    TpmStorageKeyBuilderInvalid,

    TpmHmacKeyObjectAttributesInvalid,
    TpmHmacKeyBuilderInvalid,
    TpmHmacKeyCreate,
    TpmHmacSign,
    TpmHmacInputTooLarge,

    TpmIdentityKeyObjectAttributesInvalid,
    TpmIdentityKeyAlgorithmInvalid,
    TpmIdentityKeyBuilderInvalid,
    TpmIdentityKeyCreate,
    TpmIdentityKeySign,
    TpmIdentityKeyId,
    TpmIdentityKeySignatureInvalid,
    TpmIdentityKeyEcdsaSigRInvalid,
    TpmIdentityKeyEcdsaSigSInvalid,
    TpmIdentityKeyEcdsaSigFromParams,
    TpmIdentityKeyEcdsaSigToDer,

    TpmIdentityKeyParamInvalid,
    TpmIdentityKeyParamsToRsaSig,

    TpmIdentityKeyDerToEcdsaSig,
    TpmIdentityKeyParamRInvalid,
    TpmIdentityKeyParamSInvalid,
    TpmIdentityKeyParamsToEcdsaSig,
    TpmIdentityKeyVerify,

    TpmMsRsaKeyObjectAttributesInvalid,
    TpmMsRsaKeyAlgorithmInvalid,
    TpmMsRsaKeyBuilderInvalid,
    TpmMsRsaKeyCreate,
    TpmMsRsaKeyReadPublic,
    TpmMsRsaOaepDecrypt,
    TpmMsRsaOaepInvalidKeyLength,
    TpmMsRsaSeal,
    TpmMsRsaUnseal,

    TpmOperationUnsupported,

    Entropy,
    IncorrectKeyType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadableMachineKey {
    SoftAes256GcmV1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
    },
    #[cfg(feature = "tpm")]
    TpmAes128CfbV1 {
        private: tpm::Private,
        public: tpm::Public,
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

pub enum MachineKey {
    SoftAes256Gcm {
        key: Zeroizing<Vec<u8>>,
    },
    #[cfg(feature = "tpm")]
    Tpm {
        key_context: tpm::TpmsContext,
    },
    #[cfg(not(feature = "tpm"))]
    Tpm {
        key_context: (),
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadableHmacKey {
    SoftSha256V1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
    },
    #[cfg(feature = "tpm")]
    TpmSha256V1 {
        private: tpm::Private,
        public: tpm::Public,
    },
    #[cfg(not(feature = "tpm"))]
    Tpm(()),
}

pub enum HmacKey {
    SoftSha256 {
        pkey: PKey<Private>,
    },
    #[cfg(feature = "tpm")]
    TpmSha256 {
        key_context: tpm::TpmsContext,
    },
    #[cfg(not(feature = "tpm"))]
    TpmSha256 {
        key_context: (),
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadableIdentityKey {
    SoftEcdsa256V1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
        x509: Option<Vec<u8>>,
    },
    SoftRsa2048V1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
        x509: Option<Vec<u8>>,
    },
    #[cfg(feature = "tpm")]
    TpmEcdsa256V1 {
        sk_private: tpm::Private,
        sk_public: tpm::Public,
        private: tpm::Private,
        public: tpm::Public,
        x509: Option<Vec<u8>>,
    },
    #[cfg(not(feature = "tpm"))]
    TpmEcdsa256V1 {
        sk_private: (),
        sk_public: (),
        private: (),
        public: (),
        x509: (),
    },
    #[cfg(feature = "tpm")]
    TpmRsa2048V1 {
        sk_private: tpm::Private,
        sk_public: tpm::Public,
        private: tpm::Private,
        public: tpm::Public,
        x509: Option<Vec<u8>>,
    },
    #[cfg(not(feature = "tpm"))]
    TpmRsa2048V1 {
        sk_private: (),
        sk_public: (),
        private: (),
        public: (),
        x509: (),
    },
}

pub enum IdentityKey {
    SoftEcdsa256 {
        pkey: PKey<Private>,
        x509: Option<X509>,
    },
    SoftRsa2048 {
        pkey: PKey<Private>,
        x509: Option<X509>,
    },

    // These well be "Soft" in tpm as well,
    #[cfg(feature = "tpm")]
    TpmEcdsa256 {
        key_context: tpm::TpmsContext,
        x509: Option<X509>,
    },
    #[cfg(not(feature = "tpm"))]
    TpmEcdsa256 { key_context: (), x509: () },
    #[cfg(feature = "tpm")]
    TpmRsa2048 {
        key_context: tpm::TpmsContext,
        x509: Option<X509>,
    },
    #[cfg(not(feature = "tpm"))]
    TpmRsa2048 { key_context: (), x509: () },
}

impl IdentityKey {
    pub fn alg(&self) -> KeyAlgorithm {
        match self {
            IdentityKey::SoftEcdsa256 { .. } | IdentityKey::TpmEcdsa256 { .. } => {
                KeyAlgorithm::Ecdsa256
            }
            IdentityKey::SoftRsa2048 { .. } | IdentityKey::TpmRsa2048 { .. } => {
                KeyAlgorithm::Rsa2048
            }
        }
    }
}

#[cfg(feature = "msextensions")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadableMsOapxbcRsaKey {
    Soft2048V1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
        cek: Vec<u8>,
    },
    #[cfg(feature = "tpm")]
    TpmRsa2048V1 {
        private: tpm::Private,
        public: tpm::Public,
        cek_private: tpm::Private,
        cek_public: tpm::Public,
    },
    #[cfg(not(feature = "tpm"))]
    TpmRsa2048V1 {
        private: (),
        public: (),
        cek_private: (),
        cek_public: (),
    },
}

#[cfg(feature = "msextensions")]
pub enum MsOapxbcRsaKey {
    Soft {
        key: Rsa<Private>,
        cek: Zeroizing<Vec<u8>>,
    },
    #[cfg(feature = "tpm")]
    Tpm {
        key_context: tpm::TpmsContext,
        cek_context: tpm::TpmsContext,
    },
    #[cfg(not(feature = "tpm"))]
    Tpm { key_context: () },
}

#[cfg(feature = "msextensions")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadableMsOapxbcSessionKey {
    SoftV1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
    },
    #[cfg(feature = "tpm")]
    TpmV1 {
        private: tpm::Private,
        public: tpm::Public,
    },
    #[cfg(not(feature = "tpm"))]
    TpmV1 { private: (), public: () },
}

// For now it's ms extensions only, but we should add this to other parts
// of the interface.
#[cfg(feature = "msextensions")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SealedData {
    // currently needs the parent to have a cek
    SoftV1 {
        data: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
    },
    #[cfg(feature = "tpm")]
    TpmV1 {
        private: tpm::Private,
        public: tpm::Public,
        data: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
    },
    #[cfg(not(feature = "tpm"))]
    TpmV1 {
        private: (),
        public: (),
        data: (),
        tag: (),
        iv: (),
    },
}

pub trait Tpm {
    fn machine_key_create(
        &mut self,
        auth_value: &AuthValue,
    ) -> Result<LoadableMachineKey, TpmError>;

    fn machine_key_load(
        &mut self,
        auth_value: &AuthValue,
        exported_key: &LoadableMachineKey,
    ) -> Result<MachineKey, TpmError>;

    fn hmac_key_create(&mut self, mk: &MachineKey) -> Result<LoadableHmacKey, TpmError>;

    fn hmac_key_load(
        &mut self,
        mk: &MachineKey,
        exported_key: &LoadableHmacKey,
    ) -> Result<HmacKey, TpmError>;

    fn hmac(&mut self, hk: &HmacKey, input: &[u8]) -> Result<Vec<u8>, TpmError>;

    fn identity_key_create(
        &mut self,
        mk: &MachineKey,
        auth_value: Option<&PinValue>,
        algorithm: KeyAlgorithm,
    ) -> Result<LoadableIdentityKey, TpmError>;

    fn identity_key_load(
        &mut self,
        mk: &MachineKey,
        auth_value: Option<&PinValue>,
        loadable_key: &LoadableIdentityKey,
    ) -> Result<IdentityKey, TpmError>;

    fn identity_key_id(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError>;

    fn identity_key_sign(&mut self, key: &IdentityKey, input: &[u8]) -> Result<Vec<u8>, TpmError>;

    fn identity_key_verify(
        &mut self,
        key: &IdentityKey,
        input: &[u8],
        signature: &[u8],
    ) -> Result<bool, TpmError>;

    fn identity_key_certificate_request(
        &mut self,
        mk: &MachineKey,
        auth_value: Option<&PinValue>,
        loadable_key: &LoadableIdentityKey,
        cn: &str,
    ) -> Result<Vec<u8>, TpmError>;

    fn identity_key_associate_certificate(
        &mut self,
        mk: &MachineKey,
        auth_value: Option<&PinValue>,
        loadable_key: &LoadableIdentityKey,
        certificate_der: &[u8],
    ) -> Result<LoadableIdentityKey, TpmError>;

    fn identity_key_public_as_der(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError>;

    fn identity_key_public_as_pem(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError>;

    fn identity_key_x509_as_pem(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError>;

    fn identity_key_x509_as_der(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError>;

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_key_create(
        &mut self,
        mk: &MachineKey,
    ) -> Result<LoadableMsOapxbcRsaKey, TpmError>;

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_key_import(
        &mut self,
        mk: &MachineKey,
        private_key: Rsa<Private>,
    ) -> Result<LoadableMsOapxbcRsaKey, TpmError>;

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_key_load(
        &mut self,
        mk: &MachineKey,
        loadable_key: &LoadableMsOapxbcRsaKey,
    ) -> Result<MsOapxbcRsaKey, TpmError>;

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_public_as_der(&mut self, key: &MsOapxbcRsaKey) -> Result<Vec<u8>, TpmError>;

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_decipher_session_key(
        &mut self,
        key: &MsOapxbcRsaKey,
        input: &[u8],
        expected_key_len: usize,
    ) -> Result<LoadableMsOapxbcSessionKey, TpmError>;

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_yield_session_key(
        &mut self,
        key: &MsOapxbcRsaKey,
        session_key: &LoadableMsOapxbcSessionKey,
    ) -> Result<Zeroizing<Vec<u8>>, TpmError>;

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_seal_data(
        &mut self,
        key: &MsOapxbcRsaKey,
        data: &[u8],
    ) -> Result<SealedData, TpmError>;

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_unseal_data(
        &mut self,
        key: &MsOapxbcRsaKey,
        sealed_data: &SealedData,
    ) -> Result<Zeroizing<Vec<u8>>, TpmError>;
}

pub struct BoxedDynTpm(Box<dyn Tpm + 'static + Send>);

impl BoxedDynTpm {
    pub fn new<T: Tpm + 'static + Send>(t: T) -> Self {
        BoxedDynTpm(Box::new(t))
    }
}

impl Tpm for BoxedDynTpm {
    fn machine_key_create(
        &mut self,
        auth_value: &AuthValue,
    ) -> Result<LoadableMachineKey, TpmError> {
        self.0.machine_key_create(auth_value)
    }

    fn machine_key_load(
        &mut self,
        auth_value: &AuthValue,
        exported_key: &LoadableMachineKey,
    ) -> Result<MachineKey, TpmError> {
        self.0.machine_key_load(auth_value, exported_key)
    }

    fn hmac_key_create(&mut self, mk: &MachineKey) -> Result<LoadableHmacKey, TpmError> {
        self.0.hmac_key_create(mk)
    }

    fn hmac_key_load(
        &mut self,
        mk: &MachineKey,
        exported_key: &LoadableHmacKey,
    ) -> Result<HmacKey, TpmError> {
        self.0.hmac_key_load(mk, exported_key)
    }

    fn hmac(&mut self, hk: &HmacKey, input: &[u8]) -> Result<Vec<u8>, TpmError> {
        self.0.hmac(hk, input)
    }

    fn identity_key_create(
        &mut self,
        mk: &MachineKey,
        auth_value: Option<&PinValue>,
        algorithm: KeyAlgorithm,
    ) -> Result<LoadableIdentityKey, TpmError> {
        self.0.identity_key_create(mk, auth_value, algorithm)
    }

    fn identity_key_load(
        &mut self,
        mk: &MachineKey,
        auth_value: Option<&PinValue>,
        loadable_key: &LoadableIdentityKey,
    ) -> Result<IdentityKey, TpmError> {
        self.0.identity_key_load(mk, auth_value, loadable_key)
    }

    fn identity_key_id(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        self.0.identity_key_id(key)
    }

    fn identity_key_sign(&mut self, key: &IdentityKey, input: &[u8]) -> Result<Vec<u8>, TpmError> {
        self.0.identity_key_sign(key, input)
    }

    fn identity_key_verify(
        &mut self,
        key: &IdentityKey,
        input: &[u8],
        signature: &[u8],
    ) -> Result<bool, TpmError> {
        self.0.identity_key_verify(key, input, signature)
    }

    fn identity_key_certificate_request(
        &mut self,
        mk: &MachineKey,
        auth_value: Option<&PinValue>,
        loadable_key: &LoadableIdentityKey,
        cn: &str,
    ) -> Result<Vec<u8>, TpmError> {
        self.0
            .identity_key_certificate_request(mk, auth_value, loadable_key, cn)
    }

    fn identity_key_associate_certificate(
        &mut self,
        mk: &MachineKey,
        auth_value: Option<&PinValue>,
        loadable_key: &LoadableIdentityKey,
        certificate_der: &[u8],
    ) -> Result<LoadableIdentityKey, TpmError> {
        self.0
            .identity_key_associate_certificate(mk, auth_value, loadable_key, certificate_der)
    }

    fn identity_key_public_as_der(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        self.0.identity_key_public_as_der(key)
    }

    fn identity_key_public_as_pem(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        self.0.identity_key_public_as_pem(key)
    }

    fn identity_key_x509_as_pem(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        self.0.identity_key_x509_as_pem(key)
    }

    fn identity_key_x509_as_der(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        self.0.identity_key_x509_as_der(key)
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_key_create(
        &mut self,
        mk: &MachineKey,
    ) -> Result<LoadableMsOapxbcRsaKey, TpmError> {
        self.0.msoapxbc_rsa_key_create(mk)
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_key_import(
        &mut self,
        mk: &MachineKey,
        private_key: Rsa<Private>,
    ) -> Result<LoadableMsOapxbcRsaKey, TpmError> {
        self.0.msoapxbc_rsa_key_import(mk, private_key)
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_key_load(
        &mut self,
        mk: &MachineKey,
        loadable_key: &LoadableMsOapxbcRsaKey,
    ) -> Result<MsOapxbcRsaKey, TpmError> {
        self.0.msoapxbc_rsa_key_load(mk, loadable_key)
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_public_as_der(&mut self, key: &MsOapxbcRsaKey) -> Result<Vec<u8>, TpmError> {
        self.0.msoapxbc_rsa_public_as_der(key)
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_decipher_session_key(
        &mut self,
        key: &MsOapxbcRsaKey,
        input: &[u8],
        expected_key_len: usize,
    ) -> Result<LoadableMsOapxbcSessionKey, TpmError> {
        self.0
            .msoapxbc_rsa_decipher_session_key(key, input, expected_key_len)
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_yield_session_key(
        &mut self,
        key: &MsOapxbcRsaKey,
        session_key: &LoadableMsOapxbcSessionKey,
    ) -> Result<Zeroizing<Vec<u8>>, TpmError> {
        self.0.msoapxbc_rsa_yield_session_key(key, session_key)
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_seal_data(
        &mut self,
        key: &MsOapxbcRsaKey,
        data: &[u8],
    ) -> Result<SealedData, TpmError> {
        self.0.msoapxbc_rsa_seal_data(key, data)
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_unseal_data(
        &mut self,
        key: &MsOapxbcRsaKey,
        sealed_data: &SealedData,
    ) -> Result<Zeroizing<Vec<u8>>, TpmError> {
        self.0.msoapxbc_rsa_unseal_data(key, sealed_data)
    }
}

#[cfg(test)]
mod tests {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::extension::{
        BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier,
    };
    use openssl::x509::{X509NameBuilder, X509Req, X509};

    #[macro_export]
    macro_rules! test_tpm_hmac {
        ( $tpm_a:expr, $tpm_b:expr ) => {
            use crate::{AuthValue, Tpm};
            use tracing::trace;

            let _ = tracing_subscriber::fmt::try_init();

            // Create a new random auth_value.
            let auth_value = AuthValue::ephemeral().expect("Failed to generate new random secret");

            // Request a new machine-key-context. This key "owns" anything
            // created underneath it.
            let loadable_machine_key = $tpm_a
                .machine_key_create(&auth_value)
                .expect("Unable to create new machine key");

            trace!(?loadable_machine_key);

            let machine_key = $tpm_a
                .machine_key_load(&auth_value, &loadable_machine_key)
                .expect("Unable to load machine key");

            // from that ctx, create a hmac key.
            let loadable_hmac_key = $tpm_a
                .hmac_key_create(&machine_key)
                .expect("Unable to create new hmac key");

            trace!(?loadable_hmac_key);

            let hmac_key = $tpm_a
                .hmac_key_load(&machine_key, &loadable_hmac_key)
                .expect("Unable to load hmac key");

            // do a hmac.
            let output_1 = $tpm_a
                .hmac(&hmac_key, &[0, 1, 2, 3])
                .expect("Unable to perform hmac");

            // destroy the Hsm
            drop(hmac_key);
            drop(machine_key);
            drop($tpm_a);

            // Load the contexts.
            let machine_key = $tpm_b
                .machine_key_load(&auth_value, &loadable_machine_key)
                .expect("Unable to load machine key");

            // Load the keys.
            let hmac_key = $tpm_b
                .hmac_key_load(&machine_key, &loadable_hmac_key)
                .expect("Unable to load hmac key");

            // Do another hmac
            let output_2 = $tpm_b
                .hmac(&hmac_key, &[0, 1, 2, 3])
                .expect("Unable to perform hmac");

            // Show the context load/flush is okay.
            let output_3 = $tpm_b
                .hmac(&hmac_key, &[0, 1, 2, 3])
                .expect("Unable to perform hmac");

            // It should be the same.
            assert_eq!(output_1, output_2);
            assert_eq!(output_1, output_3);
        };
    }

    #[macro_export]
    macro_rules! test_tpm_identity {
        ( $tpm:expr, $alg:expr, $pin_value:expr ) => {
            use crate::{AuthValue, Tpm};
            use openssl::hash::MessageDigest;
            use openssl::pkey::PKey;
            use openssl::sign::Verifier;
            use std::str::FromStr;
            use tracing::trace;

            let _ = tracing_subscriber::fmt::try_init();

            let auth_str = AuthValue::generate().expect("Failed to create hex pin");

            let auth_value = AuthValue::from_str(&auth_str).expect("Unable to create auth value");

            // Request a new machine-key-context. This key "owns" anything
            // created underneath it.
            let loadable_machine_key = $tpm
                .machine_key_create(&auth_value)
                .expect("Unable to create new machine key");

            trace!(?loadable_machine_key);

            let machine_key = $tpm
                .machine_key_load(&auth_value, &loadable_machine_key)
                .expect("Unable to load machine key");

            // from that ctx, create an identity key
            let loadable_id_key = $tpm
                .identity_key_create(&machine_key, $pin_value.as_ref(), $alg)
                .expect("Unable to create id key");

            trace!(?loadable_id_key);

            let id_key = $tpm
                .identity_key_load(&machine_key, $pin_value.as_ref(), &loadable_id_key)
                .expect("Unable to load id key");

            let id_key_public_pem = $tpm
                .identity_key_public_as_pem(&id_key)
                .expect("Unable to get id key public pem");

            let pem_str = String::from_utf8_lossy(&id_key_public_pem);
            trace!(?pem_str);

            let id_key_public_der = $tpm
                .identity_key_public_as_der(&id_key)
                .expect("Unable to get id key public pem");

            // Rehydrate the der to a public key.
            let public_key = PKey::public_key_from_der(&id_key_public_der).expect("Invalid DER");

            trace!(?public_key);

            let input = "test string";
            let signature = $tpm
                .identity_key_sign(&id_key, input.as_bytes())
                .expect("Unable to sign input");

            // Internal verification
            assert!($tpm
                .identity_key_verify(&id_key, input.as_bytes(), signature.as_slice())
                .expect("Unable to sign input"));

            // External verification.
            let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)
                .expect("Unable to setup verifier.");

            match $alg {
                KeyAlgorithm::Rsa2048 => {
                    verifier
                        .set_rsa_padding(openssl::rsa::Padding::PKCS1)
                        .unwrap();
                }
                _ => {}
            }

            let valid = verifier
                .verify_oneshot(&signature, input.as_bytes())
                .expect("Unable to validate signature");

            assert!(valid);
        };
    }

    #[macro_export]
    macro_rules! test_tpm_identity_csr {
        ( $tpm:expr, $alg:expr ) => {
            use crate::{AuthValue, Tpm};
            use tracing::trace;

            let _ = tracing_subscriber::fmt::try_init();

            let auth_value = AuthValue::ephemeral().expect("Unable to create auth value");

            // Request a new machine-key-context. This key "owns" anything
            // created underneath it.
            let loadable_machine_key = $tpm
                .machine_key_create(&auth_value)
                .expect("Unable to create new machine key");

            trace!(?loadable_machine_key);

            let machine_key = $tpm
                .machine_key_load(&auth_value, &loadable_machine_key)
                .expect("Unable to load machine key");

            let id_key_pin_value = None;

            // from that ctx, create an identity key
            let loadable_id_key = $tpm
                .identity_key_create(&machine_key, id_key_pin_value, $alg)
                .expect("Unable to create id key");

            trace!(?loadable_id_key);

            // Get the CSR

            let csr_der = $tpm
                .identity_key_certificate_request(
                    &machine_key,
                    id_key_pin_value,
                    &loadable_id_key,
                    "common name",
                )
                .expect("Failed to create csr");

            // Now, we need to sign this to an x509 cert externally.
            let (ca_key, ca_cert) = crate::tests::create_ca();

            let signed_cert = crate::tests::sign_request(&csr_der, &ca_key, &ca_cert);
            trace!(
                "{}",
                String::from_utf8_lossy(signed_cert.to_text().unwrap().as_slice())
            );

            let signed_cert_der = signed_cert.to_der().unwrap();

            let loadable_id_key = $tpm
                .identity_key_associate_certificate(
                    &machine_key,
                    id_key_pin_value,
                    &loadable_id_key,
                    &signed_cert_der,
                )
                .unwrap();

            // Now load it in:
            let id_key = $tpm
                .identity_key_load(&machine_key, id_key_pin_value, &loadable_id_key)
                .expect("Unable to load id key");

            let id_key_x509_pem = $tpm
                .identity_key_x509_as_pem(&id_key)
                .expect("Unable to get id key public pem");

            trace!("\n{}", String::from_utf8_lossy(&id_key_x509_pem));
        };
    }

    pub fn create_ca() -> (PKey<Private>, X509) {
        let ecgroup = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let eckey = EcKey::generate(&ecgroup).unwrap();
        let ca_key = PKey::from_ec_key(eckey).unwrap();

        let mut x509_name = X509NameBuilder::new().unwrap();
        x509_name
            .append_entry_by_text("CN", "Dynamic Softtoken CA")
            .unwrap();
        let x509_name = x509_name.build();

        let mut cert_builder = X509::builder().unwrap();
        cert_builder.set_version(2).unwrap();

        let serial_number = BigNum::from_u32(1)
            .and_then(|serial| serial.to_asn1_integer())
            .unwrap();
        cert_builder.set_serial_number(&serial_number).unwrap();
        cert_builder.set_subject_name(&x509_name).unwrap();
        cert_builder.set_issuer_name(&x509_name).unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        cert_builder.set_not_before(&not_before).unwrap();
        let not_after = Asn1Time::days_from_now(1).unwrap();
        cert_builder.set_not_after(&not_after).unwrap();

        cert_builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        cert_builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let subject_key_identifier = SubjectKeyIdentifier::new()
            .build(&cert_builder.x509v3_context(None, None))
            .unwrap();
        cert_builder
            .append_extension(subject_key_identifier)
            .unwrap();

        cert_builder.set_pubkey(&ca_key).unwrap();

        cert_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
        let ca_cert = cert_builder.build();

        (ca_key, ca_cert)
    }

    pub fn sign_request(req_der: &[u8], ca_key: &PKey<Private>, ca_cert: &X509) -> X509 {
        let req = X509Req::from_der(req_der).unwrap();

        let req_pkey = req.public_key().unwrap();
        assert!(req.verify(&req_pkey).unwrap());

        // depends on the ca, for a lot of them with machine id certs they ignore the values in
        // the csr and stomp them with their own things.

        let mut cert_builder = X509::builder().unwrap();
        cert_builder.set_version(2).unwrap();

        let serial_number = BigNum::from_u32(2)
            .and_then(|serial| serial.to_asn1_integer())
            .unwrap();
        cert_builder.set_serial_number(&serial_number).unwrap();
        cert_builder.set_subject_name(req.subject_name()).unwrap();
        cert_builder
            .set_issuer_name(ca_cert.subject_name())
            .unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        cert_builder.set_not_before(&not_before).unwrap();
        let not_after = Asn1Time::days_from_now(1).unwrap();
        cert_builder.set_not_after(&not_after).unwrap();

        cert_builder
            .append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();

        /*
        cert_builder.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .key_encipherment()
                .build().unwrap()
        ).unwrap();

        let subject_key_identifier = SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None)).unwrap();
        cert_builder.append_extension(subject_key_identifier).unwrap();
        */

        cert_builder
            .append_extension(
                ExtendedKeyUsage::new()
                    // .server_auth()
                    .client_auth()
                    .build()
                    .unwrap(),
            )
            .unwrap();

        cert_builder.set_pubkey(&req_pkey).unwrap();

        cert_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
        cert_builder.build()
    }
}

#[cfg(all(test, feature = "msextensions"))]
mod ms_extn_tests {
    #[macro_export]
    macro_rules! test_tpm_ms_extensions {
        ( $tpm_a:expr ) => {
            use crate::{AuthValue, Tpm};

            let _ = tracing_subscriber::fmt::try_init();

            // Create a new random auth_value.
            let auth_value = AuthValue::ephemeral().expect("Failed to generate new random secret");

            // Request a new machine-key-context. This key "owns" anything
            // created underneath it.
            let loadable_machine_key = $tpm_a
                .machine_key_create(&auth_value)
                .expect("Unable to create new machine key");

            let machine_key = $tpm_a
                .machine_key_load(&auth_value, &loadable_machine_key)
                .expect("Unable to load machine key");

            // from that ctx, create a hmac key.
            let loadable_ms_rsa_key = $tpm_a
                .msoapxbc_rsa_key_create(&machine_key)
                .expect("Unable to create new hmac key");

            let ms_rsa_key = $tpm_a
                .msoapxbc_rsa_key_load(&machine_key, &loadable_ms_rsa_key)
                .expect("Unable to load ms rsa key");

            // Get the public key as DER
            let ms_rsa_key_public_der = $tpm_a
                .msoapxbc_rsa_public_as_der(&ms_rsa_key)
                .expect("Unable to retrieve key as DER");

            let rsa_public = openssl::rsa::Rsa::public_key_from_der(&ms_rsa_key_public_der)
                .expect("Invalid public key");

            let secret = &[0, 1, 2, 3];

            // Create something for the key to decrypt.
            let encrypted_secret =
                crate::soft::rsa_oaep_encrypt(&rsa_public, secret).expect("unable to wrap key");

            // Decrypt it.

            let loadable_session_key = $tpm_a
                .msoapxbc_rsa_decipher_session_key(&ms_rsa_key, &encrypted_secret, secret.len())
                .expect("Unable to decipher encrypted secret");

            let yielded_session_key = $tpm_a
                .msoapxbc_rsa_yield_session_key(&ms_rsa_key, &loadable_session_key)
                .expect("unable to load session key");

            assert_eq!(yielded_session_key.as_slice(), secret);

            // Seal and unseal some data.

            let sealed_secret = $tpm_a
                .msoapxbc_rsa_seal_data(&ms_rsa_key, secret)
                .expect("Unable to seal");

            let unsealed_secret = $tpm_a
                .msoapxbc_rsa_unseal_data(&ms_rsa_key, &sealed_secret)
                .expect("Unable to unseal");

            assert_eq!(unsealed_secret.as_slice(), secret);
        };
    }
}
