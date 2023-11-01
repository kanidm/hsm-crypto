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

use std::str::FromStr;
use tracing::error;
use zeroize::Zeroizing;
use argon2::MIN_SALT_LEN;
use serde::{Deserialize, Serialize};

pub mod soft;

#[cfg(feature = "tpm")]
pub mod tpm;
// future goal ... once I can afford one ...
// mod yubihsm;

pub enum AuthValue {
    Key256Bit { auth_key: Zeroizing<[u8; 32]> },
}

pub enum KeyAlgorithm {
    Rsa2048,
    Ecdsa256,
}

impl AuthValue {
    pub fn new_random() -> Result<Self, HsmError> {
        let mut auth_key = Zeroizing::new([0; 32]);
        openssl::rand::rand_bytes(auth_key.as_mut()).map_err(|ossl_err| {
            error!(?ossl_err);
            HsmError::Entropy
        })?;

        Ok(AuthValue::Key256Bit { auth_key })
    }
}

impl FromStr for AuthValue {
    type Err = HsmError;

    fn from_str(cleartext: &str) -> Result<Self, Self::Err> {
        use argon2::{Algorithm, Argon2, Params, Version};

        let mut auth_key = Zeroizing::new([0; 32]);

        // This can't be changed else it will break key derivation for users.
        let argon2id_params =
            Params::new(32_768, 4, 1, Some(auth_key.as_ref().len())).map_err(|argon_err| {
                error!(?argon_err);
                HsmError::AuthValueDerivation
            })?;

        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2id_params);

        // Want at least 8 bytes salt, 16 bytes pw input.
        if cleartext.len() < 24 {
            return Err(HsmError::AuthValueTooShort);
        }

        let (salt, key) = cleartext.as_bytes().split_at(MIN_SALT_LEN);

        argon
            .hash_password_into(key, salt, auth_key.as_mut())
            .map_err(|argon_err| {
                error!(?argon_err);
                HsmError::AuthValueDerivation
            })?;

        Ok(AuthValue::Key256Bit { auth_key })
    }
}

#[derive(Debug, Clone)]
pub enum HsmError {
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
    IdentityKeyPublicToDer,
    IdentityKeyPublicToPem,
    IdentityKeyInvalidForSigning,
    IdentityKeySignature,
    IdentityKeyX509ToPem,
    IdentityKeyX509ToDer,
    IdentityKeyX509Missing,
    RsaGenerate,
    RsaPrivateToDer,
    RsaKeyFromDer,
    RsaToPrivateKey,
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

    TpmContextCreate,
    TpmPrimaryObjectAttributesInvalid,
    TpmPrimaryPublicBuilderInvalid,
    TpmPrimaryCreate,
    TpmEntropy,
    TpmAuthValueInvalid,

    TpmMachineKeyObjectAttributesInvalid,
    TpmMachineKeyBuilderInvalid,
    TpmMachineKeyCreate,
    TpmMachineKeyLoad,

    TpmHmacKeyObjectAttributesInvalid,
    TpmHmacKeyBuilderInvalid,
    TpmHmacKeyCreate,
    TpmHmacKeyLoad,
    TpmHmacSign,

    TpmHmacInputTooLarge,

    Entropy,
    IncorrectKeyType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadableMachineKey {
    Soft(soft::SoftLoadableMachineKey),
    #[cfg(feature = "tpm")]
    Tpm(tpm::TpmLoadableMachineKey),
    #[cfg(not(feature = "tpm"))]
    Tpm(()),
}

pub enum MachineKey {
    Soft(soft::SoftMachineKey),
    #[cfg(feature = "tpm")]
    Tpm(tpm::TpmMachineKey),
    #[cfg(not(feature = "tpm"))]
    Tpm(()),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadableHmacKey {
    Soft(soft::SoftLoadableHmacKey),
    #[cfg(feature = "tpm")]
    Tpm(tpm::TpmLoadableHmacKey),
    #[cfg(not(feature = "tpm"))]
    Tpm(()),
}

pub enum HmacKey {
    Soft(soft::SoftHmacKey),
    #[cfg(feature = "tpm")]
    Tpm(tpm::TpmHmacKey),
    #[cfg(not(feature = "tpm"))]
    Tpm(()),
}

pub trait Hsm {
    fn machine_key_create(
        &mut self,
        auth_value: &AuthValue,
    ) -> Result<LoadableMachineKey, HsmError>;

    fn machine_key_load(
        &mut self,
        auth_value: &AuthValue,
        exported_key: &LoadableMachineKey,
    ) -> Result<MachineKey, HsmError>;

    fn hmac_key_create(&mut self, mk: &MachineKey)
        -> Result<LoadableHmacKey, HsmError>;

    fn hmac_key_load(
        &mut self,
        mk: &MachineKey,
        exported_key: &LoadableHmacKey,
    ) -> Result<HmacKey, HsmError>;

    fn hmac(&mut self, hk: &HmacKey, input: &[u8]) -> Result<Vec<u8>, HsmError>;
}

pub trait HsmIdentity: Hsm {
    type IdentityKey;
    type LoadableIdentityKey;

    fn identity_key_create(
        &mut self,
        mk: &MachineKey,
        algorithm: KeyAlgorithm,
    ) -> Result<Self::LoadableIdentityKey, HsmError>;

    fn identity_key_load(
        &mut self,
        mk: &MachineKey,
        loadable_key: &Self::LoadableIdentityKey,
    ) -> Result<Self::IdentityKey, HsmError>;

    fn identity_key_sign(
        &mut self,
        key: &Self::IdentityKey,
        input: &[u8],
    ) -> Result<Vec<u8>, HsmError>;

    fn identity_key_public_as_der(&mut self, key: &Self::IdentityKey) -> Result<Vec<u8>, HsmError>;

    fn identity_key_public_as_pem(&mut self, key: &Self::IdentityKey) -> Result<Vec<u8>, HsmError>;

    fn identity_key_certificate_request(
        &mut self,
        mk: &MachineKey,
        loadable_key: &Self::LoadableIdentityKey,
        cn: &str,
    ) -> Result<Vec<u8>, HsmError>;

    fn identity_key_associate_certificate(
        &mut self,
        mk: &MachineKey,
        loadable_key: &Self::LoadableIdentityKey,
        certificate_der: &[u8],
    ) -> Result<Self::LoadableIdentityKey, HsmError>;

    fn identity_key_x509_as_pem(&mut self, key: &Self::IdentityKey) -> Result<Vec<u8>, HsmError>;
    fn identity_key_x509_as_der(&mut self, key: &Self::IdentityKey) -> Result<Vec<u8>, HsmError>;
}
