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
    X509FromDer,
    RsaGenerate,
    RsaPrivateToDer,
    RsaKeyFromDer,
    RsaToPrivateKey,

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
}

trait Hsm {
    type MachineKey;
    type LoadableMachineKey;

    type HmacKey;
    type LoadableHmacKey;

    fn machine_key_create(
        &mut self,
        auth_value: &AuthValue,
    ) -> Result<Self::LoadableMachineKey, HsmError>;

    fn machine_key_load(
        &mut self,
        auth_value: &AuthValue,
        exported_key: &Self::LoadableMachineKey,
    ) -> Result<Self::MachineKey, HsmError>;

    fn hmac_key_create(&mut self, mk: &Self::MachineKey)
        -> Result<Self::LoadableHmacKey, HsmError>;

    fn hmac_key_load(
        &mut self,
        mk: &Self::MachineKey,
        exported_key: &Self::LoadableHmacKey,
    ) -> Result<Self::HmacKey, HsmError>;

    fn hmac(&mut self, hk: &Self::HmacKey, input: &[u8]) -> Result<Vec<u8>, HsmError>;
}

trait HsmIdentity: Hsm {
    type IdentityKey;
    type LoadableIdentityKey;

    fn identity_key_create(
        &mut self,
        mk: &Self::MachineKey,
        algorithm: KeyAlgorithm,
    ) -> Result<Self::LoadableIdentityKey, HsmError>;

    fn identity_key_load(
        &mut self,
        mk: &Self::MachineKey,
        loadable_key: &Self::LoadableIdentityKey,
    ) -> Result<Self::IdentityKey, HsmError>;

    fn identity_key_sign(
        &mut self,
        key: &Self::IdentityKey,
        input: &[u8],
    ) -> Result<Vec<u8>, HsmError>;

    fn identity_key_public_as_der(&mut self, key: &Self::IdentityKey) -> Result<Vec<u8>, HsmError>;

    fn identity_key_public_as_pem(&mut self, key: &Self::IdentityKey) -> Result<Vec<u8>, HsmError>;
}
