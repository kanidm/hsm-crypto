use crate::error::TpmError;
use crypto_glue::{
    aes256::{self, Aes256Key},
    argon2, hex,
    rand::{self, RngCore},
    zeroize::Zeroizing,
};
use std::str::FromStr;
use tracing::error;

// These can't be changed else it will break key derivation.
//
// To increase these parameters we need to introduce a new AuthValue Key
// enum variant which has the changed values.
const ARGON2ID_MEMORY: u32 = 32_768;
const ARGON2ID_TIME: u32 = 4;
const ARGON2ID_PARALLEL: u32 = 1;

pub enum AuthValue {
    Key256Bit { auth_key: Aes256Key },
}

impl AuthValue {
    fn random_key() -> Result<Zeroizing<[u8; 24]>, TpmError> {
        let mut auth_key = Zeroizing::new([0; 24]);

        let mut rng = rand::thread_rng();
        rng.fill_bytes(auth_key.as_mut());

        Ok(auth_key)
    }

    pub fn generate() -> Result<String, TpmError> {
        let ak = Self::random_key()?;
        Ok(hex::encode(&ak))
    }

    pub fn ephemeral() -> Result<Self, TpmError> {
        let auth_key = aes256::new_key();

        Ok(AuthValue::Key256Bit { auth_key })
    }

    /// Derive an auth value from input bytes. This value must be at least 24 bytes in length.
    ///
    /// The key derivation is performed with Argon2id.
    pub fn derive_from_bytes(cleartext: &[u8]) -> Result<Self, TpmError> {
        use argon2::{Algorithm, Argon2, Params, Version};

        // Want at least 8 bytes salt, 16 bytes pw input.
        if cleartext.len() < 24 {
            return Err(TpmError::AuthValueTooShort);
        }

        let mut auth_key = Aes256Key::default();

        // This can't be changed else it will break key derivation for users.
        let argon2id_params = Params::new(
            ARGON2ID_MEMORY,
            ARGON2ID_TIME,
            ARGON2ID_PARALLEL,
            Some(aes256::key_size()),
        )
        .map_err(|argon_err| {
            error!(?argon_err);
            TpmError::AuthValueDerivation
        })?;

        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2id_params);

        let (salt, key) = cleartext.split_at(argon2::MIN_SALT_LEN);

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

impl From<[u8; 32]> for AuthValue {
    fn from(bytes: [u8; 32]) -> Self {
        Self::Key256Bit {
            auth_key: aes256::key_from_bytes(bytes),
        }
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
