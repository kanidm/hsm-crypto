use crate::error::TpmError;
use crypto_glue::{
    aes256::{self, Aes256Key},
    argon2,
    hmac_s256::HmacSha256Output,
    zeroize::Zeroizing,
};
use tracing::error;

pub(crate) const TPM_PIN_MIN_LEN: u8 = 6;

pub struct PinValue {
    value: Zeroizing<Vec<u8>>,
}

#[derive(Debug)]
pub enum TpmPinError {
    TooShort(u8),
}

impl PinValue {
    pub fn new(input: &str) -> Result<Self, TpmPinError> {
        if input.len() < TPM_PIN_MIN_LEN as usize {
            return Err(TpmPinError::TooShort(TPM_PIN_MIN_LEN));
        }

        Ok(PinValue {
            value: input.as_bytes().to_vec().into(),
        })
    }

    pub(crate) fn value(&self) -> &[u8] {
        self.value.as_slice()
    }

    /// Derive an AES256GCM Key from this PIN. This is used by the soft-tpm exclusively.
    pub(crate) fn derive_aes_256(&self, parent_key: &Aes256Key) -> Result<Aes256Key, TpmError> {
        // These can't be changed else it will break key derivation.
        //
        // To increase these parameters we need to introduce a new pin
        // derive function that has the new values.
        const ARGON2ID_MEMORY: u32 = 32_768;
        const ARGON2ID_TIME: u32 = 1;
        const ARGON2ID_PARALLEL: u32 = 1;

        use argon2::{Algorithm, Argon2, Params, Version};

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

        let (salt, pepper) = parent_key.as_slice().split_at(argon2::MIN_SALT_LEN);

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

    /// Derive an AES256GCM Key from this PIN. This is used by the soft-tpm exclusively.
    pub(crate) fn derive_hmac_s256_aes_256(
        &self,
        hmac_output: HmacSha256Output,
        parent_key: &Aes256Key,
    ) -> Result<Aes256Key, TpmError> {
        // These can't be changed else it will break key derivation.
        //
        // To increase these parameters we need to introduce a new pin
        // derive function that has the new values.
        const ARGON2ID_MEMORY: u32 = 32_768;
        const ARGON2ID_TIME: u32 = 1;
        const ARGON2ID_PARALLEL: u32 = 1;

        use argon2::{Algorithm, Argon2, Params, Version};

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

        let salt = hmac_output.into_bytes();
        let pepper = parent_key.as_slice();

        let argon =
            Argon2::new_with_secret(pepper, Algorithm::Argon2id, Version::V0x13, argon2id_params)
                .map_err(|argon_err| {
                error!(?argon_err);
                TpmError::AuthValueDerivation
            })?;

        // let now = std::time::SystemTime::now();

        argon
            .hash_password_into(self.value.as_ref(), salt.as_slice(), auth_key.as_mut())
            .map_err(|argon_err| {
                error!(?argon_err);
                TpmError::AuthValueDerivation
            })?;

        // error!(elapsed = ?now.elapsed());

        Ok(auth_key)
    }
}
