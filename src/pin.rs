use crate::error::TpmError;
use crypto_glue::{
    aes256::{self, Aes256Key},
    argon2,
    zeroize::Zeroizing,
};
use tracing::error;

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

    pub(crate) fn value(&self) -> &[u8] {
        self.value.as_slice()
    }

    /// Derive an AES256GCM Key from this PIN. This is used by the soft-tpm exclusively.
    pub(crate) fn derive_aes_256(&self, parent_key: &Aes256Key) -> Result<Aes256Key, TpmError> {
        use argon2::{Algorithm, Argon2, Params, Version};

        let mut auth_key = Aes256Key::default();

        // This can't be changed else it will break key derivation for users.
        let argon2id_params =
            Params::new(32_768, 1, 1, Some(aes256::key_size())).map_err(|argon_err| {
                error!(?argon_err);
                TpmError::AuthValueDerivation
            })?;

        // Want at least 8 bytes salt, 16 bytes pw input.
        if parent_key.len() < 24 {
            return Err(TpmError::AuthValueTooShort);
        }

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
}
