use crate::authvalue::AuthValue;
use crate::error::TpmError;
use crate::pin::PinValue;
use crate::provider::{Tpm, TpmES256, TpmHmacS256, TpmRS256};
use crate::structures::{
    ES256Key, HmacS256Key, LoadableES256Key, LoadableHmacS256Key, LoadableRS256Key,
    LoadableStorageKey, RS256Key, StorageKey,
};
use crypto_glue::{
    aes256::{self},
    aes256gcm::{self, AeadInPlace, Aes256Gcm, KeyInit},
    ecdsa_p256::{
        self, EcdsaP256Digest, EcdsaP256PrivateKey, EcdsaP256PublicKey, EcdsaP256Signature,
        EcdsaP256SigningKey,
    },
    hmac_s256::{self, HmacSha256Output},
    rsa::{self, RS256Digest, RS256PrivateKey, RS256PublicKey, RS256Signature, RS256SigningKey},
    s256::{self, Sha256Output},
    traits::*,
};
use tracing::error;

#[derive(Default)]
pub struct SoftTpm {}

macro_rules! wrap_aes256gcm {
    (
        $wrapping_key: expr,
        $key_to_wrap: expr
    ) => {{
        let nonce = aes256gcm::new_nonce();
        let cipher = Aes256Gcm::new($wrapping_key);

        let associated_data = b"";
        let mut enc_key = $key_to_wrap.clone();

        let tag = cipher
            .encrypt_in_place_detached(&nonce, associated_data, enc_key.as_mut_slice())
            .map_err(|_| TpmError::Aes256GcmEncrypt)?;

        if enc_key.as_slice() == $key_to_wrap.as_slice() {
            // Encryption didn't replace the buffer in place, fail.
            return Err(TpmError::Aes256GcmEncrypt);
        }

        Ok((enc_key, tag, nonce))
    }};
}

macro_rules! unwrap_aes256gcm {
    (
        $wrapping_key: expr,
        $key_to_unwrap: expr,
        $tag: expr,
        $nonce: expr
    ) => {{
        let cipher = Aes256Gcm::new($wrapping_key);

        let mut key = $key_to_unwrap.clone();

        let associated_data = b"";

        cipher
            .decrypt_in_place_detached($nonce, associated_data, key.as_mut_slice(), $tag)
            .map_err(|_| TpmError::Aes256GcmDecrypt)?;

        if key.as_slice() == $key_to_unwrap.as_slice() {
            // Encryption didn't replace the buffer in place, fail.
            return Err(TpmError::Aes256GcmDecrypt);
        }

        Ok(key)
    }};
}

impl Tpm for SoftTpm {
    // create a root-storage-key
    fn root_storage_key_create(
        &mut self,
        auth_value: &AuthValue,
    ) -> Result<LoadableStorageKey, TpmError> {
        // Key to encrypt
        let key_to_wrap = aes256::new_key();

        match auth_value {
            AuthValue::Key256Bit { auth_key } => {
                wrap_aes256gcm!(auth_key, key_to_wrap).map(|(enc_key, tag, nonce)| {
                    LoadableStorageKey::SoftAes256GcmV2 {
                        enc_key,
                        tag,
                        nonce,
                    }
                })
            }
        }
    }

    // load root storage key
    fn root_storage_key_load(
        &mut self,
        auth_value: &AuthValue,
        lsk: &LoadableStorageKey,
    ) -> Result<StorageKey, TpmError> {
        match (auth_value, lsk) {
            (
                AuthValue::Key256Bit { auth_key },
                LoadableStorageKey::SoftAes256GcmV2 {
                    enc_key,
                    tag,
                    nonce,
                },
            ) => unwrap_aes256gcm!(auth_key, enc_key, tag, nonce)
                .map(|key| StorageKey::SoftAes256GcmV2 { key }),
        }
    }

    // create a subordinate storage key.
    fn storage_key_create(
        &mut self,
        parent_key: &StorageKey,
    ) -> Result<LoadableStorageKey, TpmError> {
        let key_to_wrap = aes256::new_key();

        match parent_key {
            StorageKey::SoftAes256GcmV2 { key: parent_key } => {
                wrap_aes256gcm!(parent_key, key_to_wrap).map(|(enc_key, tag, nonce)| {
                    LoadableStorageKey::SoftAes256GcmV2 {
                        enc_key,
                        tag,
                        nonce,
                    }
                })
            }
        }
    }

    fn storage_key_load(
        &mut self,
        parent_key: &StorageKey,
        lsk: &LoadableStorageKey,
    ) -> Result<StorageKey, TpmError> {
        match (parent_key, lsk) {
            (
                StorageKey::SoftAes256GcmV2 { key: parent_key },
                LoadableStorageKey::SoftAes256GcmV2 {
                    enc_key,
                    tag,
                    nonce,
                },
            ) => unwrap_aes256gcm!(parent_key, enc_key, tag, nonce)
                .map(|key| StorageKey::SoftAes256GcmV2 { key }),
        }
    }

    // Create a storage key that has a pin value to protect it.
    fn storage_key_create_pin(
        &mut self,
        parent_key: &StorageKey,
        pin: &PinValue,
    ) -> Result<LoadableStorageKey, TpmError> {
        let key_to_wrap = aes256::new_key();

        match parent_key {
            StorageKey::SoftAes256GcmV2 { key: parent_key } => {
                let wrapping_key = pin.derive_aes_256(parent_key)?;
                wrap_aes256gcm!(&wrapping_key, key_to_wrap).map(|(enc_key, tag, nonce)| {
                    LoadableStorageKey::SoftAes256GcmV2 {
                        enc_key,
                        tag,
                        nonce,
                    }
                })
            }
        }
    }

    fn storage_key_load_pin(
        &mut self,
        parent_key: &StorageKey,
        pin: &PinValue,
        lsk: &LoadableStorageKey,
    ) -> Result<StorageKey, TpmError> {
        match (parent_key, lsk) {
            (
                StorageKey::SoftAes256GcmV2 { key: parent_key },
                LoadableStorageKey::SoftAes256GcmV2 {
                    enc_key,
                    tag,
                    nonce,
                },
            ) => {
                let wrapping_key = pin.derive_aes_256(parent_key)?;
                unwrap_aes256gcm!(&wrapping_key, enc_key, tag, nonce)
                    .map(|key| StorageKey::SoftAes256GcmV2 { key })
            }
        }
    }

    // duplicable?
}

impl TpmHmacS256 for SoftTpm {
    fn hmac_s256_create(
        &mut self,
        parent_key: &StorageKey,
    ) -> Result<LoadableHmacS256Key, TpmError> {
        let key_to_wrap = hmac_s256::new_key();

        match parent_key {
            StorageKey::SoftAes256GcmV2 { key: parent_key } => {
                wrap_aes256gcm!(parent_key, key_to_wrap).map(|(enc_key, tag, nonce)| {
                    LoadableHmacS256Key::SoftAes256GcmV2 {
                        enc_key,
                        tag,
                        nonce,
                    }
                })
            }
        }
    }

    fn hmac_s256_load(
        &mut self,
        parent_key: &StorageKey,
        hmac_key: &LoadableHmacS256Key,
    ) -> Result<HmacS256Key, TpmError> {
        match (parent_key, hmac_key) {
            (
                StorageKey::SoftAes256GcmV2 { key: parent_key },
                LoadableHmacS256Key::SoftAes256GcmV2 {
                    enc_key,
                    tag,
                    nonce,
                },
            ) => unwrap_aes256gcm!(parent_key, enc_key, tag, nonce)
                .map(|key| HmacS256Key::SoftAes256GcmV2 { key }),
        }
    }

    fn hmac_s256(
        &mut self,
        hmac_key: &HmacS256Key,
        data: &[u8],
    ) -> Result<HmacSha256Output, TpmError> {
        match hmac_key {
            HmacS256Key::SoftAes256GcmV2 { key } => Ok(hmac_s256::oneshot(key, data)),
        }
    }
}

impl TpmES256 for SoftTpm {
    fn es256_create(&mut self, parent_key: &StorageKey) -> Result<LoadableES256Key, TpmError> {
        let key_to_wrap = ecdsa_p256::new_key();

        match parent_key {
            StorageKey::SoftAes256GcmV2 { key: parent_key } => {
                let key_to_wrap_field = key_to_wrap.to_bytes();

                wrap_aes256gcm!(parent_key, key_to_wrap_field).map(|(enc_key, tag, nonce)| {
                    LoadableES256Key::SoftAes256GcmV2 {
                        enc_key,
                        tag,
                        nonce,
                    }
                })
            }
        }
    }

    fn es256_load(
        &mut self,
        parent_key: &StorageKey,
        es256_key: &LoadableES256Key,
    ) -> Result<ES256Key, TpmError> {
        match (parent_key, es256_key) {
            (
                StorageKey::SoftAes256GcmV2 { key: parent_key },
                LoadableES256Key::SoftAes256GcmV2 {
                    enc_key,
                    tag,
                    nonce,
                },
            ) => unwrap_aes256gcm!(parent_key, enc_key, tag, nonce)
                .and_then(|field_key| {
                    EcdsaP256PrivateKey::from_bytes(&field_key)
                        .map_err(|_| TpmError::EcKeyToPrivateKey)
                })
                .map(|key| ES256Key::SoftAes256GcmV2 { key }),
        }
    }

    fn es256_public(&mut self, es256_key: &ES256Key) -> Result<EcdsaP256PublicKey, TpmError> {
        match es256_key {
            ES256Key::SoftAes256GcmV2 { key } => Ok(key.public_key()),
        }
    }

    fn es256_sign(
        &mut self,
        es256_key: &ES256Key,
        data: &[u8],
    ) -> Result<EcdsaP256Signature, TpmError> {
        match es256_key {
            ES256Key::SoftAes256GcmV2 { key } => {
                let mut digest = EcdsaP256Digest::new();
                digest.update(data);

                let signer = EcdsaP256SigningKey::from(key);
                signer
                    .try_sign_digest(digest)
                    .map_err(|_| TpmError::EcdsaSignature)
            }
        }
    }
}

impl TpmRS256 for SoftTpm {
    fn rs256_create(&mut self, parent_key: &StorageKey) -> Result<LoadableRS256Key, TpmError> {
        let key_to_wrap = rsa::new_key(rsa::MIN_BITS).map_err(|err| {
            error!(?err, "Unable to generate RSA private key");
            TpmError::RsaGenerate
        })?;

        let cek_to_wrap = aes256::new_key();

        match parent_key {
            StorageKey::SoftAes256GcmV2 { key: parent_key } => {
                let key_to_wrap_pkcs8 = key_to_wrap.to_pkcs8_der().map_err(|err| {
                    error!(?err, "Unable to serialise RSA private key to der");
                    TpmError::RsaPrivateToDer
                })?;

                let (enc_key, tag, nonce) =
                    wrap_aes256gcm!(parent_key, key_to_wrap_pkcs8.to_bytes())?;

                let (cek_enc, cek_tag, cek_nonce) = wrap_aes256gcm!(parent_key, cek_to_wrap)?;

                Ok(LoadableRS256Key::SoftAes256GcmV2 {
                    enc_key,
                    tag,
                    nonce,
                    cek_enc,
                    cek_tag,
                    cek_nonce,
                })
            }
        }
    }

    fn rs256_load(
        &mut self,
        parent_key: &StorageKey,
        rs256_key: &LoadableRS256Key,
    ) -> Result<RS256Key, TpmError> {
        match (parent_key, rs256_key) {
            (
                StorageKey::SoftAes256GcmV2 { key: parent_key },
                LoadableRS256Key::SoftAes256GcmV2 {
                    enc_key,
                    tag,
                    nonce,
                    cek_enc,
                    cek_tag,
                    cek_nonce,
                },
            ) => {
                let key =
                    unwrap_aes256gcm!(parent_key, enc_key, tag, nonce).and_then(|pkcs8_bytes| {
                        RS256PrivateKey::from_pkcs8_der(&pkcs8_bytes)
                            .map_err(|_| TpmError::RsaPrivateFromDer)
                    })?;

                let content_encryption_key =
                    unwrap_aes256gcm!(parent_key, cek_enc, cek_tag, cek_nonce)?;

                Ok(RS256Key::SoftAes256GcmV2 {
                    key,
                    content_encryption_key,
                })
            }
        }
    }

    fn rs256_public(&mut self, rs256_key: &RS256Key) -> Result<RS256PublicKey, TpmError> {
        match rs256_key {
            RS256Key::SoftAes256GcmV2 { key, .. } => Ok(RS256PublicKey::from(key)),
        }
    }

    fn rs256_sign(
        &mut self,
        rs256_key: &RS256Key,
        data: &[u8],
    ) -> Result<RS256Signature, TpmError> {
        match rs256_key {
            RS256Key::SoftAes256GcmV2 { key, .. } => {
                let mut digest = RS256Digest::new();
                digest.update(data);

                let signer = RS256SigningKey::new(key.clone());

                signer
                    .try_sign_digest(digest)
                    .map_err(|_| TpmError::RsaPkcs115Sign)
            }
        }
    }

    fn rs256_oaep_dec(
        &mut self,
        rs256_key: &RS256Key,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        match rs256_key {
            RS256Key::SoftAes256GcmV2 { key, .. } => {
                let padding = rsa::Oaep::new::<s256::Sha256>();
                key.decrypt(padding, encrypted_data)
                    .map_err(|_| TpmError::RsaOaepDecrypt)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SoftTpm;

    #[test]
    fn soft_tpm_storage() {
        let soft_tpm = SoftTpm::default();

        crate::tests::test_tpm_storage(soft_tpm);
    }

    #[test]
    fn soft_tpm_hmac() {
        let soft_tpm = SoftTpm::default();

        crate::tests::test_tpm_hmac(soft_tpm);
    }

    #[test]
    fn soft_tpm_ecdsa_p256() {
        let soft_tpm = SoftTpm::default();

        crate::tests::test_tpm_ecdsa_p256(soft_tpm);
    }

    #[test]
    fn soft_tpm_rs256() {
        let soft_tpm = SoftTpm::default();

        crate::tests::test_tpm_rs256(soft_tpm);
    }
}
