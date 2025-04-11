use crate::authvalue::AuthValue;
use crate::error::TpmError;
use crate::pin::PinValue;
use crate::provider::{Tpm, TpmES256, TpmHmacS256, TpmMsExtensions, TpmRS256};
use crate::structures::{
    ES256Key, HmacS256Key, LoadableES256Key, LoadableHmacS256Key, LoadableRS256Key,
    LoadableStorageKey, RS256Key, SealedData, StorageKey,
};

use crypto_glue::{
    aes256::{self},
    aes256gcm::{
        self, AeadInPlace, Aes256Gcm, Aes256GcmN16, Aes256GcmNonce16, Aes256GcmTag, KeyInit,
    },
    ecdsa_p256::{
        self, EcdsaP256Digest, EcdsaP256PrivateKey, EcdsaP256PublicKey, EcdsaP256Signature,
        EcdsaP256SigningKey,
    },
    hmac_s256::{self, HmacSha256Output},
    rsa::{self, RS256Digest, RS256PrivateKey, RS256PublicKey, RS256Signature, RS256SigningKey},
    s256, sha1,
    traits::*,
};
use tracing::error;

use crate::wrap::{unwrap_aes256gcm, unwrap_aes256gcm_nonce16, wrap_aes256gcm};

#[derive(Default)]
pub struct SoftTpm {}

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
            (
                AuthValue::Key256Bit { auth_key },
                LoadableStorageKey::SoftAes256GcmV1 {
                    key: key_to_unwrap,
                    tag,
                    iv,
                },
            ) => unwrap_aes256gcm_nonce16!(auth_key, key_to_unwrap, tag, iv)
                .and_then(|key| {
                    aes256::key_from_vec(key.to_vec()).ok_or(TpmError::Aes256KeyInvalid)
                })
                .map(|key| StorageKey::SoftAes256GcmV2 { key }),
            (_, LoadableStorageKey::TpmAes128CfbV1 { .. }) => Err(TpmError::IncorrectKeyType),
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
            StorageKey::Tpm { .. } => Err(TpmError::IncorrectKeyType),
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
            (
                StorageKey::SoftAes256GcmV2 { key: parent_key },
                LoadableStorageKey::SoftAes256GcmV1 {
                    key: key_to_unwrap,
                    tag,
                    iv,
                },
            ) => unwrap_aes256gcm_nonce16!(parent_key, key_to_unwrap, tag, iv)
                .and_then(|key| {
                    aes256::key_from_vec(key.to_vec()).ok_or(TpmError::Aes256KeyInvalid)
                })
                .map(|key| StorageKey::SoftAes256GcmV2 { key }),
            (_, LoadableStorageKey::TpmAes128CfbV1 { .. }) | (StorageKey::Tpm { .. }, _) => {
                Err(TpmError::IncorrectKeyType)
            }
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
            StorageKey::Tpm { .. } => Err(TpmError::IncorrectKeyType),
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
            (
                StorageKey::SoftAes256GcmV2 { key: parent_key },
                LoadableStorageKey::SoftAes256GcmV1 {
                    key: key_to_unwrap,
                    tag,
                    iv,
                },
            ) => {
                let wrapping_key = pin.derive_aes_256(parent_key)?;
                unwrap_aes256gcm_nonce16!(&wrapping_key, key_to_unwrap, tag, iv)
                    .and_then(|key| {
                        aes256::key_from_vec(key.to_vec()).ok_or(TpmError::Aes256KeyInvalid)
                    })
                    .map(|key| StorageKey::SoftAes256GcmV2 { key })
            }
            (_, LoadableStorageKey::TpmAes128CfbV1 { .. }) | (StorageKey::Tpm { .. }, _) => {
                Err(TpmError::IncorrectKeyType)
            }
        }
    }

    fn seal_data(
        &mut self,
        key: &StorageKey,
        data_to_seal: Zeroizing<Vec<u8>>,
    ) -> Result<SealedData, TpmError> {
        match key {
            StorageKey::SoftAes256GcmV2 { key: parent_key } => {
                wrap_aes256gcm!(parent_key, data_to_seal)
                    .map(|(data, tag, nonce)| SealedData::SoftAes256GcmV2 { data, tag, nonce })
            }
            StorageKey::Tpm { .. } => Err(TpmError::IncorrectKeyType),
        }
    }

    fn unseal_data(
        &mut self,
        key: &StorageKey,
        data_to_unseal: &SealedData,
    ) -> Result<Zeroizing<Vec<u8>>, TpmError> {
        match (key, data_to_unseal) {
            (
                StorageKey::SoftAes256GcmV2 { key: parent_key },
                SealedData::SoftV1 { data, tag, iv },
            ) => {
                unwrap_aes256gcm_nonce16!(parent_key, data, tag, iv)
            }
            (
                StorageKey::SoftAes256GcmV2 { key: parent_key },
                SealedData::SoftAes256GcmV2 { data, tag, nonce },
            ) => {
                unwrap_aes256gcm!(parent_key, data, tag, nonce)
            }
            (StorageKey::Tpm { .. }, _) | (_, SealedData::TpmAes256GcmV2 { .. }) => {
                Err(TpmError::IncorrectKeyType)
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
            StorageKey::Tpm { .. } => Err(TpmError::IncorrectKeyType),
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
            (
                StorageKey::SoftAes256GcmV2 { key: parent_key },
                LoadableHmacS256Key::SoftSha256V1 {
                    key: key_to_unwrap,
                    tag,
                    iv,
                },
            ) => {
                tracing::trace!(key_size = %hmac_s256::key_size());
                tracing::trace!(new_key_size = %key_to_unwrap.len());

                let key = unwrap_aes256gcm_nonce16!(parent_key, key_to_unwrap, tag, iv)?;

                let mut empty_key: [u8; 64] = [0; 64];

                if let Some(view) = empty_key.get_mut(..32) {
                    view.copy_from_slice(&key)
                }

                let empty_key = hmac_s256::key_from_bytes(empty_key);

                Ok(HmacS256Key::SoftAes256GcmV2 { key: empty_key })
            }
            (StorageKey::Tpm { .. }, _) | (_, LoadableHmacS256Key::TpmSha256V1 { .. }) => {
                Err(TpmError::IncorrectKeyType)
            }
        }
    }

    fn hmac_s256(
        &mut self,
        hmac_key: &HmacS256Key,
        data: &[u8],
    ) -> Result<HmacSha256Output, TpmError> {
        match hmac_key {
            HmacS256Key::SoftAes256GcmV2 { key } => Ok(hmac_s256::oneshot(key, data)),
            HmacS256Key::Tpm { .. } => Err(TpmError::IncorrectKeyType),
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
            StorageKey::Tpm { .. } => Err(TpmError::IncorrectKeyType),
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
            (StorageKey::Tpm { .. }, _) | (_, LoadableES256Key::TpmV1 { .. }) => {
                Err(TpmError::IncorrectKeyType)
            }
        }
    }

    fn es256_public(&mut self, es256_key: &ES256Key) -> Result<EcdsaP256PublicKey, TpmError> {
        match es256_key {
            ES256Key::SoftAes256GcmV2 { key } => Ok(key.public_key()),
            ES256Key::Tpm { .. } => Err(TpmError::IncorrectKeyType),
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
            ES256Key::Tpm { .. } => Err(TpmError::IncorrectKeyType),
        }
    }
}

impl TpmRS256 for SoftTpm {
    fn rs256_create(&mut self, parent_key: &StorageKey) -> Result<LoadableRS256Key, TpmError> {
        let key_to_wrap = rsa::new_key(rsa::MIN_BITS).map_err(|err| {
            error!(?err, "Unable to generate RSA private key");
            TpmError::RsaGenerate
        })?;

        self.rs256_import(parent_key, key_to_wrap)
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

                let key = Box::new(key);

                Ok(RS256Key::SoftAes256GcmV2 {
                    key,
                    content_encryption_key,
                })
            }
            (
                StorageKey::SoftAes256GcmV2 { key: parent_key },
                LoadableRS256Key::Soft2048V1 {
                    key: key_to_unwrap,
                    tag,
                    iv,
                    cek,
                },
            ) => {
                let key = unwrap_aes256gcm_nonce16!(parent_key, key_to_unwrap, tag, iv).and_then(
                    |pkcs1_bytes| {
                        RS256PrivateKey::from_pkcs1_der(&pkcs1_bytes).map_err(|err| {
                            error!(?err, "rsa private from der");
                            TpmError::RsaPrivateFromDer
                        })
                    },
                )?;

                let padding = rsa::Oaep::new::<sha1::Sha1>();
                let cek_vec = key
                    .decrypt(padding, cek)
                    .map_err(|_| TpmError::RsaOaepDecrypt)?;

                let content_encryption_key =
                    aes256::key_from_vec(cek_vec).ok_or(TpmError::Aes256KeyInvalid)?;

                let key = Box::new(key);

                Ok(RS256Key::SoftAes256GcmV2 {
                    key,
                    content_encryption_key,
                })
            }
            (StorageKey::Tpm { .. }, _) | (_, LoadableRS256Key::TpmV1 { .. }) => {
                Err(TpmError::IncorrectKeyType)
            }
        }
    }

    fn rs256_public(&mut self, rs256_key: &RS256Key) -> Result<RS256PublicKey, TpmError> {
        match rs256_key {
            RS256Key::SoftAes256GcmV2 { key, .. } => Ok(RS256PublicKey::from(key.as_ref())),
            RS256Key::Tpm { .. } => Err(TpmError::IncorrectKeyType),
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

                let signer = RS256SigningKey::new(key.as_ref().clone());

                signer
                    .try_sign_digest(digest)
                    .map_err(|_| TpmError::RsaPkcs115Sign)
            }
            RS256Key::Tpm { .. } => Err(TpmError::IncorrectKeyType),
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
            RS256Key::Tpm { .. } => Err(TpmError::IncorrectKeyType),
        }
    }

    fn rs256_import(
        &mut self,
        parent_key: &StorageKey,
        key_to_import: RS256PrivateKey,
    ) -> Result<LoadableRS256Key, TpmError> {
        let cek_to_wrap = aes256::new_key();

        match parent_key {
            StorageKey::SoftAes256GcmV2 { key: parent_key } => {
                let key_to_wrap_pkcs8 = key_to_import.to_pkcs8_der().map_err(|err| {
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
            StorageKey::Tpm { .. } => Err(TpmError::IncorrectKeyType),
        }
    }

    fn rs256_unseal_data(
        &mut self,
        key: &RS256Key,
        sealed_data: &SealedData,
    ) -> Result<Zeroizing<Vec<u8>>, TpmError> {
        match (key, sealed_data) {
            (
                RS256Key::SoftAes256GcmV2 {
                    key: _,
                    content_encryption_key,
                },
                SealedData::SoftV1 { data, tag, iv },
            ) => {
                unwrap_aes256gcm_nonce16!(content_encryption_key, data, tag, iv)
            }
            (
                RS256Key::SoftAes256GcmV2 {
                    key: _,
                    content_encryption_key,
                },
                SealedData::SoftAes256GcmV2 { data, tag, nonce },
            ) => {
                unwrap_aes256gcm!(content_encryption_key, data, tag, nonce)
            }
            (RS256Key::Tpm { .. }, _) | (_, SealedData::TpmAes256GcmV2 { .. }) => {
                Err(TpmError::IncorrectKeyType)
            }
        }
    }
}

impl TpmMsExtensions for SoftTpm {
    fn rs256_oaep_dec_sha1(
        &mut self,
        rs256_key: &RS256Key,
        encrypted_data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, TpmError> {
        match rs256_key {
            RS256Key::SoftAes256GcmV2 { key, .. } => {
                let padding = rsa::Oaep::new::<sha1::Sha1>();
                key.decrypt(padding, encrypted_data)
                    .map(|data| data.into())
                    .map_err(|_| TpmError::RsaOaepDecrypt)
            }
            RS256Key::Tpm { .. } => Err(TpmError::IncorrectKeyType),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SoftTpm;
    use crate::authvalue::AuthValue;
    use crate::provider::{Tpm, TpmHmacS256, TpmMsExtensions, TpmRS256};
    use crate::structures::{
        LoadableHmacS256Key, LoadableRS256Key, LoadableStorageKey, SealedData,
    };
    use crypto_glue::traits::Zeroizing;

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

    #[test]
    fn soft_tpm_msoapxbc() {
        let soft_tpm = SoftTpm::default();

        crate::tests::test_tpm_msoapxbc(soft_tpm);
    }

    #[test]
    fn test_legacy_hmac_load() {
        let _ = tracing_subscriber::fmt::try_init();

        // Test values were extracted from version 0.2.0 for compatibility checking
        let auth_value = AuthValue::from([
            252, 167, 3, 221, 57, 147, 94, 141, 210, 66, 87, 126, 91, 77, 169, 43, 42, 92, 171, 74,
            158, 85, 161, 55, 79, 85, 180, 29, 12, 209, 19, 173,
        ]);

        let loadable_root = LoadableStorageKey::SoftAes256GcmV1 {
            key: Zeroizing::new(
                [
                    17, 66, 23, 95, 209, 206, 86, 81, 44, 2, 50, 137, 40, 130, 156, 39, 118, 200,
                    52, 54, 91, 34, 136, 24, 22, 70, 83, 150, 211, 188, 60, 180,
                ]
                .into(),
            ),
            tag: [
                111, 73, 224, 22, 91, 180, 12, 192, 201, 109, 85, 109, 51, 52, 18, 182,
            ],
            iv: [
                87, 117, 127, 13, 107, 56, 93, 64, 136, 30, 67, 81, 37, 136, 60, 93,
            ],
        };

        let loadable_hmac = LoadableHmacS256Key::SoftSha256V1 {
            key: Zeroizing::new(
                [
                    219, 171, 238, 89, 195, 110, 32, 176, 235, 113, 171, 15, 0, 226, 141, 3, 223,
                    237, 240, 47, 51, 227, 53, 7, 84, 70, 254, 151, 62, 97, 187, 25,
                ]
                .into(),
            ),
            tag: [
                183, 248, 10, 77, 69, 161, 167, 131, 240, 17, 79, 47, 18, 117, 119, 163,
            ],
            iv: [
                195, 77, 79, 140, 167, 246, 59, 58, 76, 15, 75, 70, 121, 254, 54, 114,
            ],
        };

        let expected_hmac = [
            78, 92, 177, 219, 206, 45, 235, 80, 202, 98, 171, 79, 120, 129, 65, 57, 126, 152, 59,
            176, 181, 39, 219, 160, 35, 245, 76, 128, 193, 82, 25, 195,
        ];

        let data = [0, 1, 2, 3];

        // =============================================

        let mut soft_tpm = SoftTpm::default();

        let root_storage = soft_tpm
            .root_storage_key_load(&auth_value, &loadable_root)
            .unwrap();

        let hmac_key = soft_tpm
            .hmac_s256_load(&root_storage, &loadable_hmac)
            .unwrap();

        let calced_hmac = soft_tpm.hmac_s256(&hmac_key, &data).unwrap();

        assert_eq!(calced_hmac.into_bytes().as_slice(), expected_hmac);
    }

    #[test]
    fn test_legacy_storage_load() {
        let _ = tracing_subscriber::fmt::try_init();
    }

    #[test]
    fn test_legacy_ms_oapxbc_load() {
        let _ = tracing_subscriber::fmt::try_init();

        // Test values were extracted from version 0.2.0 for compatibility checking
        let auth_value = AuthValue::from([
            13, 98, 135, 87, 35, 238, 254, 8, 65, 7, 84, 138, 101, 116, 123, 94, 2, 117, 7, 7, 162,
            201, 147, 126, 203, 90, 201, 218, 133, 124, 70, 134,
        ]);

        let loadable_root = LoadableStorageKey::SoftAes256GcmV1 {
            key: Zeroizing::new(
                [
                    55, 158, 111, 36, 38, 198, 93, 157, 81, 235, 4, 61, 240, 164, 119, 203, 38,
                    163, 10, 176, 48, 170, 108, 223, 5, 113, 175, 31, 4, 122, 7, 58,
                ]
                .into(),
            ),
            tag: [
                127, 177, 97, 33, 20, 34, 3, 120, 50, 51, 114, 224, 182, 182, 214, 189,
            ],
            iv: [
                221, 170, 54, 22, 80, 116, 44, 88, 9, 199, 174, 182, 209, 170, 25, 172,
            ],
        };

        let loadable_ms_oapxbc = LoadableRS256Key::Soft2048V1 {
            key: [
                239, 232, 121, 71, 97, 72, 77, 184, 214, 47, 51, 127, 240, 219, 97, 40, 122, 24,
                128, 131, 245, 74, 41, 10, 183, 112, 54, 143, 179, 174, 54, 97, 237, 42, 127, 197,
                214, 186, 46, 107, 98, 60, 18, 40, 85, 96, 210, 174, 234, 91, 44, 3, 88, 113, 145,
                40, 36, 145, 133, 33, 174, 9, 169, 70, 88, 163, 120, 82, 16, 147, 79, 222, 222,
                244, 209, 78, 73, 183, 66, 157, 63, 251, 153, 26, 115, 159, 96, 169, 99, 250, 55,
                75, 226, 199, 5, 137, 141, 53, 118, 36, 127, 61, 42, 9, 130, 65, 175, 112, 9, 227,
                217, 87, 211, 65, 3, 38, 219, 183, 74, 195, 21, 80, 200, 230, 55, 199, 78, 220,
                100, 207, 200, 104, 170, 137, 3, 144, 148, 39, 54, 39, 93, 185, 195, 186, 223, 250,
                117, 106, 204, 50, 217, 54, 112, 201, 197, 219, 228, 196, 110, 27, 183, 89, 126,
                179, 247, 25, 89, 126, 1, 185, 198, 190, 238, 20, 124, 63, 98, 123, 163, 75, 221,
                226, 255, 62, 29, 129, 178, 80, 199, 38, 187, 113, 50, 45, 126, 101, 76, 112, 199,
                189, 172, 98, 101, 227, 171, 92, 66, 229, 20, 133, 37, 120, 162, 40, 176, 29, 114,
                111, 121, 138, 247, 206, 245, 75, 154, 235, 92, 215, 2, 133, 86, 39, 214, 30, 211,
                237, 141, 246, 242, 134, 61, 66, 241, 11, 140, 60, 41, 90, 197, 21, 215, 154, 87,
                139, 219, 70, 122, 178, 216, 25, 49, 140, 88, 107, 93, 105, 175, 169, 212, 245,
                247, 201, 139, 128, 2, 220, 176, 145, 17, 156, 102, 196, 164, 108, 7, 164, 116,
                165, 239, 45, 99, 111, 183, 65, 141, 111, 54, 50, 154, 123, 87, 175, 159, 114, 145,
                26, 29, 35, 105, 147, 188, 22, 189, 34, 199, 58, 235, 227, 71, 86, 122, 114, 47,
                151, 128, 254, 24, 11, 2, 127, 45, 93, 67, 138, 149, 165, 146, 118, 100, 52, 206,
                156, 103, 192, 236, 137, 66, 113, 143, 62, 106, 94, 20, 155, 114, 55, 112, 9, 178,
                107, 248, 122, 250, 40, 56, 109, 253, 160, 79, 232, 223, 198, 147, 148, 133, 123,
                98, 192, 93, 172, 228, 83, 89, 23, 6, 171, 247, 92, 203, 144, 248, 22, 250, 255,
                154, 147, 155, 110, 35, 34, 135, 65, 5, 211, 50, 28, 56, 117, 96, 213, 42, 226, 81,
                239, 140, 205, 112, 180, 236, 255, 46, 162, 88, 204, 245, 157, 122, 5, 242, 236,
                124, 100, 175, 47, 92, 1, 213, 94, 248, 114, 101, 203, 214, 106, 12, 13, 116, 227,
                73, 207, 191, 22, 92, 39, 118, 92, 97, 18, 141, 85, 0, 155, 168, 152, 121, 228,
                253, 44, 13, 188, 210, 147, 89, 209, 122, 225, 126, 19, 38, 46, 51, 200, 247, 253,
                36, 77, 155, 81, 22, 202, 2, 254, 222, 149, 220, 79, 196, 80, 94, 159, 89, 251,
                191, 239, 176, 101, 213, 60, 244, 37, 51, 255, 42, 123, 213, 90, 87, 98, 126, 67,
                241, 240, 19, 140, 12, 193, 11, 65, 24, 132, 152, 14, 68, 8, 66, 192, 71, 107, 152,
                46, 84, 207, 182, 138, 187, 147, 57, 219, 107, 15, 181, 224, 131, 19, 233, 224, 22,
                138, 183, 3, 62, 201, 77, 142, 196, 145, 207, 193, 194, 186, 128, 159, 33, 120,
                146, 20, 126, 175, 31, 213, 103, 102, 93, 239, 169, 67, 182, 18, 94, 70, 143, 214,
                209, 219, 227, 110, 58, 70, 146, 49, 157, 254, 218, 125, 51, 141, 160, 192, 51, 83,
                254, 91, 55, 178, 59, 254, 9, 39, 59, 54, 96, 11, 81, 191, 113, 83, 139, 220, 151,
                125, 218, 0, 156, 195, 234, 29, 28, 99, 50, 163, 162, 7, 209, 79, 79, 90, 2, 188,
                141, 213, 90, 54, 171, 246, 109, 40, 241, 84, 100, 104, 61, 116, 136, 153, 4, 191,
                221, 67, 126, 131, 99, 200, 192, 59, 18, 241, 140, 182, 10, 148, 151, 247, 106,
                186, 156, 86, 28, 109, 7, 70, 55, 111, 241, 93, 239, 24, 244, 109, 245, 44, 188,
                227, 191, 138, 175, 166, 189, 238, 40, 4, 155, 43, 158, 1, 223, 167, 36, 123, 214,
                89, 93, 242, 201, 223, 233, 84, 202, 106, 111, 19, 206, 55, 205, 243, 72, 26, 41,
                255, 244, 178, 214, 207, 81, 26, 182, 210, 234, 177, 55, 13, 153, 154, 232, 200,
                42, 50, 81, 69, 138, 17, 66, 68, 0, 114, 169, 242, 30, 251, 214, 89, 102, 188, 213,
                145, 16, 150, 50, 91, 24, 47, 200, 84, 196, 164, 147, 125, 152, 88, 26, 177, 121,
                113, 231, 25, 198, 193, 229, 176, 25, 133, 144, 8, 218, 115, 118, 174, 187, 103,
                198, 73, 20, 194, 98, 216, 24, 183, 56, 158, 58, 194, 73, 56, 107, 81, 73, 74, 39,
                162, 178, 72, 99, 109, 35, 200, 183, 81, 48, 235, 123, 195, 9, 74, 89, 88, 67, 56,
                102, 225, 147, 98, 118, 62, 169, 125, 136, 42, 183, 204, 137, 229, 249, 43, 247,
                168, 11, 90, 165, 6, 125, 54, 247, 235, 232, 185, 131, 37, 222, 117, 157, 113, 73,
                18, 66, 13, 102, 238, 199, 106, 57, 99, 88, 217, 16, 3, 71, 184, 49, 142, 213, 220,
                31, 37, 105, 31, 150, 148, 209, 116, 224, 141, 255, 217, 241, 83, 23, 233, 83, 99,
                9, 196, 211, 132, 39, 77, 24, 15, 30, 187, 81, 229, 53, 207, 182, 7, 231, 87, 107,
                113, 210, 226, 116, 87, 144, 57, 156, 247, 40, 3, 200, 105, 140, 98, 129, 53, 235,
                107, 46, 119, 118, 154, 75, 203, 184, 117, 247, 28, 68, 102, 181, 193, 144, 67,
                214, 53, 134, 214, 253, 44, 125, 44, 105, 211, 152, 140, 36, 39, 175, 177, 213, 48,
                242, 58, 26, 211, 204, 62, 68, 68, 127, 231, 176, 85, 83, 220, 22, 77, 40, 238,
                120, 55, 163, 144, 92, 164, 204, 85, 136, 151, 227, 140, 217, 63, 177, 240, 206,
                142, 235, 174, 46, 236, 182, 168, 191, 129, 142, 211, 210, 155, 246, 142, 247, 111,
                131, 30, 85, 252, 21, 246, 223, 165, 155, 249, 82, 229, 203, 145, 182, 176, 6, 147,
                69, 3, 32, 164, 246, 174, 16, 233, 197, 247, 185, 251, 54, 164, 7, 85, 241, 226,
                164, 101, 157, 246, 229, 62, 47, 220, 69, 74, 110, 23, 186, 22, 173, 185, 237, 183,
                218, 239, 18, 175, 21, 234, 227, 170, 236, 182, 56, 208, 116, 93, 0, 193, 162, 182,
                125, 191, 30, 100, 118, 124, 230, 168, 18, 124, 20, 201, 143, 56, 206, 74, 158, 45,
                61, 177, 80, 181, 248, 171, 130, 46, 202, 29, 226, 63, 185, 109, 154, 120, 124, 52,
                82, 82, 88, 154, 40, 222, 251, 121, 130, 170, 94, 99, 104, 22, 207, 203, 207, 104,
                99, 187, 150, 9, 201, 232, 38, 66, 222, 96, 187, 175, 41, 153, 41, 244, 181, 12,
                143, 254, 116, 211, 235, 244,
            ]
            .into(),
            tag: [
                137, 28, 64, 241, 54, 24, 241, 121, 63, 180, 250, 192, 19, 232, 248, 111,
            ],
            iv: [
                206, 45, 219, 249, 117, 61, 19, 131, 79, 211, 230, 70, 157, 131, 35, 14,
            ],
            cek: [
                98, 90, 173, 179, 110, 22, 197, 252, 47, 217, 130, 83, 192, 114, 130, 0, 231, 78,
                69, 128, 146, 45, 239, 152, 223, 61, 253, 166, 57, 101, 64, 145, 174, 159, 111, 28,
                183, 62, 136, 95, 114, 35, 205, 224, 218, 54, 237, 73, 210, 21, 164, 27, 136, 117,
                143, 37, 59, 31, 180, 196, 75, 55, 251, 150, 198, 153, 217, 95, 19, 208, 194, 24,
                223, 229, 135, 144, 32, 71, 21, 145, 128, 116, 26, 174, 179, 168, 192, 242, 47,
                190, 172, 155, 95, 230, 236, 60, 136, 115, 182, 185, 186, 248, 171, 203, 78, 99,
                249, 163, 58, 197, 15, 197, 203, 148, 85, 158, 11, 173, 104, 0, 65, 16, 211, 44,
                113, 75, 176, 123, 192, 230, 13, 142, 102, 158, 243, 115, 176, 165, 70, 239, 109,
                236, 154, 96, 123, 206, 164, 1, 182, 205, 241, 94, 195, 50, 23, 160, 106, 188, 191,
                8, 42, 237, 235, 147, 249, 119, 196, 14, 132, 58, 249, 24, 24, 118, 227, 194, 209,
                248, 76, 178, 155, 188, 245, 135, 204, 202, 16, 208, 3, 68, 72, 65, 56, 235, 5, 73,
                53, 161, 0, 224, 196, 176, 223, 154, 107, 122, 63, 68, 58, 185, 198, 171, 220, 171,
                168, 203, 7, 37, 92, 236, 118, 133, 91, 21, 45, 59, 8, 251, 6, 118, 82, 9, 156, 80,
                19, 203, 80, 155, 69, 93, 74, 219, 243, 22, 73, 96, 151, 110, 123, 41, 176, 177,
                167, 181, 76, 65,
            ]
            .into(),
        };

        let public_der = [
            48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15,
            0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 182, 152, 115, 30, 254, 224, 96, 0, 228, 244, 45,
            134, 38, 79, 125, 208, 203, 238, 96, 131, 109, 151, 220, 74, 116, 154, 198, 93, 96,
            255, 52, 86, 121, 149, 7, 79, 91, 140, 90, 251, 142, 45, 54, 189, 18, 180, 4, 51, 99,
            16, 154, 25, 64, 75, 207, 52, 54, 251, 80, 238, 39, 84, 75, 102, 39, 184, 178, 58, 161,
            147, 95, 44, 220, 46, 175, 95, 69, 119, 2, 12, 104, 29, 20, 169, 121, 79, 200, 36, 116,
            70, 88, 124, 74, 20, 217, 122, 96, 77, 40, 108, 74, 169, 81, 215, 210, 93, 129, 119,
            125, 156, 5, 25, 130, 71, 43, 45, 165, 157, 76, 199, 110, 238, 27, 227, 74, 233, 180,
            244, 143, 15, 140, 120, 142, 77, 125, 124, 101, 103, 175, 109, 85, 153, 180, 81, 105,
            227, 230, 108, 161, 178, 210, 80, 10, 188, 132, 222, 111, 120, 235, 53, 176, 236, 218,
            84, 242, 117, 49, 196, 77, 200, 13, 236, 58, 192, 33, 150, 148, 5, 127, 86, 60, 107,
            158, 33, 105, 219, 196, 30, 115, 243, 132, 68, 184, 46, 195, 132, 14, 226, 249, 43,
            156, 141, 211, 176, 112, 29, 33, 60, 188, 75, 50, 51, 249, 111, 160, 156, 77, 234, 49,
            86, 10, 33, 204, 163, 59, 0, 147, 76, 111, 12, 87, 155, 122, 180, 216, 181, 92, 178,
            43, 112, 225, 101, 233, 149, 169, 60, 66, 212, 122, 188, 43, 225, 16, 156, 204, 207, 2,
            3, 1, 0, 1,
        ];

        let enc_secret = [
            80, 148, 198, 31, 249, 254, 16, 176, 60, 183, 149, 10, 90, 99, 207, 183, 107, 168, 44,
            163, 251, 186, 141, 67, 66, 232, 105, 161, 67, 169, 244, 215, 93, 226, 45, 124, 205,
            30, 130, 65, 131, 188, 166, 105, 186, 178, 154, 185, 6, 154, 144, 29, 83, 68, 64, 103,
            93, 86, 14, 8, 97, 50, 249, 209, 46, 237, 217, 179, 86, 45, 48, 69, 186, 1, 126, 161,
            27, 204, 226, 75, 190, 95, 109, 116, 160, 82, 15, 222, 154, 217, 237, 99, 167, 154,
            202, 179, 124, 114, 247, 147, 148, 156, 142, 171, 138, 179, 4, 21, 219, 44, 182, 191,
            154, 173, 204, 17, 7, 133, 94, 12, 207, 137, 80, 112, 123, 207, 153, 2, 169, 96, 194,
            47, 231, 213, 250, 122, 144, 51, 142, 206, 90, 183, 239, 72, 162, 131, 179, 162, 56,
            171, 60, 16, 77, 153, 10, 19, 196, 160, 102, 157, 203, 93, 157, 173, 33, 225, 183, 183,
            160, 40, 108, 37, 207, 78, 94, 11, 180, 207, 231, 76, 129, 213, 153, 184, 198, 216, 48,
            23, 34, 145, 211, 186, 51, 63, 32, 42, 158, 29, 248, 134, 142, 8, 97, 16, 212, 116, 56,
            52, 215, 98, 114, 98, 53, 87, 43, 152, 178, 243, 143, 64, 105, 202, 165, 102, 185, 151,
            120, 31, 95, 97, 56, 59, 41, 205, 174, 189, 79, 149, 22, 231, 219, 181, 221, 9, 17,
            226, 104, 99, 48, 156, 92, 132, 26, 2, 72, 74,
        ];

        let secret = [0, 1, 2, 3];

        let loadable_session_key = SealedData::SoftV1 {
            data: Zeroizing::new([87, 226, 232, 212].into()),
            tag: [
                252, 18, 22, 251, 45, 71, 194, 127, 176, 97, 65, 223, 10, 37, 245, 17,
            ],
            iv: [
                230, 92, 51, 250, 96, 53, 159, 46, 112, 216, 253, 30, 37, 121, 118, 167,
            ],
        };

        // =============================================

        let mut soft_tpm = SoftTpm::default();

        let root_storage = soft_tpm
            .root_storage_key_load(&auth_value, &loadable_root)
            .unwrap();

        let ms_oapxbc_key = soft_tpm
            .rs256_load(&root_storage, &loadable_ms_oapxbc)
            .unwrap();

        let ms_oapxbc_public_der = soft_tpm.rs256_public_der(&ms_oapxbc_key).unwrap();

        assert_eq!(ms_oapxbc_public_der, public_der);

        #[allow(deprecated)]
        let yielded_secret_a = soft_tpm
            .rs256_unseal_data(&ms_oapxbc_key, &loadable_session_key)
            .unwrap();

        assert_eq!(&secret, yielded_secret_a.as_slice());

        let loadable_session_key = soft_tpm
            .msoapxbc_rsa_decipher_session_key(
                &ms_oapxbc_key,
                &root_storage,
                &enc_secret,
                secret.len(),
            )
            .unwrap();

        let yielded_secret_b = soft_tpm
            .unseal_data(&root_storage, &loadable_session_key)
            .unwrap();

        assert_eq!(&secret, yielded_secret_b.as_slice());
    }
}
