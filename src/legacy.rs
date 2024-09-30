use crate::authvalue::AuthValue;
use crate::error::TpmError;
use crate::provider::SoftTpm;
use crate::provider::Tpm;
use crate::structures::{HmacS256Key, LoadableHmacS256Key, StorageKey};
use serde::{Deserialize, Serialize};

use crypto_glue::aes256;
use crypto_glue::aes256gcm::{AeadInPlace, Aes256GcmN16, Aes256GcmNonce16, Aes256GcmTag, KeyInit};
use crypto_glue::hmac_s256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadableMachineKey {
    SoftAes256GcmV1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadableStorageKey {
    SoftAes256GcmV1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadableHmacKey {
    SoftSha256V1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadableMsOapxbcRsaKey {
    Soft2048V1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
        cek: Vec<u8>,
    },
}

#[cfg(feature = "msextensions")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadableMsOapxbcSessionKey {
    SoftV1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
    },
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
}

trait LegacyTpm: Tpm {
    fn machine_key_load(
        &mut self,
        auth_value: &AuthValue,
        exported_key: &LoadableMachineKey,
    ) -> Result<StorageKey, TpmError>;

    fn hmac_key_load(
        &mut self,
        mk: &StorageKey,
        loadable_key: &LoadableHmacKey,
    ) -> Result<HmacS256Key, TpmError>;
}

macro_rules! unwrap_aes256gcm_nonce16 {
    (
        $wrapping_key: expr,
        $key_to_unwrap: expr,
        $tag: expr,
        $nonce: expr
    ) => {{
        let cipher = Aes256GcmN16::new($wrapping_key);

        let mut key = $key_to_unwrap.clone();

        let iv = Aes256GcmNonce16::from_slice($nonce);
        let tag = Aes256GcmTag::from_slice($tag);

        let associated_data = b"";

        cipher
            .decrypt_in_place_detached(iv, associated_data, key.as_mut_slice(), tag)
            .map_err(|_| TpmError::Aes256GcmDecrypt)?;

        if key.as_slice() == $key_to_unwrap.as_slice() {
            // Encryption didn't replace the buffer in place, fail.
            return Err(TpmError::Aes256GcmDecrypt);
        }

        Ok(key)
    }};
}

impl LegacyTpm for SoftTpm {
    fn machine_key_load(
        &mut self,
        auth_value: &AuthValue,
        exported_key: &LoadableMachineKey,
    ) -> Result<StorageKey, TpmError> {
        match (auth_value, exported_key) {
            (
                AuthValue::Key256Bit { auth_key },
                LoadableMachineKey::SoftAes256GcmV1 {
                    key: key_to_unwrap,
                    tag,
                    iv,
                },
            ) => {
                let key = aes256::key_from_vec(key_to_unwrap.clone())
                    .ok_or(TpmError::Aes256KeyInvalid)?;

                unwrap_aes256gcm_nonce16!(auth_key, key, tag, iv)
                    .map(|key| StorageKey::SoftAes256GcmV2 { key })
            }
        }
    }

    fn hmac_key_load(
        &mut self,
        parent_key: &StorageKey,
        hmac_key: &LoadableHmacKey,
    ) -> Result<HmacS256Key, TpmError> {
        match (parent_key, hmac_key) {
            (
                StorageKey::SoftAes256GcmV2 { key: parent_key },
                LoadableHmacKey::SoftSha256V1 {
                    key: key_to_unwrap,
                    tag,
                    iv,
                },
            ) => {
                tracing::trace!(key_size = %hmac_s256::key_size());
                tracing::trace!(new_key_size = %key_to_unwrap.len());

                let key = unwrap_aes256gcm_nonce16!(parent_key, key_to_unwrap, tag, iv)?;

                let mut empty_key: [u8; 64] = [0; 64];

                empty_key
                    .get_mut(..32)
                    .map(|view| view.copy_from_slice(&key));

                let empty_key = hmac_s256::key_from_bytes(empty_key);

                Ok(HmacS256Key::SoftAes256GcmV2 { key: empty_key })
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::authvalue::AuthValue;
    use crate::legacy::LegacyTpm;
    use crate::legacy::{LoadableHmacKey, LoadableMachineKey};
    use crate::provider::{SoftTpm, TpmHmacS256};

    use crypto_glue::aes256::{self, Aes256Key};
    use crypto_glue::aes256gcm::Aes256Gcm;

    #[test]
    fn test_legacy_hmac_load() {
        let _ = tracing_subscriber::fmt::try_init();

        let auth_value = AuthValue::from([
            252, 167, 3, 221, 57, 147, 94, 141, 210, 66, 87, 126, 91, 77, 169, 43, 42, 92, 171, 74,
            158, 85, 161, 55, 79, 85, 180, 29, 12, 209, 19, 173,
        ]);

        let loadable_root = LoadableMachineKey::SoftAes256GcmV1 {
            key: [
                17, 66, 23, 95, 209, 206, 86, 81, 44, 2, 50, 137, 40, 130, 156, 39, 118, 200, 52,
                54, 91, 34, 136, 24, 22, 70, 83, 150, 211, 188, 60, 180,
            ]
            .into(),
            tag: [
                111, 73, 224, 22, 91, 180, 12, 192, 201, 109, 85, 109, 51, 52, 18, 182,
            ]
            .into(),
            iv: [
                87, 117, 127, 13, 107, 56, 93, 64, 136, 30, 67, 81, 37, 136, 60, 93,
            ]
            .into(),
        };

        let loadable_hmac = LoadableHmacKey::SoftSha256V1 {
            key: [
                219, 171, 238, 89, 195, 110, 32, 176, 235, 113, 171, 15, 0, 226, 141, 3, 223, 237,
                240, 47, 51, 227, 53, 7, 84, 70, 254, 151, 62, 97, 187, 25,
            ]
            .into(),
            tag: [
                183, 248, 10, 77, 69, 161, 167, 131, 240, 17, 79, 47, 18, 117, 119, 163,
            ]
            .into(),
            iv: [
                195, 77, 79, 140, 167, 246, 59, 58, 76, 15, 75, 70, 121, 254, 54, 114,
            ]
            .into(),
        };

        let expected_hmac = [
            78, 92, 177, 219, 206, 45, 235, 80, 202, 98, 171, 79, 120, 129, 65, 57, 126, 152, 59,
            176, 181, 39, 219, 160, 35, 245, 76, 128, 193, 82, 25, 195,
        ];

        let data = [0, 1, 2, 3];

        let mut soft_tpm = SoftTpm::default();

        let root_storage = soft_tpm
            .machine_key_load(&auth_value, &loadable_root)
            .unwrap();

        let hmac_key = soft_tpm
            .hmac_key_load(&root_storage, &loadable_hmac)
            .unwrap();

        let calced_hmac = soft_tpm.hmac_s256(&hmac_key, &data).unwrap();

        assert_eq!(calced_hmac.into_bytes().as_slice(), expected_hmac);
    }
}
