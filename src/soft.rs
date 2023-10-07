use crate::{Hsm, HsmError};

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rand::rand_bytes;
use openssl::sign::Signer;
use openssl::symm::{Cipher, Crypter, Mode};

use serde::{Deserialize, Serialize};
use tracing::trace;

#[derive(Default)]
pub struct SoftHsm {}

impl Drop for SoftHsm {
    fn drop(&mut self) {
        // TODO: cleanup tasks, maybe? clippy had a sad about us using drop.
    }
}

impl SoftHsm {
    pub fn new() -> Self {
        Self::default()
    }
}

pub enum SoftMachineKey {
    Aes256Gcm { key: [u8; 32] },
}

impl Drop for SoftMachineKey {
    fn drop(&mut self) {
        // TODO: cleanup tasks, maybe? clippy had a sad about us using drop.
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SoftLoadableMachineKey {
    Aes256GcmV1 { key: [u8; 32] },
}

pub enum SoftHmacKey {
    Sha256 { pkey: PKey<Private> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SoftLoadableHmacKey {
    Sha256V1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
    },
}

impl Hsm for SoftHsm {
    type MachineKey = SoftMachineKey;
    type LoadableMachineKey = SoftLoadableMachineKey;

    type HmacKey = SoftHmacKey;
    type LoadableHmacKey = SoftLoadableHmacKey;

    fn machine_key_create(&mut self) -> Result<Self::LoadableMachineKey, HsmError> {
        // Create a "machine binding" key.
        let mut buf = [0; 32];
        rand_bytes(&mut buf).map_err(|ossl_err| {
            trace!(?ossl_err);
            HsmError::Entropy
        })?;

        Ok(SoftLoadableMachineKey::Aes256GcmV1 { key: buf })
    }

    fn machine_key_load(
        &mut self,
        loadable_key: &Self::LoadableMachineKey,
    ) -> Result<Self::MachineKey, HsmError> {
        match loadable_key {
            SoftLoadableMachineKey::Aes256GcmV1 { key } => {
                Ok(SoftMachineKey::Aes256Gcm { key: *key })
            }
        }
    }

    fn hmac_key_create(
        &mut self,
        mk: &Self::MachineKey,
    ) -> Result<Self::LoadableHmacKey, HsmError> {
        let mut buf = [0; 32];
        rand_bytes(&mut buf).map_err(|ossl_err| {
            trace!(?ossl_err);
            HsmError::Entropy
        })?;

        let mut iv = [0; 16];
        rand_bytes(&mut iv).map_err(|ossl_err| {
            trace!(?ossl_err);
            HsmError::Entropy
        })?;

        let (key, tag) = match mk {
            SoftMachineKey::Aes256Gcm { key } => aes_256_gcm_encrypt(&buf, key, &iv)?,
        };

        Ok(SoftLoadableHmacKey::Sha256V1 { key, tag, iv })
    }

    fn hmac_key_load(
        &mut self,
        mk: &Self::MachineKey,
        loadable_key: &Self::LoadableHmacKey,
    ) -> Result<Self::HmacKey, HsmError> {
        match (mk, loadable_key) {
            (
                SoftMachineKey::Aes256Gcm { key: mk_key },
                SoftLoadableHmacKey::Sha256V1 { key, tag, iv },
            ) => {
                let raw_key = aes_256_gcm_decrypt(key, tag, mk_key, iv)?;

                let pkey = PKey::hmac(&raw_key).map_err(|ossl_err| {
                    trace!(?ossl_err);
                    HsmError::HmacKey
                })?;

                Ok(SoftHmacKey::Sha256 { pkey })
            }
        }
    }

    fn hmac(&mut self, hk: &Self::HmacKey, input: &[u8]) -> Result<Vec<u8>, HsmError> {
        match hk {
            SoftHmacKey::Sha256 { pkey } => {
                let mut signer =
                    Signer::new(MessageDigest::sha256(), pkey).map_err(|ossl_err| {
                        trace!(?ossl_err);
                        HsmError::HmacKey
                    })?;

                signer.update(input).map_err(|ossl_err| {
                    trace!(?ossl_err);
                    HsmError::HmacSign
                })?;

                signer.sign_to_vec().map_err(|ossl_err| {
                    trace!(?ossl_err);
                    HsmError::HmacSign
                })
            }
        }
    }
}

fn aes_256_gcm_encrypt(
    input: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), HsmError> {
    let cipher = Cipher::aes_256_gcm();

    let block_size = cipher.block_size();
    let mut ciphertext = vec![0; input.len() + block_size];

    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv)).map_err(|ossl_err| {
        trace!(?ossl_err);
        HsmError::Aes256GcmConfig
    })?;

    // Enable padding.
    encrypter.pad(true);

    let mut count = encrypter
        .update(input, &mut ciphertext)
        .map_err(|ossl_err| {
            trace!(?ossl_err);
            HsmError::Aes256GcmEncrypt
        })?;
    count += encrypter.finalize(&mut ciphertext).map_err(|ossl_err| {
        trace!(?ossl_err);
        HsmError::Aes256GcmEncrypt
    })?;
    ciphertext.truncate(count);

    let mut tag = [0; 16];
    encrypter.get_tag(&mut tag).map_err(|ossl_err| {
        trace!(?ossl_err);
        HsmError::Aes256GcmEncrypt
    })?;

    Ok((ciphertext, tag))
}

fn aes_256_gcm_decrypt(
    input: &[u8],
    tag: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, HsmError> {
    let cipher = Cipher::aes_256_gcm();

    let block_size = cipher.block_size();
    let mut plaintext = vec![0; input.len() + block_size];

    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv)).map_err(|ossl_err| {
        trace!(?ossl_err);
        HsmError::Aes256GcmConfig
    })?;

    decrypter.pad(true);
    decrypter.set_tag(tag).map_err(|ossl_err| {
        trace!(?ossl_err);
        HsmError::Aes256GcmConfig
    })?;

    let mut count = decrypter
        .update(input, &mut plaintext)
        .map_err(|ossl_err| {
            trace!(?ossl_err);
            HsmError::Aes256GcmDecrypt
        })?;

    count += decrypter.finalize(&mut plaintext).map_err(|ossl_err| {
        trace!(?ossl_err);
        HsmError::Aes256GcmDecrypt
    })?;

    plaintext.truncate(count);

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::{aes_256_gcm_decrypt, aes_256_gcm_encrypt, SoftHsm};
    use crate::Hsm;
    use tracing::trace;

    #[test]
    fn aes_256_gcm_enc_dec() {
        let _ = tracing_subscriber::fmt::try_init();

        let input = [0, 1, 2, 3];
        let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
        let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";
        #[allow(clippy::expect_used)]
        let (enc, tag) = aes_256_gcm_encrypt(&input, key, iv).expect("Unable to encrypt");

        trace!(?enc, ?tag, key_len = key.len());
        #[allow(clippy::expect_used)]
        let output = aes_256_gcm_decrypt(&enc, &tag, key, iv).expect("Unable to decrypt");

        assert_eq!(&input, output.as_slice());
    }

    #[test]
    fn soft_hmac_hw_bound() {
        let _ = tracing_subscriber::fmt::try_init();
        // Create the Hsm.
        let mut hsm = SoftHsm::new();

        // Request a new machine-key-context. This key "owns" anything
        // created underneath it.
        let loadable_machine_key = hsm
            .machine_key_create()
            .expect("Unable to create new machine key");

        trace!(?loadable_machine_key);

        let machine_key = hsm
            .machine_key_load(&loadable_machine_key)
            .expect("Unable to load machine key");

        // from that ctx, create a hmac key.
        let loadable_hmac_key = hsm
            .hmac_key_create(&machine_key)
            .expect("Unable to create new hmac key");

        trace!(?loadable_hmac_key);

        let hmac_key = hsm
            .hmac_key_load(&machine_key, &loadable_hmac_key)
            .expect("Unable to load hmac key");

        // do a hmac.
        let output_1 = hsm
            .hmac(&hmac_key, &[0, 1, 2, 3])
            .expect("Unable to perform hmac");

        // destroy the Hsm
        drop(hmac_key);
        drop(machine_key);
        drop(hsm);

        // Make a new Hsm context.
        let mut hsm = SoftHsm::new();

        // Load the contexts.
        let machine_key = hsm
            .machine_key_load(&loadable_machine_key)
            .expect("Unable to load machine key");

        // Load the keys.
        let hmac_key = hsm
            .hmac_key_load(&machine_key, &loadable_hmac_key)
            .expect("Unable to load hmac key");

        // Do another hmac
        let output_2 = hsm
            .hmac(&hmac_key, &[0, 1, 2, 3])
            .expect("Unable to perform hmac");

        // It should be the same.
        assert_eq!(output_1, output_2);
    }
}
