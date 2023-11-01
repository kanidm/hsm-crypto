use crate::{
    AuthValue, HmacKey, Hsm, HsmError, HsmIdentity, KeyAlgorithm, LoadableHmacKey,
    LoadableMachineKey, MachineKey,
};
use zeroize::Zeroizing;

use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rand::rand_bytes;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::x509::{X509NameBuilder, X509ReqBuilder, X509};

use serde::{Deserialize, Serialize};
use tracing::error;

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
    Aes256Gcm { key: Zeroizing<Vec<u8>> },
}

impl Drop for SoftMachineKey {
    fn drop(&mut self) {
        // TODO: cleanup tasks, maybe? clippy had a sad about us using drop.
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SoftLoadableMachineKey {
    Aes256GcmV1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
    },
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

pub enum SoftIdentityKey {
    Rsa2048 {
        pkey: PKey<Private>,
        x509: Option<X509>,
    },
    Ecdsa256 {
        pkey: PKey<Private>,
        x509: Option<X509>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SoftLoadableIdentityKey {
    Rsa2048V1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
        x509: Option<Vec<u8>>,
    },
    Ecdsa256V1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
        x509: Option<Vec<u8>>,
    },
}

impl Hsm for SoftHsm {
    fn machine_key_create(
        &mut self,
        auth_value: &AuthValue,
    ) -> Result<LoadableMachineKey, HsmError> {
        // Create a "machine binding" key.
        let mut buf = Zeroizing::new([0; 32]);
        rand_bytes(buf.as_mut()).map_err(|ossl_err| {
            error!(?ossl_err);
            HsmError::Entropy
        })?;

        // Encrypt it.
        let mut iv = [0; 16];
        rand_bytes(&mut iv).map_err(|ossl_err| {
            error!(?ossl_err);
            HsmError::Entropy
        })?;

        let (key, tag) = match auth_value {
            AuthValue::Key256Bit { auth_key } => {
                aes_256_gcm_encrypt(buf.as_ref(), auth_key.as_ref(), &iv)?
            }
        };

        Ok(LoadableMachineKey::Soft(
            SoftLoadableMachineKey::Aes256GcmV1 { key, tag, iv },
        ))
    }

    fn machine_key_load(
        &mut self,
        auth_value: &AuthValue,
        loadable_key: &LoadableMachineKey,
    ) -> Result<MachineKey, HsmError> {
        match loadable_key {
            LoadableMachineKey::Soft(SoftLoadableMachineKey::Aes256GcmV1 { key, tag, iv }) => {
                let raw_key = match auth_value {
                    AuthValue::Key256Bit { auth_key } => {
                        aes_256_gcm_decrypt(key, tag, auth_key.as_ref(), iv)?
                    }
                };
                Ok(MachineKey::Soft(SoftMachineKey::Aes256Gcm { key: raw_key }))
            }
            LoadableMachineKey::Tpm(_) => Err(HsmError::IncorrectKeyType),
        }
    }

    fn hmac_key_create(&mut self, mk: &MachineKey) -> Result<LoadableHmacKey, HsmError> {
        let mut buf = Zeroizing::new([0; 32]);
        rand_bytes(buf.as_mut()).map_err(|ossl_err| {
            error!(?ossl_err);
            HsmError::Entropy
        })?;

        let mut iv = [0; 16];
        rand_bytes(&mut iv).map_err(|ossl_err| {
            error!(?ossl_err);
            HsmError::Entropy
        })?;

        let (key, tag) = match mk {
            MachineKey::Soft(SoftMachineKey::Aes256Gcm { key }) => {
                aes_256_gcm_encrypt(buf.as_ref(), key.as_ref(), &iv)?
            }
            MachineKey::Tpm(_) => return Err(HsmError::IncorrectKeyType),
        };

        Ok(LoadableHmacKey::Soft(SoftLoadableHmacKey::Sha256V1 {
            key,
            tag,
            iv,
        }))
    }

    fn hmac_key_load(
        &mut self,
        mk: &MachineKey,
        loadable_key: &LoadableHmacKey,
    ) -> Result<HmacKey, HsmError> {
        match (mk, loadable_key) {
            (
                MachineKey::Soft(SoftMachineKey::Aes256Gcm { key: mk_key }),
                LoadableHmacKey::Soft(SoftLoadableHmacKey::Sha256V1 { key, tag, iv }),
            ) => {
                let raw_key = aes_256_gcm_decrypt(key, tag, mk_key.as_ref(), iv)?;

                let pkey = PKey::hmac(raw_key.as_ref()).map_err(|ossl_err| {
                    error!(?ossl_err);
                    HsmError::HmacKey
                })?;

                Ok(HmacKey::Soft(SoftHmacKey::Sha256 { pkey }))
            }
            (_, _) => Err(HsmError::IncorrectKeyType),
        }
    }

    fn hmac(&mut self, hk: &HmacKey, input: &[u8]) -> Result<Vec<u8>, HsmError> {
        match hk {
            HmacKey::Soft(SoftHmacKey::Sha256 { pkey }) => {
                let mut signer =
                    Signer::new(MessageDigest::sha256(), pkey).map_err(|ossl_err| {
                        error!(?ossl_err);
                        HsmError::HmacKey
                    })?;

                signer.update(input).map_err(|ossl_err| {
                    error!(?ossl_err);
                    HsmError::HmacSign
                })?;

                signer.sign_to_vec().map_err(|ossl_err| {
                    error!(?ossl_err);
                    HsmError::HmacSign
                })
            }
            HmacKey::Tpm(_) => Err(HsmError::IncorrectKeyType),
        }
    }
}

impl HsmIdentity for SoftHsm {
    type IdentityKey = SoftIdentityKey;
    type LoadableIdentityKey = SoftLoadableIdentityKey;

    fn identity_key_create(
        &mut self,
        mk: &MachineKey,
        algorithm: KeyAlgorithm,
    ) -> Result<Self::LoadableIdentityKey, HsmError> {
        match algorithm {
            KeyAlgorithm::Ecdsa256 => {
                let ecgroup =
                    EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|ossl_err| {
                        error!(?ossl_err);
                        HsmError::EcGroup
                    })?;

                let eckey = EcKey::generate(&ecgroup).map_err(|ossl_err| {
                    error!(?ossl_err);
                    HsmError::EcKeyGenerate
                })?;

                let der = eckey
                    .private_key_to_der()
                    .map(Zeroizing::new)
                    .map_err(|ossl_err| {
                        error!(?ossl_err);
                        HsmError::EcKeyPrivateToDer
                    })?;

                let mut iv = [0; 16];
                rand_bytes(&mut iv).map_err(|ossl_err| {
                    error!(?ossl_err);
                    HsmError::Entropy
                })?;

                let (key, tag) = match mk {
                    MachineKey::Soft(SoftMachineKey::Aes256Gcm { key }) => {
                        aes_256_gcm_encrypt(der.as_ref(), key.as_ref(), &iv)?
                    }
                    MachineKey::Tpm(_) => return Err(HsmError::IncorrectKeyType),
                };

                let x509 = None;

                Ok(SoftLoadableIdentityKey::Ecdsa256V1 { key, tag, iv, x509 })
            }
            KeyAlgorithm::Rsa2048 => {
                let rsa = Rsa::generate(2048).map_err(|ossl_err| {
                    error!(?ossl_err);
                    HsmError::RsaGenerate
                })?;

                let der = rsa
                    .private_key_to_der()
                    .map(Zeroizing::new)
                    .map_err(|ossl_err| {
                        error!(?ossl_err);
                        HsmError::RsaPrivateToDer
                    })?;

                let mut iv = [0; 16];
                rand_bytes(&mut iv).map_err(|ossl_err| {
                    error!(?ossl_err);
                    HsmError::Entropy
                })?;

                let (key, tag) = match mk {
                    MachineKey::Soft(SoftMachineKey::Aes256Gcm { key }) => {
                        aes_256_gcm_encrypt(der.as_ref(), key.as_ref(), &iv)?
                    }
                    MachineKey::Tpm(_) => return Err(HsmError::IncorrectKeyType),
                };

                let x509 = None;

                Ok(SoftLoadableIdentityKey::Rsa2048V1 { key, tag, iv, x509 })
            }
        }
    }

    fn identity_key_load(
        &mut self,
        mk: &MachineKey,
        loadable_key: &Self::LoadableIdentityKey,
    ) -> Result<Self::IdentityKey, HsmError> {
        match (mk, loadable_key) {
            (
                MachineKey::Soft(SoftMachineKey::Aes256Gcm { key: mk_key }),
                SoftLoadableIdentityKey::Ecdsa256V1 { key, tag, iv, x509 },
            ) => {
                let key_der = aes_256_gcm_decrypt(key, tag, mk_key.as_ref(), iv)?;

                let eckey = EcKey::private_key_from_der(key_der.as_ref()).map_err(|ossl_err| {
                    error!(?ossl_err);
                    HsmError::EcKeyFromDer
                })?;

                let pkey = PKey::from_ec_key(eckey).map_err(|ossl_err| {
                    error!(?ossl_err);
                    HsmError::EcKeyToPrivateKey
                })?;

                let x509 = match x509 {
                    Some(der) => {
                        let x509 = X509::from_der(der).map_err(|ossl_err| {
                            error!(?ossl_err);
                            HsmError::X509FromDer
                        })?;

                        let x509_pkey = x509.public_key().map_err(|ossl_err| {
                            error!(?ossl_err);
                            HsmError::X509PublicKey
                        })?;

                        if !pkey.public_eq(&x509_pkey) {
                            return Err(HsmError::X509KeyMismatch);
                        }

                        Some(x509)
                    }
                    None => None,
                };

                Ok(SoftIdentityKey::Ecdsa256 { pkey, x509 })
            }
            (
                MachineKey::Soft(SoftMachineKey::Aes256Gcm { key: mk_key }),
                SoftLoadableIdentityKey::Rsa2048V1 { key, tag, iv, x509 },
            ) => {
                let key_der = aes_256_gcm_decrypt(key, tag, mk_key.as_ref(), iv)?;

                let eckey = Rsa::private_key_from_der(key_der.as_ref()).map_err(|ossl_err| {
                    error!(?ossl_err);
                    HsmError::RsaKeyFromDer
                })?;

                let pkey = PKey::from_rsa(eckey).map_err(|ossl_err| {
                    error!(?ossl_err);
                    HsmError::RsaToPrivateKey
                })?;

                let x509 = match x509 {
                    Some(der) => {
                        let x509 = X509::from_der(der).map_err(|ossl_err| {
                            error!(?ossl_err);
                            HsmError::X509FromDer
                        })?;

                        let x509_pkey = x509.public_key().map_err(|ossl_err| {
                            error!(?ossl_err);
                            HsmError::X509PublicKey
                        })?;

                        if !pkey.public_eq(&x509_pkey) {
                            return Err(HsmError::X509KeyMismatch);
                        }

                        Some(x509)
                    }
                    None => None,
                };

                Ok(SoftIdentityKey::Rsa2048 { pkey, x509 })
            }
            (_, _) => Err(HsmError::IncorrectKeyType),
        }
    }

    fn identity_key_public_as_der(&mut self, key: &Self::IdentityKey) -> Result<Vec<u8>, HsmError> {
        match key {
            SoftIdentityKey::Ecdsa256 { pkey, x509: _ }
            | SoftIdentityKey::Rsa2048 { pkey, x509: _ } => {
                pkey.public_key_to_der().map_err(|ossl_err| {
                    error!(?ossl_err);
                    HsmError::IdentityKeyPublicToDer
                })
            }
        }
    }

    fn identity_key_public_as_pem(&mut self, key: &Self::IdentityKey) -> Result<Vec<u8>, HsmError> {
        match key {
            SoftIdentityKey::Ecdsa256 { pkey, x509: _ }
            | SoftIdentityKey::Rsa2048 { pkey, x509: _ } => {
                pkey.public_key_to_pem().map_err(|ossl_err| {
                    error!(?ossl_err);
                    HsmError::IdentityKeyPublicToPem
                })
            }
        }
    }

    fn identity_key_x509_as_pem(&mut self, key: &Self::IdentityKey) -> Result<Vec<u8>, HsmError> {
        match key {
            SoftIdentityKey::Ecdsa256 {
                pkey: _,
                x509: Some(x509),
            }
            | SoftIdentityKey::Rsa2048 {
                pkey: _,
                x509: Some(x509),
            } => x509.to_pem().map_err(|ossl_err| {
                error!(?ossl_err);
                HsmError::IdentityKeyX509ToPem
            }),
            _ => Err(HsmError::IdentityKeyX509Missing),
        }
    }

    fn identity_key_x509_as_der(&mut self, key: &Self::IdentityKey) -> Result<Vec<u8>, HsmError> {
        match key {
            SoftIdentityKey::Ecdsa256 {
                pkey: _,
                x509: Some(x509),
            }
            | SoftIdentityKey::Rsa2048 {
                pkey: _,
                x509: Some(x509),
            } => x509.to_der().map_err(|ossl_err| {
                error!(?ossl_err);
                HsmError::IdentityKeyX509ToDer
            }),
            _ => Err(HsmError::IdentityKeyX509Missing),
        }
    }

    fn identity_key_sign(
        &mut self,
        key: &Self::IdentityKey,
        input: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        let mut signer = match key {
            SoftIdentityKey::Ecdsa256 { pkey, x509: _ }
            | SoftIdentityKey::Rsa2048 { pkey, x509: _ } => {
                Signer::new(MessageDigest::sha256(), pkey).map_err(|ossl_err| {
                    error!(?ossl_err);
                    HsmError::IdentityKeyInvalidForSigning
                })?
            }
        };

        signer.sign_oneshot_to_vec(input).map_err(|ossl_err| {
            error!(?ossl_err);
            HsmError::IdentityKeySignature
        })
    }

    fn identity_key_certificate_request(
        &mut self,
        mk: &MachineKey,
        loadable_key: &Self::LoadableIdentityKey,
        cn: &str,
    ) -> Result<Vec<u8>, HsmError> {
        let id_key = self.identity_key_load(mk, loadable_key)?;

        let mut req_builder = X509ReqBuilder::new().map_err(|ossl_err| {
            error!(?ossl_err);
            HsmError::X509RequestBuilder
        })?;

        let mut x509_name = X509NameBuilder::new().map_err(|ossl_err| {
            error!(?ossl_err);
            HsmError::X509NameBuilder
        })?;

        x509_name
            .append_entry_by_text("CN", cn)
            .map_err(|ossl_err| {
                error!(?ossl_err);
                HsmError::X509NameAppend
            })?;

        let x509_name = x509_name.build();
        req_builder
            .set_subject_name(&x509_name)
            .map_err(|ossl_err| {
                error!(?ossl_err);
                HsmError::X509RequestSubjectName
            })?;

        match id_key {
            SoftIdentityKey::Ecdsa256 { pkey, x509: _ }
            | SoftIdentityKey::Rsa2048 { pkey, x509: _ } => {
                req_builder.set_pubkey(&pkey).map_err(|ossl_err| {
                    error!(?ossl_err);
                    HsmError::X509RequestSetPublic
                })?;

                req_builder
                    .sign(&pkey, MessageDigest::sha256())
                    .map_err(|ossl_err| {
                        error!(?ossl_err);
                        HsmError::X509RequestSign
                    })?;
            }
        }

        req_builder.build().to_der().map_err(|ossl_err| {
            error!(?ossl_err);
            HsmError::X509RequestToDer
        })
    }

    fn identity_key_associate_certificate(
        &mut self,
        mk: &MachineKey,
        loadable_key: &Self::LoadableIdentityKey,
        certificate_der: &[u8],
    ) -> Result<Self::LoadableIdentityKey, HsmError> {
        let id_key = self.identity_key_load(mk, loadable_key)?;

        // Verify the certificate matches our key
        let certificate = X509::from_der(certificate_der).map_err(|ossl_err| {
            error!(?ossl_err);
            HsmError::X509FromDer
        })?;

        let certificate_pkey = certificate.public_key().map_err(|ossl_err| {
            error!(?ossl_err);
            HsmError::X509PublicKey
        })?;

        match id_key {
            SoftIdentityKey::Ecdsa256 { pkey, x509: _ }
            | SoftIdentityKey::Rsa2048 { pkey, x509: _ } => {
                if !pkey.public_eq(&certificate_pkey) {
                    return Err(HsmError::X509KeyMismatch);
                }
            }
        };

        // At this point we know the cert belongs to this key, so lets
        // get it bound.

        let mut cloned_key = loadable_key.clone();

        match &mut cloned_key {
            SoftLoadableIdentityKey::Ecdsa256V1 { ref mut x509, .. } => {
                *x509 = Some(certificate_der.to_vec());
            }
            SoftLoadableIdentityKey::Rsa2048V1 { ref mut x509, .. } => {
                *x509 = Some(certificate_der.to_vec());
            }
        };

        Ok(cloned_key)
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
        error!(?ossl_err);
        HsmError::Aes256GcmConfig
    })?;

    // Enable padding.
    encrypter.pad(true);

    let mut count = encrypter
        .update(input, &mut ciphertext)
        .map_err(|ossl_err| {
            error!(?ossl_err);
            HsmError::Aes256GcmEncrypt
        })?;
    count += encrypter.finalize(&mut ciphertext).map_err(|ossl_err| {
        error!(?ossl_err);
        HsmError::Aes256GcmEncrypt
    })?;
    ciphertext.truncate(count);

    let mut tag = [0; 16];
    encrypter.get_tag(&mut tag).map_err(|ossl_err| {
        error!(?ossl_err);
        HsmError::Aes256GcmEncrypt
    })?;

    Ok((ciphertext, tag))
}

fn aes_256_gcm_decrypt(
    input: &[u8],
    tag: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Zeroizing<Vec<u8>>, HsmError> {
    let cipher = Cipher::aes_256_gcm();

    let block_size = cipher.block_size();
    let mut plaintext = Zeroizing::new(vec![0; input.len() + block_size]);

    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv)).map_err(|ossl_err| {
        error!(?ossl_err);
        HsmError::Aes256GcmConfig
    })?;

    decrypter.pad(true);
    decrypter.set_tag(tag).map_err(|ossl_err| {
        error!(?ossl_err);
        HsmError::Aes256GcmConfig
    })?;

    let mut count = decrypter
        .update(input, &mut plaintext)
        .map_err(|ossl_err| {
            error!(?ossl_err);
            HsmError::Aes256GcmDecrypt
        })?;

    count += decrypter.finalize(&mut plaintext).map_err(|ossl_err| {
        error!(?ossl_err);
        HsmError::Aes256GcmDecrypt
    })?;

    plaintext.truncate(count);

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::{aes_256_gcm_decrypt, aes_256_gcm_encrypt, KeyAlgorithm, SoftHsm};
    use crate::{AuthValue, Hsm, HsmIdentity};
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::sign::Verifier;
    use openssl::x509::extension::{
        BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier,
    };
    use openssl::x509::{X509NameBuilder, X509Req, X509};
    use std::str::FromStr;
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

        let auth_value =
            AuthValue::from_str("Ohquiech9jis7Poo8Di7eth3").expect("Unable to create auth value");

        // Request a new machine-key-context. This key "owns" anything
        // created underneath it.
        let loadable_machine_key = hsm
            .machine_key_create(&auth_value)
            .expect("Unable to create new machine key");

        trace!(?loadable_machine_key);

        let machine_key = hsm
            .machine_key_load(&auth_value, &loadable_machine_key)
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
            .machine_key_load(&auth_value, &loadable_machine_key)
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

    #[test]
    fn soft_identity_ecdsa256_hw_bound() {
        let _ = tracing_subscriber::fmt::try_init();
        // Create the Hsm.
        let mut hsm = SoftHsm::new();

        let auth_value =
            AuthValue::from_str("Ohquiech9jis7Poo8Di7eth3").expect("Unable to create auth value");

        // Request a new machine-key-context. This key "owns" anything
        // created underneath it.
        let loadable_machine_key = hsm
            .machine_key_create(&auth_value)
            .expect("Unable to create new machine key");

        trace!(?loadable_machine_key);

        let machine_key = hsm
            .machine_key_load(&auth_value, &loadable_machine_key)
            .expect("Unable to load machine key");

        // from that ctx, create an identity key
        let loadable_id_key = hsm
            .identity_key_create(&machine_key, KeyAlgorithm::Ecdsa256)
            .expect("Unable to create id key");

        trace!(?loadable_id_key);

        let id_key = hsm
            .identity_key_load(&machine_key, &loadable_id_key)
            .expect("Unable to load id key");

        let id_key_public_pem = hsm
            .identity_key_public_as_pem(&id_key)
            .expect("Unable to get id key public pem");

        let pem_str = String::from_utf8_lossy(&id_key_public_pem);
        trace!(?pem_str);

        let id_key_public_der = hsm
            .identity_key_public_as_der(&id_key)
            .expect("Unable to get id key public pem");

        // Rehydrate the der to a public key.

        let public_key = PKey::public_key_from_der(&id_key_public_der).expect("Invalid DER");

        let input = "test string";
        let signature = hsm
            .identity_key_sign(&id_key, input.as_bytes())
            .expect("Unable to sign input");

        let mut verifier =
            Verifier::new(MessageDigest::sha256(), &public_key).expect("Unable to setup verifier.");

        let valid = verifier
            .verify_oneshot(&signature, input.as_bytes())
            .expect("Unable to validate signature");

        assert!(valid);
    }

    #[test]
    fn soft_identity_rsa2048_hw_bound() {
        let _ = tracing_subscriber::fmt::try_init();
        // Create the Hsm.
        let mut hsm = SoftHsm::new();

        let auth_value =
            AuthValue::from_str("Ohquiech9jis7Poo8Di7eth3").expect("Unable to create auth value");

        // Request a new machine-key-context. This key "owns" anything
        // created underneath it.
        let loadable_machine_key = hsm
            .machine_key_create(&auth_value)
            .expect("Unable to create new machine key");

        trace!(?loadable_machine_key);

        let machine_key = hsm
            .machine_key_load(&auth_value, &loadable_machine_key)
            .expect("Unable to load machine key");

        // from that ctx, create an identity key
        let loadable_id_key = hsm
            .identity_key_create(&machine_key, KeyAlgorithm::Rsa2048)
            .expect("Unable to create id key");

        trace!(?loadable_id_key);

        let id_key = hsm
            .identity_key_load(&machine_key, &loadable_id_key)
            .expect("Unable to load id key");

        let id_key_public_pem = hsm
            .identity_key_public_as_pem(&id_key)
            .expect("Unable to get id key public pem");

        let pem_str = String::from_utf8_lossy(&id_key_public_pem);
        trace!(?pem_str);

        let id_key_public_der = hsm
            .identity_key_public_as_der(&id_key)
            .expect("Unable to get id key public pem");

        // Rehydrate the der to a public key.

        let public_key = PKey::public_key_from_der(&id_key_public_der).expect("Invalid DER");

        let input = "test string";
        let signature = hsm
            .identity_key_sign(&id_key, input.as_bytes())
            .expect("Unable to sign input");

        let mut verifier =
            Verifier::new(MessageDigest::sha256(), &public_key).expect("Unable to setup verifier.");

        let valid = verifier
            .verify_oneshot(&signature, input.as_bytes())
            .expect("Unable to validate signature");

        assert!(valid);
    }

    fn create_ca() -> (PKey<Private>, X509) {
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

    fn sign_request(req_der: &[u8], ca_key: &PKey<Private>, ca_cert: &X509) -> X509 {
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

    #[test]
    fn soft_identity_ecdsa256_csr() {
        let _ = tracing_subscriber::fmt::try_init();
        // Create the Hsm.
        let mut hsm = SoftHsm::new();

        let auth_value =
            AuthValue::from_str("Ohquiech9jis7Poo8Di7eth3").expect("Unable to create auth value");

        // Request a new machine-key-context. This key "owns" anything
        // created underneath it.
        let loadable_machine_key = hsm
            .machine_key_create(&auth_value)
            .expect("Unable to create new machine key");

        trace!(?loadable_machine_key);

        let machine_key = hsm
            .machine_key_load(&auth_value, &loadable_machine_key)
            .expect("Unable to load machine key");

        // from that ctx, create an identity key
        let loadable_id_key = hsm
            .identity_key_create(&machine_key, KeyAlgorithm::Ecdsa256)
            .expect("Unable to create id key");

        trace!(?loadable_id_key);

        // Get the CSR

        let csr_der = hsm
            .identity_key_certificate_request(&machine_key, &loadable_id_key, "common name")
            .expect("Failed to create csr");

        // Now, we need to sign this to an x509 cert externally.
        let (ca_key, ca_cert) = create_ca();

        let signed_cert = sign_request(&csr_der, &ca_key, &ca_cert);
        trace!(
            "{}",
            String::from_utf8_lossy(signed_cert.to_text().unwrap().as_slice())
        );

        let signed_cert_der = signed_cert.to_der().unwrap();

        let loadable_id_key = hsm
            .identity_key_associate_certificate(&machine_key, &loadable_id_key, &signed_cert_der)
            .unwrap();

        // Now load it in:
        let id_key = hsm
            .identity_key_load(&machine_key, &loadable_id_key)
            .expect("Unable to load id key");

        let id_key_x509_pem = hsm
            .identity_key_x509_as_pem(&id_key)
            .expect("Unable to get id key public pem");

        trace!("\n{}", String::from_utf8_lossy(&id_key_x509_pem));
    }
}
