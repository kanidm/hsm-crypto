use crate::{
    AuthValue, HmacKey, IdentityKey, KeyAlgorithm, LoadableHmacKey, LoadableIdentityKey,
    LoadableMachineKey, MachineKey, Tpm, TpmError, AES256GCM_IV_LEN, AES256GCM_KEY_LEN,
    HMAC_KEY_LEN,
};
use zeroize::Zeroizing;

#[cfg(feature = "msextensions")]
use crate::{LoadableMsOapxbcRsaKey, LoadableMsOapxbcSessionKey, MsOapxbcRsaKey, SealedData};

use openssl::ec::{EcGroup, EcKey};
use openssl::hash::{hash, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::x509::{X509NameBuilder, X509ReqBuilder, X509};

use tracing::error;

#[derive(Default)]
pub struct SoftTpm {}

impl SoftTpm {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Tpm for SoftTpm {
    fn machine_key_create(
        &mut self,
        auth_value: &AuthValue,
    ) -> Result<LoadableMachineKey, TpmError> {
        // Create a "machine binding" key.
        let mut buf = Zeroizing::new([0; AES256GCM_KEY_LEN]);
        rand_bytes(buf.as_mut()).map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::Entropy
        })?;

        // Encrypt it.
        let mut iv = [0; AES256GCM_IV_LEN];
        rand_bytes(&mut iv).map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::Entropy
        })?;

        let (key, tag) = match auth_value {
            AuthValue::Key256Bit { auth_key } => {
                aes_256_gcm_encrypt(buf.as_ref(), auth_key.as_ref(), &iv)?
            }
        };

        Ok(LoadableMachineKey::SoftAes256GcmV1 { key, tag, iv })
    }

    fn machine_key_load(
        &mut self,
        auth_value: &AuthValue,
        loadable_key: &LoadableMachineKey,
    ) -> Result<MachineKey, TpmError> {
        match loadable_key {
            LoadableMachineKey::SoftAes256GcmV1 { key, tag, iv } => {
                let raw_key = match auth_value {
                    AuthValue::Key256Bit { auth_key } => {
                        aes_256_gcm_decrypt(key, tag, auth_key.as_ref(), iv)?
                    }
                };
                Ok(MachineKey::SoftAes256Gcm { key: raw_key })
            }
            LoadableMachineKey::TpmAes128CfbV1 { .. } => Err(TpmError::IncorrectKeyType),
        }
    }

    fn hmac_key_create(&mut self, mk: &MachineKey) -> Result<LoadableHmacKey, TpmError> {
        let mut buf = Zeroizing::new([0; HMAC_KEY_LEN]);
        rand_bytes(buf.as_mut()).map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::Entropy
        })?;

        let mut iv = [0; 16];
        rand_bytes(&mut iv).map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::Entropy
        })?;

        let (key, tag) = match mk {
            MachineKey::SoftAes256Gcm { key } => {
                aes_256_gcm_encrypt(buf.as_ref(), key.as_ref(), &iv)?
            }
            MachineKey::Tpm { .. } => return Err(TpmError::IncorrectKeyType),
        };

        Ok(LoadableHmacKey::SoftSha256V1 { key, tag, iv })
    }

    fn hmac_key_load(
        &mut self,
        mk: &MachineKey,
        loadable_key: &LoadableHmacKey,
    ) -> Result<HmacKey, TpmError> {
        match (mk, loadable_key) {
            (
                MachineKey::SoftAes256Gcm { key: mk_key },
                LoadableHmacKey::SoftSha256V1 { key, tag, iv },
            ) => {
                let raw_key = aes_256_gcm_decrypt(key, tag, mk_key.as_ref(), iv)?;

                let pkey = PKey::hmac(raw_key.as_ref()).map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::HmacKey
                })?;

                Ok(HmacKey::SoftSha256 { pkey })
            }
            (_, _) => Err(TpmError::IncorrectKeyType),
        }
    }

    fn hmac(&mut self, hk: &HmacKey, input: &[u8]) -> Result<Vec<u8>, TpmError> {
        match hk {
            HmacKey::SoftSha256 { pkey } => {
                let mut signer =
                    Signer::new(MessageDigest::sha256(), pkey).map_err(|ossl_err| {
                        error!(?ossl_err);
                        TpmError::HmacKey
                    })?;

                signer.update(input).map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::HmacSign
                })?;

                signer.sign_to_vec().map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::HmacSign
                })
            }
            HmacKey::TpmSha256 { .. } => Err(TpmError::IncorrectKeyType),
        }
    }

    fn identity_key_create(
        &mut self,
        mk: &MachineKey,
        algorithm: KeyAlgorithm,
    ) -> Result<LoadableIdentityKey, TpmError> {
        match algorithm {
            KeyAlgorithm::Ecdsa256 => {
                let ecgroup =
                    EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|ossl_err| {
                        error!(?ossl_err);
                        TpmError::EcGroup
                    })?;

                let eckey = EcKey::generate(&ecgroup).map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::EcKeyGenerate
                })?;

                let der = eckey
                    .private_key_to_der()
                    .map(Zeroizing::new)
                    .map_err(|ossl_err| {
                        error!(?ossl_err);
                        TpmError::EcKeyPrivateToDer
                    })?;

                let mut iv = [0; 16];
                rand_bytes(&mut iv).map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::Entropy
                })?;

                let (key, tag) = match mk {
                    MachineKey::SoftAes256Gcm { key } => {
                        aes_256_gcm_encrypt(der.as_ref(), key.as_ref(), &iv)?
                    }
                    MachineKey::Tpm { .. } => return Err(TpmError::IncorrectKeyType),
                };

                let x509 = None;

                Ok(LoadableIdentityKey::SoftEcdsa256V1 { key, tag, iv, x509 })
            }
            KeyAlgorithm::Rsa2048 => {
                let rsa = Rsa::generate(2048).map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::RsaGenerate
                })?;

                let der = rsa
                    .private_key_to_der()
                    .map(Zeroizing::new)
                    .map_err(|ossl_err| {
                        error!(?ossl_err);
                        TpmError::RsaPrivateToDer
                    })?;

                let mut iv = [0; 16];
                rand_bytes(&mut iv).map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::Entropy
                })?;

                let (key, tag) = match mk {
                    MachineKey::SoftAes256Gcm { key } => {
                        aes_256_gcm_encrypt(der.as_ref(), key.as_ref(), &iv)?
                    }
                    MachineKey::Tpm { .. } => return Err(TpmError::IncorrectKeyType),
                };

                let x509 = None;

                Ok(LoadableIdentityKey::SoftRsa2048V1 { key, tag, iv, x509 })
            }
        }
    }

    fn identity_key_load(
        &mut self,
        mk: &MachineKey,
        loadable_key: &LoadableIdentityKey,
    ) -> Result<IdentityKey, TpmError> {
        match (mk, loadable_key) {
            (
                MachineKey::SoftAes256Gcm { key: mk_key },
                LoadableIdentityKey::SoftEcdsa256V1 { key, tag, iv, x509 },
            ) => {
                let key_der = aes_256_gcm_decrypt(key, tag, mk_key.as_ref(), iv)?;

                let eckey = EcKey::private_key_from_der(key_der.as_ref()).map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::EcKeyFromDer
                })?;

                let pkey = PKey::from_ec_key(eckey).map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::EcKeyToPrivateKey
                })?;

                let x509 = match x509 {
                    Some(der) => {
                        let x509 = X509::from_der(der).map_err(|ossl_err| {
                            error!(?ossl_err);
                            TpmError::X509FromDer
                        })?;

                        let x509_pkey = x509.public_key().map_err(|ossl_err| {
                            error!(?ossl_err);
                            TpmError::X509PublicKey
                        })?;

                        if !pkey.public_eq(&x509_pkey) {
                            return Err(TpmError::X509KeyMismatch);
                        }

                        Some(x509)
                    }
                    None => None,
                };

                Ok(IdentityKey::SoftEcdsa256 { pkey, x509 })
            }
            (
                MachineKey::SoftAes256Gcm { key: mk_key },
                LoadableIdentityKey::SoftRsa2048V1 { key, tag, iv, x509 },
            ) => {
                let key_der = aes_256_gcm_decrypt(key, tag, mk_key.as_ref(), iv)?;

                let eckey = Rsa::private_key_from_der(key_der.as_ref()).map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::RsaKeyFromDer
                })?;

                let pkey = PKey::from_rsa(eckey).map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::RsaToPrivateKey
                })?;

                let x509 = match x509 {
                    Some(der) => {
                        let x509 = X509::from_der(der).map_err(|ossl_err| {
                            error!(?ossl_err);
                            TpmError::X509FromDer
                        })?;

                        let x509_pkey = x509.public_key().map_err(|ossl_err| {
                            error!(?ossl_err);
                            TpmError::X509PublicKey
                        })?;

                        if !pkey.public_eq(&x509_pkey) {
                            return Err(TpmError::X509KeyMismatch);
                        }

                        Some(x509)
                    }
                    None => None,
                };

                Ok(IdentityKey::SoftRsa2048 { pkey, x509 })
            }
            (_, _) => Err(TpmError::IncorrectKeyType),
        }
    }

    /// Aka key fingerprint
    fn identity_key_id(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        let der = self.identity_key_public_as_der(key)?;

        let digest = MessageDigest::sha256();
        hash(digest, &der)
            .map(|bytes| bytes.to_vec())
            .map_err(|ossl_err| {
                error!(?ossl_err);
                TpmError::IdentityKeyDigest
            })
    }

    fn identity_key_public_as_der(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        match key {
            IdentityKey::SoftEcdsa256 { pkey, x509: _ }
            | IdentityKey::SoftRsa2048 { pkey, x509: _ } => {
                pkey.public_key_to_der().map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::IdentityKeyPublicToDer
                })
            }
            IdentityKey::TpmEcdsa256 { .. } | IdentityKey::TpmRsa2048 { .. } => {
                Err(TpmError::IncorrectKeyType)
            }
        }
    }

    fn identity_key_public_as_pem(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        match key {
            IdentityKey::SoftEcdsa256 { pkey, x509: _ }
            | IdentityKey::SoftRsa2048 { pkey, x509: _ } => {
                pkey.public_key_to_pem().map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::IdentityKeyPublicToPem
                })
            }
            IdentityKey::TpmEcdsa256 { .. } | IdentityKey::TpmRsa2048 { .. } => {
                Err(TpmError::IncorrectKeyType)
            }
        }
    }

    fn identity_key_x509_as_pem(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        match key {
            IdentityKey::SoftEcdsa256 {
                pkey: _,
                x509: Some(x509),
            }
            | IdentityKey::SoftRsa2048 {
                pkey: _,
                x509: Some(x509),
            } => x509.to_pem().map_err(|ossl_err| {
                error!(?ossl_err);
                TpmError::IdentityKeyX509ToPem
            }),
            IdentityKey::TpmEcdsa256 { .. } | IdentityKey::TpmRsa2048 { .. } => {
                Err(TpmError::IncorrectKeyType)
            }
            _ => Err(TpmError::IdentityKeyX509Missing),
        }
    }

    fn identity_key_x509_as_der(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        match key {
            IdentityKey::SoftEcdsa256 {
                pkey: _,
                x509: Some(x509),
            }
            | IdentityKey::SoftRsa2048 {
                pkey: _,
                x509: Some(x509),
            } => x509.to_der().map_err(|ossl_err| {
                error!(?ossl_err);
                TpmError::IdentityKeyX509ToDer
            }),
            IdentityKey::TpmEcdsa256 { .. } | IdentityKey::TpmRsa2048 { .. } => {
                Err(TpmError::IncorrectKeyType)
            }
            _ => Err(TpmError::IdentityKeyX509Missing),
        }
    }

    fn identity_key_sign(&mut self, key: &IdentityKey, input: &[u8]) -> Result<Vec<u8>, TpmError> {
        let mut signer = match key {
            IdentityKey::SoftEcdsa256 { pkey, x509: _ }
            | IdentityKey::SoftRsa2048 { pkey, x509: _ } => {
                Signer::new(MessageDigest::sha256(), pkey).map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::IdentityKeyInvalidForSigning
                })?
            }
            IdentityKey::TpmEcdsa256 { .. } | IdentityKey::TpmRsa2048 { .. } => {
                return Err(TpmError::IncorrectKeyType)
            }
        };

        signer
            .sign_oneshot_to_vec(input)
            .map_err(|ossl_err| {
                error!(?ossl_err);
                TpmError::IdentityKeySignature
            })
            .map(|sig| {
                let res = openssl::ecdsa::EcdsaSig::from_der(&sig);
                tracing::debug!(res = %res.is_ok());

                sig
            })
    }

    fn identity_key_verify(
        &mut self,
        key: &IdentityKey,
        input: &[u8],
        signature: &[u8],
    ) -> Result<bool, TpmError> {
        let mut verifier = match key {
            IdentityKey::SoftEcdsa256 { pkey, x509: _ }
            | IdentityKey::SoftRsa2048 { pkey, x509: _ } => {
                Verifier::new(MessageDigest::sha256(), pkey).map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::IdentityKeyInvalidForVerification
                })?
            }
            IdentityKey::TpmEcdsa256 { .. } | IdentityKey::TpmRsa2048 { .. } => {
                return Err(TpmError::IncorrectKeyType)
            }
        };

        verifier
            .verify_oneshot(signature, input)
            .map_err(|ossl_err| {
                error!(?ossl_err);
                TpmError::IdentityKeyVerification
            })
    }

    fn identity_key_certificate_request(
        &mut self,
        mk: &MachineKey,
        loadable_key: &LoadableIdentityKey,
        cn: &str,
    ) -> Result<Vec<u8>, TpmError> {
        let id_key = self.identity_key_load(mk, loadable_key)?;

        let mut req_builder = X509ReqBuilder::new().map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::X509RequestBuilder
        })?;

        let mut x509_name = X509NameBuilder::new().map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::X509NameBuilder
        })?;

        x509_name
            .append_entry_by_text("CN", cn)
            .map_err(|ossl_err| {
                error!(?ossl_err);
                TpmError::X509NameAppend
            })?;

        let x509_name = x509_name.build();
        req_builder
            .set_subject_name(&x509_name)
            .map_err(|ossl_err| {
                error!(?ossl_err);
                TpmError::X509RequestSubjectName
            })?;

        match id_key {
            IdentityKey::SoftEcdsa256 { pkey, x509: _ }
            | IdentityKey::SoftRsa2048 { pkey, x509: _ } => {
                req_builder.set_pubkey(&pkey).map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::X509RequestSetPublic
                })?;

                req_builder
                    .sign(&pkey, MessageDigest::sha256())
                    .map_err(|ossl_err| {
                        error!(?ossl_err);
                        TpmError::X509RequestSign
                    })?;
            }
            IdentityKey::TpmEcdsa256 { .. } | IdentityKey::TpmRsa2048 { .. } => {
                return Err(TpmError::IncorrectKeyType)
            }
        }

        req_builder.build().to_der().map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::X509RequestToDer
        })
    }

    fn identity_key_associate_certificate(
        &mut self,
        mk: &MachineKey,
        loadable_key: &LoadableIdentityKey,
        certificate_der: &[u8],
    ) -> Result<LoadableIdentityKey, TpmError> {
        let id_key = self.identity_key_load(mk, loadable_key)?;

        // Verify the certificate matches our key
        let certificate = X509::from_der(certificate_der).map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::X509FromDer
        })?;

        let certificate_pkey = certificate.public_key().map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::X509PublicKey
        })?;

        match id_key {
            IdentityKey::SoftEcdsa256 { pkey, x509: _ }
            | IdentityKey::SoftRsa2048 { pkey, x509: _ } => {
                if !pkey.public_eq(&certificate_pkey) {
                    return Err(TpmError::X509KeyMismatch);
                }
            }
            IdentityKey::TpmEcdsa256 { .. } | IdentityKey::TpmRsa2048 { .. } => {
                return Err(TpmError::IncorrectKeyType)
            }
        };

        // At this point we know the cert belongs to this key, so lets
        // get it bound.

        let mut cloned_key = loadable_key.clone();

        match &mut cloned_key {
            LoadableIdentityKey::SoftEcdsa256V1 { ref mut x509, .. } => {
                *x509 = Some(certificate_der.to_vec());
            }
            LoadableIdentityKey::SoftRsa2048V1 { ref mut x509, .. } => {
                *x509 = Some(certificate_der.to_vec());
            }
            LoadableIdentityKey::TpmEcdsa256V1 { .. }
            | LoadableIdentityKey::TpmRsa2048V1 { .. } => return Err(TpmError::IncorrectKeyType),
        };

        Ok(cloned_key)
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_key_create(
        &mut self,
        mk: &MachineKey,
    ) -> Result<LoadableMsOapxbcRsaKey, TpmError> {
        let rsa = Rsa::generate(2048).map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::RsaGenerate
        })?;

        self.msoapxbc_rsa_key_import(mk, rsa)
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_key_import(
        &mut self,
        mk: &MachineKey,
        private_key: Rsa<openssl::pkey::Private>,
    ) -> Result<LoadableMsOapxbcRsaKey, TpmError> {
        // Create our AES GCM key as well. This lets us encrypt "against" the
        // RSA key here. For real TPM's we'll be using seal/unseal against the
        // keyhandle as a parent.
        let mut buf = Zeroizing::new([0; AES256GCM_KEY_LEN]);
        rand_bytes(buf.as_mut()).map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::Entropy
        })?;

        let cek = rsa_oaep_encrypt(&private_key, buf.as_ref())?;

        let der = private_key
            .private_key_to_der()
            .map(Zeroizing::new)
            .map_err(|ossl_err| {
                error!(?ossl_err);
                TpmError::RsaPrivateToDer
            })?;

        let mut iv = [0; 16];
        rand_bytes(&mut iv).map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::Entropy
        })?;

        let (key, tag) = match mk {
            MachineKey::SoftAes256Gcm { key } => {
                aes_256_gcm_encrypt(der.as_ref(), key.as_ref(), &iv)?
            }
            MachineKey::Tpm { .. } => return Err(TpmError::IncorrectKeyType),
        };

        Ok(LoadableMsOapxbcRsaKey::Soft2048V1 { key, tag, iv, cek })
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_key_load(
        &mut self,
        mk: &MachineKey,
        loadable_key: &LoadableMsOapxbcRsaKey,
    ) -> Result<MsOapxbcRsaKey, TpmError> {
        match (mk, loadable_key) {
            (
                MachineKey::SoftAes256Gcm { key: mk_key },
                LoadableMsOapxbcRsaKey::Soft2048V1 { key, tag, iv, cek },
            ) => {
                let key_der = aes_256_gcm_decrypt(key, tag, mk_key.as_ref(), iv)?;

                let key = Rsa::private_key_from_der(key_der.as_ref()).map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::RsaKeyFromDer
                })?;

                let mut cek = rsa_oaep_decrypt(&key, &cek)?;

                cek.truncate(AES256GCM_KEY_LEN);

                Ok(MsOapxbcRsaKey::Soft { key, cek })
            }
            (_, _) => Err(TpmError::IncorrectKeyType),
        }
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_public_as_der(&mut self, key: &MsOapxbcRsaKey) -> Result<Vec<u8>, TpmError> {
        match key {
            MsOapxbcRsaKey::Soft { key, cek: _ } => key.public_key_to_der().map_err(|ossl_err| {
                error!(?ossl_err);
                TpmError::MsOapxbcKeyPublicToDer
            }),
            _ => Err(TpmError::IncorrectKeyType),
        }
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_decipher_session_key(
        &mut self,
        key: &MsOapxbcRsaKey,
        input: &[u8],
        expected_key_len: usize,
    ) -> Result<LoadableMsOapxbcSessionKey, TpmError> {
        match key {
            MsOapxbcRsaKey::Soft { key, cek } => {
                let mut unwrapped_key = rsa_oaep_decrypt(key, input)?;

                unwrapped_key.truncate(expected_key_len);

                // Bind to the parent.
                let mut iv = [0; 16];
                rand_bytes(&mut iv).map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::Entropy
                })?;

                let (enc_session_key, tag) =
                    aes_256_gcm_encrypt(unwrapped_key.as_ref(), cek.as_ref(), &iv)?;

                // Return it in it's loadable form.
                Ok(LoadableMsOapxbcSessionKey::SoftV1 {
                    key: enc_session_key,
                    tag,
                    iv,
                })
            }
            _ => Err(TpmError::IncorrectKeyType),
        }
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_yield_session_key(
        &mut self,
        key: &MsOapxbcRsaKey,
        session_key: &LoadableMsOapxbcSessionKey,
    ) -> Result<Zeroizing<Vec<u8>>, TpmError> {
        match (key, session_key) {
            (
                MsOapxbcRsaKey::Soft { key: _, cek },
                LoadableMsOapxbcSessionKey::SoftV1 { key, tag, iv },
            ) => aes_256_gcm_decrypt(key, tag, cek, iv),
            (_, _) => Err(TpmError::IncorrectKeyType),
        }
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_seal_data(
        &mut self,
        key: &MsOapxbcRsaKey,
        data: &[u8],
    ) -> Result<SealedData, TpmError> {
        match key {
            MsOapxbcRsaKey::Soft { key: _, cek } => {
                // Bind to the parent's cek
                let mut iv = [0; 16];
                rand_bytes(&mut iv).map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::Entropy
                })?;

                let (enc_data, tag) = aes_256_gcm_encrypt(data, cek.as_ref(), &iv)?;

                Ok(SealedData::SoftV1 {
                    data: enc_data,
                    tag,
                    iv,
                })
            }
            _ => Err(TpmError::IncorrectKeyType),
        }
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_unseal_data(
        &mut self,
        key: &MsOapxbcRsaKey,
        sealed_data: &SealedData,
    ) -> Result<Zeroizing<Vec<u8>>, TpmError> {
        match (key, sealed_data) {
            (MsOapxbcRsaKey::Soft { key: _, cek }, SealedData::SoftV1 { data, tag, iv }) => {
                aes_256_gcm_decrypt(data, tag, &cek, iv)
            }
            (_, _) => Err(TpmError::IncorrectKeyType),
        }
    }
}

#[cfg(feature = "msextensions")]
pub(crate) fn rsa_oaep_encrypt<T: openssl::pkey::HasPublic>(
    key: &Rsa<T>,
    key_to_wrap: &[u8],
) -> Result<Vec<u8>, TpmError> {
    use openssl::encrypt::Encrypter;
    use openssl::rsa::Padding;

    let rsa_pub_key = PKey::from_rsa(key.clone()).map_err(|ossl_err| {
        error!(?ossl_err);
        TpmError::MsOapxbcKeyOaepOption
    })?;

    let mut wrap_key_encrypter = Encrypter::new(&rsa_pub_key).map_err(|ossl_err| {
        error!(?ossl_err);
        TpmError::MsOapxbcKeyOaepOption
    })?;

    wrap_key_encrypter
        .set_rsa_padding(Padding::PKCS1_OAEP)
        .map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::MsOapxbcKeyOaepOption
        })?;

    wrap_key_encrypter
        .set_rsa_mgf1_md(MessageDigest::sha1())
        .map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::MsOapxbcKeyOaepOption
        })?;

    wrap_key_encrypter
        .set_rsa_oaep_md(MessageDigest::sha1())
        .map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::MsOapxbcKeyOaepOption
        })?;

    let buf_len = wrap_key_encrypter
        .encrypt_len(key_to_wrap)
        .map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::MsOapxbcKeyOaepEncipher
        })?;

    let mut wrapped_key = vec![0; buf_len];

    let encoded_len = wrap_key_encrypter
        .encrypt(key_to_wrap, wrapped_key.as_mut())
        .map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::MsOapxbcKeyOaepEncipher
        })?;

    wrapped_key.truncate(encoded_len);

    Ok(wrapped_key)
}

#[cfg(feature = "msextensions")]
fn rsa_oaep_decrypt(
    key: &Rsa<openssl::pkey::Private>,
    input: &[u8],
) -> Result<Zeroizing<Vec<u8>>, TpmError> {
    use openssl::encrypt::Decrypter;
    use openssl::rsa::Padding;

    let rsa_priv_key = PKey::from_rsa(key.clone()).map_err(|ossl_err| {
        error!(?ossl_err);
        TpmError::MsOapxbcKeyOaepOption
    })?;

    let mut wrap_key_decrypter = Decrypter::new(&rsa_priv_key).map_err(|ossl_err| {
        error!(?ossl_err);
        TpmError::MsOapxbcKeyOaepOption
    })?;

    wrap_key_decrypter
        .set_rsa_padding(Padding::PKCS1_OAEP)
        .map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::MsOapxbcKeyOaepOption
        })?;

    wrap_key_decrypter
        .set_rsa_mgf1_md(MessageDigest::sha1())
        .map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::MsOapxbcKeyOaepOption
        })?;

    wrap_key_decrypter
        .set_rsa_oaep_md(MessageDigest::sha1())
        .map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::MsOapxbcKeyOaepOption
        })?;

    // Rsa oaep will often work on bigger block sizes, so we need a larger buffer and then we
    // can copy later. First we check the expected length of the decryption.
    let buf_len = wrap_key_decrypter.decrypt_len(input).map_err(|ossl_err| {
        error!(?ossl_err);
        TpmError::MsOapxbcKeyOaepDecipher
    })?;

    let mut unwrapped_key = Zeroizing::new(vec![0; buf_len]);

    wrap_key_decrypter
        .decrypt(input, unwrapped_key.as_mut())
        .map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::MsOapxbcKeyOaepDecipher
        })?;

    Ok(unwrapped_key)
}

pub(crate) fn aes_256_gcm_encrypt(
    input: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), TpmError> {
    let cipher = Cipher::aes_256_gcm();

    let block_size = cipher.block_size();
    let mut ciphertext = vec![0; input.len() + block_size];

    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv)).map_err(|ossl_err| {
        error!(?ossl_err);
        TpmError::Aes256GcmConfig
    })?;

    // Enable padding.
    encrypter.pad(true);

    let mut count = encrypter
        .update(input, &mut ciphertext)
        .map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::Aes256GcmEncrypt
        })?;
    count += encrypter.finalize(&mut ciphertext).map_err(|ossl_err| {
        error!(?ossl_err);
        TpmError::Aes256GcmEncrypt
    })?;
    ciphertext.truncate(count);

    let mut tag = [0; 16];
    encrypter.get_tag(&mut tag).map_err(|ossl_err| {
        error!(?ossl_err);
        TpmError::Aes256GcmEncrypt
    })?;

    Ok((ciphertext, tag))
}

pub(crate) fn aes_256_gcm_decrypt(
    input: &[u8],
    tag: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Zeroizing<Vec<u8>>, TpmError> {
    let cipher = Cipher::aes_256_gcm();

    let block_size = cipher.block_size();
    let mut plaintext = Zeroizing::new(vec![0; input.len() + block_size]);

    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv)).map_err(|ossl_err| {
        error!(?ossl_err);
        TpmError::Aes256GcmConfig
    })?;

    decrypter.pad(true);
    decrypter.set_tag(tag).map_err(|ossl_err| {
        error!(?ossl_err);
        TpmError::Aes256GcmConfig
    })?;

    let mut count = decrypter
        .update(input, &mut plaintext)
        .map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::Aes256GcmDecrypt
        })?;

    count += decrypter.finalize(&mut plaintext).map_err(|ossl_err| {
        error!(?ossl_err);
        TpmError::Aes256GcmDecrypt
    })?;

    plaintext.truncate(count);

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::{aes_256_gcm_decrypt, aes_256_gcm_encrypt, KeyAlgorithm, SoftTpm};
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
    fn aes_256_gcm_enc_dec_large() {
        let _ = tracing_subscriber::fmt::try_init();

        let input = [0xf; 256];
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

        let mut hsm_a = SoftTpm::new();
        let mut hsm_b = SoftTpm::new();

        crate::test_tpm_hmac!(hsm_a, hsm_b);
    }

    #[test]
    fn soft_identity_ecdsa256_hw_bound() {
        // Create the Hsm.
        let mut hsm = SoftTpm::new();

        crate::test_tpm_identity!(hsm, KeyAlgorithm::Ecdsa256);
    }

    #[test]
    fn soft_identity_rsa2048_hw_bound() {
        // Create the Hsm.
        let mut hsm = SoftTpm::new();

        crate::test_tpm_identity!(hsm, KeyAlgorithm::Rsa2048);
    }

    #[test]
    fn soft_identity_ecdsa256_csr() {
        let mut hsm = SoftTpm::new();

        crate::test_tpm_identity_csr!(hsm, KeyAlgorithm::Ecdsa256);
    }
}

#[cfg(all(test, feature = "msextensions"))]
mod ms_extn_tests {
    use crate::soft::SoftTpm;

    #[test]
    fn soft_ms_extensions() {
        let mut hsm = SoftTpm::new();

        crate::test_tpm_ms_extensions!(hsm);
    }
}
