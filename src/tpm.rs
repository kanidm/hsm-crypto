use crate::{
    AuthValue, HmacKey, IdentityKey, KeyAlgorithm, LoadableHmacKey, LoadableIdentityKey,
    LoadableMachineKey, MachineKey, Tpm, TpmError,
};

use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{hash, MessageDigest};
use openssl::x509::X509;

// use serde::{Deserialize, Serialize};
use tracing::error;

use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::SessionType;
use tss_esapi::structures::{
    Auth, CreateKeyResult, CreatePrimaryKeyResult, Digest, EccParameter, EccPoint, EccScheme,
    EccSignature, HashScheme, HashcheckTicket, KeyedHashScheme, MaxBuffer, PublicBuilder,
    PublicEccParametersBuilder, PublicKeyRsa, PublicKeyedHashParameters,
    PublicRsaParametersBuilder, RsaExponent, RsaScheme, RsaSignature, Signature, SignatureScheme,
    SymmetricCipherParameters, SymmetricDefinition, SymmetricDefinitionObject,
};
use tss_esapi::Context;
use tss_esapi::TctiNameConf;

use tss_esapi::interface_types::resource_handles::Hierarchy;

use tss_esapi::constants::tss::TPM2_RH_NULL;
use tss_esapi::constants::tss::TPM2_ST_HASHCHECK;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;

use tss_esapi::handles::ObjectHandle;

pub use tss_esapi::handles::KeyHandle;
pub use tss_esapi::structures::{Private, Public};
pub use tss_esapi::utils::TpmsContext;

use std::str::FromStr;

pub struct TpmTss {
    tpm_ctx: Context,
    _auth_session: AuthSession,
}

impl TpmTss {
    pub fn new(tcti_name: &str) -> Result<Self, TpmError> {
        let tpm_name_config = TctiNameConf::from_str(tcti_name).map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TpmTctiNameInvalid
        })?;

        let mut tpm_ctx = Context::new(tpm_name_config).map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TpmContextCreate
        })?;

        let maybe_auth_session = tpm_ctx
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmAuthSession
            })?;

        let auth_session = maybe_auth_session.ok_or_else(|| {
            error!("No auth session created by tpm context");
            TpmError::TpmAuthSession
        })?;

        let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();

        tpm_ctx
            .tr_sess_set_attributes(auth_session, session_attributes, session_attributes_mask)
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmAuthSession
            })?;

        let session_handles = (Some(auth_session), None, None);

        tpm_ctx.set_sessions(session_handles);

        Ok(TpmTss {
            tpm_ctx,
            _auth_session: auth_session,
        })
    }
}

impl TpmTss {
    fn setup_owner_primary(&mut self) -> Result<CreatePrimaryKeyResult, TpmError> {
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_restricted(true)
            .build()
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmPrimaryObjectAttributesInvalid
            })?;

        let primary_pub = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::SymCipher)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
                SymmetricDefinitionObject::AES_128_CFB,
            ))
            .with_symmetric_cipher_unique_identifier(Digest::default())
            .build()
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmPrimaryPublicBuilderInvalid
            })?;

        // Create the key under the "owner" hierarchy. Other hierarchies are platform
        // which is for boot services, null which is ephemeral and resets after a reboot,
        // and endorsement which allows key certification by the TPM manufacturer.
        self.tpm_ctx
            .create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmPrimaryCreate
            })
    }

    fn execute_with_temporary_object<F, T>(
        &mut self,
        object: ObjectHandle,
        f: F,
    ) -> Result<T, TpmError>
    where
        F: FnOnce(&mut Self, ObjectHandle) -> Result<T, TpmError>,
    {
        let res = f(self, object);

        self.tpm_ctx.flush_context(object).map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TpmContextFlushObject
        })?;

        res
    }

    fn execute_with_temporary_object_context<F, T>(
        &mut self,
        tpms_context: TpmsContext,
        f: F,
    ) -> Result<T, TpmError>
    where
        F: FnOnce(&mut Self, ObjectHandle) -> Result<T, TpmError>,
    {
        let object = self.tpm_ctx.context_load(tpms_context).map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TpmContextLoad
        })?;

        let res = f(self, object);

        self.tpm_ctx.flush_context(object).map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TpmContextFlushObject
        })?;

        res
    }
}

impl Tpm for TpmTss {
    fn machine_key_create(
        &mut self,
        auth_value: &AuthValue,
    ) -> Result<LoadableMachineKey, TpmError> {
        // Setup the primary key.
        let primary = self.setup_owner_primary()?;

        self.execute_with_temporary_object(
            primary.key_handle.into(),
            |hsm_ctx, primary_key_handle| {
                // Create the Machine Key.
                let unique_key_identifier = hsm_ctx
                    .tpm_ctx
                    .get_random(16)
                    .and_then(|random| Digest::from_bytes(random.as_slice()))
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TpmEntropy
                    })?;

                let object_attributes = ObjectAttributesBuilder::new()
                    .with_fixed_tpm(true)
                    .with_fixed_parent(true)
                    .with_st_clear(false)
                    .with_sensitive_data_origin(true)
                    .with_user_with_auth(true)
                    .with_admin_with_policy(true)
                    .with_decrypt(true)
                    .with_restricted(true)
                    .build()
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TpmMachineKeyObjectAttributesInvalid
                    })?;

                let key_pub = PublicBuilder::new()
                    .with_public_algorithm(PublicAlgorithm::SymCipher)
                    .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                    .with_object_attributes(object_attributes)
                    .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
                        SymmetricDefinitionObject::AES_128_CFB,
                    ))
                    .with_symmetric_cipher_unique_identifier(unique_key_identifier)
                    .build()
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TpmMachineKeyBuilderInvalid
                    })?;

                let tpm_auth_value = match auth_value {
                    AuthValue::Key256Bit { auth_key } => Auth::from_bytes(auth_key.as_ref()),
                }
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TpmAuthValueInvalid
                })?;

                hsm_ctx
                    .tpm_ctx
                    .create(
                        primary_key_handle.into(),
                        key_pub,
                        Some(tpm_auth_value),
                        None,
                        None,
                        None,
                    )
                    .map(
                        |CreateKeyResult {
                             out_private: private,
                             out_public: public,
                             creation_data: _,
                             creation_hash: _,
                             creation_ticket: _,
                         }| {
                            LoadableMachineKey::TpmAes128CfbV1 { private, public }
                        },
                    )
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TpmMachineKeyCreate
                    })
            },
        )

        // Remember this isn't loaded and can't be used yet!
    }

    fn machine_key_load(
        &mut self,
        auth_value: &AuthValue,
        loadable_key: &LoadableMachineKey,
    ) -> Result<MachineKey, TpmError> {
        let (private, public) = match loadable_key {
            LoadableMachineKey::TpmAes128CfbV1 { private, public } => {
                (private.clone(), public.clone())
            }
            _ => return Err(TpmError::IncorrectKeyType),
        };

        // Was this cleared in the former stages?
        let primary = self.setup_owner_primary()?;

        self.execute_with_temporary_object(
            primary.key_handle.into(),
            |hsm_ctx, primary_key_handle| {
                let tpm_auth_value = match auth_value {
                    AuthValue::Key256Bit { auth_key } => Auth::from_bytes(auth_key.as_ref()),
                }
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TpmAuthValueInvalid
                })?;

                hsm_ctx
                    .tpm_ctx
                    .load(primary_key_handle.into(), private.clone(), public.clone())
                    .and_then(|key_handle| {
                        hsm_ctx
                            .tpm_ctx
                            .tr_set_auth(key_handle.into(), tpm_auth_value)
                            .map(|()| key_handle)
                    })
                    .map(|key_handle| MachineKey::Tpm { key_handle })
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TpmMachineKeyLoad
                    })
            },
        )
    }

    fn hmac_key_create(&mut self, mk: &MachineKey) -> Result<LoadableHmacKey, TpmError> {
        let mk_key_handle = match mk {
            MachineKey::Tpm { key_handle } => key_handle.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let unique_key_identifier = self
            .tpm_ctx
            .get_random(16)
            .and_then(|random| Digest::from_bytes(random.as_slice()))
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmEntropy
            })?;

        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .build()
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmHmacKeyObjectAttributesInvalid
            })?;

        let key_pub = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
                KeyedHashScheme::HMAC_SHA_256,
            ))
            .with_keyed_hash_unique_identifier(unique_key_identifier)
            .build()
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmHmacKeyBuilderInvalid
            })?;

        self.tpm_ctx
            .create(mk_key_handle, key_pub, None, None, None, None)
            .map(
                |CreateKeyResult {
                     out_private: private,
                     out_public: public,
                     creation_data: _,
                     creation_hash: _,
                     creation_ticket: _,
                 }| { LoadableHmacKey::TpmSha256V1 { private, public } },
            )
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmHmacKeyCreate
            })
    }

    fn hmac_key_load(
        &mut self,
        mk: &MachineKey,
        loadable_key: &LoadableHmacKey,
    ) -> Result<HmacKey, TpmError> {
        let (private, public) = match loadable_key {
            LoadableHmacKey::TpmSha256V1 { private, public } => (private.clone(), public.clone()),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let mk_key_handle = match mk {
            MachineKey::Tpm { key_handle } => key_handle.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let key_handle = self
            .tpm_ctx
            .load(mk_key_handle, private, public)
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmHmacKeyLoad
            })?;

        // Now it's loaded, lets setup the context we will load/unload as needed. In this
        // process we WILL be unloading the keyhandle.
        self.execute_with_temporary_object(key_handle.into(), |hsm_ctx, hmac_key_handle| {
            hsm_ctx
                .tpm_ctx
                .context_save(hmac_key_handle.into())
                .map(|key_context| HmacKey::TpmSha256 { key_context })
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TpmContextSave
                })
        })
    }

    fn hmac(&mut self, hk: &HmacKey, input: &[u8]) -> Result<Vec<u8>, TpmError> {
        let (hk_key_context, hk_alg) = match hk {
            HmacKey::TpmSha256 { key_context } => (key_context.clone(), HashingAlgorithm::Sha256),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let data_buffer = MaxBuffer::from_bytes(input).map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TpmHmacInputTooLarge
        })?;

        self.execute_with_temporary_object_context(hk_key_context, |hsm_ctx, key_handle| {
            hsm_ctx
                .tpm_ctx
                .hmac(key_handle.into(), data_buffer, hk_alg)
                .map(|digest| digest.as_bytes().to_vec())
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TpmHmacSign
                })
        })
    }

    fn identity_key_create(
        &mut self,
        mk: &MachineKey,
        algorithm: KeyAlgorithm,
    ) -> Result<LoadableIdentityKey, TpmError> {
        let mk_key_handle = match mk {
            MachineKey::Tpm { key_handle } => key_handle.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .build()
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmIdentityKeyObjectAttributesInvalid
            })?;

        let key_pub = match algorithm {
            KeyAlgorithm::Ecdsa256 => {
                let ecc_params = PublicEccParametersBuilder::new_unrestricted_signing_key(
                    EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
                    EccCurve::NistP256,
                )
                .build()
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TpmIdentityKeyAlgorithmInvalid
                })?;

                PublicBuilder::new()
                    .with_public_algorithm(PublicAlgorithm::Ecc)
                    .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                    .with_object_attributes(object_attributes)
                    .with_ecc_parameters(ecc_params)
                    .with_ecc_unique_identifier(EccPoint::default())
                    .build()
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TpmIdentityKeyBuilderInvalid
                    })?
            }
            KeyAlgorithm::Rsa2048 => {
                let rsa_params = PublicRsaParametersBuilder::new_unrestricted_signing_key(
                    RsaScheme::RsaPss(HashScheme::new(HashingAlgorithm::Sha256)),
                    RsaKeyBits::Rsa2048,
                    RsaExponent::default(),
                )
                .build()
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TpmIdentityKeyAlgorithmInvalid
                })?;

                PublicBuilder::new()
                    .with_public_algorithm(PublicAlgorithm::Rsa)
                    .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                    .with_object_attributes(object_attributes)
                    .with_rsa_parameters(rsa_params)
                    .with_rsa_unique_identifier(PublicKeyRsa::default())
                    .build()
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TpmIdentityKeyBuilderInvalid
                    })?
            }
        };

        self.tpm_ctx
            .create(mk_key_handle.into(), key_pub, None, None, None, None)
            .map(
                |CreateKeyResult {
                     out_private: private,
                     out_public: public,
                     creation_data: _,
                     creation_hash: _,
                     creation_ticket: _,
                 }| {
                    match algorithm {
                        KeyAlgorithm::Ecdsa256 => LoadableIdentityKey::TpmEcdsa256V1 {
                            private,
                            public,
                            x509: None,
                        },
                        KeyAlgorithm::Rsa2048 => LoadableIdentityKey::TpmRsa2048V1 {
                            private,
                            public,
                            x509: None,
                        },
                    }
                },
            )
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmIdentityKeyCreate
            })
    }

    fn identity_key_load(
        &mut self,
        mk: &MachineKey,
        loadable_key: &LoadableIdentityKey,
    ) -> Result<IdentityKey, TpmError> {
        let (private, public, algorithm, x509) = match loadable_key {
            LoadableIdentityKey::TpmEcdsa256V1 {
                private,
                public,
                x509,
            } => (
                private.clone(),
                public.clone(),
                KeyAlgorithm::Ecdsa256,
                x509.as_ref(),
            ),
            LoadableIdentityKey::TpmRsa2048V1 {
                private,
                public,
                x509,
            } => (
                private.clone(),
                public.clone(),
                KeyAlgorithm::Rsa2048,
                x509.as_ref(),
            ),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let x509 = match x509 {
            Some(der) => {
                let x509 = X509::from_der(der).map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::X509FromDer
                })?;

                /*
                let x509_pkey = x509.public_key().map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::X509PublicKey
                })?;

                if !pkey.public_eq(&x509_pkey) {
                    return Err(TpmError::X509KeyMismatch);
                }
                */

                Some(x509)
            }
            None => None,
        };

        let mk_key_handle = match mk {
            MachineKey::Tpm { key_handle } => key_handle.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let key_handle = self
            .tpm_ctx
            .load(mk_key_handle, private, public)
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmHmacKeyLoad
            })?;

        // Now it's loaded, lets setup the context we will load/unload as needed. In this
        // process we WILL be unloading the keyhandle.
        self.execute_with_temporary_object(key_handle.into(), |hsm_ctx, hmac_key_handle| {
            hsm_ctx
                .tpm_ctx
                .context_save(hmac_key_handle.into())
                .map(|key_context| match algorithm {
                    KeyAlgorithm::Ecdsa256 => IdentityKey::TpmEcdsa256 { key_context, x509 },
                    KeyAlgorithm::Rsa2048 => IdentityKey::TpmRsa2048 { key_context, x509 },
                })
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TpmContextSave
                })
        })
    }

    fn identity_key_id(&mut self, _key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        Err(TpmError::TpmOperationUnsupported)
    }

    fn identity_key_sign(&mut self, key: &IdentityKey, input: &[u8]) -> Result<Vec<u8>, TpmError> {
        let (key_context, sig_scheme, digest_alg) = match key {
            IdentityKey::TpmEcdsa256 {
                key_context,
                x509: _,
            } => (
                key_context.clone(),
                SignatureScheme::Null,
                MessageDigest::sha256(),
            ),
            IdentityKey::TpmRsa2048 {
                key_context,
                x509: _,
            } => (
                key_context.clone(),
                SignatureScheme::Null,
                MessageDigest::sha256(),
            ),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        // Future, may need to change this size for non sha256
        // Hash the input.
        let bytes = hash(digest_alg, &input).map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::IdentityKeyDigest
        })?;

        let tpm_digest: Digest = Digest::from_bytes(&bytes as &[u8]).map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::IdentityKeyDigest
        })?;

        // No need for hashcheck, unrestricted key.
        let validation: HashcheckTicket = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        }
        .try_into()
        .unwrap();

        // Now we can sign.
        let signature =
            self.execute_with_temporary_object_context(key_context, |hsm_ctx, key_handle| {
                hsm_ctx
                    .tpm_ctx
                    .sign(key_handle.into(), tpm_digest, sig_scheme, validation)
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TpmIdentityKeySign
                    })
            })?;

        tracing::debug!(?signature);

        match signature {
            Signature::RsaPss(rsasig) => Ok(rsasig.signature().to_vec()),
            Signature::EcDsa(ecsig) => {
                let s = BigNum::from_slice(ecsig.signature_s().as_slice()).map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::TpmIdentityKeyEcdsaSigSInvalid
                })?;

                let r = BigNum::from_slice(ecsig.signature_r().as_slice()).map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::TpmIdentityKeyEcdsaSigRInvalid
                })?;

                let sig = EcdsaSig::from_private_components(r, s).map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::TpmIdentityKeyEcdsaSigFromParams
                })?;

                sig.to_der().map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::TpmIdentityKeyEcdsaSigToDer
                })
            }
            _ => {
                error!("tpm returned an invalid signature type");
                Err(TpmError::TpmIdentityKeySignatureInvalid)
            }
        }
    }

    fn identity_key_verify(
        &mut self,
        key: &IdentityKey,
        input: &[u8],
        signature: &[u8],
    ) -> Result<bool, TpmError> {
        let (key_context, tpm_signature, digest_alg) = match key {
            IdentityKey::TpmEcdsa256 {
                key_context,
                x509: _,
            } => {
                let sig = EcdsaSig::from_der(signature).map_err(|ossl_err| {
                    error!(?ossl_err);
                    TpmError::TpmIdentityKeyDerToEcdsaSig
                })?;

                let r = EccParameter::try_from(sig.r().to_vec()).map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TpmIdentityKeyParamRInvalid
                })?;

                let s = EccParameter::try_from(sig.s().to_vec()).map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TpmIdentityKeyParamSInvalid
                })?;

                let ecsig =
                    EccSignature::create(HashingAlgorithm::Sha256, r, s).map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TpmIdentityKeyParamsToEcdsaSig
                    })?;

                let tpm_signature = Signature::EcDsa(ecsig);

                tracing::debug!(?tpm_signature);

                (key_context.clone(), tpm_signature, MessageDigest::sha256())
            }
            IdentityKey::TpmRsa2048 {
                key_context,
                x509: _,
            } => {
                let pk_rsa = PublicKeyRsa::from_bytes(signature).map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TpmIdentityKeyParamInvalid
                })?;

                let rsa_sig =
                    RsaSignature::create(HashingAlgorithm::Sha256, pk_rsa).map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TpmIdentityKeyParamsToRsaSig
                    })?;

                let tpm_signature = Signature::RsaPss(rsa_sig);

                (key_context.clone(), tpm_signature, MessageDigest::sha256())
            }
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let bytes = hash(digest_alg, &input).map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::IdentityKeyDigest
        })?;

        let tpm_digest: Digest = Digest::from_bytes(&bytes as &[u8]).map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::IdentityKeyDigest
        })?;

        let verified =
            self.execute_with_temporary_object_context(key_context, |hsm_ctx, key_handle| {
                hsm_ctx
                    .tpm_ctx
                    .verify_signature(key_handle.into(), tpm_digest, tpm_signature)
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TpmIdentityKeyVerify
                    })
            });

        tracing::trace!(?verified);

        Ok(verified.is_ok())
    }

    fn identity_key_certificate_request(
        &mut self,
        _mk: &MachineKey,
        _loadable_key: &LoadableIdentityKey,
        _cn: &str,
    ) -> Result<Vec<u8>, TpmError> {
        Err(TpmError::TpmOperationUnsupported)
    }

    fn identity_key_associate_certificate(
        &mut self,
        _mk: &MachineKey,
        _loadable_key: &LoadableIdentityKey,
        _certificate_der: &[u8],
    ) -> Result<LoadableIdentityKey, TpmError> {
        Err(TpmError::TpmOperationUnsupported)
    }

    fn identity_key_public_as_der(&mut self, _key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        Err(TpmError::TpmOperationUnsupported)
    }

    fn identity_key_public_as_pem(&mut self, _key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        Err(TpmError::TpmOperationUnsupported)
    }

    fn identity_key_x509_as_pem(&mut self, _key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        Err(TpmError::TpmOperationUnsupported)
    }

    fn identity_key_x509_as_der(&mut self, _key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        Err(TpmError::TpmOperationUnsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::TpmTss;
    use crate::KeyAlgorithm;

    #[test]
    fn tpm_hmac_hw_bound() {
        let _ = tracing_subscriber::fmt::try_init();

        // Create the Hsm.
        let mut hsm_a = TpmTss::new("device:/dev/tpmrm0").expect("Unable to build Tpm Context");

        // Make a new Hsm context.
        let mut hsm_b = TpmTss::new("device:/dev/tpmrm0").expect("Unable to build Tpm Context");

        crate::test_tpm_hmac!(hsm_a, hsm_b);
    }

    #[test]
    fn tpm_identity_ecdsa256_hw_bound() {
        let mut hsm = TpmTss::new("device:/dev/tpmrm0").expect("Unable to build Tpm Context");

        crate::test_tpm_identity_no_export!(hsm, KeyAlgorithm::Ecdsa256);
    }

    #[test]
    fn tpm_identity_rsa2048_hw_bound() {
        // Create the Hsm.
        let mut hsm = TpmTss::new("device:/dev/tpmrm0").expect("Unable to build Tpm Context");

        crate::test_tpm_identity_no_export!(hsm, KeyAlgorithm::Rsa2048);
    }
}
