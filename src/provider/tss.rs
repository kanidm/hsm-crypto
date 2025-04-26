use crate::authvalue::AuthValue;
use crate::error::TpmError;
use crate::pin::PinValue;
use crate::provider::{Tpm, TpmES256, TpmHmacS256, TpmMsExtensions, TpmPinHmacS256, TpmRS256};
use crate::structures::{
    ES256Key, HmacS256Key, LoadableES256Key, LoadableHmacS256Key, LoadableRS256Key,
    LoadableStorageKey, RS256Key, SealedData, StorageKey,
};
use crypto_glue::{
    aes256,
    aes256gcm::{self, AeadInPlace, Aes256Gcm, KeyInit},
    ecdsa_p256::{
        EcdsaP256PublicCoordinate, EcdsaP256PublicEncodedPoint, EcdsaP256PublicKey,
        EcdsaP256Signature,
    },
    hmac_s256::HmacSha256Output,
    rsa::{self, RS256PrivateKey, RS256PublicKey, RS256Signature},
    s256::{Sha256, Sha256Output},
    traits::{Digest as TraitDigest, FromEncodedPoint, Zeroizing},
};
use std::str::FromStr;
use tracing::error;
use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::tss::TPM2_RH_NULL;
use tss_esapi::constants::tss::TPM2_ST_HASHCHECK;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::ObjectHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{Auth, Private, Public};
use tss_esapi::structures::{
    CreateKeyResult, CreatePrimaryKeyResult, Data, Digest, EccPoint, EccScheme, HashScheme,
    HashcheckTicket, KeyedHashScheme, MaxBuffer, Nonce, PublicBuilder, PublicEccParametersBuilder,
    PublicKeyRsa, PublicKeyedHashParameters, PublicRsaParametersBuilder, RsaDecryptionScheme,
    RsaExponent, RsaScheme, SensitiveData, Signature, SignatureScheme, SymmetricCipherParameters,
    SymmetricDefinition, SymmetricDefinitionObject,
};
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;
use tss_esapi::utils::TpmsContext;
use tss_esapi::Context;
use tss_esapi::TctiNameConf;

use crate::wrap::{unwrap_aes256gcm, wrap_aes256gcm};

pub struct TssTpm {
    tpm_ctx: Context,
    _auth_session: AuthSession,
}

impl Drop for TssTpm {
    fn drop(&mut self) {
        // Drop the auth_session if possible.
        self.tpm_ctx.clear_sessions();
    }
}

impl TssTpm {
    pub fn new(tcti_name: &str) -> Result<Self, TpmError> {
        let tpm_name_config = TctiNameConf::from_str(tcti_name).map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TssTctiNameInvalid
        })?;

        let mut tpm_ctx = Context::new(tpm_name_config).map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TssContextCreate
        })?;

        let key = None;
        let bind = None;

        // As we have a long lived session with the tpm, the introduction of our own
        // nonce helps to prevent attacks against authValues.
        let nonce = tpm_ctx
            .get_random(32)
            .and_then(|random| Nonce::from_bytes(random.as_slice()))
            .map(Some)
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TssEntropy
            })?;

        let maybe_auth_session = tpm_ctx
            .start_auth_session(
                key,
                bind,
                nonce,
                SessionType::Hmac,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TssAuthSession
            })?;

        let auth_session = maybe_auth_session.ok_or_else(|| {
            error!("No auth session created by tpm context");
            TpmError::TssAuthSession
        })?;

        let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();

        tpm_ctx
            .tr_sess_set_attributes(auth_session, session_attributes, session_attributes_mask)
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TssAuthSession
            })?;

        let session_handles = (Some(auth_session), None, None);

        tpm_ctx.set_sessions(session_handles);

        Ok(TssTpm {
            tpm_ctx,
            _auth_session: auth_session,
        })
    }

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
                TpmError::TssPrimaryObjectAttributesInvalid
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
                TpmError::TssPrimaryPublicBuilderInvalid
            })?;

        // Create the key under the "owner" hierarchy. Other hierarchies are platform
        // which is for boot services, null which is ephemeral and resets after a reboot,
        // and endorsement which allows key certification by the TPM manufacturer.
        self.tpm_ctx
            .create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TssPrimaryCreate
            })
    }

    fn create_storage_key_public() -> Result<Public, TpmError> {
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
                TpmError::TssStorageKeyObjectAttributesInvalid
            })?;

        PublicBuilder::new()
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
                TpmError::TssStorageKeyBuilderInvalid
            })
    }

    fn create_storage_key(
        &mut self,
        auth_value: Option<Auth>,
        parent_key_handle: ObjectHandle,
    ) -> Result<(Private, Public), TpmError> {
        let key_pub = Self::create_storage_key_public()?;

        self.tpm_ctx
            .create(
                parent_key_handle.into(),
                key_pub,
                auth_value,
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
                 }| { (private, public) },
            )
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TssStorageKeyCreate
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
            TpmError::TssContextFlushObject
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
            TpmError::TssContextLoad
        })?;

        let res = f(self, object);

        self.tpm_ctx.flush_context(object).map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TssContextFlushObject
        })?;

        res
    }

    fn execute_key_load_to_context(
        &mut self,
        parent_context: TpmsContext,
        private: Private,
        public: Public,
    ) -> Result<TpmsContext, TpmError> {
        // Load our private/public under our parent context, and immediately
        // flush the parent handle from the context.
        let key_handle = self.execute_with_temporary_object_context(
            parent_context,
            |hsm_ctx, parent_key_handle| {
                hsm_ctx
                    .tpm_ctx
                    .load(parent_key_handle.into(), private, public)
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TssKeyLoad
                    })
            },
        )?;

        // The object is now loaded, and the parent key has been released. Now we can
        // save the context for the child key so that we don't fill up objectMemory in
        // the context.
        self.execute_with_temporary_object(key_handle.into(), |hsm_ctx, key_handle| {
            hsm_ctx.tpm_ctx.context_save(key_handle).map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TssContextSave
            })
        })
    }
}

impl Tpm for TssTpm {
    // create a root-storage-key
    fn root_storage_key_create(
        &mut self,
        auth_value: &AuthValue,
    ) -> Result<LoadableStorageKey, TpmError> {
        // Setup the primary key.
        let primary = self.setup_owner_primary()?;

        let tpm_auth_value = match auth_value {
            AuthValue::Key256Bit { auth_key } => Auth::from_bytes(auth_key.as_ref()),
        }
        .map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TssAuthValueInvalid
        })?;

        self.execute_with_temporary_object(
            primary.key_handle.into(),
            |hsm_ctx, primary_key_handle| {
                let (private, public) =
                    hsm_ctx.create_storage_key(Some(tpm_auth_value.clone()), primary_key_handle)?;

                // Now do a temporary load and create for the storage key.
                let key_handle = hsm_ctx
                    .tpm_ctx
                    .load(primary_key_handle.into(), private.clone(), public.clone())
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TssStorageKeyLoad
                    })?;

                // Now it's loaded, create the machine storage key
                let (sk_private, sk_public) = hsm_ctx.execute_with_temporary_object(
                    key_handle.into(),
                    |hsm_ctx, parent_key_handle| {
                        hsm_ctx
                            .tpm_ctx
                            .tr_set_auth(parent_key_handle, tpm_auth_value)
                            .map_err(|tpm_err| {
                                error!(?tpm_err);
                                TpmError::TssStorageKeyLoad
                            })?;

                        hsm_ctx.create_storage_key(None, parent_key_handle)
                    },
                )?;

                Ok(LoadableStorageKey::TpmAes128CfbV1 {
                    private: Some(private),
                    public: Some(public),
                    sk_private,
                    sk_public,
                })
            },
        )
    }

    // load root storage key
    fn root_storage_key_load(
        &mut self,
        auth_value: &AuthValue,
        lsk: &LoadableStorageKey,
    ) -> Result<StorageKey, TpmError> {
        match lsk {
            LoadableStorageKey::TpmAes128CfbV1 {
                private: Some(private),
                public: Some(public),
                sk_private,
                sk_public,
            } => {
                let primary = self.setup_owner_primary()?;

                let auth_value = match auth_value {
                    AuthValue::Key256Bit { auth_key } => Auth::from_bytes(auth_key.as_ref()),
                }
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TssAuthValueInvalid
                })?;

                // Load the root storage key. This is what has the authValue attached, which we
                // need to supply to use it.
                let root_key_handle = self.execute_with_temporary_object(
                    primary.key_handle.into(),
                    |hsm_ctx, primary_key_handle| {
                        hsm_ctx
                            .tpm_ctx
                            .load(primary_key_handle.into(), private.clone(), public.clone())
                            .map_err(|tpm_err| {
                                error!(?tpm_err);
                                TpmError::TssStorageKeyLoad
                            })
                    },
                )?;

                // At the end of this fn, root_key_handle is unloaded and our storage key
                // handle is ready to rock.
                let key_handle = self.execute_with_temporary_object(
                    root_key_handle.into(),
                    |hsm_ctx, root_key_handle| {
                        hsm_ctx
                            .tpm_ctx
                            .tr_set_auth(root_key_handle, auth_value.clone())
                            .map_err(|tpm_err| {
                                error!(?tpm_err);
                                TpmError::TssStorageKeyLoad
                            })?;

                        hsm_ctx
                            .tpm_ctx
                            .load(
                                root_key_handle.into(),
                                sk_private.clone(),
                                sk_public.clone(),
                            )
                            .map_err(|tpm_err| {
                                error!(?tpm_err);
                                TpmError::TssStorageKeyLoad
                            })
                    },
                )?;

                // Load the subordinate storage key. This is what roots our actual storage because
                // when you unload/load a context with an authValue you must always supply that
                // authValue. To reduce the need to keep authValue in memory and ship it around, we
                // have a subordinate key without an authValue that can only exist if the parent
                // with the authValue was supplied at least once.

                self.execute_with_temporary_object(key_handle.into(), |hsm_ctx, key_handle| {
                    hsm_ctx
                        .tpm_ctx
                        .context_save(key_handle)
                        .map(|key_context| StorageKey::Tpm { key_context })
                        .map_err(|tpm_err| {
                            error!(?tpm_err);
                            TpmError::TssStorageKeyLoad
                        })
                })
            }
            _ => Err(TpmError::IncorrectKeyType),
        }
    }

    // create a subordinate storage key.
    fn storage_key_create(
        &mut self,
        parent_key: &StorageKey,
    ) -> Result<LoadableStorageKey, TpmError> {
        let storage_key_context = match parent_key {
            StorageKey::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let (sk_private, sk_public) = self.execute_with_temporary_object_context(
            storage_key_context,
            |hsm_ctx, parent_key_handle| hsm_ctx.create_storage_key(None, parent_key_handle),
        )?;

        Ok(LoadableStorageKey::TpmAes128CfbV1 {
            private: None,
            public: None,
            sk_private,
            sk_public,
        })
    }

    fn storage_key_load(
        &mut self,
        parent_key: &StorageKey,
        lsk: &LoadableStorageKey,
    ) -> Result<StorageKey, TpmError> {
        let storage_key_context = match parent_key {
            StorageKey::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let LoadableStorageKey::TpmAes128CfbV1 {
            private: None,
            public: None,
            sk_private,
            sk_public,
        } = lsk
        else {
            return Err(TpmError::IncorrectKeyType);
        };

        self.execute_key_load_to_context(storage_key_context, sk_private.clone(), sk_public.clone())
            .map(|key_context| StorageKey::Tpm { key_context })
    }

    fn seal_data(
        &mut self,
        key: &StorageKey,
        data_to_seal: Zeroizing<Vec<u8>>,
    ) -> Result<SealedData, TpmError> {
        let storage_key_context = match key {
            StorageKey::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let content_encryption_key = aes256::new_key();

        let (data, tag, nonce) = wrap_aes256gcm!(&content_encryption_key, data_to_seal)?;

        let unsealed_key = SensitiveData::from_bytes(content_encryption_key.as_slice())
            .map_err(|_| TpmError::TssSealDataTooLarge)?;

        // Seal it.
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
            .with_user_with_auth(true)
            .build()
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TssKeyObjectAttributesInvalid
            })?;

        let key_pub = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
            .with_keyed_hash_unique_identifier(Digest::default())
            .build()
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TssKeyBuilderInvalid
            })?;

        self.execute_with_temporary_object_context(storage_key_context, |hsm_ctx, key_handle| {
            hsm_ctx
                .tpm_ctx
                .create(
                    key_handle.into(),
                    key_pub,
                    None,
                    Some(unsealed_key),
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
                        SealedData::TpmAes256GcmV2 {
                            private,
                            public,
                            data,
                            tag,
                            nonce,
                        }
                    },
                )
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TssSeal
                })
        })
    }

    fn unseal_data(
        &mut self,
        key: &StorageKey,
        data_to_unseal: &SealedData,
    ) -> Result<Zeroizing<Vec<u8>>, TpmError> {
        let storage_key_context = match key {
            StorageKey::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let SealedData::TpmAes256GcmV2 {
            private,
            public,
            data,
            tag,
            nonce,
        } = data_to_unseal
        else {
            return Err(TpmError::IncorrectKeyType);
        };

        let unsealed_key = self.execute_with_temporary_object_context(
            storage_key_context,
            |hsm_ctx, key_handle| {
                let sealed_object = hsm_ctx
                    .tpm_ctx
                    .load(key_handle.into(), private.clone(), public.clone())
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TssSealingKeyLoad
                    })?;

                hsm_ctx
                    .tpm_ctx
                    .unseal(sealed_object.into())
                    .map(|data| Vec::from(data.as_slice()))
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TssUnseal
                    })
            },
        )?;

        let content_encryption_key =
            aes256::key_from_vec(unsealed_key).ok_or(TpmError::Aes256KeyInvalid)?;

        unwrap_aes256gcm!(&content_encryption_key, data, tag, nonce)
    }
}

impl TpmHmacS256 for TssTpm {
    fn hmac_s256_create(
        &mut self,
        parent_key: &StorageKey,
    ) -> Result<LoadableHmacS256Key, TpmError> {
        let storage_key_context = match parent_key {
            StorageKey::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let unique_key_identifier = self
            .tpm_ctx
            .get_random(16)
            .and_then(|random| Digest::from_bytes(random.as_slice()))
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TssEntropy
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
                TpmError::TssHmacKeyObjectAttributesInvalid
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
                TpmError::TssHmacKeyBuilderInvalid
            })?;

        self.execute_with_temporary_object_context(
            storage_key_context,
            |hsm_ctx, storage_key_handle| {
                hsm_ctx
                    .tpm_ctx
                    .create(storage_key_handle.into(), key_pub, None, None, None, None)
                    .map(
                        |CreateKeyResult {
                             out_private: private,
                             out_public: public,
                             creation_data: _,
                             creation_hash: _,
                             creation_ticket: _,
                         }| {
                            LoadableHmacS256Key::TpmSha256V1 { private, public }
                        },
                    )
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TssHmacKeyCreate
                    })
            },
        )
    }

    fn hmac_s256_load(
        &mut self,
        parent_key: &StorageKey,
        hmac_key: &LoadableHmacS256Key,
    ) -> Result<HmacS256Key, TpmError> {
        let storage_key_context = match parent_key {
            StorageKey::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let LoadableHmacS256Key::TpmSha256V1 { private, public } = hmac_key else {
            return Err(TpmError::IncorrectKeyType);
        };

        self.execute_key_load_to_context(storage_key_context, private.clone(), public.clone())
            .map(|key_context| HmacS256Key::Tpm { key_context })
    }

    fn hmac_s256(
        &mut self,
        hmac_key: &HmacS256Key,
        data: &[u8],
    ) -> Result<HmacSha256Output, TpmError> {
        let (hmac_key_context, hmac_alg) = match hmac_key {
            HmacS256Key::Tpm { key_context } => (key_context, HashingAlgorithm::Sha256),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let data_buffer = MaxBuffer::from_bytes(data).map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TssHmacInputTooLarge
        })?;

        let digest = self.execute_with_temporary_object_context(
            hmac_key_context.clone(),
            |hsm_ctx, key_handle| {
                hsm_ctx
                    .tpm_ctx
                    .hmac(key_handle, data_buffer, hmac_alg)
                    .map(|digest| digest.as_bytes().to_vec())
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TssHmacSign
                    })
            },
        )?;

        let hmac_output = Sha256Output::from_exact_iter(digest.into_iter())
            .ok_or(TpmError::TssHmacOutputInvalid)?;

        Ok(HmacSha256Output::from(hmac_output))
    }
}

impl TpmPinHmacS256 for TssTpm {
    fn storage_key_create_pin_hmac_s256(
        &mut self,
        parent_key: &StorageKey,
        hmac_key: &HmacS256Key,
        pin: &PinValue,
    ) -> Result<LoadableStorageKey, TpmError> {
        let storage_key_context = match parent_key {
            StorageKey::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let hmac_output = self.hmac_s256(hmac_key, pin.value())?;
        let hmac_output = hmac_output.into_bytes();

        let tpm_auth_value = Auth::from_bytes(hmac_output.as_slice()).map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TssAuthValueInvalid
        })?;

        self.execute_with_temporary_object_context(
            storage_key_context,
            |hsm_ctx, parent_key_handle| {
                let (private, public) =
                    hsm_ctx.create_storage_key(Some(tpm_auth_value.clone()), parent_key_handle)?;

                // Now do a temporary load and create for the storage key.
                let key_handle = hsm_ctx
                    .tpm_ctx
                    .load(parent_key_handle.into(), private.clone(), public.clone())
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TssStorageKeyLoad
                    })?;

                // Now it's loaded, create the machine storage key
                let (sk_private, sk_public) = hsm_ctx.execute_with_temporary_object(
                    key_handle.into(),
                    |hsm_ctx, parent_key_handle| {
                        hsm_ctx
                            .tpm_ctx
                            .tr_set_auth(parent_key_handle, tpm_auth_value)
                            .map_err(|tpm_err| {
                                error!(?tpm_err);
                                TpmError::TssStorageKeyLoad
                            })?;

                        hsm_ctx.create_storage_key(None, parent_key_handle)
                    },
                )?;

                Ok(LoadableStorageKey::TpmAes128CfbV1 {
                    private: Some(private),
                    public: Some(public),
                    sk_private,
                    sk_public,
                })
            },
        )
    }

    fn storage_key_load_pin_hmac_s256(
        &mut self,
        parent_key: &StorageKey,
        hmac_key: &HmacS256Key,
        pin: &PinValue,
        lsk: &LoadableStorageKey,
    ) -> Result<StorageKey, TpmError> {
        let storage_key_context = match parent_key {
            StorageKey::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let LoadableStorageKey::TpmAes128CfbV1 {
            private: Some(private),
            public: Some(public),
            sk_private,
            sk_public,
        } = lsk
        else {
            return Err(TpmError::IncorrectKeyType);
        };

        let hmac_output = self.hmac_s256(hmac_key, pin.value())?;
        let hmac_output = hmac_output.into_bytes();

        let tpm_auth_value = Auth::from_bytes(hmac_output.as_slice()).map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TssAuthValueInvalid
        })?;

        let auth_parent_key_handle = self.execute_with_temporary_object_context(
            storage_key_context,
            |hsm_ctx, parent_key_handle| {
                hsm_ctx
                    .tpm_ctx
                    .load(parent_key_handle.into(), private.clone(), public.clone())
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TssStorageKeyLoad
                    })
            },
        )?;

        // At the end of this fn, root_key_handle is unloaded and our storage key
        // handle is ready to rock.
        let key_handle = self.execute_with_temporary_object(
            auth_parent_key_handle.into(),
            |hsm_ctx, auth_parent_key_handle| {
                hsm_ctx
                    .tpm_ctx
                    .tr_set_auth(auth_parent_key_handle, tpm_auth_value.clone())
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TssStorageKeyLoad
                    })?;

                hsm_ctx
                    .tpm_ctx
                    .load(
                        auth_parent_key_handle.into(),
                        sk_private.clone(),
                        sk_public.clone(),
                    )
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TssStorageKeyLoad
                    })
            },
        )?;

        self.execute_with_temporary_object(key_handle.into(), |hsm_ctx, key_handle| {
            hsm_ctx
                .tpm_ctx
                .context_save(key_handle)
                .map(|key_context| StorageKey::Tpm { key_context })
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TssStorageKeyLoad
                })
        })
    }
}

impl TpmES256 for TssTpm {
    fn es256_create(&mut self, parent_key: &StorageKey) -> Result<LoadableES256Key, TpmError> {
        let storage_key_context = match parent_key {
            StorageKey::Tpm { key_context } => key_context.clone(),
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
                TpmError::TssKeyObjectAttributesInvalid
            })?;

        let ecc_params = PublicEccParametersBuilder::new_unrestricted_signing_key(
            EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
            EccCurve::NistP256,
        )
        .build()
        .map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TssKeyAlgorithmInvalid
        })?;

        let key_pub = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_ecc_parameters(ecc_params)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TssKeyBuilderInvalid
            })?;

        self.execute_with_temporary_object_context(
            storage_key_context,
            |hsm_ctx, storage_key_handle| {
                hsm_ctx
                    .tpm_ctx
                    .create(storage_key_handle.into(), key_pub, None, None, None, None)
                    .map(
                        |CreateKeyResult {
                             out_private: private,
                             out_public: public,
                             creation_data: _,
                             creation_hash: _,
                             creation_ticket: _,
                         }| { LoadableES256Key::TpmV1 { private, public } },
                    )
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TssEs256KeyCreate
                    })
            },
        )
    }

    fn es256_load(
        &mut self,
        parent_key: &StorageKey,
        es256_key: &LoadableES256Key,
    ) -> Result<ES256Key, TpmError> {
        let storage_key_context = match parent_key {
            StorageKey::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let LoadableES256Key::TpmV1 { private, public } = es256_key else {
            return Err(TpmError::IncorrectKeyType);
        };

        self.execute_key_load_to_context(storage_key_context, private.clone(), public.clone())
            .map(|key_context| ES256Key::Tpm { key_context })
    }

    fn es256_public(&mut self, es256_key: &ES256Key) -> Result<EcdsaP256PublicKey, TpmError> {
        let es256_key_context = match es256_key {
            ES256Key::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let (public, _, _) = self.execute_with_temporary_object_context(
            es256_key_context,
            |hsm_ctx, key_handle| {
                hsm_ctx
                    .tpm_ctx
                    .read_public(key_handle.into())
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TssKeyReadPublic
                    })
            },
        )?;

        let Public::Ecc { unique, .. } = public else {
            return Err(TpmError::IncorrectKeyType);
        };

        let x = EcdsaP256PublicCoordinate::from_exact_iter(unique.x().as_slice().iter().copied());
        let y = EcdsaP256PublicCoordinate::from_exact_iter(unique.y().as_slice().iter().copied());

        let (Some(x), Some(y)) = (x, y) else {
            return Err(TpmError::TssEs256PublicCoordinatesInvalid);
        };

        let encoded_point = EcdsaP256PublicEncodedPoint::from_affine_coordinates(&x, &y, false);

        let maybe_pk = EcdsaP256PublicKey::from_encoded_point(&encoded_point);

        if maybe_pk.is_some().into() {
            Ok(maybe_pk.unwrap())
        } else {
            Err(TpmError::TssEs256PublicCoordinatesInvalid)
        }
    }

    fn es256_sign(
        &mut self,
        es256_key: &ES256Key,
        data: &[u8],
    ) -> Result<EcdsaP256Signature, TpmError> {
        let es256_key_context = match es256_key {
            ES256Key::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let sig_scheme = SignatureScheme::Null;

        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest_bytes: Sha256Output = hasher.finalize();

        let tpm_digest: Digest =
            Digest::from_bytes(digest_bytes.as_slice()).map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TssKeyDigest
            })?;

        // No need for hashcheck, unrestricted key.
        let validation: HashcheckTicket = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        }
        .try_into()
        .map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TssKeyDigest
        })?;

        // Now we can sign.
        let signature = self.execute_with_temporary_object_context(
            es256_key_context,
            |hsm_ctx, key_handle| {
                hsm_ctx
                    .tpm_ctx
                    .sign(key_handle.into(), tpm_digest, sig_scheme, validation)
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TssKeySign
                    })
            },
        )?;

        tracing::debug!(?signature);

        match signature {
            Signature::EcDsa(ecsig) => {
                let s = EcdsaP256PublicCoordinate::from_exact_iter(
                    ecsig.signature_s().as_slice().iter().copied(),
                );
                let r = EcdsaP256PublicCoordinate::from_exact_iter(
                    ecsig.signature_r().as_slice().iter().copied(),
                );

                let (Some(s), Some(r)) = (s, r) else {
                    return Err(TpmError::TssEs256SignatureCoordinatesInvalid);
                };

                EcdsaP256Signature::from_scalars(r, s)
                    .map_err(|_| TpmError::TssEs256SignatureCoordinatesInvalid)
            }
            _ => Err(TpmError::TssInvalidSignature),
        }
    }
}

impl TpmRS256 for TssTpm {
    fn rs256_create(&mut self, parent_key: &StorageKey) -> Result<LoadableRS256Key, TpmError> {
        let storage_key_context = match parent_key {
            StorageKey::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            // NEEDED FOR RSA OAEP
            .with_decrypt(true)
            .build()
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TssKeyObjectAttributesInvalid
            })?;

        let rsa_params = PublicRsaParametersBuilder::new()
            .with_scheme(RsaScheme::Null)
            .with_key_bits(RsaKeyBits::Rsa2048)
            .with_exponent(RsaExponent::default())
            .with_is_decryption_key(true)
            .with_is_signing_key(true)
            .with_restricted(false)
            .build()
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TssKeyAlgorithmInvalid
            })?;

        let key_pub = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_rsa_parameters(rsa_params)
            .with_rsa_unique_identifier(PublicKeyRsa::default())
            .build()
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TssKeyBuilderInvalid
            })?;

        self.execute_with_temporary_object_context(
            storage_key_context,
            |hsm_ctx, storage_key_handle| {
                hsm_ctx
                    .tpm_ctx
                    .create(storage_key_handle.into(), key_pub, None, None, None, None)
                    .map(
                        |CreateKeyResult {
                             out_private: private,
                             out_public: public,
                             creation_data: _,
                             creation_hash: _,
                             creation_ticket: _,
                         }| { LoadableRS256Key::TpmV1 { private, public } },
                    )
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TssRs256KeyCreate
                    })
            },
        )
    }

    fn rs256_load(
        &mut self,
        parent_key: &StorageKey,
        rs256_key: &LoadableRS256Key,
    ) -> Result<RS256Key, TpmError> {
        let storage_key_context = match parent_key {
            StorageKey::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let LoadableRS256Key::TpmV1 { private, public } = rs256_key else {
            return Err(TpmError::IncorrectKeyType);
        };

        self.execute_key_load_to_context(storage_key_context, private.clone(), public.clone())
            .map(|key_context| RS256Key::Tpm { key_context })
    }

    fn rs256_public(&mut self, rs256_key: &RS256Key) -> Result<RS256PublicKey, TpmError> {
        let rs256_key_context = match rs256_key {
            RS256Key::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let (public, _, _) = self.execute_with_temporary_object_context(
            rs256_key_context,
            |hsm_ctx, key_handle| {
                hsm_ctx
                    .tpm_ctx
                    .read_public(key_handle.into())
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TssKeyReadPublic
                    })
            },
        )?;

        let Public::Rsa {
            parameters: params,
            unique,
            ..
        } = public
        else {
            return Err(TpmError::IncorrectKeyType);
        };

        // This is a big endian signed value as expected
        let n = rsa::BigUint::from_bytes_be(unique.as_slice());

        // Gotcha https://docs.rs/tss-esapi/latest/src/tss_esapi/abstraction/public.rs.html#81
        // If value == 0, set default of 65537
        let mut e_u32 = params.exponent().value();
        if e_u32 == 0 {
            e_u32 = 65537;
        };

        RS256PublicKey::new(n, e_u32.into()).map_err(|_| TpmError::TssRsaPublicFromComponents)
    }

    fn rs256_sign(
        &mut self,
        rs256_key: &RS256Key,
        data: &[u8],
    ) -> Result<RS256Signature, TpmError> {
        let rs256_key_context = match rs256_key {
            RS256Key::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let sig_scheme = SignatureScheme::RsaSsa {
            scheme: HashScheme::new(HashingAlgorithm::Sha256),
        };

        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest_bytes: Sha256Output = hasher.finalize();

        let tpm_digest: Digest =
            Digest::from_bytes(digest_bytes.as_slice()).map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TssKeyDigest
            })?;

        // No need for hashcheck, unrestricted key.
        let validation: HashcheckTicket = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        }
        .try_into()
        .map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TssKeyDigest
        })?;

        // Now we can sign.
        let signature = self.execute_with_temporary_object_context(
            rs256_key_context,
            |hsm_ctx, key_handle| {
                hsm_ctx
                    .tpm_ctx
                    .sign(key_handle.into(), tpm_digest, sig_scheme, validation)
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TssKeySign
                    })
            },
        )?;

        tracing::debug!(?signature);

        match signature {
            Signature::RsaSsa(rsasig) => RS256Signature::try_from(rsasig.signature().as_slice())
                .map_err(|_| TpmError::TssRs256SignatureInvalid),
            _ => Err(TpmError::TssInvalidSignature),
        }
    }

    fn rs256_oaep_dec(
        &mut self,
        rs256_key: &RS256Key,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        let RS256Key::Tpm {
            key_context: rs256_key_context,
        } = rs256_key
        else {
            return Err(TpmError::IncorrectKeyType);
        };

        let encrypted_input = PublicKeyRsa::try_from(encrypted_data.to_vec())
            .map_err(|_| TpmError::TpmRs256OaepInvalidInputLength)?;

        self.execute_with_temporary_object_context(
            rs256_key_context.clone(),
            |hsm_ctx, key_handle| {
                hsm_ctx
                    .tpm_ctx
                    .rsa_decrypt(
                        key_handle.into(),
                        encrypted_input,
                        RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha256)),
                        Data::default(),
                    )
                    .map(|pk_rsa| pk_rsa.as_slice().to_vec())
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TssRs256OaepDecrypt
                    })
            },
        )
    }

    fn rs256_import(
        &mut self,
        _parent_key: &StorageKey,
        _private_key: RS256PrivateKey,
    ) -> Result<LoadableRS256Key, TpmError> {
        Err(TpmError::TssRs256ImportNotSupported)
    }

    fn rs256_unseal_data(
        &mut self,
        _key: &RS256Key,
        _sealed_data: &SealedData,
    ) -> Result<Zeroizing<Vec<u8>>, TpmError> {
        Err(TpmError::TssRs256UnsealNotSupported)
    }
}

impl TpmMsExtensions for TssTpm {
    fn rs256_oaep_dec_sha1(
        &mut self,
        rs256_key: &RS256Key,
        encrypted_data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, TpmError> {
        let RS256Key::Tpm {
            key_context: rs256_key_context,
        } = rs256_key
        else {
            return Err(TpmError::IncorrectKeyType);
        };

        let encrypted_input = PublicKeyRsa::try_from(encrypted_data.to_vec())
            .map_err(|_| TpmError::TpmRs256OaepInvalidInputLength)?;

        self.execute_with_temporary_object_context(
            rs256_key_context.clone(),
            |hsm_ctx, key_handle| {
                hsm_ctx
                    .tpm_ctx
                    .rsa_decrypt(
                        key_handle.into(),
                        encrypted_input,
                        RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha1)),
                        Data::default(),
                    )
                    .map(|pk_rsa| Zeroizing::new(pk_rsa.as_slice().to_vec()))
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TssRs256OaepDecrypt
                    })
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::TssTpm;

    #[test]
    fn tss_tpm_storage() {
        let tss_tpm = TssTpm::new("device:/dev/tpmrm0").unwrap();

        crate::tests::test_tpm_storage(tss_tpm);
    }

    #[test]
    fn tss_tpm_hmac() {
        let tss_tpm = TssTpm::new("device:/dev/tpmrm0").unwrap();

        crate::tests::test_tpm_hmac(tss_tpm);
    }

    #[test]
    fn tss_tpm_ecdsa_p256() {
        let tss_tpm = TssTpm::new("device:/dev/tpmrm0").unwrap();

        crate::tests::test_tpm_ecdsa_p256(tss_tpm);
    }

    #[test]
    fn tss_tpm_rs256() {
        let tss_tpm = TssTpm::new("device:/dev/tpmrm0").unwrap();

        crate::tests::test_tpm_rs256(tss_tpm);
    }

    #[test]
    fn tss_tpm_msoapxbc() {
        let tss_tpm = TssTpm::new("device:/dev/tpmrm0").unwrap();

        crate::tests::test_tpm_msoapxbc(tss_tpm);
    }
}
