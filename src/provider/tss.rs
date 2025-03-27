use std::str::FromStr;
use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::tss::TPM2_RH_NULL;
use tss_esapi::constants::tss::TPM2_ST_HASHCHECK;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::KeyHandle;
use tss_esapi::handles::ObjectHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{Auth, Private, Public};
use tss_esapi::structures::{
    CreateKeyResult, CreatePrimaryKeyResult, Digest, EccParameter, EccPoint, EccScheme,
    EccSignature, HashScheme, HashcheckTicket, KeyedHashScheme, MaxBuffer, PublicBuilder,
    PublicEccParametersBuilder, PublicKeyRsa, PublicKeyedHashParameters,
    PublicRsaParametersBuilder, RsaExponent, RsaScheme, RsaSignature, Signature, SignatureScheme,
    SymmetricCipherParameters, SymmetricDefinition, SymmetricDefinitionObject,
};
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;
use tss_esapi::utils::TpmsContext;
use tss_esapi::Context;
use tss_esapi::TctiNameConf;

use crate::authvalue::AuthValue;
use crate::error::TpmError;
use crate::pin::PinValue;
use crate::provider::{Tpm, TpmHmacS256};
use crate::structures::{HmacS256Key, LoadableHmacS256Key, LoadableStorageKey, StorageKey};
use tracing::error;

use crypto_glue::{
    hmac_s256::{self, HmacSha256Output},
    s256::Sha256Output,
};

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
                let (private, public) = hsm_ctx
                    .create_storage_key(Some(tpm_auth_value.clone()), primary_key_handle.into())?;

                // Now do a temporary load and create for the storage key.
                let key_handle = hsm_ctx
                    .tpm_ctx
                    .load(primary_key_handle.into(), private.clone(), public.clone())
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        assert!(false);
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
                                assert!(false);
                                TpmError::TssStorageKeyLoad
                            })?;

                        hsm_ctx.create_storage_key(None, parent_key_handle.into())
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

        // Remember this isn't loaded and can't be used yet!
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
                                assert!(false);
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
                                assert!(false);
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
                                assert!(false);
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
                            assert!(false);
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
            |hsm_ctx, parent_key_handle| hsm_ctx.create_storage_key(None, parent_key_handle.into()),
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

        let (sk_private, sk_public) = match lsk {
            LoadableStorageKey::TpmAes128CfbV1 {
                private: None,
                public: None,
                sk_private,
                sk_public,
            } => (sk_private, sk_public),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        self.execute_key_load_to_context(storage_key_context, sk_private.clone(), sk_public.clone())
            .map(|key_context| StorageKey::Tpm { key_context })
    }

    // Create a storage key that has a pin value to protect it.
    fn storage_key_create_pin(
        &mut self,
        parent_key: &StorageKey,
        pin: &PinValue,
    ) -> Result<LoadableStorageKey, TpmError> {
        let storage_key_context = match parent_key {
            StorageKey::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let tpm_auth_value = Auth::from_bytes(pin.value()).map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TssAuthValueInvalid
        })?;

        self.execute_with_temporary_object_context(
            storage_key_context,
            |hsm_ctx, parent_key_handle| {
                let (private, public) = hsm_ctx
                    .create_storage_key(Some(tpm_auth_value.clone()), parent_key_handle.into())?;

                // Now do a temporary load and create for the storage key.
                let key_handle = hsm_ctx
                    .tpm_ctx
                    .load(parent_key_handle.into(), private.clone(), public.clone())
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        assert!(false);
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
                                assert!(false);
                                TpmError::TssStorageKeyLoad
                            })?;

                        hsm_ctx.create_storage_key(None, parent_key_handle.into())
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

    fn storage_key_load_pin(
        &mut self,
        parent_key: &StorageKey,
        pin: &PinValue,
        lsk: &LoadableStorageKey,
    ) -> Result<StorageKey, TpmError> {
        let storage_key_context = match parent_key {
            StorageKey::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let (private, public, sk_private, sk_public) = match lsk {
            LoadableStorageKey::TpmAes128CfbV1 {
                private: Some(private),
                public: Some(public),
                sk_private,
                sk_public,
            } => (private, public, sk_private, sk_public),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let tpm_auth_value = Auth::from_bytes(pin.value()).map_err(|tpm_err| {
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
                        assert!(false);
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
                        assert!(false);
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
                        assert!(false);
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
                    assert!(false);
                    TpmError::TssStorageKeyLoad
                })
        })
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

        let (private, public) = match hmac_key {
            LoadableHmacS256Key::TpmSha256V1 { private, public } => (private, public),
            _ => return Err(TpmError::IncorrectKeyType),
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
}
