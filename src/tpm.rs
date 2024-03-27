use crate::{
    AuthValue, HmacKey, IdentityKey, KeyAlgorithm, LoadableHmacKey, LoadableIdentityKey,
    LoadableMachineKey, MachineKey, PinValue, Tpm, TpmError,
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
    CreateKeyResult, CreatePrimaryKeyResult, Digest, EccParameter, EccPoint, EccScheme,
    EccSignature, HashScheme, HashcheckTicket, KeyedHashScheme, MaxBuffer, PublicBuilder,
    PublicEccParametersBuilder, PublicKeyRsa, PublicKeyedHashParameters,
    PublicRsaParametersBuilder, RsaExponent, RsaScheme, RsaSignature, Signature, SignatureScheme,
    SymmetricCipherParameters, SymmetricDefinition, SymmetricDefinitionObject,
};
use tss_esapi::Context;
use tss_esapi::TctiNameConf;

use tss_esapi::interface_types::reserved_handles::Hierarchy;
// use tss_esapi::interface_types::resource_handles::Hierarchy;

use tss_esapi::constants::tss::TPM2_RH_NULL;
use tss_esapi::constants::tss::TPM2_ST_HASHCHECK;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;

use tss_esapi::handles::ObjectHandle;

pub use tss_esapi::handles::KeyHandle;
pub use tss_esapi::structures::{Auth, Private, Public};
// pub use tss_esapi::utils::TpmsContext;
pub use tss_esapi::structures::SavedTpmContext as TpmsContext;

#[cfg(feature = "msextensions")]
use crate::soft::{aes_256_gcm_decrypt, aes_256_gcm_encrypt};
#[cfg(feature = "msextensions")]
use crate::{
    LoadableMsOapxbcRsaKey, LoadableMsOapxbcSessionKey, MsOapxbcRsaKey, SealedData,
    AES256GCM_IV_LEN, AES256GCM_KEY_LEN,
};
#[cfg(feature = "msextensions")]
use tss_esapi::structures::{Data, RsaDecryptionScheme, SensitiveData};
#[cfg(feature = "msextensions")]
use zeroize::Zeroizing;

use std::str::FromStr;

impl TryInto<Auth> for &PinValue {
    type Error = TpmError;

    fn try_into(self) -> Result<Auth, Self::Error> {
        Auth::from_bytes(self.value.as_slice()).map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TpmAuthValueInvalid
        })
    }
}

pub struct TpmTss {
    tpm_ctx: Context,
    _auth_session: AuthSession,
}

// It is possible in some cases you may get:
// [  200.968893] tpm tpm0: tpm2_save_context: failed with a TPM error 0x0901
// [  200.972263] tpm tpm0: A TPM error (459) occurred flushing context
// [  200.974210] tpm tpm0: tpm2_commit_space: error -14
//
// This is a bug in the linux kernel resource manager. It seems not to be an issue
// for unixd, but it could be an issue with himmelblau with a lot of keys in flight.
//
// see also: https://github.com/tpm2-software/tpm2-tools/issues/2279
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

impl Drop for TpmTss {
    fn drop(&mut self) {
        // Drop the auth_session if possible.
        self.tpm_ctx.clear_sessions();
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
                TpmError::TpmStorageKeyObjectAttributesInvalid
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
                TpmError::TpmStorageKeyBuilderInvalid
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
                        TpmError::TpmKeyLoad
                    })
            },
        )?;

        // The object is now loaded, and the parent key has been released. Now we can
        // save the context for the child key so that we don't fill up objectMemory in
        // the context.
        self.execute_with_temporary_object(key_handle.into(), |hsm_ctx, key_handle| {
            hsm_ctx.tpm_ctx.context_save(key_handle).map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmContextSave
            })
        })
    }

    fn public_ecdsa_to_der(&mut self, key_context: TpmsContext) -> Result<Vec<u8>, TpmError> {
        use openssl::bn;
        use openssl::ec;
        use openssl::nid;

        let (public, _, _) =
            self.execute_with_temporary_object_context(key_context, |hsm_ctx, key_handle| {
                hsm_ctx
                    .tpm_ctx
                    .read_public(key_handle.into())
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TpmMsRsaKeyReadPublic
                    })
            })?;

        let Public::Ecc { unique, .. } = public else {
            return Err(TpmError::IncorrectKeyType);
        };

        let curve = nid::Nid::X9_62_PRIME256V1;
        let ec_group = ec::EcGroup::from_curve_name(curve).map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::EcdsaPublicFromComponents
        })?;

        let xbn = bn::BigNum::from_slice(unique.x().as_slice()).map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::EcdsaPublicFromComponents
        })?;

        let ybn = bn::BigNum::from_slice(unique.y().as_slice()).map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::EcdsaPublicFromComponents
        })?;

        let pkey = ec::EcKey::from_public_key_affine_coordinates(&ec_group, &xbn, &ybn).map_err(
            |ossl_err| {
                error!(?ossl_err);
                TpmError::EcdsaPublicFromComponents
            },
        )?;

        pkey.public_key_to_der().map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::EcdsaPublicToDer
        })
    }

    fn public_rsa_to_der(&mut self, key_context: TpmsContext) -> Result<Vec<u8>, TpmError> {
        let (public, _, _) =
            self.execute_with_temporary_object_context(key_context, |hsm_ctx, key_handle| {
                hsm_ctx
                    .tpm_ctx
                    .read_public(key_handle.into())
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TpmMsRsaKeyReadPublic
                    })
            })?;

        let Public::Rsa {
            parameters: params,
            unique,
            ..
        } = public
        else {
            return Err(TpmError::IncorrectKeyType);
        };

        // This is a big endian signed value as expected
        let n = BigNum::from_slice(unique.as_slice()).map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::RsaPublicFromComponents
        })?;

        // Gotcha https://docs.rs/tss-esapi/latest/src/tss_esapi/abstraction/public.rs.html#81
        // If value == 0, set default of 65537
        let mut e_u32 = params.exponent().value();
        if e_u32 == 0 {
            e_u32 = 65537;
        };

        let e = BigNum::from_u32(e_u32).map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::RsaPublicFromComponents
        })?;

        let rsa_public = openssl::rsa::Rsa::from_public_components(n, e).map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::RsaPublicFromComponents
        })?;

        rsa_public.public_key_to_der().map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::RsaPublicToDer
        })
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
                let key_pub = Self::create_storage_key_public()?;

                let tpm_auth_value = match auth_value {
                    AuthValue::Key256Bit { auth_key } => Auth::from_bytes(auth_key.as_ref()),
                }
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TpmAuthValueInvalid
                })?;

                let (private, public) = hsm_ctx
                    .tpm_ctx
                    .create(
                        primary_key_handle.into(),
                        key_pub,
                        Some(tpm_auth_value.clone()),
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
                        TpmError::TpmMachineKeyCreate
                    })?;

                let storage_key_pub = Self::create_storage_key_public()?;

                // Now do a temporary load and create for the storage key.
                let key_handle = hsm_ctx
                    .tpm_ctx
                    .load(primary_key_handle.into(), private.clone(), public.clone())
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TpmMachineKeyLoad
                    })?;

                // Now it's loaded, create the machine storage key
                let (sk_private, sk_public) = hsm_ctx.execute_with_temporary_object(
                    key_handle.into(),
                    |hsm_ctx, mk_key_handle| {
                        hsm_ctx
                            .tpm_ctx
                            .tr_set_auth(mk_key_handle, tpm_auth_value.clone())
                            .map_err(|tpm_err| {
                                error!(?tpm_err);
                                TpmError::TpmMachineKeyLoad
                            })?;

                        hsm_ctx
                            .tpm_ctx
                            .create(key_handle, storage_key_pub, None, None, None, None)
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
                                TpmError::TpmMachineKeyCreate
                            })
                    },
                )?;

                Ok(LoadableMachineKey::TpmAes128CfbV1 {
                    private,
                    public,
                    sk_private,
                    sk_public,
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
        match loadable_key {
            LoadableMachineKey::TpmAes128CfbV1 {
                private,
                public,
                sk_private,
                sk_public,
            } => {
                let primary = self.setup_owner_primary()?;

                let auth_value = match auth_value {
                    AuthValue::Key256Bit { auth_key } => Auth::from_bytes(auth_key.as_ref()),
                }
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TpmAuthValueInvalid
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
                                TpmError::TpmMachineKeyLoad
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
                                TpmError::TpmMachineKeyLoad
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
                                TpmError::TpmMachineKeyLoad
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
                        .map(|key_context| MachineKey::Tpm { key_context })
                        .map_err(|tpm_err| {
                            error!(?tpm_err);
                            TpmError::TpmMachineKeyLoad
                        })
                })
            }
            _ => Err(TpmError::IncorrectKeyType),
        }
    }

    fn hmac_key_create(&mut self, mk: &MachineKey) -> Result<LoadableHmacKey, TpmError> {
        let mk_key_context = match mk {
            MachineKey::Tpm { key_context } => key_context.clone(),
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

        self.execute_with_temporary_object_context(mk_key_context, |hsm_ctx, mk_key_handle| {
            hsm_ctx
                .tpm_ctx
                .create(mk_key_handle.into(), key_pub, None, None, None, None)
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

        let mk_key_context = match mk {
            MachineKey::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        self.execute_key_load_to_context(mk_key_context, private, public)
            .map(|key_context| HmacKey::TpmSha256 { key_context })
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
                .hmac(key_handle, data_buffer, hk_alg)
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
        pin_value: Option<&PinValue>,
        algorithm: KeyAlgorithm,
    ) -> Result<LoadableIdentityKey, TpmError> {
        let mk_key_context = match mk {
            MachineKey::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let storage_key_pub = Self::create_storage_key_public()?;

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
                    RsaScheme::RsaSsa(HashScheme::new(HashingAlgorithm::Sha256)),
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

        // Now the auth_value is optional, so we don't need special pathing for
        // if it's present or not, since the tpm interfaces expect this to be an
        // option type anyway. If we set it at create, it's required during load,
        // if it's not set here, then it's not needed during load.
        //
        // Realistically we should just say "it's required".
        let auth_value = pin_value.map(|pv| pv.try_into()).transpose()?;

        self.execute_with_temporary_object_context(mk_key_context, |hsm_ctx, mk_key_handle| {
            // Create the storage key - this is what actually has the auth_value
            // associated to it.
            let (sk_private, sk_public) = hsm_ctx
                .tpm_ctx
                .create(
                    mk_key_handle.into(),
                    storage_key_pub,
                    auth_value.clone(),
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
                    TpmError::TpmMachineKeyCreate
                })?;

            // Now do a temporary load for the storage key.
            let storage_key_handle = hsm_ctx
                .tpm_ctx
                .load(mk_key_handle.into(), sk_private.clone(), sk_public.clone())
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TpmMachineKeyLoad
                })?;

            // Create the ID key private/public.
            let (private, public) = hsm_ctx.execute_with_temporary_object(
                storage_key_handle.into(),
                |hsm_ctx, sk_key_handle| {
                    if let Some(av) = auth_value {
                        hsm_ctx
                            .tpm_ctx
                            .tr_set_auth(sk_key_handle, av)
                            .map_err(|tpm_err| {
                                error!(?tpm_err);
                                TpmError::TpmMachineKeyLoad
                            })?;
                    }

                    hsm_ctx
                        .tpm_ctx
                        .create(sk_key_handle.into(), key_pub, None, None, None, None)
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
                            TpmError::TpmMachineKeyCreate
                        })
                },
            )?;

            // Now assign everything to it's structures.

            Ok(match algorithm {
                KeyAlgorithm::Ecdsa256 => LoadableIdentityKey::TpmEcdsa256V1 {
                    private,
                    public,
                    sk_private,
                    sk_public,
                    x509: None,
                },
                KeyAlgorithm::Rsa2048 => LoadableIdentityKey::TpmRsa2048V1 {
                    private,
                    public,
                    sk_private,
                    sk_public,
                    x509: None,
                },
            })
        })
    }

    fn identity_key_load(
        &mut self,
        mk: &MachineKey,
        pin_value: Option<&PinValue>,
        loadable_key: &LoadableIdentityKey,
    ) -> Result<IdentityKey, TpmError> {
        let (private, public, sk_private, sk_public, algorithm, x509) = match loadable_key {
            LoadableIdentityKey::TpmEcdsa256V1 {
                private,
                public,
                sk_private,
                sk_public,
                x509,
            } => (
                private.clone(),
                public.clone(),
                sk_private.clone(),
                sk_public.clone(),
                KeyAlgorithm::Ecdsa256,
                x509.as_ref(),
            ),
            LoadableIdentityKey::TpmRsa2048V1 {
                private,
                public,
                sk_private,
                sk_public,
                x509,
            } => (
                private.clone(),
                public.clone(),
                sk_private.clone(),
                sk_public.clone(),
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

        let mk_key_context = match mk {
            MachineKey::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let auth_value = pin_value.map(|pv| pv.try_into()).transpose()?;

        // Load the storage key. This is what has the authValue attached, which we
        // need to supply to use it.
        let storage_key_handle = self.execute_with_temporary_object_context(
            mk_key_context,
            |hsm_ctx, mk_key_handle| {
                hsm_ctx
                    .tpm_ctx
                    .load(mk_key_handle.into(), sk_private.clone(), sk_public.clone())
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TpmKeyLoad
                    })
            },
        )?;

        // At the end of this fn, storage_key_handle is unloaded and our identity key
        // handle is ready to rock.
        let key_handle = self.execute_with_temporary_object(
            storage_key_handle.into(),
            |hsm_ctx, sk_key_handle| {
                // Authenticate to the storage key if we have an auth_value
                if let Some(av) = auth_value.clone() {
                    hsm_ctx
                        .tpm_ctx
                        .tr_set_auth(sk_key_handle, av)
                        .map_err(|tpm_err| {
                            error!(?tpm_err);
                            TpmError::TpmKeyLoad
                        })?;
                }

                // Load the real key now.
                hsm_ctx
                    .tpm_ctx
                    .load(sk_key_handle.into(), private.clone(), public.clone())
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TpmKeyLoad
                    })
            },
        )?;

        self.execute_with_temporary_object(key_handle.into(), |hsm_ctx, key_handle| {
            hsm_ctx
                .tpm_ctx
                .context_save(key_handle)
                .map(|key_context| match algorithm {
                    KeyAlgorithm::Ecdsa256 => IdentityKey::TpmEcdsa256 { key_context, x509 },
                    KeyAlgorithm::Rsa2048 => IdentityKey::TpmRsa2048 { key_context, x509 },
                })
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TpmKeyLoad
                })
        })
    }

    fn identity_key_id(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        let key_context = match key {
            IdentityKey::TpmEcdsa256 {
                key_context,
                x509: _,
            } => key_context.clone(),
            IdentityKey::TpmRsa2048 {
                key_context,
                x509: _,
            } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        self.execute_with_temporary_object_context(key_context, |hsm_ctx, key_handle| {
            hsm_ctx
                .tpm_ctx
                .read_public(key_handle.into())
                .map(|(_, name, _qualified_name)| name.value().to_vec())
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TpmIdentityKeyId
                })
        })
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
                SignatureScheme::RsaSsa {
                    scheme: HashScheme::new(HashingAlgorithm::Sha256),
                },
                MessageDigest::sha256(),
            ),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        // Future, may need to change this size for non sha256
        // Hash the input.
        let bytes = hash(digest_alg, input).map_err(|ossl_err| {
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
        .map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::IdentityKeyDigest
        })?;

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
            Signature::RsaSsa(rsasig) => Ok(rsasig.signature().to_vec()),
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

                let tpm_signature = Signature::RsaSsa(rsa_sig);

                (key_context.clone(), tpm_signature, MessageDigest::sha256())
            }
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let bytes = hash(digest_alg, input).map_err(|ossl_err| {
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
        _auth_value: Option<&PinValue>,
        _loadable_key: &LoadableIdentityKey,
        _cn: &str,
    ) -> Result<Vec<u8>, TpmError> {
        Err(TpmError::TpmOperationUnsupported)
    }

    fn identity_key_associate_certificate(
        &mut self,
        _mk: &MachineKey,
        _auth_value: Option<&PinValue>,
        _loadable_key: &LoadableIdentityKey,
        _certificate_der: &[u8],
    ) -> Result<LoadableIdentityKey, TpmError> {
        Err(TpmError::TpmOperationUnsupported)
    }

    fn identity_key_public_as_der(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        match key {
            IdentityKey::TpmEcdsa256 {
                key_context,
                x509: _,
            } => self.public_ecdsa_to_der(key_context.clone()),
            IdentityKey::TpmRsa2048 {
                key_context,
                x509: _,
            } => self.public_rsa_to_der(key_context.clone()),
            _ => Err(TpmError::IncorrectKeyType),
        }
    }

    fn identity_key_public_as_pem(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        let pkey_der = self.identity_key_public_as_der(key)?;
        openssl::pkey::PKey::public_key_from_der(&pkey_der)
            .and_then(|pkey| pkey.public_key_to_pem())
            .map_err(|ossl_err| {
                error!(?ossl_err);
                TpmError::IdentityKeyPublicToPem
            })
    }

    fn identity_key_x509_as_pem(&mut self, _key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        Err(TpmError::TpmOperationUnsupported)
    }

    fn identity_key_x509_as_der(&mut self, _key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        Err(TpmError::TpmOperationUnsupported)
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_key_create(
        &mut self,
        mk: &MachineKey,
    ) -> Result<LoadableMsOapxbcRsaKey, TpmError> {
        let mk_key_context = match mk {
            MachineKey::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .with_decrypt(true)
            .build()
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmMsRsaKeyObjectAttributesInvalid
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
                TpmError::TpmMsRsaKeyAlgorithmInvalid
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
                TpmError::TpmMsRsaKeyBuilderInvalid
            })?;

        let (private, public) = self.execute_with_temporary_object_context(
            mk_key_context.clone(),
            |hsm_ctx, mk_key_handle| {
                hsm_ctx
                    .tpm_ctx
                    .create(mk_key_handle.into(), key_pub, None, None, None, None)
                    .map(
                        |CreateKeyResult {
                             out_private: private,
                             out_public: public,
                             creation_data: _,
                             creation_hash: _,
                             creation_ticket: _,
                         }| (private, public),
                    )
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TpmMsRsaKeyCreate
                    })
            },
        )?;

        let key_pub = Self::create_storage_key_public()?;

        self.execute_with_temporary_object_context(mk_key_context, |hsm_ctx, mk_key_handle| {
            hsm_ctx
                .tpm_ctx
                .create(mk_key_handle.into(), key_pub, None, None, None, None)
                .map(
                    |CreateKeyResult {
                         out_private: cek_private,
                         out_public: cek_public,
                         creation_data: _,
                         creation_hash: _,
                         creation_ticket: _,
                     }| {
                        LoadableMsOapxbcRsaKey::TpmRsa2048V1 {
                            private,
                            public,
                            cek_private,
                            cek_public,
                        }
                    },
                )
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TpmMsRsaKeyCreate
                })
        })
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_key_import(
        &mut self,
        _mk: &MachineKey,
        _private_key: openssl::rsa::Rsa<openssl::pkey::Private>,
    ) -> Result<LoadableMsOapxbcRsaKey, TpmError> {
        Err(TpmError::TpmOperationUnsupported)
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_key_load(
        &mut self,
        mk: &MachineKey,
        loadable_key: &LoadableMsOapxbcRsaKey,
    ) -> Result<MsOapxbcRsaKey, TpmError> {
        let (private, public, cek_private, cek_public) = match loadable_key {
            LoadableMsOapxbcRsaKey::TpmRsa2048V1 {
                private,
                public,
                cek_private,
                cek_public,
            } => (
                private.clone(),
                public.clone(),
                cek_private.clone(),
                cek_public.clone(),
            ),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let mk_key_context = match mk {
            MachineKey::Tpm { key_context } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let cek_context =
            self.execute_key_load_to_context(mk_key_context.clone(), cek_private, cek_public)?;

        tracing::trace!("cek context created");

        self.execute_key_load_to_context(mk_key_context, private, public)
            .map(|key_context| MsOapxbcRsaKey::Tpm {
                key_context,
                cek_context,
            })
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_public_as_der(&mut self, key: &MsOapxbcRsaKey) -> Result<Vec<u8>, TpmError> {
        let key_context = match key {
            MsOapxbcRsaKey::Tpm {
                key_context,
                cek_context: _,
            } => key_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        self.public_rsa_to_der(key_context)
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_decipher_session_key(
        &mut self,
        key: &MsOapxbcRsaKey,
        input: &[u8],
        expected_key_len: usize,
    ) -> Result<LoadableMsOapxbcSessionKey, TpmError> {
        let (key_context, cek_context) = match key {
            MsOapxbcRsaKey::Tpm {
                key_context,
                cek_context,
            } => (key_context.clone(), cek_context.clone()),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let encrypted_input = PublicKeyRsa::try_from(input.to_vec())
            .map_err(|_| TpmError::TpmMsRsaOaepInvalidKeyLength)?;

        let decrypted_session_key = self.execute_with_temporary_object_context(
            key_context.clone(),
            |hsm_ctx, key_handle| {
                hsm_ctx
                    .tpm_ctx
                    .rsa_decrypt(
                        key_handle.into(),
                        encrypted_input,
                        RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha1)),
                        Data::default(),
                    )
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        TpmError::TpmMsRsaOaepDecrypt
                    })
            },
        )?;

        // Truncate - note this is a slice, and everything here is zeroizing.
        // to minimise exposure.
        let session_key = decrypted_session_key
            .get(0..expected_key_len)
            .ok_or(TpmError::TpmMsRsaOaepInvalidKeyLength)?;

        let session_key = SensitiveData::try_from(session_key.to_vec())
            .map_err(|_| TpmError::TpmMsRsaOaepInvalidKeyLength)?;

        // Seal it.
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
            .with_user_with_auth(true)
            .build()
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmMsRsaKeyObjectAttributesInvalid
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
                TpmError::TpmMsRsaKeyObjectAttributesInvalid
            })?;

        // NOTE: We use the cek_context here to seal the data against since the RSA key
        // can not act as a storage key.
        self.execute_with_temporary_object_context(cek_context, |hsm_ctx, key_handle| {
            hsm_ctx
                .tpm_ctx
                .create(
                    key_handle.into(),
                    key_pub,
                    None,
                    Some(session_key),
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
                        LoadableMsOapxbcSessionKey::TpmV1 { private, public }
                    },
                )
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TpmMsRsaSeal
                })
        })
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_yield_session_key(
        &mut self,
        key: &MsOapxbcRsaKey,
        session_key: &LoadableMsOapxbcSessionKey,
    ) -> Result<Zeroizing<Vec<u8>>, TpmError> {
        let key_context = match key {
            MsOapxbcRsaKey::Tpm {
                key_context: _,
                cek_context,
            } => cek_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let (private, public) = match session_key {
            LoadableMsOapxbcSessionKey::TpmV1 { private, public } => {
                (private.clone(), public.clone())
            }
            _ => return Err(TpmError::IncorrectKeyType),
        };

        self.execute_with_temporary_object_context(key_context, |hsm_ctx, key_handle| {
            let sealed_object = hsm_ctx
                .tpm_ctx
                .load(key_handle.into(), private, public)
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TpmMsRsaKeyLoad
                })?;

            hsm_ctx
                .tpm_ctx
                .unseal(sealed_object.into())
                .map(|data| Zeroizing::new(Vec::from(data.as_slice())))
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TpmMsRsaUnseal
                })
        })
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_seal_data(
        &mut self,
        key: &MsOapxbcRsaKey,
        data: &[u8],
    ) -> Result<SealedData, TpmError> {
        let cek_context = match key {
            MsOapxbcRsaKey::Tpm {
                key_context: _,
                cek_context,
            } => cek_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let mut iv = [0; AES256GCM_IV_LEN];
        self.tpm_ctx
            .get_random(AES256GCM_IV_LEN)
            .map(|random| iv.copy_from_slice(random.as_slice()))
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmEntropy
            })?;

        let unsealed_key = self
            .tpm_ctx
            .get_random(AES256GCM_KEY_LEN)
            .and_then(|random| SensitiveData::from_bytes(random.as_slice()))
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmEntropy
            })?;

        let (data, tag) = aes_256_gcm_encrypt(data, unsealed_key.as_slice(), &iv)?;

        // Seal it.
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
            .with_user_with_auth(true)
            .build()
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmMsRsaKeyObjectAttributesInvalid
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
                TpmError::TpmMsRsaKeyObjectAttributesInvalid
            })?;

        self.execute_with_temporary_object_context(cek_context, |hsm_ctx, key_handle| {
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
                        SealedData::TpmV1 {
                            private,
                            public,
                            data,
                            tag,
                            iv,
                        }
                    },
                )
                .map_err(|tpm_err| {
                    error!(?tpm_err);
                    TpmError::TpmMsRsaSeal
                })
        })
    }

    #[cfg(feature = "msextensions")]
    fn msoapxbc_rsa_unseal_data(
        &mut self,
        key: &MsOapxbcRsaKey,
        sealed_data: &SealedData,
    ) -> Result<Zeroizing<Vec<u8>>, TpmError> {
        let key_context = match key {
            MsOapxbcRsaKey::Tpm {
                key_context: _,
                cek_context,
            } => cek_context.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        match sealed_data {
            SealedData::TpmV1 {
                private,
                public,
                data,
                tag,
                iv,
            } => {
                let unsealed_key = self.execute_with_temporary_object_context(
                    key_context,
                    |hsm_ctx, key_handle| {
                        let sealed_object = hsm_ctx
                            .tpm_ctx
                            .load(key_handle.into(), private.clone(), public.clone())
                            .map_err(|tpm_err| {
                                error!(?tpm_err);
                                TpmError::TpmMsRsaKeyLoad
                            })?;

                        hsm_ctx
                            .tpm_ctx
                            .unseal(sealed_object.into())
                            .map(|data| Zeroizing::new(Vec::from(data.as_slice())))
                            .map_err(|tpm_err| {
                                error!(?tpm_err);
                                TpmError::TpmMsRsaUnseal
                            })
                    },
                )?;

                // Decrypt now.
                aes_256_gcm_decrypt(data, tag, unsealed_key.as_slice(), iv)
            }
            _ => Err(TpmError::IncorrectKeyType),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TpmTss;
    use crate::KeyAlgorithm;
    use crate::PinValue;

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

        let pin_value = None;

        crate::test_tpm_identity!(hsm, KeyAlgorithm::Ecdsa256, pin_value);
    }

    #[test]
    fn tpm_identity_rsa2048_hw_bound() {
        // Create the Hsm.
        let mut hsm = TpmTss::new("device:/dev/tpmrm0").expect("Unable to build Tpm Context");

        let pin_value = None;

        crate::test_tpm_identity!(hsm, KeyAlgorithm::Rsa2048, pin_value);
    }

    #[test]
    fn tpm_identity_ecdsa256_pin_hw_bound() {
        let mut hsm = TpmTss::new("device:/dev/tpmrm0").expect("Unable to build Tpm Context");

        let pin_value = Some(PinValue::new("12345678").expect("Invalid Pin"));

        crate::test_tpm_identity!(hsm, KeyAlgorithm::Ecdsa256, pin_value);
    }

    #[test]
    fn tpm_identity_rsa2048_pin_hw_bound() {
        // Create the Hsm.
        let mut hsm = TpmTss::new("device:/dev/tpmrm0").expect("Unable to build Tpm Context");

        let pin_value = Some(PinValue::new("12345678").expect("Invalid Pin"));

        crate::test_tpm_identity!(hsm, KeyAlgorithm::Rsa2048, pin_value);
    }
}

#[cfg(all(test, feature = "msextensions"))]
mod ms_extn_tests {
    use super::TpmTss;

    #[test]
    fn tpm_ms_extensions() {
        let mut hsm = TpmTss::new("device:/dev/tpmrm0").expect("Unable to build Tpm Context");

        crate::test_tpm_ms_extensions!(hsm);
    }
}
