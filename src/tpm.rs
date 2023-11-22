use crate::{
    AuthValue, HmacKey, IdentityKey, KeyAlgorithm, LoadableHmacKey, LoadableIdentityKey,
    LoadableMachineKey, MachineKey, Tpm, TpmError,
};
// use serde::{Deserialize, Serialize};
use tracing::error;

use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::structures::{
    Auth, CreateKeyResult, CreatePrimaryKeyResult, Digest, KeyedHashScheme, MaxBuffer,
    PublicBuilder, PublicKeyedHashParameters, SymmetricCipherParameters, SymmetricDefinitionObject,
};
use tss_esapi::Context;
use tss_esapi::TctiNameConf;

use tss_esapi::interface_types::resource_handles::Hierarchy;

use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};

pub use tss_esapi::handles::KeyHandle;
pub use tss_esapi::structures::{Private, Public};

use std::str::FromStr;

pub struct TpmTss {
    tpm_ctx: Context,
}

impl TpmTss {
    pub fn new(tcti_name: &str) -> Result<Self, TpmError> {
        let tpm_name_config = TctiNameConf::from_str(tcti_name).map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TpmTctiNameInvalid
        })?;

        Context::new(tpm_name_config)
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmContextCreate
            })
            .map(|tpm_ctx| TpmTss { tpm_ctx })
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

        self.tpm_ctx
            .execute_with_nullauth_session(|ctx| {
                // Create the key under the "owner" hierarchy. Other hierarchies are platform
                // which is for boot services, null which is ephemeral and resets after a reboot,
                // and endorsement which allows key certification by the TPM manufacturer.
                ctx.create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
            })
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmPrimaryCreate
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

        // Create the Machine Key.
        let unique_key_identifier = self
            .tpm_ctx
            .get_random(16)
            .and_then(|random| Digest::try_from(random.as_slice()))
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
            AuthValue::Key256Bit { auth_key } => Auth::try_from(auth_key.as_ref()),
        }
        .map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TpmAuthValueInvalid
        })?;

        self.tpm_ctx
            .execute_with_nullauth_session(|ctx_outer| {
                ctx_outer.execute_with_temporary_object(
                    primary.key_handle.into(),
                    |ctx, object_handle| {
                        ctx.create(
                            object_handle.into(),
                            key_pub,
                            Some(tpm_auth_value),
                            None,
                            None,
                            None,
                        )
                    },
                )
            })
            .map(
                |CreateKeyResult {
                     out_private: private,
                     out_public: public,
                     creation_data: _,
                     creation_hash: _,
                     creation_ticket: _,
                 }| { LoadableMachineKey::TpmAes128CfbV1 { private, public } },
            )
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmMachineKeyCreate
            })

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

        let tpm_auth_value = match auth_value {
            AuthValue::Key256Bit { auth_key } => Auth::try_from(auth_key.as_ref()),
        }
        .map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TpmAuthValueInvalid
        })?;

        self.tpm_ctx
            .execute_with_nullauth_session(|ctx_outer| {
                ctx_outer.execute_with_temporary_object(
                    primary.key_handle.into(),
                    |ctx, object_handle| {
                        ctx.load(object_handle.into(), private.clone(), public.clone())
                            .and_then(|key_handle| {
                                ctx.tr_set_auth(key_handle.into(), tpm_auth_value)
                                    .map(|()| key_handle)
                            })
                    },
                )
            })
            .map(|key_handle| MachineKey::Tpm { key_handle })
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmMachineKeyLoad
            })
    }

    fn hmac_key_create(&mut self, mk: &MachineKey) -> Result<LoadableHmacKey, TpmError> {
        let mk_key_handle = match mk {
            MachineKey::Tpm { key_handle } => key_handle.clone(),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let unique_key_identifier = self
            .tpm_ctx
            .get_random(16)
            .and_then(|random| Digest::try_from(random.as_slice()))
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
            .execute_with_nullauth_session(|ctx| {
                ctx.create(mk_key_handle, key_pub, None, None, None, None)
            })
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

        self.tpm_ctx
            .execute_with_nullauth_session(|ctx| ctx.load(mk_key_handle, private, public))
            .map(|key_handle| HmacKey::TpmSha256 { key_handle })
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmHmacKeyLoad
            })
    }

    fn hmac(&mut self, hk: &HmacKey, input: &[u8]) -> Result<Vec<u8>, TpmError> {
        let (hk_key_handle, hk_alg) = match hk {
            HmacKey::TpmSha256 { key_handle } => (key_handle.clone(), HashingAlgorithm::Sha256),
            _ => return Err(TpmError::IncorrectKeyType),
        };

        let data_buffer = MaxBuffer::try_from(input).map_err(|tpm_err| {
            error!(?tpm_err);
            TpmError::TpmHmacInputTooLarge
        })?;

        self.tpm_ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.hmac(hk_key_handle.into(), data_buffer, hk_alg)
            })
            .map(|digest| digest.value().to_vec())
            .map_err(|tpm_err| {
                error!(?tpm_err);
                TpmError::TpmHmacSign
            })
    }

    fn identity_key_create(
        &mut self,
        _mk: &MachineKey,
        _algorithm: KeyAlgorithm,
    ) -> Result<LoadableIdentityKey, TpmError> {
        Err(TpmError::TpmOperationUnsupported)
    }

    fn identity_key_load(
        &mut self,
        _mk: &MachineKey,
        _loadable_key: &LoadableIdentityKey,
    ) -> Result<IdentityKey, TpmError> {
        Err(TpmError::TpmOperationUnsupported)
    }

    fn identity_key_id(&mut self, _key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        Err(TpmError::TpmOperationUnsupported)
    }

    fn identity_key_sign(
        &mut self,
        _key: &IdentityKey,
        _input: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        Err(TpmError::TpmOperationUnsupported)
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

    #[test]
    fn tpm_hmac_hw_bound() {
        let _ = tracing_subscriber::fmt::try_init();

        // Create the Hsm.
        let mut hsm_a = TpmTss::new("device:/dev/tpmrm0").expect("Unable to build Tpm Context");

        // Make a new Hsm context.
        let mut hsm_b = TpmTss::new("device:/dev/tpmrm0").expect("Unable to build Tpm Context");

        crate::test_tpm_hmac!(hsm_a, hsm_b);
    }
}
