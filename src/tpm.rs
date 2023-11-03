use crate::{
    AuthValue, HmacKey, Hsm, HsmError, IdentityKey, KeyAlgorithm, LoadableHmacKey,
    LoadableIdentityKey, LoadableMachineKey, MachineKey,
};
// use serde::{Deserialize, Serialize};
use tracing::error;

use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::structures::{
    Auth, CreateKeyResult, CreatePrimaryKeyResult, Digest, KeyedHashScheme, MaxBuffer,
    PublicBuilder, PublicKeyedHashParameters, SymmetricCipherParameters, SymmetricDefinitionObject,
};
use tss_esapi::Context;

use tss_esapi::interface_types::resource_handles::Hierarchy;

use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};

pub use tss_esapi::handles::KeyHandle;
pub use tss_esapi::structures::{Private, Public};
pub use tss_esapi::TctiNameConf;

pub struct TpmHsm {
    tpm_ctx: Context,
}

impl TpmHsm {
    pub fn new(name_conf: TctiNameConf) -> Result<Self, HsmError> {
        Context::new(name_conf)
            .map_err(|tpm_err| {
                error!(?tpm_err);
                HsmError::TpmContextCreate
            })
            .map(|tpm_ctx| TpmHsm { tpm_ctx })
    }
}

impl TpmHsm {
    fn setup_owner_primary(&mut self) -> Result<CreatePrimaryKeyResult, HsmError> {
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
                HsmError::TpmPrimaryObjectAttributesInvalid
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
                HsmError::TpmPrimaryPublicBuilderInvalid
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
                HsmError::TpmPrimaryCreate
            })
    }
}

impl Hsm for TpmHsm {
    fn machine_key_create(
        &mut self,
        auth_value: &AuthValue,
    ) -> Result<LoadableMachineKey, HsmError> {
        // Setup the primary key.
        let primary = self.setup_owner_primary()?;

        // Create the Machine Key.
        let unique_key_identifier = self
            .tpm_ctx
            .get_random(16)
            .and_then(|random| Digest::try_from(random.as_slice()))
            .map_err(|tpm_err| {
                error!(?tpm_err);
                HsmError::TpmEntropy
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
                HsmError::TpmMachineKeyObjectAttributesInvalid
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
                HsmError::TpmMachineKeyBuilderInvalid
            })?;

        let tpm_auth_value = match auth_value {
            AuthValue::Key256Bit { auth_key } => Auth::try_from(auth_key.as_ref()),
        }
        .map_err(|tpm_err| {
            error!(?tpm_err);
            HsmError::TpmAuthValueInvalid
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
                HsmError::TpmMachineKeyCreate
            })

        // Remember this isn't loaded and can't be used yet!
    }

    fn machine_key_load(
        &mut self,
        auth_value: &AuthValue,
        loadable_key: &LoadableMachineKey,
    ) -> Result<MachineKey, HsmError> {
        let (private, public) = match loadable_key {
            LoadableMachineKey::TpmAes128CfbV1 { private, public } => {
                (private.clone(), public.clone())
            }
            _ => return Err(HsmError::IncorrectKeyType),
        };

        // Was this cleared in the former stages?
        let primary = self.setup_owner_primary()?;

        let tpm_auth_value = match auth_value {
            AuthValue::Key256Bit { auth_key } => Auth::try_from(auth_key.as_ref()),
        }
        .map_err(|tpm_err| {
            error!(?tpm_err);
            HsmError::TpmAuthValueInvalid
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
                HsmError::TpmMachineKeyLoad
            })
    }

    fn hmac_key_create(&mut self, mk: &MachineKey) -> Result<LoadableHmacKey, HsmError> {
        let mk_key_handle = match mk {
            MachineKey::Tpm { key_handle } => key_handle.clone(),
            _ => return Err(HsmError::IncorrectKeyType),
        };

        let unique_key_identifier = self
            .tpm_ctx
            .get_random(16)
            .and_then(|random| Digest::try_from(random.as_slice()))
            .map_err(|tpm_err| {
                error!(?tpm_err);
                HsmError::TpmEntropy
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
                HsmError::TpmHmacKeyObjectAttributesInvalid
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
                HsmError::TpmHmacKeyBuilderInvalid
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
                HsmError::TpmHmacKeyCreate
            })
    }

    fn hmac_key_load(
        &mut self,
        mk: &MachineKey,
        loadable_key: &LoadableHmacKey,
    ) -> Result<HmacKey, HsmError> {
        let (private, public) = match loadable_key {
            LoadableHmacKey::TpmSha256V1 { private, public } => (private.clone(), public.clone()),
            _ => return Err(HsmError::IncorrectKeyType),
        };

        let mk_key_handle = match mk {
            MachineKey::Tpm { key_handle } => key_handle.clone(),
            _ => return Err(HsmError::IncorrectKeyType),
        };

        self.tpm_ctx
            .execute_with_nullauth_session(|ctx| ctx.load(mk_key_handle, private, public))
            .map(|key_handle| HmacKey::TpmSha256 { key_handle })
            .map_err(|tpm_err| {
                error!(?tpm_err);
                HsmError::TpmHmacKeyLoad
            })
    }

    fn hmac(&mut self, hk: &HmacKey, input: &[u8]) -> Result<Vec<u8>, HsmError> {
        let (hk_key_handle, hk_alg) = match hk {
            HmacKey::TpmSha256 { key_handle } => (key_handle.clone(), HashingAlgorithm::Sha256),
            _ => return Err(HsmError::IncorrectKeyType),
        };

        let data_buffer = MaxBuffer::try_from(input).map_err(|tpm_err| {
            error!(?tpm_err);
            HsmError::TpmHmacInputTooLarge
        })?;

        self.tpm_ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.hmac(hk_key_handle.into(), data_buffer, hk_alg)
            })
            .map(|digest| digest.value().to_vec())
            .map_err(|tpm_err| {
                error!(?tpm_err);
                HsmError::TpmHmacSign
            })
    }

    fn identity_key_create(
        &mut self,
        _mk: &MachineKey,
        _algorithm: KeyAlgorithm,
    ) -> Result<LoadableIdentityKey, HsmError> {
        Err(HsmError::TpmOperationUnsupported)
    }

    fn identity_key_load(
        &mut self,
        _mk: &MachineKey,
        _loadable_key: &LoadableIdentityKey,
    ) -> Result<IdentityKey, HsmError> {
        Err(HsmError::TpmOperationUnsupported)
    }

    fn identity_key_sign(
        &mut self,
        _key: &IdentityKey,
        _input: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::TpmOperationUnsupported)
    }

    fn identity_key_certificate_request(
        &mut self,
        _mk: &MachineKey,
        _loadable_key: &LoadableIdentityKey,
        _cn: &str,
    ) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::TpmOperationUnsupported)
    }

    fn identity_key_associate_certificate(
        &mut self,
        _mk: &MachineKey,
        _loadable_key: &LoadableIdentityKey,
        _certificate_der: &[u8],
    ) -> Result<LoadableIdentityKey, HsmError> {
        Err(HsmError::TpmOperationUnsupported)
    }

    fn identity_key_public_as_der(&mut self, _key: &IdentityKey) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::TpmOperationUnsupported)
    }

    fn identity_key_public_as_pem(&mut self, _key: &IdentityKey) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::TpmOperationUnsupported)
    }

    fn identity_key_x509_as_pem(&mut self, _key: &IdentityKey) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::TpmOperationUnsupported)
    }

    fn identity_key_x509_as_der(&mut self, _key: &IdentityKey) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::TpmOperationUnsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::{TctiNameConf, TpmHsm};
    use crate::{AuthValue, Hsm};
    use std::str::FromStr;
    use tracing::trace;

    #[test]
    fn tpm_hmac_hw_bound() {
        let _ = tracing_subscriber::fmt::try_init();

        let tpm_name_config =
            TctiNameConf::from_str("device:/dev/tpmrm0").expect("Failed to get TCTI");

        // Create the Hsm.
        let mut hsm = TpmHsm::new(tpm_name_config.clone()).expect("Unable to build Tpm Context");

        // Create a new random auth_value.
        let auth_value = AuthValue::new_random().expect("Failed to generate new random secret");

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
        let mut hsm = TpmHsm::new(tpm_name_config).expect("Unable to build Tpm Context");

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
}
