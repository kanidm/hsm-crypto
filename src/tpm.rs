use crate::{Hsm, HsmError};
// use serde::{Deserialize, Serialize};
use tracing::error;

use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::handles::KeyHandle;
use tss_esapi::structures::{
    CreateKeyResult, CreatePrimaryKeyResult, Digest, KeyedHashScheme, MaxBuffer,
    Private as TpmPrivate, Public as TpmPublic, PublicBuilder, PublicKeyedHashParameters,
    SymmetricCipherParameters, SymmetricDefinitionObject,
};
use tss_esapi::Context;

use tss_esapi::interface_types::resource_handles::Hierarchy;

use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};

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

// No need to be an enum, tpms internally do the switching
// over keyhandles for us.
pub struct TpmMachineKey {
    key_handle: KeyHandle,
}

// TODO: How can we serialise this?
#[derive(Debug, Clone)]
pub enum TpmLoadableMachineKey {
    Aes128CfbV1 {
        private: TpmPrivate,
        public: TpmPublic,
    },
}

// This needs to be an enum so we can switch on the hash algo.
pub enum TpmHmacKey {
    Sha256 { key_handle: KeyHandle },
}

#[derive(Debug, Clone)]
pub enum TpmLoadableHmacKey {
    Sha256V1 {
        private: TpmPrivate,
        public: TpmPublic,
    },
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
    type MachineKey = TpmMachineKey;
    type LoadableMachineKey = TpmLoadableMachineKey;

    type HmacKey = TpmHmacKey;
    type LoadableHmacKey = TpmLoadableHmacKey;

    fn machine_key_create(&mut self) -> Result<Self::LoadableMachineKey, HsmError> {
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

        self.tpm_ctx
            .execute_with_nullauth_session(|ctx_outer| {
                ctx_outer.execute_with_temporary_object(
                    primary.key_handle.into(),
                    |ctx, object_handle| {
                        ctx.create(object_handle.into(), key_pub, None, None, None, None)
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
                 }| { TpmLoadableMachineKey::Aes128CfbV1 { private, public } },
            )
            .map_err(|tpm_err| {
                error!(?tpm_err);
                HsmError::TpmMachineKeyCreate
            })

        // Remember this isn't loaded and can't be used yet!
    }

    fn machine_key_load(
        &mut self,
        loadable_key: &Self::LoadableMachineKey,
    ) -> Result<Self::MachineKey, HsmError> {
        // Was this cleared in the former stages?
        let primary = self.setup_owner_primary()?;

        self.tpm_ctx
            .execute_with_nullauth_session(|ctx_outer| {
                ctx_outer.execute_with_temporary_object(
                    primary.key_handle.into(),
                    |ctx, object_handle| match loadable_key {
                        TpmLoadableMachineKey::Aes128CfbV1 { private, public } => {
                            ctx.load(object_handle.into(), private.clone(), public.clone())
                        }
                    },
                )
            })
            .map(|key_handle| TpmMachineKey { key_handle })
            .map_err(|tpm_err| {
                error!(?tpm_err);
                HsmError::TpmMachineKeyLoad
            })
    }

    fn hmac_key_create(
        &mut self,
        mk: &Self::MachineKey,
    ) -> Result<Self::LoadableHmacKey, HsmError> {
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
                ctx.create(mk.key_handle.clone(), key_pub, None, None, None, None)
            })
            .map(
                |CreateKeyResult {
                     out_private: private,
                     out_public: public,
                     creation_data: _,
                     creation_hash: _,
                     creation_ticket: _,
                 }| { TpmLoadableHmacKey::Sha256V1 { private, public } },
            )
            .map_err(|tpm_err| {
                error!(?tpm_err);
                HsmError::TpmHmacKeyCreate
            })
    }

    fn hmac_key_load(
        &mut self,
        mk: &Self::MachineKey,
        loadable_key: &Self::LoadableHmacKey,
    ) -> Result<Self::HmacKey, HsmError> {
        self.tpm_ctx
            .execute_with_nullauth_session(|ctx| match loadable_key {
                TpmLoadableHmacKey::Sha256V1 { private, public } => {
                    ctx.load(mk.key_handle.clone(), private.clone(), public.clone())
                }
            })
            .map(|key_handle| TpmHmacKey::Sha256 { key_handle })
            .map_err(|tpm_err| {
                error!(?tpm_err);
                HsmError::TpmHmacKeyLoad
            })
    }

    fn hmac(&mut self, hk: &Self::HmacKey, input: &[u8]) -> Result<Vec<u8>, HsmError> {
        let data_buffer = MaxBuffer::try_from(input).map_err(|tpm_err| {
            error!(?tpm_err);
            HsmError::TpmHmacInputTooLarge
        })?;

        self.tpm_ctx
            .execute_with_nullauth_session(|ctx| match hk {
                TpmHmacKey::Sha256 { key_handle } => ctx.hmac(
                    key_handle.clone().into(),
                    data_buffer,
                    HashingAlgorithm::Sha256,
                ),
            })
            .map(|digest| digest.value().to_vec())
            .map_err(|tpm_err| {
                error!(?tpm_err);
                HsmError::TpmHmacSign
            })
    }
}

#[cfg(test)]
mod tests {
    use super::{TctiNameConf, TpmHsm};
    use crate::Hsm;
    use std::str::FromStr;
    use tracing::trace;

    #[test]
    fn tpm_hmac_hw_bound() {
        let _ = tracing_subscriber::fmt::try_init();

        let tpm_name_config =
            TctiNameConf::from_str("device:/dev/tpmrm0").expect("Failed to get TCTI");

        // Create the Hsm.
        let mut hsm = TpmHsm::new(tpm_name_config.clone()).expect("Unable to build Tpm Context");

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
        let mut hsm = TpmHsm::new(tpm_name_config).expect("Unable to build Tpm Context");

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
