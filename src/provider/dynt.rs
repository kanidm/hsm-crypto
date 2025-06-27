use crate::authvalue::AuthValue;
use crate::error::TpmError;
use crate::pin::PinValue;
use crate::provider::{Tpm, TpmES256, TpmFullSupport, TpmMsExtensions, TpmRS256};
use crate::structures::{
    ES256Key, LoadableES256Key, LoadableRS256Key, LoadableStorageKey, RS256Key, SealedData,
    StorageKey,
};
use crypto_glue::{
    ecdsa_p256::{EcdsaP256PublicKey, EcdsaP256Signature},
    rsa::{RS256PrivateKey, RS256PublicKey, RS256Signature},
    traits::Zeroizing,
};

pub struct BoxedDynTpm(Box<dyn TpmFullSupport + 'static + Send>);

impl BoxedDynTpm {
    pub fn new<T>(tpm: T) -> Self
    where
        T: TpmFullSupport + 'static + Send,
    {
        Self::from(tpm)
    }
}

impl<T> From<T> for BoxedDynTpm
where
    T: TpmFullSupport + 'static + Send,
{
    fn from(tpm: T) -> Self {
        BoxedDynTpm(Box::new(tpm))
    }
}

impl std::ops::Deref for BoxedDynTpm {
    type Target = dyn TpmFullSupport;

    // Required method
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl std::ops::DerefMut for BoxedDynTpm {
    // Required method
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut()
    }
}

impl Tpm for BoxedDynTpm {
    fn root_storage_key_create(
        &mut self,
        auth_value: &AuthValue,
    ) -> Result<LoadableStorageKey, TpmError> {
        self.0.root_storage_key_create(auth_value)
    }

    fn root_storage_key_load(
        &mut self,
        auth_value: &AuthValue,
        lsk: &LoadableStorageKey,
    ) -> Result<StorageKey, TpmError> {
        self.0.root_storage_key_load(auth_value, lsk)
    }

    fn storage_key_create(
        &mut self,
        parent_key: &StorageKey,
    ) -> Result<LoadableStorageKey, TpmError> {
        self.0.storage_key_create(parent_key)
    }

    fn storage_key_load(
        &mut self,
        parent_key: &StorageKey,
        lsk: &LoadableStorageKey,
    ) -> Result<StorageKey, TpmError> {
        self.0.storage_key_load(parent_key, lsk)
    }

    fn storage_key_create_pin(
        &mut self,
        parent_key: &StorageKey,
        pin: &PinValue,
    ) -> Result<LoadableStorageKey, TpmError> {
        self.0.storage_key_create_pin(parent_key, pin)
    }

    fn storage_key_load_pin(
        &mut self,
        parent_key: &StorageKey,
        pin: &PinValue,
        lsk: &LoadableStorageKey,
    ) -> Result<StorageKey, TpmError> {
        self.0.storage_key_load_pin(parent_key, pin, lsk)
    }

    fn seal_data(
        &mut self,
        key: &StorageKey,
        data_to_seal: Zeroizing<Vec<u8>>,
    ) -> Result<SealedData, TpmError> {
        self.0.seal_data(key, data_to_seal)
    }

    fn unseal_data(
        &mut self,
        key: &StorageKey,
        sealed_data: &SealedData,
    ) -> Result<Zeroizing<Vec<u8>>, TpmError> {
        self.0.unseal_data(key, sealed_data)
    }
}

impl TpmES256 for BoxedDynTpm {
    fn es256_create(&mut self, parent_key: &StorageKey) -> Result<LoadableES256Key, TpmError> {
        self.0.es256_create(parent_key)
    }

    fn es256_load(
        &mut self,
        parent_key: &StorageKey,
        loadable_es256_key: &LoadableES256Key,
    ) -> Result<ES256Key, TpmError> {
        self.0.es256_load(parent_key, loadable_es256_key)
    }

    fn es256_public(&mut self, es256_key: &ES256Key) -> Result<EcdsaP256PublicKey, TpmError> {
        self.0.es256_public(es256_key)
    }

    fn es256_sign(
        &mut self,
        es256_key: &ES256Key,
        data: &[u8],
    ) -> Result<EcdsaP256Signature, TpmError> {
        self.0.es256_sign(es256_key, data)
    }
}

impl TpmRS256 for BoxedDynTpm {
    fn rs256_create(&mut self, parent_key: &StorageKey) -> Result<LoadableRS256Key, TpmError> {
        self.0.rs256_create(parent_key)
    }

    fn rs256_load(
        &mut self,
        parent_key: &StorageKey,
        loadable_rs256_key: &LoadableRS256Key,
    ) -> Result<RS256Key, TpmError> {
        self.0.rs256_load(parent_key, loadable_rs256_key)
    }

    fn rs256_public(&mut self, rs256_key: &RS256Key) -> Result<RS256PublicKey, TpmError> {
        self.0.rs256_public(rs256_key)
    }

    fn rs256_sign(
        &mut self,
        rs256_key: &RS256Key,
        data: &[u8],
    ) -> Result<RS256Signature, TpmError> {
        self.0.rs256_sign(rs256_key, data)
    }

    fn rs256_import(
        &mut self,
        parent_key: &StorageKey,
        private_key: RS256PrivateKey,
    ) -> Result<LoadableRS256Key, TpmError> {
        self.0.rs256_import(parent_key, private_key)
    }

    fn rs256_oaep_dec(
        &mut self,
        rs256_key: &RS256Key,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        self.0.rs256_oaep_dec(rs256_key, encrypted_data)
    }
}

impl TpmMsExtensions for BoxedDynTpm {
    fn rs256_oaep_dec_sha1(
        &mut self,
        rs256_key: &RS256Key,
        encrypted_data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, TpmError> {
        self.0.rs256_oaep_dec_sha1(rs256_key, encrypted_data)
    }

    fn rs256_yield_cek(&mut self, key: &RS256Key) -> Option<StorageKey> {
        self.0.rs256_yield_cek(key)
    }
}
