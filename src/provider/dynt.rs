use crate::authvalue::AuthValue;
use crate::error::TpmError;
use crate::pin::PinValue;
use crate::provider::{Tpm,
    // TpmES256, TpmHmacS256,
    TpmMsExtensions, TpmRS256,
    TpmFullSupport,
    };
use crate::structures::{
    // ES256Key, HmacS256Key, LoadableES256Key, LoadableHmacS256Key, 
    LoadableRS256Key,
    LoadableStorageKey, RS256Key, SealedData, StorageKey,
};
use crypto_glue::{
    /*
    aes256::{self},
    aes256gcm::{
        self, AeadInPlace, Aes256Gcm, Aes256GcmN16, Aes256GcmNonce16, Aes256GcmTag, KeyInit,
    },
    ecdsa_p256::{
        self, EcdsaP256Digest, EcdsaP256PrivateKey, EcdsaP256PublicKey, EcdsaP256Signature,
        EcdsaP256SigningKey,
    },
    hmac_s256::{self, HmacSha256Output},
    */

    rsa::{RS256PrivateKey, RS256PublicKey, RS256Signature},
    traits::Zeroizing,
    /*
    s256,
    sha1,
    traits::*,
    // x509::Certificate,
    */
};


pub struct BoxedDynTpm(Box<dyn TpmFullSupport + 'static + Send>);

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

    fn rs256_sign(&mut self, rs256_key: &RS256Key, data: &[u8])
        -> Result<RS256Signature, TpmError> {
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




