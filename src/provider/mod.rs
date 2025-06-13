use crate::authvalue::AuthValue;
use crate::error::TpmError;
use crate::pin::PinValue;
use crate::structures::LoadableMsHelloKey;
use crate::structures::SealedData;
use crate::structures::{ES256Key, LoadableES256Key};
use crate::structures::{HmacS256Key, LoadableHmacS256Key};
use crate::structures::{
    LoadableMsDeviceEnrolmentKey, LoadableMsOapxbcRsaKey, MsInProgressEnrolment,
};
use crate::structures::{LoadableRS256Key, RS256Key};
use crate::structures::{LoadableStorageKey, StorageKey};
use crypto_glue::ecdsa_p256::{EcdsaP256PublicKey, EcdsaP256Signature, EcdsaP256VerifyingKey};
use crypto_glue::hmac_s256::HmacSha256Output;
use crypto_glue::rand;
use crypto_glue::rsa::{self, RS256PrivateKey, RS256PublicKey, RS256Signature, RS256VerifyingKey};
use crypto_glue::s256::{self, Sha256Output};
use crypto_glue::sha1;
use crypto_glue::spki;
use crypto_glue::traits::*;
use crypto_glue::x509::{
    self, BitString, Builder, Certificate, CertificateRequest, CertificateRequestBuilder,
};
use std::str::FromStr;

mod soft;
pub use self::soft::SoftTpm;

#[cfg(feature = "tpm")]
mod tss;
#[cfg(feature = "tpm")]
pub use self::tss::TssTpm;

mod dynt;
pub use self::dynt::BoxedDynTpm;

// This is a super trait which defines full tpm feature support.
pub trait TpmFullSupport: Tpm + TpmRS256 + TpmMsExtensions {}

pub trait Tpm {
    fn root_storage_key_create(
        &mut self,
        auth_value: &AuthValue,
    ) -> Result<LoadableStorageKey, TpmError>;

    fn root_storage_key_load(
        &mut self,
        auth_value: &AuthValue,
        lsk: &LoadableStorageKey,
    ) -> Result<StorageKey, TpmError>;

    fn storage_key_create(
        &mut self,
        parent_key: &StorageKey,
    ) -> Result<LoadableStorageKey, TpmError>;

    fn storage_key_load(
        &mut self,
        parent_key: &StorageKey,
        lsk: &LoadableStorageKey,
    ) -> Result<StorageKey, TpmError>;

    fn storage_key_create_pin(
        &mut self,
        parent_key: &StorageKey,
        pin: &PinValue,
    ) -> Result<LoadableStorageKey, TpmError>;

    fn storage_key_load_pin(
        &mut self,
        parent_key: &StorageKey,
        pin: &PinValue,
        lsk: &LoadableStorageKey,
    ) -> Result<StorageKey, TpmError>;

    fn seal_data(
        &mut self,
        key: &StorageKey,
        data_to_seal: Zeroizing<Vec<u8>>,
    ) -> Result<SealedData, TpmError>;

    fn unseal_data(
        &mut self,
        key: &StorageKey,
        sealed_data: &SealedData,
    ) -> Result<Zeroizing<Vec<u8>>, TpmError>;
}

pub trait TpmHmacS256 {
    fn hmac_s256_create(
        &mut self,
        parent_key: &StorageKey,
    ) -> Result<LoadableHmacS256Key, TpmError>;

    fn hmac_s256_load(
        &mut self,
        parent_key: &StorageKey,
        hmac_key: &LoadableHmacS256Key,
    ) -> Result<HmacS256Key, TpmError>;

    fn hmac_s256(
        &mut self,
        hmac_key: &HmacS256Key,
        data: &[u8],
    ) -> Result<HmacSha256Output, TpmError>;
}

pub struct TpmES256Keypair {
    verifier: EcdsaP256VerifyingKey,
}

impl Keypair for TpmES256Keypair {
    type VerifyingKey = EcdsaP256VerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.verifier
    }
}

impl spki::DynSignatureAlgorithmIdentifier for TpmES256Keypair {
    fn signature_algorithm_identifier(
        &self,
    ) -> Result<spki::AlgorithmIdentifierOwned, spki::Error> {
        self.verifier.signature_algorithm_identifier()
    }
}

pub trait TpmES256 {
    fn es256_create(&mut self, parent_key: &StorageKey) -> Result<LoadableES256Key, TpmError>;

    fn es256_load(
        &mut self,
        parent_key: &StorageKey,
        hmac_key: &LoadableES256Key,
    ) -> Result<ES256Key, TpmError>;

    fn es256_public(&mut self, es256_key: &ES256Key) -> Result<EcdsaP256PublicKey, TpmError>;

    fn es256_sign(
        &mut self,
        es256_key: &ES256Key,
        data: &[u8],
    ) -> Result<EcdsaP256Signature, TpmError>;

    // ====== Generic implementations ======
    fn es256_fingerprint(&mut self, es256_key: &ES256Key) -> Result<Sha256Output, TpmError> {
        self.es256_public(es256_key).map(|pub_key| {
            let mut hasher = s256::Sha256::new();
            hasher.update(pub_key.to_sec1_bytes());
            hasher.finalize()
        })
    }

    fn es256_public_der(&mut self, es256_key: &ES256Key) -> Result<Vec<u8>, TpmError> {
        self.es256_public(es256_key)?
            .to_public_key_der()
            .map(|asn1_der| asn1_der.to_vec())
            .map_err(|_| TpmError::EcdsaPublicToDer)
    }

    fn es256_public_pem(&mut self, es256_key: &ES256Key) -> Result<String, TpmError> {
        self.es256_public(es256_key)?
            .to_public_key_pem(Default::default())
            .map_err(|_| TpmError::EcdsaPublicToPem)
    }

    fn es256_sign_to_bitstring(
        &mut self,
        es256_key: &ES256Key,
        data: &[u8],
    ) -> Result<BitString, TpmError> {
        let signature = self.es256_sign(es256_key, data)?;

        BitString::new(0, signature.to_vec()).map_err(|_| TpmError::AsnBitStringInvalid)
    }

    fn es256_verify(
        &mut self,
        es256_key: &ES256Key,
        data: &[u8],
        sig: &EcdsaP256Signature,
    ) -> Result<bool, TpmError> {
        let pub_key = self.es256_public(es256_key)?;

        let verifier = EcdsaP256VerifyingKey::from(&pub_key);

        Ok(verifier.verify(data, sig).is_ok())
    }

    fn es256_keypair(&mut self, es256_key: &ES256Key) -> Result<TpmES256Keypair, TpmError> {
        let pub_key = self.es256_public(es256_key)?;

        let verifier = EcdsaP256VerifyingKey::from(&pub_key);

        Ok(TpmES256Keypair { verifier })
    }
}

pub struct TpmRS256Keypair {
    verifier: RS256VerifyingKey,
}

impl Keypair for TpmRS256Keypair {
    type VerifyingKey = RS256VerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.verifier.clone()
    }
}

impl spki::DynSignatureAlgorithmIdentifier for TpmRS256Keypair {
    fn signature_algorithm_identifier(
        &self,
    ) -> Result<spki::AlgorithmIdentifierOwned, spki::Error> {
        self.verifier.signature_algorithm_identifier()
    }
}

pub trait TpmRS256 {
    fn rs256_create(&mut self, parent_key: &StorageKey) -> Result<LoadableRS256Key, TpmError>;

    fn rs256_load(
        &mut self,
        parent_key: &StorageKey,
        loadable_rs256_key: &LoadableRS256Key,
    ) -> Result<RS256Key, TpmError>;

    fn rs256_public(&mut self, rs256_key: &RS256Key) -> Result<RS256PublicKey, TpmError>;

    fn rs256_sign(&mut self, rs256_key: &RS256Key, data: &[u8])
        -> Result<RS256Signature, TpmError>;

    fn rs256_import(
        &mut self,
        parent_key: &StorageKey,
        private_key: RS256PrivateKey,
    ) -> Result<LoadableRS256Key, TpmError>;

    fn rs256_oaep_dec(
        &mut self,
        rs256_key: &RS256Key,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>, TpmError>;

    // ====== Generic implementations ======
    // oaep enc/dec
    fn rs256_oaep_enc(&mut self, rs256_key: &RS256Key, data: &[u8]) -> Result<Vec<u8>, TpmError> {
        let public_key = self.rs256_public(rs256_key)?;
        let padding = rsa::Oaep::new::<s256::Sha256>();
        let mut rng = rand::thread_rng();

        public_key
            .encrypt(&mut rng, padding, data)
            .map_err(|_| TpmError::RsaOaepEncrypt)
    }

    fn rs256_fingerprint(&mut self, rs256_key: &RS256Key) -> Result<Sha256Output, TpmError> {
        self.rs256_public_der(rs256_key).map(|pub_key_der| {
            let mut hasher = s256::Sha256::new();
            hasher.update(pub_key_der);
            hasher.finalize()
        })
    }

    fn rs256_public_der(&mut self, rs256_key: &RS256Key) -> Result<Vec<u8>, TpmError> {
        self.rs256_public(rs256_key)?
            .to_public_key_der()
            .map(|asn1_der| asn1_der.to_vec())
            .map_err(|_| TpmError::RsaPublicToDer)
    }

    fn rs256_public_pem(&mut self, rs256_key: &RS256Key) -> Result<String, TpmError> {
        self.rs256_public(rs256_key)?
            .to_public_key_pem(Default::default())
            .map_err(|_| TpmError::RsaPublicToPem)
    }

    fn rs256_sign_to_bitstring(
        &mut self,
        rs256_key: &RS256Key,
        data: &[u8],
    ) -> Result<BitString, TpmError> {
        let signature = self.rs256_sign(rs256_key, data)?;

        BitString::new(0, signature.to_vec()).map_err(|_| TpmError::AsnBitStringInvalid)
    }

    fn rs256_verify(
        &mut self,
        rs256_key: &RS256Key,
        data: &[u8],
        sig: &RS256Signature,
    ) -> Result<bool, TpmError> {
        let pub_key = self.rs256_public(rs256_key)?;

        let verifier = RS256VerifyingKey::new(pub_key);

        Ok(verifier.verify(data, sig).is_ok())
    }

    fn rs256_keypair(&mut self, rs256_key: &RS256Key) -> Result<TpmRS256Keypair, TpmError> {
        let pub_key = self.rs256_public(rs256_key)?;

        let verifier = RS256VerifyingKey::new(pub_key);

        Ok(TpmRS256Keypair { verifier })
    }
}

pub trait TpmMsExtensions: Tpm + TpmRS256 {
    fn rs256_oaep_dec_sha1(
        &mut self,
        rs256_key: &RS256Key,
        encrypted_data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, TpmError>;

    /*
    #[deprecated(
        since = "0.3.0",
        note = "RS256 Keys no longer have associated content encryption keys - use storage keys instead"
    )]
    */
    fn rs256_yield_cek(&mut self, _key: &RS256Key) -> Option<StorageKey> {
        None
    }

    fn msoapxbc_rsa_key_load(
        &mut self,
        parent_key: &StorageKey,
        loadable_rs256_key: &LoadableMsOapxbcRsaKey,
    ) -> Result<RS256Key, TpmError> {
        self.rs256_load(parent_key, loadable_rs256_key)
    }

    fn msoapxbc_rsa_key_create(
        &mut self,
        parent_key: &StorageKey,
    ) -> Result<LoadableRS256Key, TpmError> {
        self.rs256_create(parent_key)
    }

    fn msoapxbc_rsa_public_as_der(&mut self, rs256_key: &RS256Key) -> Result<Vec<u8>, TpmError> {
        self.rs256_public_der(rs256_key)
    }

    fn msoapxbc_rsa_decipher_session_key(
        &mut self,
        rs256_key: &RS256Key,
        parent_key: &StorageKey,
        input: &[u8],
        expected_key_len: usize,
    ) -> Result<SealedData, TpmError> {
        let mut data = self.rs256_oaep_dec_sha1(rs256_key, input)?;

        data.truncate(expected_key_len);

        self.seal_data(parent_key, data)
    }

    fn msoapxbc_rsa_encipher_session_key(
        &mut self,
        rs256_key: &RS256Key,
        input: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        let public_key = self.rs256_public(rs256_key)?;
        let padding = rsa::Oaep::new::<sha1::Sha1>();
        let mut rng = rand::thread_rng();

        public_key
            .encrypt(&mut rng, padding, input)
            .map_err(|_| TpmError::RsaOaepEncrypt)
    }

    fn ms_device_enrolment_begin(
        &mut self,
        parent_key: &StorageKey,
        cn: &str,
    ) -> Result<(MsInProgressEnrolment, CertificateRequest), TpmError> {
        let loadable_rs256_key = self.rs256_create(parent_key)?;

        let rs256_key = self.rs256_load(parent_key, &loadable_rs256_key)?;

        // Create the CSR.
        let cn_str = format!("CN={}", cn);
        let subject =
            x509::Name::from_str(cn_str.as_str()).map_err(|_| TpmError::X509NameInvalid)?;

        let signing_key = self.rs256_keypair(&rs256_key)?;

        let mut req_builder = CertificateRequestBuilder::new(subject, &signing_key)
            .map_err(|_| TpmError::X509RequestBuilder)?;

        let csr_to_sign = req_builder
            .finalize()
            .map_err(|_| TpmError::X509RequestSign)?;

        let signature = self.rs256_sign_to_bitstring(&rs256_key, &csr_to_sign)?;

        let cert_sign_req = req_builder
            .assemble(signature)
            .map_err(|_| TpmError::X509RequestAssemble)?;

        let in_progress_enrolment = MsInProgressEnrolment { loadable_rs256_key };

        Ok((in_progress_enrolment, cert_sign_req))
    }

    fn ms_device_enrolment_finalise(
        &mut self,
        parent_key: &StorageKey,
        in_progress_enrolment: MsInProgressEnrolment,
        // What format should this be? Der? X509? PEM?
        // Der, to help  shield david from this. Not sure how best to return it.
        // certificate: Certificate,
        certificate_der: &[u8],
    ) -> Result<LoadableMsDeviceEnrolmentKey, TpmError> {
        // Associate the cert with the key,

        let certificate =
            Certificate::from_der(certificate_der).map_err(|_| TpmError::X509FromDer)?;

        let MsInProgressEnrolment { loadable_rs256_key } = in_progress_enrolment;

        let rs256_key = self.rs256_load(parent_key, &loadable_rs256_key)?;

        let public_key = self.rs256_public(&rs256_key)?;

        let cert_pub_key = RS256PublicKey::try_from(
            certificate
                .tbs_certificate
                .subject_public_key_info
                .owned_to_ref(),
        )
        .map_err(|_| TpmError::X509PublicKey)?;

        if public_key != cert_pub_key {
            return Err(TpmError::X509KeyMismatch);
        }

        let x509_der = certificate.to_der().map_err(|_| TpmError::X509ToDer)?;

        Ok(LoadableMsDeviceEnrolmentKey::Rsa2048V1 {
            loadable_rs256_key,
            x509_der,
        })
    }

    fn ms_device_enrolment_key_load(
        &mut self,
        parent_key: &StorageKey,
        loadable_device_key: LoadableMsDeviceEnrolmentKey,
    ) -> Result<(RS256Key, Certificate), TpmError> {
        let (loadable_rs256_key, x509_der) = match loadable_device_key {
            LoadableMsDeviceEnrolmentKey::SoftRsa2048V1 { key, tag, iv, x509 } => {
                let loadable_rs256_key = LoadableRS256Key::Soft2048V2 { key, tag, iv };

                (loadable_rs256_key, x509)
            }
            LoadableMsDeviceEnrolmentKey::Rsa2048V1 {
                loadable_rs256_key,
                x509_der,
            } => (loadable_rs256_key, x509_der),
        };

        let certificate = Certificate::from_der(&x509_der).map_err(|_| TpmError::X509FromDer)?;

        let rs256_key = self.rs256_load(parent_key, &loadable_rs256_key)?;

        Ok((rs256_key, certificate))
    }

    fn ms_hello_key_create(
        &mut self,
        parent_key: &StorageKey,
        pin: &PinValue,
    ) -> Result<LoadableMsHelloKey, TpmError> {
        let loadable_storage_key = self.storage_key_create_pin(parent_key, pin)?;

        let storage_key = self.storage_key_load_pin(parent_key, pin, &loadable_storage_key)?;

        let loadable_rs256_key = self.rs256_create(&storage_key)?;

        Ok(LoadableMsHelloKey::Rsa2048V1 {
            loadable_storage_key,
            loadable_rs256_key,
        })
    }

    // Currently I don't think that there is a need for this to have a custom return type, unless
    // we plan to swap out the type that the hello key is underneath? That creates it's own
    // issues later though I guess ....
    fn ms_hello_key_load(
        &mut self,
        parent_key: &StorageKey,
        ms_hello_key: &LoadableMsHelloKey,
        pin: &PinValue,
    ) -> Result<(RS256Key, StorageKey), TpmError> {
        match ms_hello_key {
            LoadableMsHelloKey::SoftRsa2048V1 { key, tag, iv } => {
                // Special case!!!!
                SoftTpm::ms_hello_key_load_legacy(parent_key, pin, key, tag, iv)
            }
            LoadableMsHelloKey::Rsa2048V1 {
                loadable_storage_key,
                loadable_rs256_key,
            } => {
                let storage_key =
                    self.storage_key_load_pin(parent_key, pin, loadable_storage_key)?;

                let rs256_key = self.rs256_load(&storage_key, loadable_rs256_key)?;

                Ok((rs256_key, storage_key))
            }
        }
    }

    fn ms_hello_rsa_public_as_der(&mut self, rs256_key: &RS256Key) -> Result<Vec<u8>, TpmError> {
        self.rs256_public_der(rs256_key)
    }
}
