#![deny(warnings)]
#![warn(unused_extern_crates)]
// Enable some groups of clippy lints.
#![deny(clippy::suspicious)]
#![deny(clippy::perf)]
// Specific lints to enforce.
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![deny(clippy::disallowed_types)]
#![deny(clippy::manual_let_else)]
#![allow(clippy::unreachable)]

use argon2::MIN_SALT_LEN;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tracing::error;
use zeroize::Zeroizing;

pub mod soft;

#[cfg(feature = "tpm")]
pub mod tpm;
// future goal ... once I can afford one ...
// mod yubihsm;

pub enum AuthValue {
    Key256Bit { auth_key: Zeroizing<[u8; 32]> },
}

#[derive(Debug, Copy, Clone)]
pub enum KeyAlgorithm {
    Rsa2048,
    Ecdsa256,
}

impl AuthValue {
    fn random_key() -> Result<Zeroizing<[u8; 24]>, TpmError> {
        let mut auth_key = Zeroizing::new([0; 24]);
        openssl::rand::rand_bytes(auth_key.as_mut()).map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::Entropy
        })?;
        Ok(auth_key)
    }

    pub fn generate() -> Result<String, TpmError> {
        let ak = Self::random_key()?;
        Ok(hex::encode(&ak))
    }

    pub fn ephemeral() -> Result<Self, TpmError> {
        let mut auth_key = Zeroizing::new([0; 32]);
        openssl::rand::rand_bytes(auth_key.as_mut()).map_err(|ossl_err| {
            error!(?ossl_err);
            TpmError::Entropy
        })?;

        Ok(AuthValue::Key256Bit { auth_key })
    }

    /// Derive an auth value from input bytes. This value must be at least 24 bytes in length.
    ///
    /// The key derivation is performed with Argon2id.
    pub fn derive_from_bytes(cleartext: &[u8]) -> Result<Self, TpmError> {
        use argon2::{Algorithm, Argon2, Params, Version};

        let mut auth_key = Zeroizing::new([0; 32]);

        // This can't be changed else it will break key derivation for users.
        let argon2id_params =
            Params::new(32_768, 4, 1, Some(auth_key.as_ref().len())).map_err(|argon_err| {
                error!(?argon_err);
                TpmError::AuthValueDerivation
            })?;

        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2id_params);

        // Want at least 8 bytes salt, 16 bytes pw input.
        if cleartext.len() < 24 {
            return Err(TpmError::AuthValueTooShort);
        }

        let (salt, key) = cleartext.split_at(MIN_SALT_LEN);

        argon
            .hash_password_into(key, salt, auth_key.as_mut())
            .map_err(|argon_err| {
                error!(?argon_err);
                TpmError::AuthValueDerivation
            })?;

        Ok(AuthValue::Key256Bit { auth_key })
    }

    /// Derive an auth value from input hex. The input hex string must contain at least
    /// 24 bytes (the string is at least 48 hex chars)
    pub fn derive_from_hex(cleartext: &str) -> Result<Self, TpmError> {
        hex::decode(cleartext)
            .map_err(|_| TpmError::AuthValueInvalidHexInput)
            .and_then(|bytes| Self::derive_from_bytes(bytes.as_slice()))
    }
}

impl TryFrom<&[u8]> for AuthValue {
    type Error = TpmError;

    fn try_from(cleartext: &[u8]) -> Result<Self, Self::Error> {
        Self::derive_from_bytes(cleartext)
    }
}

impl FromStr for AuthValue {
    type Err = TpmError;

    fn from_str(cleartext: &str) -> Result<Self, Self::Err> {
        Self::derive_from_hex(cleartext)
    }
}

#[derive(Debug, Clone)]
pub enum TpmError {
    AuthValueInvalidHexInput,
    AuthValueTooShort,
    AuthValueDerivation,
    Aes256GcmConfig,
    Aes256GcmEncrypt,
    Aes256GcmDecrypt,
    HmacKey,
    HmacSign,
    EcGroup,
    EcKeyGenerate,
    EcKeyPrivateToDer,
    EcKeyFromDer,
    EcKeyToPrivateKey,
    IdentityKeyDigest,
    IdentityKeyPublicToDer,
    IdentityKeyPublicToPem,
    IdentityKeyInvalidForSigning,
    IdentityKeyInvalidForVerification,
    IdentityKeySignature,
    IdentityKeyVerification,
    IdentityKeyX509ToPem,
    IdentityKeyX509ToDer,
    IdentityKeyX509Missing,
    RsaGenerate,
    RsaPrivateToDer,
    RsaKeyFromDer,
    RsaToPrivateKey,
    X509FromDer,
    X509PublicKey,
    X509KeyMismatch,
    X509RequestBuilder,
    X509NameBuilder,
    X509NameAppend,
    X509RequestSubjectName,
    X509RequestSign,
    X509RequestToDer,
    X509RequestSetPublic,

    TpmTctiNameInvalid,
    TpmAuthSession,
    TpmContextCreate,
    TpmContextFlushObject,
    TpmContextSave,
    TpmContextLoad,
    TpmPrimaryObjectAttributesInvalid,
    TpmPrimaryPublicBuilderInvalid,
    TpmPrimaryCreate,
    TpmEntropy,
    TpmAuthValueInvalid,

    TpmMachineKeyObjectAttributesInvalid,
    TpmMachineKeyBuilderInvalid,
    TpmMachineKeyCreate,
    TpmMachineKeyLoad,

    TpmHmacKeyObjectAttributesInvalid,
    TpmHmacKeyBuilderInvalid,
    TpmHmacKeyCreate,
    TpmHmacKeyLoad,
    TpmHmacSign,

    TpmHmacInputTooLarge,

    TpmOperationUnsupported,

    Entropy,
    IncorrectKeyType,
}

#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "tpm"), derive(Serialize, Deserialize))]
pub enum LoadableMachineKey {
    SoftAes256GcmV1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
    },
    #[cfg(feature = "tpm")]
    TpmAes128CfbV1 {
        private: tpm::Private,
        public: tpm::Public,
    },
    #[cfg(not(feature = "tpm"))]
    TpmAes128CfbV1 { private: (), public: () },
}

pub enum MachineKey {
    SoftAes256Gcm {
        key: Zeroizing<Vec<u8>>,
    },
    #[cfg(feature = "tpm")]
    Tpm {
        key_handle: tpm::KeyHandle,
    },
    #[cfg(not(feature = "tpm"))]
    Tpm {
        key_handle: (),
    },
}

#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "tpm"), derive(Serialize, Deserialize))]
pub enum LoadableHmacKey {
    SoftSha256V1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
    },
    #[cfg(feature = "tpm")]
    TpmSha256V1 {
        private: tpm::Private,
        public: tpm::Public,
    },
    #[cfg(not(feature = "tpm"))]
    Tpm(()),
}

pub enum HmacKey {
    SoftSha256 {
        pkey: PKey<Private>,
    },
    #[cfg(feature = "tpm")]
    TpmSha256 {
        key_context: tpm::TpmsContext,
    },
    #[cfg(not(feature = "tpm"))]
    TpmSha256 {
        key_handle: (),
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadableIdentityKey {
    SoftEcdsa256V1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
        x509: Option<Vec<u8>>,
    },
    SoftRsa2048V1 {
        key: Vec<u8>,
        tag: [u8; 16],
        iv: [u8; 16],
        x509: Option<Vec<u8>>,
    },
}

pub enum IdentityKey {
    SoftEcdsa256 {
        pkey: PKey<Private>,
        x509: Option<X509>,
    },
    SoftRsa2048 {
        pkey: PKey<Private>,
        x509: Option<X509>,
    },
}

impl IdentityKey {
    pub fn alg(&self) -> KeyAlgorithm {
        match self {
            IdentityKey::SoftEcdsa256 { .. } => KeyAlgorithm::Ecdsa256,
            IdentityKey::SoftRsa2048 { .. } => KeyAlgorithm::Rsa2048,
        }
    }
}

pub trait Tpm {
    fn machine_key_create(
        &mut self,
        auth_value: &AuthValue,
    ) -> Result<LoadableMachineKey, TpmError>;

    fn machine_key_load(
        &mut self,
        auth_value: &AuthValue,
        exported_key: &LoadableMachineKey,
    ) -> Result<MachineKey, TpmError>;

    fn hmac_key_create(&mut self, mk: &MachineKey) -> Result<LoadableHmacKey, TpmError>;

    fn hmac_key_load(
        &mut self,
        mk: &MachineKey,
        exported_key: &LoadableHmacKey,
    ) -> Result<HmacKey, TpmError>;

    fn hmac(&mut self, hk: &HmacKey, input: &[u8]) -> Result<Vec<u8>, TpmError>;

    fn identity_key_create(
        &mut self,
        mk: &MachineKey,
        algorithm: KeyAlgorithm,
    ) -> Result<LoadableIdentityKey, TpmError>;

    fn identity_key_load(
        &mut self,
        mk: &MachineKey,
        loadable_key: &LoadableIdentityKey,
    ) -> Result<IdentityKey, TpmError>;

    fn identity_key_id(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError>;

    fn identity_key_sign(&mut self, key: &IdentityKey, input: &[u8]) -> Result<Vec<u8>, TpmError>;

    fn identity_key_verify(
        &mut self,
        key: &IdentityKey,
        input: &[u8],
        signature: &[u8],
    ) -> Result<bool, TpmError>;

    fn identity_key_certificate_request(
        &mut self,
        mk: &MachineKey,
        loadable_key: &LoadableIdentityKey,
        cn: &str,
    ) -> Result<Vec<u8>, TpmError>;

    fn identity_key_associate_certificate(
        &mut self,
        mk: &MachineKey,
        loadable_key: &LoadableIdentityKey,
        certificate_der: &[u8],
    ) -> Result<LoadableIdentityKey, TpmError>;

    fn identity_key_public_as_der(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError>;

    fn identity_key_public_as_pem(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError>;

    fn identity_key_x509_as_pem(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError>;

    fn identity_key_x509_as_der(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError>;
}

pub struct BoxedDynTpm(Box<dyn Tpm>);

impl BoxedDynTpm {
    pub fn new<T: Tpm + 'static>(t: T) -> Self {
        BoxedDynTpm(Box::new(t))
    }
}

impl Tpm for BoxedDynTpm {
    fn machine_key_create(
        &mut self,
        auth_value: &AuthValue,
    ) -> Result<LoadableMachineKey, TpmError> {
        self.0.machine_key_create(auth_value)
    }

    fn machine_key_load(
        &mut self,
        auth_value: &AuthValue,
        exported_key: &LoadableMachineKey,
    ) -> Result<MachineKey, TpmError> {
        self.0.machine_key_load(auth_value, exported_key)
    }

    fn hmac_key_create(&mut self, mk: &MachineKey) -> Result<LoadableHmacKey, TpmError> {
        self.0.hmac_key_create(mk)
    }

    fn hmac_key_load(
        &mut self,
        mk: &MachineKey,
        exported_key: &LoadableHmacKey,
    ) -> Result<HmacKey, TpmError> {
        self.0.hmac_key_load(mk, exported_key)
    }

    fn hmac(&mut self, hk: &HmacKey, input: &[u8]) -> Result<Vec<u8>, TpmError> {
        self.0.hmac(hk, input)
    }

    fn identity_key_create(
        &mut self,
        mk: &MachineKey,
        algorithm: KeyAlgorithm,
    ) -> Result<LoadableIdentityKey, TpmError> {
        self.0.identity_key_create(mk, algorithm)
    }

    fn identity_key_load(
        &mut self,
        mk: &MachineKey,
        loadable_key: &LoadableIdentityKey,
    ) -> Result<IdentityKey, TpmError> {
        self.0.identity_key_load(mk, loadable_key)
    }

    fn identity_key_id(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        self.0.identity_key_id(key)
    }

    fn identity_key_sign(&mut self, key: &IdentityKey, input: &[u8]) -> Result<Vec<u8>, TpmError> {
        self.0.identity_key_sign(key, input)
    }

    fn identity_key_verify(
        &mut self,
        key: &IdentityKey,
        input: &[u8],
        signature: &[u8],
    ) -> Result<bool, TpmError> {
        self.0.identity_key_verify(key, input, signature)
    }

    fn identity_key_certificate_request(
        &mut self,
        mk: &MachineKey,
        loadable_key: &LoadableIdentityKey,
        cn: &str,
    ) -> Result<Vec<u8>, TpmError> {
        self.0
            .identity_key_certificate_request(mk, loadable_key, cn)
    }

    fn identity_key_associate_certificate(
        &mut self,
        mk: &MachineKey,
        loadable_key: &LoadableIdentityKey,
        certificate_der: &[u8],
    ) -> Result<LoadableIdentityKey, TpmError> {
        self.0
            .identity_key_associate_certificate(mk, loadable_key, certificate_der)
    }

    fn identity_key_public_as_der(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        self.0.identity_key_public_as_der(key)
    }

    fn identity_key_public_as_pem(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        self.0.identity_key_public_as_pem(key)
    }

    fn identity_key_x509_as_pem(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        self.0.identity_key_x509_as_pem(key)
    }

    fn identity_key_x509_as_der(&mut self, key: &IdentityKey) -> Result<Vec<u8>, TpmError> {
        self.0.identity_key_x509_as_der(key)
    }
}

#[cfg(test)]
mod tests {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::extension::{
        BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier,
    };
    use openssl::x509::{X509NameBuilder, X509Req, X509};

    #[macro_export]
    macro_rules! test_tpm_hmac {
        ( $tpm_a:expr, $tpm_b:expr ) => {
            use crate::{AuthValue, Tpm};
            use tracing::trace;

            let _ = tracing_subscriber::fmt::try_init();

            // Create a new random auth_value.
            let auth_value = AuthValue::ephemeral().expect("Failed to generate new random secret");

            // Request a new machine-key-context. This key "owns" anything
            // created underneath it.
            let loadable_machine_key = $tpm_a
                .machine_key_create(&auth_value)
                .expect("Unable to create new machine key");

            trace!(?loadable_machine_key);

            let machine_key = $tpm_a
                .machine_key_load(&auth_value, &loadable_machine_key)
                .expect("Unable to load machine key");

            // from that ctx, create a hmac key.
            let loadable_hmac_key = $tpm_a
                .hmac_key_create(&machine_key)
                .expect("Unable to create new hmac key");

            trace!(?loadable_hmac_key);

            let hmac_key = $tpm_a
                .hmac_key_load(&machine_key, &loadable_hmac_key)
                .expect("Unable to load hmac key");

            // do a hmac.
            let output_1 = $tpm_a
                .hmac(&hmac_key, &[0, 1, 2, 3])
                .expect("Unable to perform hmac");

            // destroy the Hsm
            drop(hmac_key);
            drop(machine_key);
            drop($tpm_a);

            // Load the contexts.
            let machine_key = $tpm_b
                .machine_key_load(&auth_value, &loadable_machine_key)
                .expect("Unable to load machine key");

            // Load the keys.
            let hmac_key = $tpm_b
                .hmac_key_load(&machine_key, &loadable_hmac_key)
                .expect("Unable to load hmac key");

            // Do another hmac
            let output_2 = $tpm_b
                .hmac(&hmac_key, &[0, 1, 2, 3])
                .expect("Unable to perform hmac");

            // Show the context load/flush is okay.
            let output_3 = $tpm_b
                .hmac(&hmac_key, &[0, 1, 2, 3])
                .expect("Unable to perform hmac");

            // It should be the same.
            assert_eq!(output_1, output_2);
            assert_eq!(output_1, output_3);
        };
    }

    #[macro_export]
    macro_rules! test_tpm_identity {
        ( $tpm:expr, $alg:expr ) => {
            use crate::{AuthValue, Tpm};
            use openssl::hash::MessageDigest;
            use openssl::pkey::PKey;
            use openssl::sign::Verifier;
            use std::str::FromStr;
            use tracing::trace;

            let _ = tracing_subscriber::fmt::try_init();

            let auth_str = AuthValue::generate().expect("Failed to create hex pin");

            let auth_value = AuthValue::from_str(&auth_str).expect("Unable to create auth value");

            // Request a new machine-key-context. This key "owns" anything
            // created underneath it.
            let loadable_machine_key = $tpm
                .machine_key_create(&auth_value)
                .expect("Unable to create new machine key");

            trace!(?loadable_machine_key);

            let machine_key = $tpm
                .machine_key_load(&auth_value, &loadable_machine_key)
                .expect("Unable to load machine key");

            // from that ctx, create an identity key
            let loadable_id_key = $tpm
                .identity_key_create(&machine_key, $alg)
                .expect("Unable to create id key");

            trace!(?loadable_id_key);

            let id_key = $tpm
                .identity_key_load(&machine_key, &loadable_id_key)
                .expect("Unable to load id key");

            let id_key_public_pem = $tpm
                .identity_key_public_as_pem(&id_key)
                .expect("Unable to get id key public pem");

            let pem_str = String::from_utf8_lossy(&id_key_public_pem);
            trace!(?pem_str);

            let id_key_public_der = $tpm
                .identity_key_public_as_der(&id_key)
                .expect("Unable to get id key public pem");

            // Rehydrate the der to a public key.
            let public_key = PKey::public_key_from_der(&id_key_public_der).expect("Invalid DER");

            let input = "test string";
            let signature = $tpm
                .identity_key_sign(&id_key, input.as_bytes())
                .expect("Unable to sign input");

            // Internal verification
            assert!($tpm
                .identity_key_verify(&id_key, input.as_bytes(), signature.as_slice())
                .expect("Unable to sign input"));

            // External verification.
            let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)
                .expect("Unable to setup verifier.");

            let valid = verifier
                .verify_oneshot(&signature, input.as_bytes())
                .expect("Unable to validate signature");

            assert!(valid);
        };
    }

    #[macro_export]
    macro_rules! test_tpm_identity_csr {
        ( $tpm:expr, $alg:expr ) => {
            use crate::{AuthValue, Tpm};
            use tracing::trace;

            let _ = tracing_subscriber::fmt::try_init();

            let auth_value = AuthValue::ephemeral().expect("Unable to create auth value");

            // Request a new machine-key-context. This key "owns" anything
            // created underneath it.
            let loadable_machine_key = $tpm
                .machine_key_create(&auth_value)
                .expect("Unable to create new machine key");

            trace!(?loadable_machine_key);

            let machine_key = $tpm
                .machine_key_load(&auth_value, &loadable_machine_key)
                .expect("Unable to load machine key");

            // from that ctx, create an identity key
            let loadable_id_key = $tpm
                .identity_key_create(&machine_key, $alg)
                .expect("Unable to create id key");

            trace!(?loadable_id_key);

            // Get the CSR

            let csr_der = $tpm
                .identity_key_certificate_request(&machine_key, &loadable_id_key, "common name")
                .expect("Failed to create csr");

            // Now, we need to sign this to an x509 cert externally.
            let (ca_key, ca_cert) = crate::tests::create_ca();

            let signed_cert = crate::tests::sign_request(&csr_der, &ca_key, &ca_cert);
            trace!(
                "{}",
                String::from_utf8_lossy(signed_cert.to_text().unwrap().as_slice())
            );

            let signed_cert_der = signed_cert.to_der().unwrap();

            let loadable_id_key = $tpm
                .identity_key_associate_certificate(
                    &machine_key,
                    &loadable_id_key,
                    &signed_cert_der,
                )
                .unwrap();

            // Now load it in:
            let id_key = $tpm
                .identity_key_load(&machine_key, &loadable_id_key)
                .expect("Unable to load id key");

            let id_key_x509_pem = $tpm
                .identity_key_x509_as_pem(&id_key)
                .expect("Unable to get id key public pem");

            trace!("\n{}", String::from_utf8_lossy(&id_key_x509_pem));
        };
    }

    pub fn create_ca() -> (PKey<Private>, X509) {
        let ecgroup = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let eckey = EcKey::generate(&ecgroup).unwrap();
        let ca_key = PKey::from_ec_key(eckey).unwrap();

        let mut x509_name = X509NameBuilder::new().unwrap();
        x509_name
            .append_entry_by_text("CN", "Dynamic Softtoken CA")
            .unwrap();
        let x509_name = x509_name.build();

        let mut cert_builder = X509::builder().unwrap();
        cert_builder.set_version(2).unwrap();

        let serial_number = BigNum::from_u32(1)
            .and_then(|serial| serial.to_asn1_integer())
            .unwrap();
        cert_builder.set_serial_number(&serial_number).unwrap();
        cert_builder.set_subject_name(&x509_name).unwrap();
        cert_builder.set_issuer_name(&x509_name).unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        cert_builder.set_not_before(&not_before).unwrap();
        let not_after = Asn1Time::days_from_now(1).unwrap();
        cert_builder.set_not_after(&not_after).unwrap();

        cert_builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        cert_builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let subject_key_identifier = SubjectKeyIdentifier::new()
            .build(&cert_builder.x509v3_context(None, None))
            .unwrap();
        cert_builder
            .append_extension(subject_key_identifier)
            .unwrap();

        cert_builder.set_pubkey(&ca_key).unwrap();

        cert_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
        let ca_cert = cert_builder.build();

        (ca_key, ca_cert)
    }

    pub fn sign_request(req_der: &[u8], ca_key: &PKey<Private>, ca_cert: &X509) -> X509 {
        let req = X509Req::from_der(req_der).unwrap();

        let req_pkey = req.public_key().unwrap();
        assert!(req.verify(&req_pkey).unwrap());

        // depends on the ca, for a lot of them with machine id certs they ignore the values in
        // the csr and stomp them with their own things.

        let mut cert_builder = X509::builder().unwrap();
        cert_builder.set_version(2).unwrap();

        let serial_number = BigNum::from_u32(2)
            .and_then(|serial| serial.to_asn1_integer())
            .unwrap();
        cert_builder.set_serial_number(&serial_number).unwrap();
        cert_builder.set_subject_name(req.subject_name()).unwrap();
        cert_builder
            .set_issuer_name(ca_cert.subject_name())
            .unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        cert_builder.set_not_before(&not_before).unwrap();
        let not_after = Asn1Time::days_from_now(1).unwrap();
        cert_builder.set_not_after(&not_after).unwrap();

        cert_builder
            .append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();

        /*
        cert_builder.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .key_encipherment()
                .build().unwrap()
        ).unwrap();

        let subject_key_identifier = SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None)).unwrap();
        cert_builder.append_extension(subject_key_identifier).unwrap();
        */

        cert_builder
            .append_extension(
                ExtendedKeyUsage::new()
                    // .server_auth()
                    .client_auth()
                    .build()
                    .unwrap(),
            )
            .unwrap();

        cert_builder.set_pubkey(&req_pkey).unwrap();

        cert_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
        cert_builder.build()
    }
}
