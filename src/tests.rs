use crate::authvalue::AuthValue;
use crate::pin::PinValue;
use crate::provider::{Tpm, TpmES256, TpmHmacS256, TpmMsExtensions, TpmRS256};
use crate::structures::StorageKey;
use crypto_glue::ecdsa_p256::EcdsaP256PublicKey;
use crypto_glue::ecdsa_p256::EcdsaP256Signature;
use crypto_glue::ecdsa_p256::EcdsaP256VerifyingKey;
use crypto_glue::rsa::{RS256PublicKey, RS256Signature, RS256VerifyingKey};
use crypto_glue::spki::der::referenced::OwnedToRef;
use crypto_glue::spki::der::Encode;
use crypto_glue::spki::DynSignatureAlgorithmIdentifier;
use crypto_glue::traits::*;
use crypto_glue::x509;
use crypto_glue::x509::Builder;
use crypto_glue::x509::X509Display;
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use tracing::trace;

pub(crate) fn test_tpm_storage<T: Tpm>(mut tpm_a: T) {
    let _ = tracing_subscriber::fmt::try_init();

    // Create a new random auth_value.
    let auth_value = AuthValue::ephemeral().expect("Failed to generate new random secret");

    // Request a new root storage-key-context. This key "owns" anything
    // created underneath it.
    let loadable_storage_key = tpm_a
        .root_storage_key_create(&auth_value)
        .expect("Unable to create new storage key");

    trace!(?loadable_storage_key);

    let root_storage_key = tpm_a
        .root_storage_key_load(&auth_value, &loadable_storage_key)
        .expect("Unable to load storage key");

    let loadable_child_storage_key = tpm_a
        .storage_key_create(&root_storage_key)
        .expect("Unable to create child storage key.");

    trace!(?loadable_child_storage_key);

    let _storage_key = tpm_a
        .storage_key_load(&root_storage_key, &loadable_child_storage_key)
        .expect("Unable to load child storage key.");

    // Create and load a child storage key that requires an authValue as well.

    let pin = PinValue::new("012345").expect("Invalid TPM pin");

    let loadable_child_storage_key = tpm_a
        .storage_key_create_pin(&root_storage_key, &pin)
        .expect("Unable to create child storage key.");

    trace!(?loadable_child_storage_key);

    let storage_key = tpm_a
        .storage_key_load_pin(&root_storage_key, &pin, &loadable_child_storage_key)
        .expect("Unable to load child storage key.");

    let secret = Zeroizing::new(vec![0, 1, 2, 3, 4, 5, 6, 7]);

    let sealed_secret = tpm_a
        .seal_data(&storage_key, secret.clone())
        .expect("Unable to seal data");

    let unsealed_secret = tpm_a
        .unseal_data(&storage_key, &sealed_secret)
        .expect("Unable to unseal data");

    assert_eq!(unsealed_secret.as_slice(), secret.as_slice());
}

fn setup_tpm_test<T: Tpm>(tpm_a: &mut T) -> StorageKey {
    let _ = tracing_subscriber::fmt::try_init();

    // Create a new random auth_value.
    let auth_value = AuthValue::ephemeral().expect("Failed to generate new random secret");

    // Request a new root storage-key-context. This key "owns" anything
    // created underneath it.
    let loadable_storage_key = tpm_a
        .root_storage_key_create(&auth_value)
        .expect("Unable to create new storage key");

    trace!(?loadable_storage_key);

    tpm_a
        .root_storage_key_load(&auth_value, &loadable_storage_key)
        .expect("Unable to load storage key")
}

// Hmac
pub(crate) fn test_tpm_hmac<T: Tpm + TpmHmacS256>(mut tpm_a: T) {
    let rsk = setup_tpm_test(&mut tpm_a);

    let loadable_hmac_key = tpm_a
        .hmac_s256_create(&rsk)
        .expect("Unable to create hmac key");

    let hmac_key = tpm_a
        .hmac_s256_load(&rsk, &loadable_hmac_key)
        .expect("Unable to load hmac key");

    let data = [0, 1, 2, 3];

    let hmac_output = tpm_a
        .hmac_s256(&hmac_key, &data)
        .expect("Unable to perform hmac");

    // Should be the same
    let hmac_output_ck = tpm_a
        .hmac_s256(&hmac_key, &data)
        .expect("Unable to perform hmac");

    assert!(hmac_output == hmac_output_ck);

    let data = [1, 2, 3, 4];

    let hmac_output_ck = tpm_a
        .hmac_s256(&hmac_key, &data)
        .expect("Unable to perform hmac");

    // Any change to the input, changes the hmac
    assert!(hmac_output != hmac_output_ck);
}

// Sealed Data

// Asymmetric (prob by alg)

pub(crate) fn test_tpm_ecdsa_p256<T: Tpm + TpmES256>(mut tpm_a: T) {
    let rsk = setup_tpm_test(&mut tpm_a);

    let loadable_es256_key = tpm_a
        .es256_create(&rsk)
        .expect("Unable to create es256 key");

    let es256_key = tpm_a
        .es256_load(&rsk, &loadable_es256_key)
        .expect("Unable to load es256 key");

    let _fprint = tpm_a
        .es256_fingerprint(&es256_key)
        .expect("Unable to fingerprent es256 key");

    let pub_key = tpm_a
        .es256_public(&es256_key)
        .expect("Unable to retrieve es256 public key");

    let _pub_key_der = tpm_a
        .es256_public_der(&es256_key)
        .expect("Unable to retrieve es256 public key der");

    let _pub_key_pem = tpm_a
        .es256_public_pem(&es256_key)
        .expect("Unable to retrieve es256 public key pem");

    let data = [1, 2, 3, 4];

    let signature = tpm_a
        .es256_sign(&es256_key, &data)
        .expect("Unable to sign with es256 private key");

    let valid = tpm_a
        .es256_verify(&es256_key, &data, &signature)
        .expect("Unable to perform verification");

    assert!(valid);

    // Test making a self-signed certificate. This generally implies and satisfies
    // the requirements for a CSR builder too.

    let profile = x509::Profile::Manual { issuer: None };
    let serial_number = x509::SerialNumber::from(1u32);

    let now = SystemTime::now();
    let not_before = x509::Time::try_from(now).unwrap();
    let not_after = x509::Time::try_from(now + Duration::new(3600, 0)).unwrap();

    let validity = x509::Validity {
        not_after,
        not_before,
    };

    let subject = x509::Name::from_str("CN=selfsigned").unwrap();

    let signing_key = tpm_a
        .es256_keypair(&es256_key)
        .expect("Unable to access es256 signing pair");

    let verifier = signing_key.verifying_key();

    let subject_public_key_info =
        x509::SubjectPublicKeyInfoOwned::from_key(signing_key.verifying_key()).unwrap();

    let mut cert_builder = x509::CertificateBuilder::new(
        profile,
        serial_number,
        validity,
        subject,
        subject_public_key_info,
        &signing_key,
    )
    .unwrap();

    let csr_to_sign = cert_builder.finalize().unwrap();

    let signature = tpm_a
        .es256_sign_to_bitstring(&es256_key, &csr_to_sign)
        .expect("Unable to sign csr with es256 private key");

    let cert = cert_builder.assemble(signature).unwrap();

    println!("{}", X509Display::from(&cert));

    // Check the public keys are the same. Fuck me the rust crypto apis don't
    // make this easy at all .....
    assert_eq!(
        cert.signature_algorithm,
        verifier.signature_algorithm_identifier().unwrap()
    );
    let cert_pub_key =
        EcdsaP256PublicKey::try_from(cert.tbs_certificate.subject_public_key_info.owned_to_ref())
            .unwrap();

    assert_eq!(pub_key, cert_pub_key);
    let verifier = EcdsaP256VerifyingKey::from(&pub_key);

    // As pub_key and cert_pub_key are the same, we can reuse the verifier from before.

    let cert_signature = cert
        .signature
        .as_bytes()
        .and_then(|bytes| EcdsaP256Signature::from_slice(bytes).ok())
        .unwrap();

    let cert_data_to_validate = cert.tbs_certificate.to_der().unwrap();

    assert!(verifier
        .verify(&cert_data_to_validate, &cert_signature)
        .is_ok());
}

pub(crate) fn test_tpm_rs256<T: Tpm + TpmRS256>(mut tpm_a: T) {
    let rsk = setup_tpm_test(&mut tpm_a);

    let loadable_rs256_key = tpm_a
        .rs256_create(&rsk)
        .expect("Unable to create rs256 key");

    let rs256_key = tpm_a
        .rs256_load(&rsk, &loadable_rs256_key)
        .expect("Unable to load rs256 key");

    let _fprint = tpm_a
        .rs256_fingerprint(&rs256_key)
        .expect("Unable to fingerprent rs256 key");

    let pub_key = tpm_a
        .rs256_public(&rs256_key)
        .expect("Unable to retrieve rs256 public key");

    let _pub_key_der = tpm_a
        .rs256_public_der(&rs256_key)
        .expect("Unable to retrieve rs256 public key der");

    let _pub_key_pem = tpm_a
        .rs256_public_pem(&rs256_key)
        .expect("Unable to retrieve rs256 public key pem");

    let data = [1, 2, 3, 4];

    let signature = tpm_a
        .rs256_sign(&rs256_key, &data)
        .expect("Unable to sign with rs256 private key");

    let valid = tpm_a
        .rs256_verify(&rs256_key, &data, &signature)
        .expect("Unable to perform verification");

    assert!(valid);

    // Test OAEP enc/dec

    let enc_data = tpm_a
        .rs256_oaep_enc(&rs256_key, &data)
        .expect("Unable to encrypt with rs256 private key");

    assert_ne!(&enc_data, &data);

    let dec_data = tpm_a
        .rs256_oaep_dec(&rs256_key, &enc_data)
        .expect("Unable to decrypt with rs256 private key");

    assert_eq!(&dec_data, &data);

    // Test making a self-signed certificate. This generally implies and satisfies
    // the requirements for a CSR builder too.

    let profile = x509::Profile::Manual { issuer: None };
    let serial_number = x509::SerialNumber::from(1u32);

    let now = SystemTime::now();
    let not_before = x509::Time::try_from(now).unwrap();
    let not_after = x509::Time::try_from(now + Duration::new(3600, 0)).unwrap();

    let validity = x509::Validity {
        not_after,
        not_before,
    };

    let subject = x509::Name::from_str("CN=selfsigned").unwrap();

    let signing_key = tpm_a
        .rs256_keypair(&rs256_key)
        .expect("Unable to access rs256 signing pair");

    let verifier = signing_key.verifying_key();

    let subject_public_key_info =
        x509::SubjectPublicKeyInfoOwned::from_key(signing_key.verifying_key()).unwrap();

    let mut cert_builder = x509::CertificateBuilder::new(
        profile,
        serial_number,
        validity,
        subject,
        subject_public_key_info,
        &signing_key,
    )
    .unwrap();

    let csr_to_sign = cert_builder.finalize().unwrap();

    let signature = tpm_a
        .rs256_sign_to_bitstring(&rs256_key, &csr_to_sign)
        .expect("Unable to sign csr with rs256 private key");

    let cert = cert_builder.assemble(signature).unwrap();

    println!("{}", X509Display::from(&cert));

    // Check the public keys are the same. Fuck me the rust crypto apis don't
    // make this easy at all .....
    assert_eq!(
        cert.signature_algorithm,
        verifier.signature_algorithm_identifier().unwrap()
    );
    let cert_pub_key =
        RS256PublicKey::try_from(cert.tbs_certificate.subject_public_key_info.owned_to_ref())
            .unwrap();

    assert_eq!(pub_key, cert_pub_key);
    let verifier = RS256VerifyingKey::new(pub_key);

    // As pub_key and cert_pub_key are the same, we can reuse the verifier from before.

    let cert_signature = cert
        .signature
        .as_bytes()
        .and_then(|bytes| RS256Signature::try_from(bytes).ok())
        .unwrap();

    let cert_data_to_validate = cert.tbs_certificate.to_der().unwrap();

    assert!(verifier
        .verify(&cert_data_to_validate, &cert_signature)
        .is_ok());
}

pub(crate) fn test_tpm_msoapxbc<T: Tpm + TpmRS256 + TpmMsExtensions>(mut tpm_a: T) {
    let rsk = setup_tpm_test(&mut tpm_a);

    let loadable_rs256_key = tpm_a
        .rs256_create(&rsk)
        .expect("Unable to create rs256 key");

    let rs256_key = tpm_a
        .rs256_load(&rsk, &loadable_rs256_key)
        .expect("Unable to load rs256 key");

    let secret = [0, 1, 2, 3, 4, 5, 6, 7];

    let enc_secret = tpm_a
        .msoapxbc_rsa_encipher_session_key(&rs256_key, &secret)
        .expect("Unable to encipher secret");

    let loadable_session_key = tpm_a
        .msoapxbc_rsa_decipher_session_key(&rs256_key, &rsk, &enc_secret, secret.len())
        .unwrap();

    let yielded_secret = tpm_a.unseal_data(&rsk, &loadable_session_key).unwrap();

    assert_eq!(&secret, yielded_secret.as_slice());
}
