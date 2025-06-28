# Kanidm HSM Crypto

This library allows the use of HSM's, TPM's or SoftHSM's in cryptographic
applications. The goal is to simplify interactions with these devices so that
applications can utilise these.

## Upgrading 0.2 to 0.3

Existing *soft* tpm keys will continue to work during this upgrade. Most types have changed name
and path to better reflect their capabilities within a TPM.

* Tpm functionality has been broken down to specific traits allowing you to mix and match what you need.
* Keys are separated by their cryptographic type, rather than purpose.
* PIN's may now only be set on `StorageKey`s.
* OpenSSL is no longer required as a library.
* `ES256` and `RS256` can now be used with X509 Certificate requests and operations.
* `ES256` and `RS256` keys no longer host/store their X509 Certificates.

Some structs have changed paths. This is not an complete list, but should give an idea about the changes.

* `kanidm_hsm_crypto::Loadable X Key` -> `kanidm_hsm_crypto::structures::Loadable X Key`
* `kanidm_hsm_crypto::X Key` -> `kanidm_hsm_crypto::structures::X Key`
* `kanidm_hsm_crypto::soft::SoftTpm` -> `kanidm_hsm_crypto::provider::SoftTpm`
* `kanidm_hsm_crypto::BoxedDynTpm` -> `kanidm_hsm_crypto::provider::BoxedDynTpm`
* `kanidm_hsm_crypto::IdentityKey` -> `kanidm_hsm_crypto::structures::RS256Key` OR `kanidm_hsm_crypto::structures::ES256Key`

There are a number of `aliases` available to help you rename some types.


