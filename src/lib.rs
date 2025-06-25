#![deny(warnings)]
#![allow(dead_code)]
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

mod authvalue;
mod error;
mod pin;
pub mod provider;
pub mod structures;

pub use crypto_glue as glue;
pub use {authvalue::AuthValue, error::TpmError, pin::PinValue};

pub(crate) mod wrap;

#[cfg(test)]
mod tests;

// Deprecation notices.
#[deprecated(since = "0.3.0", note = "Use `kanidm_hsm_crypto::provider`")]
pub mod soft {
    #[deprecated(
        since = "0.3.0",
        note = "Use `kanidm_hsm_crypto::provider::SoftTpm` instead."
    )]
    pub struct SoftTpm;
}

#[deprecated(
    since = "0.3.0",
    note = "Use `kanidm_hsm_crypto::provider::BoxedDynTpm` instead."
)]
pub struct BoxedDynTpm;

#[deprecated(
    since = "0.3.0",
    note = "Use `kanidm_hsm_crypto::structures::LoadableHmacS256Key` instead."
)]
pub struct LoadableHmacKey;

#[deprecated(
    since = "0.3.0",
    note = "Use `kanidm_hsm_crypto::structures::LoadableStorageKey` instead."
)]
pub struct LoadableMachineKey;

#[deprecated(
    since = "0.3.0",
    note = "Use `kanidm_hsm_crypto::provider::Tpm` and associated traits instead."
)]
pub trait Tpm {}

#[deprecated(
    since = "0.3.0",
    note = "Use `kanidm_hsm_crypto::structures::LoadableRS256Key` instead."
)]
pub struct LoadableMsOapxbcRsaKey;

#[deprecated(
    since = "0.3.0",
    note = "Use `kanidm_hsm_crypto::structures::SealedData` instead."
)]
pub struct LoadableMsOapxbcSessionKey;
