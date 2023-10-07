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

pub mod soft;

#[cfg(feature = "tpm")]
pub mod tpm;
// future goal ... once I can afford one ...
// mod yubihsm;

#[derive(Debug, Clone)]
pub enum HsmError {
    Aes256GcmConfig,
    Aes256GcmEncrypt,
    Aes256GcmDecrypt,
    HmacKey,
    HmacSign,

    TpmContextCreate,
    TpmPrimaryObjectAttributesInvalid,
    TpmPrimaryPublicBuilderInvalid,
    TpmPrimaryCreate,
    TpmEntropy,

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

    Entropy,
}

trait Hsm {
    type MachineKey;
    type LoadableMachineKey;

    type HmacKey;
    type LoadableHmacKey;

    fn machine_key_create(&mut self) -> Result<Self::LoadableMachineKey, HsmError>;

    fn machine_key_load(
        &mut self,
        exported_key: &Self::LoadableMachineKey,
    ) -> Result<Self::MachineKey, HsmError>;

    fn hmac_key_create(&mut self, mk: &Self::MachineKey)
        -> Result<Self::LoadableHmacKey, HsmError>;

    fn hmac_key_load(
        &mut self,
        mk: &Self::MachineKey,
        exported_key: &Self::LoadableHmacKey,
    ) -> Result<Self::HmacKey, HsmError>;

    fn hmac(&mut self, hk: &Self::HmacKey, input: &[u8]) -> Result<Vec<u8>, HsmError>;
}
