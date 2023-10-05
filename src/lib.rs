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
// mod tpm;
// future goal ... once I can afford one ...
// mod yubihsm;

#[derive(Debug, Clone)]
enum HsmError {
    Aes256GcmConfig,
    Aes256GcmEncrypt,
    Aes256GcmDecrypt,
    HmacKey,
    HmacSign,

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

#[cfg(test)]
mod tests {
    use super::soft::*;
    use super::*;

    use tracing::trace;

    #[test]
    fn basic_interaction_hw_bound_key() {
        let _ = tracing_subscriber::fmt::try_init();
        // Create the Hsm.
        let mut hsm = SoftHsm::new();

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
        let mut hsm = SoftHsm::new();

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
