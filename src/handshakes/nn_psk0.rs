//! This module encapsulates the [`NNpsk0`] handshake.
//!
//! With the `NNpsk0` handshake, both parties know a pre-shared key (PSK)
//! which is mixed into the handshake before any communication takes place.
//! Every message is protected by the PSK.

use snow::params::{
    BaseChoice, HandshakeChoice, HandshakeModifier, HandshakeModifierList, HandshakePattern,
    NoiseParams,
};

use super::{CryptoChoices, Handshake};

/// Represents an `NNpsk0` handshake, where both parties have a pre-shared key (PSK)
/// which they can use to identify and authenticate each other during the handshake.
#[derive(Clone, Copy, Debug)]
pub struct NNpsk0<'a> {
    /// The pre-shared key (PSK) known to both initiator and responder.
    pub psk: &'a [u8],
    /// The cryptographic primitives needed for the handshake.
    pub choices: CryptoChoices,
}

impl<'a> NNpsk0<'a> {
    /// Constructs an `NNpsk0` handshake using the given PSK.
    pub fn new(psk: &'a [u8]) -> Self {
        assert!(
            psk.len() >= 16,
            "PSK length {} is unsafe, not enough entropy",
            psk.len()
        );

        NNpsk0 {
            psk,
            choices: CryptoChoices::default(),
        }
    }

    /// Constructs an `NNpsk0` handshake using the given PSK and ciphersuite parameters.
    pub fn new_custom(psk: &'a [u8], choices: CryptoChoices) -> Self {
        NNpsk0 { psk, choices }
    }
}

impl<'a> Handshake for NNpsk0<'a> {
    fn name(&self) -> String {
        self.choices.stringify_with_pattern("NNpsk0")
    }

    fn new_builder(&self) -> snow::Builder {
        let params = NoiseParams {
            name: self.name(),
            base: BaseChoice::Noise,
            handshake: HandshakeChoice {
                pattern: HandshakePattern::NN,
                modifiers: HandshakeModifierList {
                    list: vec![HandshakeModifier::Psk(0)],
                },
            },
            dh: self.choices.dh,
            cipher: self.choices.cipher,
            hash: self.choices.hash,
        };
        snow::Builder::new(params).psk(0, self.psk)
    }
}
