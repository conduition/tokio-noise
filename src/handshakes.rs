//! This module encapsulates an interface for customizing handshake protocols.

use snow::{
    params::{
        BaseChoice, CipherChoice, DHChoice, HandshakeChoice, HandshakeModifier,
        HandshakeModifierList, HandshakePattern, HashChoice, NoiseParams,
    },
    HandshakeState,
};

use crate::errors::{HandshakeError, NoiseError};

/// A default choice for the diffie-hellman key-exchange group.
pub const DEFAULT_DH_CHOICE: DHChoice = DHChoice::Curve25519;

/// A default choice for the encryption cipher.
pub const DEFAULT_CIPHER_CHOICE: CipherChoice = CipherChoice::ChaChaPoly;

/// A default choice for a secure hash function.
pub const DEFAULT_HASH_CHOICE: HashChoice = HashChoice::SHA512;

/// A set of cryptographic primitives which make up the functional dependencies
/// of a Noise handshake protocol instantiation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CryptoChoices {
    /// A diffie-hellman key exchange group.
    pub dh: DHChoice,
    /// An encryption cipher.
    pub cipher: CipherChoice,
    /// A secure hash function.
    pub hash: HashChoice,
}

impl Default for CryptoChoices {
    fn default() -> Self {
        CryptoChoices {
            dh: DEFAULT_DH_CHOICE,
            cipher: DEFAULT_CIPHER_CHOICE,
            hash: DEFAULT_HASH_CHOICE,
        }
    }
}

impl CryptoChoices {
    /// Create a stringified handshake pattern. The `pattern` parameter includes any
    /// modifiers such as `psk`.
    pub fn stringify_with_pattern(&self, pattern: &str) -> String {
        format!(
            "Noise_{}_{}_{}_{}",
            pattern,
            match self.dh {
                DHChoice::Curve25519 => "25519",
                DHChoice::Ed448 => "448",
            },
            match self.cipher {
                CipherChoice::AESGCM => "AESGCM",
                CipherChoice::ChaChaPoly => "ChaChaPoly",
                // CipherChoice::XChaChaPoly => "XChaChaPoly",
            },
            match self.hash {
                HashChoice::SHA256 => "SHA256",
                HashChoice::SHA512 => "SHA512",
                HashChoice::Blake2s => "BLAKE2s",
                HashChoice::Blake2b => "BLAKE2b",
            },
        )
    }
}

/// A type which implements `Handshake` is a particular instantiation of the Noise protocol
/// with a pre-arranged authentication and encryption procedure.
///
/// A `Handshake` type is passed to methods on [`NoiseTcpStream`][crate::NoiseTcpStream] to
/// conduct a specific kind of handshake.
///
/// By overriding certain methods on `Handshake`, a caller can extend the handshake protocol
/// by attaching additional authenticated data along with each Noise protocol message.
pub trait Handshake {
    /// Returns a string pattern representing the handshake pattern and cryptographic primitives
    /// in use. This can be constructed with [`CryptoChoices::stringify_with_pattern`].
    fn name(&self) -> String;

    /// Construct a handshake state [`Builder`][snow::Builder]. This can be useful for setting a custom
    /// [`CryptoResolver`][snow::resolvers::CryptoResolver], or to set pre-shared symmetric keys or
    /// known static public keys.
    fn new_builder(&self) -> snow::Builder;

    /// Creates the initiator's first message. This begins the Noise conversation.
    ///
    /// By default, this method simply calls `initiator.write_message(&[], send_buf)`
    /// to create the first message. This returns the number of bytes written to `send_buf`
    /// starting from index 0.
    ///
    /// By overwriting this method, the caller can add additional data to the first message. For example:
    ///
    /// ```ignore
    /// initiator.write_message(b"hello world!", send_buf)?;
    /// ```
    ///
    /// ## Caution
    ///
    /// Any data written to `send_buf[..n]` (where `n` is the `usize` returned by this method)
    /// will be sent in **plain text** to the responder. You should only use
    /// [`HandshakeState::write_message`] to write to `send_buf`.
    ///
    /// Depending on the [`HandshakeState`] configuration, the output of `initiator.write_message`
    /// written to `send_buf` may or may not have been encrypted. See
    /// [`HandshakeState::was_write_payload_encrypted`] to confirm.
    fn initiator_first_message(
        &mut self,
        initiator: &mut HandshakeState,
        send_buf: &mut [u8],
    ) -> Result<usize, NoiseError> {
        Ok(initiator.write_message(&[], send_buf)?)
    }

    /// Creates the responder's reply to the initial message from the initiator.
    ///
    /// By default, this method simply calls `responder.write_message(&[], send_buf)`
    /// to create the reply. By overwriting this method, the caller can add additional data
    /// to the first reply based on the _cleartext_ data received from the initiator's first
    /// message.
    ///
    /// ## Caution
    ///
    /// Any data written to `send_buf[..n]` (where `n` is the `usize` returned by this method)
    /// will be sent in **plain text** to the responder. You should only use
    /// [`HandshakeState::write_message`] to write to `send_buf`.
    fn responder_first_message(
        &mut self,
        responder: &mut HandshakeState,
        _recv_buf: &[u8],
        send_buf: &mut [u8],
    ) -> Result<usize, NoiseError> {
        Ok(responder.write_message(&[], send_buf)?)
    }

    /// Creates the initiator's follow-up response to the first reply from the responder.
    /// This is the 3rd message in the sequence. Many handshakes do not require this message.
    ///
    /// By default, this method simply calls `initiator.write_message(&[], send_buf)`
    /// to create the reply. By overwriting this method, the caller can add additional data
    /// to the message based on the _cleartext_ data received from the responder's reply.
    ///
    /// ## Caution
    ///
    /// Any data written to `send_buf[..n]` (where `n` is the `usize` returned by this method)
    /// will be sent in **plain text** to the responder. You should only use
    /// [`HandshakeState::write_message`] to write to `send_buf`.
    fn initiator_second_message(
        &mut self,
        initiator: &mut HandshakeState,
        _recv_buf: &[u8],
        send_buf: &mut [u8],
    ) -> Result<usize, NoiseError> {
        Ok(initiator.write_message(&[], send_buf)?)
    }

    /// Creates the responder's reply to the second message from the initiator.
    /// This is the 4th message in the sequence. Only a select few Noise handshakes
    /// require a 4th message.
    ///
    /// By default, this method simply calls `responder.write_message(&[], send_buf)`
    /// to create the reply. By overwriting this method, the caller can add additional data
    /// to the second reply based on the _cleartext_ data received from the initiator's
    /// second message.
    ///
    /// ## Caution
    ///
    /// Any data written to `send_buf[..n]` (where `n` is the `usize` returned by this method)
    /// will be sent in **plain text** to the responder. You should only use
    /// [`HandshakeState::write_message`] to write to `send_buf`.
    fn responder_second_message(
        &mut self,
        responder: &mut HandshakeState,
        _recv_buf: &[u8],
        send_buf: &mut [u8],
    ) -> Result<usize, NoiseError> {
        Ok(responder.write_message(&[], send_buf)?)
    }

    /// This is a helpful utility method to construct a [`HandshakeError`] quickly.
    fn error(&self, description: impl std::fmt::Display) -> HandshakeError {
        HandshakeError {
            description: description.to_string(),
            handshake_pattern: self.name(),
        }
    }
}

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
