use snow::{
    params::{
        BaseChoice, HandshakeChoice, HandshakeModifier, HandshakeModifierList, HandshakePattern,
        NoiseParams,
    },
    HandshakeState,
};

use crate::errors::NoiseError;

use super::{CryptoChoices, Handshake};

#[derive(Clone, Copy, Debug)]
pub struct Initiator<'p> {
    /// The identity given in plaintext to the responder.
    pub identity: &'p [u8],
    /// The PSK which will be mixed into the handshake after the first initial message.
    /// The responder should be able to look up the same PSK using the value of the
    /// [`Initiator::identity`] field.
    pub psk: &'p [u8],
}

#[derive(Clone, Debug)]
pub struct Responder<F: FnMut(&[u8]) -> Option<&[u8]>> {
    find_psk: F,
    initiator_identity: Option<Vec<u8>>,
}

impl<F: FnMut(&[u8]) -> Option<&[u8]>> Responder<F> {
    pub fn new(find_psk: F) -> Self {
        Responder {
            find_psk,
            initiator_identity: None,
        }
    }

    pub fn initiator_identity(&self) -> Option<&[u8]> {
        self.initiator_identity.as_ref().map(|vec| vec.as_ref())
    }
}

/// Represents an `NNpsk2` handshake, where the initiator already knows a PSK, but
/// must identify themselves in cleartext to the responder in order for the responder
/// to also find that same PSK.
#[derive(Clone, Debug)]
pub struct NNpsk2<P> {
    /// The party object, which looks up the PSK for the handshake. This should either
    /// be an [`Initiator`] or a [`Responder`].
    pub party: P,
    /// The cryptographic primitives needed for the handshake.
    pub choices: CryptoChoices,
}

impl<P> NNpsk2<P> {
    /// Constructs an `NNpsk2` handshake for the given party, which should either be
    /// an [`Initiator`] or a [`Responder`].
    pub fn new(party: P) -> Self {
        NNpsk2 {
            party,
            choices: CryptoChoices::default(),
        }
    }

    /// Constructs an `NNpsk2` handshake for the given party, which should either be
    /// an [`Initiator`] or a [`Responder`]. Allows customizing the ciphersuite parameters.
    pub fn new_custom(party: P, choices: CryptoChoices) -> Self {
        NNpsk2 { party, choices }
    }
}

impl Handshake for NNpsk2<Initiator<'_>> {
    fn name(&self) -> String {
        self.choices.stringify_with_pattern("NNpsk2")
    }

    fn new_builder(&self) -> snow::Builder {
        let params = NoiseParams {
            name: self.name(),
            base: BaseChoice::Noise,
            handshake: HandshakeChoice {
                pattern: HandshakePattern::NN,
                modifiers: HandshakeModifierList {
                    list: vec![HandshakeModifier::Psk(2)],
                },
            },
            dh: self.choices.dh,
            cipher: self.choices.cipher,
            hash: self.choices.hash,
        };
        snow::Builder::new(params)
    }

    fn initiator_first_message(
        &mut self,
        initiator: &mut HandshakeState,
        send_buf: &mut [u8],
    ) -> Result<usize, NoiseError> {
        if self.party.identity.len() > send_buf.len() {
            return Err(self.error(format!(
                "initiator identity size exceeds send buffer size ({} bytes)",
                send_buf.len()
            )))?;
        }
        let n = initiator.write_message(self.party.identity, send_buf)?;
        initiator.set_psk(2, self.party.psk)?;
        Ok(n)
    }
}

impl<F: FnMut(&[u8]) -> Option<&[u8]>> Handshake for NNpsk2<&mut Responder<F>> {
    fn name(&self) -> String {
        self.choices.stringify_with_pattern("NNpsk2")
    }

    fn new_builder(&self) -> snow::Builder {
        let params = NoiseParams {
            name: self.name(),
            base: BaseChoice::Noise,
            handshake: HandshakeChoice {
                pattern: HandshakePattern::NN,
                modifiers: HandshakeModifierList {
                    list: vec![HandshakeModifier::Psk(2)],
                },
            },
            dh: self.choices.dh,
            cipher: self.choices.cipher,
            hash: self.choices.hash,
        };
        snow::Builder::new(params)
    }

    fn responder_first_message(
        &mut self,
        responder: &mut HandshakeState,
        recv_buf: &[u8],
        send_buf: &mut [u8],
    ) -> Result<usize, NoiseError> {
        // Assume the initiator sent us their identity
        let initiator_identity = &recv_buf[..];

        if initiator_identity.len() == 0 {
            return Err(self.error("initiator did not send us their identity to look up a PSK"))?;
        }

        let psk = (self.party.find_psk)(initiator_identity)
            .ok_or_else(|| self.error("found no PSK for initiator"))?;

        self.party.initiator_identity = Some(Vec::from(initiator_identity));
        responder.set_psk(2, psk)?;
        Ok(responder.write_message(&[], send_buf)?)
    }
}
