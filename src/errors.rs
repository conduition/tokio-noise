use std::{error::Error, fmt, io};

/// An error derived from either `std::io::Error` or `snow::Error`.
#[derive(Debug)]
pub enum NoiseError {
    /// An error occurred during an IO operation, such as reading or writing a socket.
    Io(io::Error),
    /// An error occurred on the noise protocol level, such as a decryption failure.
    Snow(snow::Error),
    /// An error occurred within a [`Handshake`][crate::handshakes::Handshake] implementation.
    Handshake(HandshakeError),
}

impl From<io::Error> for NoiseError {
    fn from(e: io::Error) -> Self {
        NoiseError::Io(e)
    }
}

impl From<snow::Error> for NoiseError {
    fn from(e: snow::Error) -> Self {
        NoiseError::Snow(e)
    }
}

impl From<HandshakeError> for NoiseError {
    fn from(e: HandshakeError) -> Self {
        NoiseError::Handshake(e)
    }
}

impl fmt::Display for NoiseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NoiseError::Io(e) => write!(f, "Noise IO error: {}", e),
            NoiseError::Snow(e) => write!(f, "Noise snow error: {}", e),
            NoiseError::Handshake(e) => write!(f, "Noise snow error: {}", e),
        }
    }
}
impl Error for NoiseError {}

/// An error returned from custom handshake extension methods.
#[derive(Debug)]
pub struct HandshakeError {
    /// A description of the error.
    pub description: String,
    /// The handshake pattern during which the error occurred.
    pub handshake_pattern: String,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} handshake error: {}",
            self.handshake_pattern, self.description
        )
    }
}
impl Error for HandshakeError {}
