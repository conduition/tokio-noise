/// An error derived from either `std::io::Error` or `snow::Error`.
#[derive(Debug)]
pub enum NoiseError {
    /// An error occurred during an IO operation, such as reading or writing a socket.
    Io(std::io::Error),
    /// An error occurred on the noise protocol level, such as a decryption failure.
    Snow(snow::Error),
}

impl From<std::io::Error> for NoiseError {
    fn from(e: std::io::Error) -> Self {
        NoiseError::Io(e)
    }
}

impl From<snow::Error> for NoiseError {
    fn from(e: snow::Error) -> Self {
        NoiseError::Snow(e)
    }
}

impl std::fmt::Display for NoiseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            NoiseError::Io(e) => write!(f, "Noise IO error: {}", e),
            NoiseError::Snow(e) => write!(f, "Noise snow error: {}", e),
        }
    }
}

impl std::error::Error for NoiseError {}
