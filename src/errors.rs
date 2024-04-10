#[derive(Debug)]
pub enum NoiseError {
    Io(std::io::Error),
    Snow(snow::Error),
    UnknownRemoteIdentity,
    RemoteAuthFailure,
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
