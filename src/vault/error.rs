use std::fmt;

#[derive(Debug)]
pub enum VaultError {
    TooLarge,
    Crypto(chacha20poly1305::Error),
    Io(std::io::Error),
    Slice(std::array::TryFromSliceError),
    LengthMismatch,
    ParseError,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::TooLarge => write!(f, "data too large for vault format"),
            VaultError::Crypto(e) => write!(f, "crypto error: {}", e),
            VaultError::Io(e) => write!(f, "io error: {}", e),
            VaultError::LengthMismatch => {
                write!(f, "mismatch between data length and length header")
            }
            VaultError::Slice(e) => write!(f, "Slice invalid size: {}", e),
            VaultError::ParseError => write!(f, "Could not parse value"),
        }
    }
}

impl std::error::Error for VaultError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VaultError::Crypto(e) => None,
            VaultError::Io(e) => Some(e),
            VaultError::TooLarge => None,
            VaultError::LengthMismatch => None,
            VaultError::Slice(e) => Some(e),
            VaultError::ParseError => None,
        }
    }
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e)
    }
}

impl From<chacha20poly1305::Error> for VaultError {
    fn from(e: chacha20poly1305::Error) -> Self {
        VaultError::Crypto(e)
    }
}