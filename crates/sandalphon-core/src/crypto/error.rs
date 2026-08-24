use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error(transparent)]
    ChaCha20Poly1305Error(#[from] chacha20poly1305::Error),

    #[error("nonce overflow")]
    NonceOverflow,

    #[error("public key error")]
    PublicKeyError,

    #[error("invalid Noise handshake message")]
    InvalidNoiseHandshake,
}
