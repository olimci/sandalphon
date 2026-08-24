use core::cmp::Ordering;

use k256::schnorr::{VerifyingKey as SchnorrVerifyingKey, signature::Verifier};

use crate::crypto::{CryptoError, Signature};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub(crate) SchnorrVerifyingKey);

impl PublicKey {
    pub const LEN: usize = 32;

    pub(crate) fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.0.verify(message, &signature.0).is_ok()
    }

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        self.0.to_bytes().into()
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl TryFrom<[u8; PublicKey::LEN]> for PublicKey {
    type Error = CryptoError;

    fn try_from(value: [u8; PublicKey::LEN]) -> Result<Self, Self::Error> {
        Ok(Self(
            SchnorrVerifyingKey::from_slice(value.as_slice())
                .map_err(|_| CryptoError::PublicKeyError)?,
        ))
    }
}
