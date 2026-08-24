use k256::{
    ecdh::diffie_hellman,
    elliptic_curve::Generate,
    schnorr::{SigningKey as SchnorrSigningKey, signature::Signer},
};
use rand_core::CryptoRng;

use super::SharedSecret;
use crate::crypto::{PublicKey, Signature};

#[derive(Debug, Clone)]
pub struct PrivateKey(SchnorrSigningKey);

impl PrivateKey {
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        Self(SchnorrSigningKey::generate_from_rng(rng))
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(*self.0.verifying_key())
    }

    pub(crate) fn diffie_hellman(&self, public: &PublicKey) -> SharedSecret {
        SharedSecret(diffie_hellman(
            self.0.as_nonzero_scalar(),
            public.0.as_affine(),
        ))
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message))
    }
}
