use alloc::vec::Vec;

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};

use crate::crypto::CryptoError;

#[derive(Clone, Default)]
pub(super) struct CipherState {
    k: Option<ChaCha20Poly1305>,
    pub(super) n: u64,
}

impl CipherState {
    pub(super) fn new(k: &[u8; 32]) -> Self {
        Self {
            k: Some(ChaCha20Poly1305::new_from_slice(k).expect("key length is 32")),
            n: 0,
        }
    }

    pub(super) fn encrypt_with_ad(
        &mut self,
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if self.n == u64::MAX {
            return Err(CryptoError::NonceOverflow);
        }

        match &self.k {
            Some(k) => {
                let out = k.encrypt(
                    &nonce(self.n),
                    Payload {
                        msg: plaintext,
                        aad: ad,
                    },
                )?;
                self.n += 1;
                Ok(out)
            }
            None => Ok(plaintext.to_vec()),
        }
    }

    pub(super) fn decrypt_with_ad(
        &mut self,
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if self.n == u64::MAX {
            return Err(CryptoError::NonceOverflow);
        }

        match &self.k {
            Some(k) => {
                let out = k.decrypt(
                    &nonce(self.n),
                    Payload {
                        msg: ciphertext,
                        aad: ad,
                    },
                )?;
                self.n += 1;
                Ok(out)
            }
            None => Ok(ciphertext.to_vec()),
        }
    }

    pub(super) fn rekey(&mut self) {
        let old_k = self.k.as_ref().expect("key required to rekey");

        let ciphertext = old_k
            .encrypt(
                &nonce(u64::MAX),
                Payload {
                    msg: &[0; 32],
                    aad: &[],
                },
            )
            .expect("rekey input must be valid");

        self.k =
            Some(ChaCha20Poly1305::new_from_slice(&ciphertext[..32]).expect("key length is 32"));
    }
}

// fuck you
fn nonce(n: u64) -> Nonce {
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&n.to_le_bytes());
    nonce.into()
}
