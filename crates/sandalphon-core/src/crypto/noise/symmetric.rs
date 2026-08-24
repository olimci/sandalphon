use alloc::vec::Vec;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{CryptoError, noise::cipher::CipherState};

pub(crate) struct SymmetricState {
    cipher: CipherState,
    ck: Zeroizing<[u8; 32]>,
    h: [u8; 32],
}

impl SymmetricState {
    pub(super) fn new() -> Self {
        // Note: if this for some reason becomes shorter, we might not need to hash the name.
        // Specifically, noise specifies <= HASHLEN (32 bytes for us), then h is just the name 0-padded to 32 bytes.
        let h: [u8; 32] = Sha256::digest(b"Noise_IK_secp256k1_ChaChaPoly_SHA256").into();

        Self {
            cipher: CipherState::default(),
            ck: Zeroizing::new(h),
            h,
        }
    }

    pub(super) fn mix_key(&mut self, input: &[u8]) {
        let mut output = Zeroizing::new([0; 64]);

        Hkdf::<Sha256>::new(Some(self.ck.as_ref()), input)
            .expand(&[], output.as_mut())
            .expect("is 64 bytes");

        let (chunks, []) = output.as_chunks::<32>() else {
            unreachable!();
        };

        let [ck, key] = chunks else {
            unreachable!();
        };

        self.ck.copy_from_slice(ck);
        self.cipher = CipherState::new(key);
    }

    pub(super) fn mix_hash(&mut self, data: &[u8]) {
        self.h = Sha256::new()
            .chain_update(self.h)
            .chain_update(data)
            .finalize()
            .into();
    }

    pub(super) fn get_handshake_hash(&self) -> &[u8] {
        &self.h
    }

    pub(super) fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let ciphertext = self.cipher.encrypt_with_ad(&self.h, plaintext)?;
        self.mix_hash(ciphertext.as_slice());
        Ok(ciphertext)
    }

    pub(super) fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let plaintext = self.cipher.decrypt_with_ad(&self.h, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    pub(super) fn split(self) -> (CipherState, CipherState) {
        let mut output = Zeroizing::new([0; 64]);

        Hkdf::<Sha256>::new(Some(self.ck.as_ref()), &[])
            .expand(&[], output.as_mut())
            .expect("is 64 bytes");

        let (chunks, []) = output.as_chunks::<32>() else {
            unreachable!();
        };

        let [k1, k2] = chunks else {
            unreachable!();
        };

        (CipherState::new(k1), CipherState::new(k2))
    }
}
