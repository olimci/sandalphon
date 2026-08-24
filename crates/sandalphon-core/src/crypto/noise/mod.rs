use alloc::vec::Vec;
use core::mem;

use crate::crypto::{CryptoError, noise::cipher::CipherState};

mod cipher;
mod handshake;
mod symmetric;

pub(crate) use handshake::*;

const REKEY_INTERVAL: u64 = 1 << 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SessionId(pub u32);

impl SessionId {
    pub const LEN: usize = size_of::<u32>();
}

#[derive(Debug, Default)]
struct Window {
    top: Option<u64>,
    seen: u128,
}

impl Window {
    const WIDTH: u64 = u128::BITS as u64;

    fn contains(&self, seq: u64) -> bool {
        let Some(top) = self.top else {
            return false;
        };

        if seq > top {
            return false;
        }

        let dist = top - seq;
        dist >= Self::WIDTH || self.seen & (1 << dist) != 0
    }

    fn insert(&mut self, seq: u64) {
        match self.top {
            None => {
                self.top = Some(seq);
                self.seen = 1;
            }
            Some(top) if seq > top => {
                let dist = seq - top;
                self.seen = if dist < Self::WIDTH {
                    self.seen << dist
                } else {
                    0
                } | 1;
                self.top = Some(seq);
            }
            Some(top) => self.seen |= 1 << (top - seq),
        }
    }
}

pub(crate) struct NoiseSession {
    send: CipherState,
    send_epoch: u64,
    recv: CipherState,
    recv_epoch: u64,
    previous_recv: Option<CipherState>,
    window: Window,
}

impl NoiseSession {
    pub(crate) fn seal(
        &mut self,
        context: &[u8],
        plaintext: &[u8],
    ) -> Result<(u32, Vec<u8>), CryptoError> {
        let seq = u32::try_from(self.send.n).map_err(|_| CryptoError::NonceOverflow)?;
        let epoch = u64::from(seq) / REKEY_INTERVAL;
        if epoch > self.send_epoch {
            self.send.rekey();
            self.send_epoch = epoch;
        }
        let mut ad = Vec::with_capacity(context.len() + size_of::<u32>());
        ad.extend(context);
        ad.extend(seq.to_le_bytes());

        self.send
            .encrypt_with_ad(&ad, plaintext)
            .map(|ciphertext| (seq, ciphertext))
    }

    pub(crate) fn open(&mut self, seq: u32, context: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let sequence = seq;
        let seq = u64::from(seq);
        if self.window.contains(seq) {
            return None;
        }

        let mut ad = Vec::with_capacity(context.len() + size_of::<u32>());
        ad.extend(context);
        ad.extend(sequence.to_le_bytes());

        let epoch = seq / REKEY_INTERVAL;
        let plaintext = if epoch == self.recv_epoch {
            self.recv.n = seq;
            self.recv.decrypt_with_ad(&ad, ciphertext).ok()?
        } else if epoch + 1 == self.recv_epoch {
            let previous = self.previous_recv.as_mut()?;
            previous.n = seq;
            previous.decrypt_with_ad(&ad, ciphertext).ok()?
        } else if epoch == self.recv_epoch + 1 {
            let mut next = self.recv.clone();
            next.rekey();
            next.n = seq;
            let plaintext = next.decrypt_with_ad(&ad, ciphertext).ok()?;
            self.previous_recv = Some(mem::replace(&mut self.recv, next));
            self.recv_epoch = epoch;
            plaintext
        } else {
            return None;
        };

        self.window.insert(seq);
        if self
            .window
            .top
            .is_some_and(|top| top >= self.recv_epoch * REKEY_INTERVAL + Window::WIDTH - 1)
        {
            self.previous_recv = None;
        }

        Some(plaintext)
    }
}
