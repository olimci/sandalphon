use bytes::{Buf, BufMut};

use super::Edge;
use crate::crypto::PublicKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Offer {
    public_key: PublicKey,
    mtu: u16,
    expires_ms: u64,
}

impl Offer {
    const LEN: usize = PublicKey::LEN + size_of::<u16>() + size_of::<u64>();

    pub(crate) fn new(public_key: PublicKey, mtu: u16, expires_ms: u64) -> Self {
        Self {
            public_key,
            mtu,
            expires_ms,
        }
    }

    pub(crate) fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut output = [0; Self::LEN];
        let mut cursor = output.as_mut_slice();
        cursor.put_slice(&self.public_key.to_bytes());
        cursor.put_u16_le(self.mtu);
        cursor.put_u64_le(self.expires_ms);
        output
    }

    pub(crate) fn from_bytes(bytes: &[u8; Self::LEN]) -> Option<Self> {
        let mut cursor = bytes.as_slice();
        let mut public_key = [0; PublicKey::LEN];
        cursor.copy_to_slice(&mut public_key);

        Some(Self {
            public_key: PublicKey::try_from(public_key).ok()?,
            mtu: cursor.get_u16_le(),
            expires_ms: cursor.get_u64_le(),
        })
    }

    pub(crate) fn edge(&self, remote: &Self, salt: [u8; 16]) -> Option<Edge> {
        Edge::new(
            [self.public_key, remote.public_key],
            salt,
            self.mtu.min(remote.mtu),
            self.expires_ms.min(remote.expires_ms),
        )
    }
}
