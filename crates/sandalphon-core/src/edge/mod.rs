use sha2::{Digest, Sha256};

use crate::crypto::PublicKey;

mod offer;
mod path;
mod signed;

pub(crate) use offer::*;
pub use path::{ChunkId, Path, PathChunk, PathId};
pub use signed::SignedEdge;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edge {
    endpoints: [PublicKey; 2],
    pub salt: [u8; 16],
    pub mtu: u16,
    pub expires_ms: u64,
}

impl Edge {
    pub const LEN: usize = PublicKey::LEN * 2 + 16 + size_of::<u16>() + size_of::<u64>();

    pub fn new(
        mut endpoints: [PublicKey; 2],
        salt: [u8; 16],
        mtu: u16,
        expires_ms: u64,
    ) -> Option<Self> {
        if endpoints[0] == endpoints[1] {
            return None;
        }
        endpoints.sort_unstable();

        Some(Self {
            endpoints,
            salt,
            mtu,
            expires_ms,
        })
    }

    pub fn endpoints(&self) -> &[PublicKey; 2] {
        &self.endpoints
    }

    pub fn endpoint(&self, public_key: PublicKey) -> Option<&PublicKey> {
        self.endpoints
            .iter()
            .find(|endpoint| **endpoint == public_key)
    }

    pub fn other(&self, public_key: PublicKey) -> Option<&PublicKey> {
        match self.endpoints {
            [first, _] if first == public_key => Some(&self.endpoints[1]),
            [_, second] if second == public_key => Some(&self.endpoints[0]),
            _ => None,
        }
    }

    pub fn id(&self) -> EdgeId {
        EdgeId::from_edge(self)
    }

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut output = [0; Self::LEN];

        for (index, endpoint) in self.endpoints.iter().enumerate() {
            let start = index * PublicKey::LEN;
            output[start..start + PublicKey::LEN].copy_from_slice(&endpoint.to_bytes());
        }
        output[PublicKey::LEN * 2..PublicKey::LEN * 2 + 16].copy_from_slice(&self.salt);
        output[PublicKey::LEN * 2 + 16..PublicKey::LEN * 2 + 18]
            .copy_from_slice(&self.mtu.to_le_bytes());
        output[PublicKey::LEN * 2 + 18..].copy_from_slice(&self.expires_ms.to_le_bytes());

        output
    }

    pub fn from_bytes(bytes: &[u8; Self::LEN]) -> Option<Self> {
        let first_bytes: [u8; PublicKey::LEN] = bytes[..PublicKey::LEN].try_into().unwrap();
        let second_bytes: [u8; PublicKey::LEN] = bytes[PublicKey::LEN..PublicKey::LEN * 2]
            .try_into()
            .unwrap();
        let first = PublicKey::try_from(first_bytes).ok()?;
        let second = PublicKey::try_from(second_bytes).ok()?;
        if first >= second {
            return None;
        }

        Some(Self {
            endpoints: [first, second],
            salt: bytes[PublicKey::LEN * 2..PublicKey::LEN * 2 + 16]
                .try_into()
                .unwrap(),
            mtu: u16::from_le_bytes(
                bytes[PublicKey::LEN * 2 + 16..PublicKey::LEN * 2 + 18]
                    .try_into()
                    .unwrap(),
            ),
            expires_ms: u64::from_le_bytes(bytes[PublicKey::LEN * 2 + 18..].try_into().unwrap()),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EdgeId(pub [u8; EdgeId::LEN]);

impl EdgeId {
    pub const LEN: usize = 16;

    fn from_edge(edge: &Edge) -> Self {
        let full: [u8; 32] = Sha256::new()
            .chain_update(edge.to_bytes())
            .finalize()
            .into();
        Self(full[..Self::LEN].try_into().unwrap())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
