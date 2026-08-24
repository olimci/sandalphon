use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolId([u8; ProtocolId::LEN]);

impl ProtocolId {
    pub const LEN: usize = 16;

    pub fn from_name(name: &str) -> Self {
        let full: [u8; 32] = Sha256::new()
            .chain_update(name.as_bytes())
            .finalize()
            .into();

        Self(full[..Self::LEN].try_into().unwrap())
    }

    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    pub const fn to_bytes(self) -> [u8; Self::LEN] {
        self.0
    }
}
