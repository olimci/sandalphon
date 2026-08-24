use crate::{crypto::Signature, edge::Edge};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedEdge {
    pub edge: Edge,
    pub signatures: (Signature, Signature),
}

impl SignedEdge {
    pub const LEN: usize = Edge::LEN + Signature::LEN * 2;

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut output = [0; Self::LEN];
        output[..Edge::LEN].copy_from_slice(&self.edge.to_bytes());
        output[Edge::LEN..Edge::LEN + Signature::LEN]
            .copy_from_slice(&self.signatures.0.to_bytes());
        output[Edge::LEN + Signature::LEN..].copy_from_slice(&self.signatures.1.to_bytes());
        output
    }

    pub fn from_bytes(bytes: &[u8; Self::LEN]) -> Option<Self> {
        let first_signature: [u8; Signature::LEN] = bytes[Edge::LEN..Edge::LEN + Signature::LEN]
            .try_into()
            .unwrap();
        let second_signature: [u8; Signature::LEN] =
            bytes[Edge::LEN + Signature::LEN..].try_into().unwrap();
        let signed = Self {
            edge: Edge::from_bytes(bytes[..Edge::LEN].try_into().unwrap())?,
            signatures: (
                Signature::try_from(first_signature).ok()?,
                Signature::try_from(second_signature).ok()?,
            ),
        };

        signed.verify().then_some(signed)
    }

    pub fn verify(&self) -> bool {
        let bytes = self.edge.to_bytes();
        self.edge
            .endpoints()
            .iter()
            .zip([&self.signatures.0, &self.signatures.1])
            .all(|(public_key, signature)| public_key.verify(&bytes, signature))
    }
}
