use alloc::vec::Vec;

use bytes::{Buf, BufMut};

use crate::edge::PathId;

mod effect;
mod router;
mod transit;

pub(crate) use effect::NetworkEffect;
pub use effect::NetworkError;
pub(crate) use router::{Router, RouterInsertError};
pub use transit::TransitGroupId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub path: PathId,
    pub payload: Vec<u8>,
}

impl Datagram {
    pub(crate) const OVERHEAD: usize = PathId::LEN;

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(PathId::LEN + self.payload.len());
        output.put_slice(self.path.as_bytes());
        output.put_slice(&self.payload);
        output
    }

    pub(crate) fn from_bytes(mut input: &[u8]) -> Option<Self> {
        let mut path = [0; PathId::LEN];
        input.try_copy_to_slice(&mut path).ok()?;

        Some(Self {
            path: PathId(path),
            payload: input.to_vec(),
        })
    }
}
