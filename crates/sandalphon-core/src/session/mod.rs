use alloc::vec::Vec;

mod effect;
mod manager;
mod packet;
mod protocol;

pub(crate) use effect::SessionEffect;
pub use effect::SessionError;
pub(crate) use manager::{SessionManager, SessionStartError};
pub use protocol::ProtocolId;

use crate::crypto::SessionId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Packet {
    HandshakeInit {
        message: Vec<u8>,
    },
    HandshakeResponse {
        session: SessionId,
        message: Vec<u8>,
    },
    Transport {
        session: SessionId,
        sequence: u32,
        ciphertext: Vec<u8>,
    },
}
