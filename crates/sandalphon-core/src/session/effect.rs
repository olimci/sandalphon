use alloc::vec::Vec;

use crate::{
    crypto::{PublicKey, SessionId},
    session::{Packet, ProtocolId},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionEffect {
    Transmit {
        destination: PublicKey,
        packet: Packet,
    },
    Incoming {
        session: SessionId,
        peer: PublicKey,
        protocol: ProtocolId,
        data: Vec<u8>,
    },
    Established {
        session: SessionId,
        peer: PublicKey,
        protocol: ProtocolId,
        data: Vec<u8>,
    },
    Deliver {
        session: SessionId,
        peer: PublicKey,
        protocol: ProtocolId,
        payload: Vec<u8>,
    },
    Error(SessionError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    UnknownSession { session: SessionId },
    NotIncoming { session: SessionId },
    NotEstablished { session: SessionId },
    StorageFull { resource: &'static str },
}
