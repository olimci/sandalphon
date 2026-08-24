use alloc::vec::Vec;

use crate::{
    crypto::PublicKey,
    edge::{EdgeId, PathId},
    network::Datagram,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NetworkEffect {
    Transmit { edge: EdgeId, datagram: Datagram },
    Deliver(Vec<u8>),
    Error(NetworkError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkError {
    NoRoute { destination: PublicKey },
    UnknownPath { path: PathId },
    UnknownIngress { edge: EdgeId },
    TransitDenied { ingress: EdgeId, egress: EdgeId },
    PayloadTooLarge { maximum: usize, actual: usize },
}
