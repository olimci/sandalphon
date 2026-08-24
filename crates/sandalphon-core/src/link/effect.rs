use alloc::boxed::Box;

use crate::{
    crypto::PublicKey,
    edge::{EdgeId, Path, SignedEdge},
    link::LinkFrame,
    network::Datagram,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkEffect {
    UnknownEdge(EdgeId),
    Capacity {
        resource: &'static str,
    },
    Transmit {
        frame: LinkFrame,
    },
    Opened(Box<SignedEdge>),
    Closed(EdgeId),
    Route {
        ingress: EdgeId,
        path: Path,
    },
    RouteRequest {
        ingress: EdgeId,
        destination: PublicKey,
    },
    Edge(Box<SignedEdge>),
    EdgeRequest {
        ingress: EdgeId,
        requested: EdgeId,
    },
    Datagram {
        ingress: EdgeId,
        datagram: Datagram,
    },
}
