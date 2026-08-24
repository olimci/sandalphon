use alloc::{boxed::Box, vec::Vec};

use bytes::{Buf, BufMut};

use crate::{
    crypto::{PublicKey, SessionId, Signature},
    edge::{ChunkId, Edge, EdgeId, PathChunk, SignedEdge},
    network::Datagram,
};

mod effect;
mod manager;

pub use effect::LinkEffect;
pub use manager::LinkManager;

pub(crate) const SESSION_OVERHEAD: usize = 1 + size_of::<u32>() * 2 + 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkFrame {
    Announce {
        public_key: PublicKey,
    },
    HandshakeInit {
        recipient: PublicKey,
        message: Vec<u8>,
    },
    HandshakeResp {
        session: SessionId,
        recipient: PublicKey,
        message: Vec<u8>,
    },
    TransportAccept {
        session: SessionId,
        sequence: u32,
        ciphertext: Vec<u8>,
    },
    TransportConfirm {
        session: SessionId,
        sequence: u32,
        ciphertext: Vec<u8>,
    },
    TransportDatagram {
        session: SessionId,
        sequence: u32,
        ciphertext: Vec<u8>,
    },
    TransportRoute {
        session: SessionId,
        sequence: u32,
        ciphertext: Vec<u8>,
    },
    TransportRouteRequest {
        session: SessionId,
        sequence: u32,
        ciphertext: Vec<u8>,
    },
    TransportPathChunk {
        session: SessionId,
        sequence: u32,
        ciphertext: Vec<u8>,
    },
    TransportPathChunkRequest {
        session: SessionId,
        sequence: u32,
        ciphertext: Vec<u8>,
    },
    TransportEdge {
        session: SessionId,
        sequence: u32,
        ciphertext: Vec<u8>,
    },
    TransportEdgeRequest {
        session: SessionId,
        sequence: u32,
        ciphertext: Vec<u8>,
    },
}

impl LinkFrame {
    const ANNOUNCE: u8 = 0x00;
    const HANDSHAKE_INIT: u8 = 0x01;
    const HANDSHAKE_RESP: u8 = 0x02;
    const TRANSPORT_ACCEPT: u8 = 0x03;
    const TRANSPORT_CONFIRM: u8 = 0x04;
    const TRANSPORT_DATAGRAM: u8 = 0x05;
    const TRANSPORT_ROUTE: u8 = 0x06;
    const TRANSPORT_ROUTE_REQUEST: u8 = 0x07;
    const TRANSPORT_PATH_CHUNK: u8 = 0x08;
    const TRANSPORT_PATH_CHUNK_REQUEST: u8 = 0x09;
    const TRANSPORT_EDGE: u8 = 0x0a;
    const TRANSPORT_EDGE_REQUEST: u8 = 0x0b;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();

        match self {
            Self::Announce { public_key } => {
                output.put_u8(Self::ANNOUNCE);
                output.put_slice(&public_key.to_bytes());
            }
            Self::HandshakeInit { recipient, message } => {
                output.put_u8(Self::HANDSHAKE_INIT);
                output.put_slice(&recipient.to_bytes());
                output.put_slice(message);
            }
            Self::HandshakeResp {
                session,
                recipient,
                message,
            } => {
                output.put_u8(Self::HANDSHAKE_RESP);
                output.put_u32_le(session.0);
                output.put_slice(&recipient.to_bytes());
                output.put_slice(message);
            }
            transport => {
                let (kind, session, sequence, ciphertext) = match transport {
                    Self::TransportAccept {
                        session,
                        sequence,
                        ciphertext,
                    } => (Self::TRANSPORT_ACCEPT, session, sequence, ciphertext),
                    Self::TransportConfirm {
                        session,
                        sequence,
                        ciphertext,
                    } => (Self::TRANSPORT_CONFIRM, session, sequence, ciphertext),
                    Self::TransportDatagram {
                        session,
                        sequence,
                        ciphertext,
                    } => (Self::TRANSPORT_DATAGRAM, session, sequence, ciphertext),
                    Self::TransportRoute {
                        session,
                        sequence,
                        ciphertext,
                    } => (Self::TRANSPORT_ROUTE, session, sequence, ciphertext),
                    Self::TransportRouteRequest {
                        session,
                        sequence,
                        ciphertext,
                    } => (Self::TRANSPORT_ROUTE_REQUEST, session, sequence, ciphertext),
                    Self::TransportPathChunk {
                        session,
                        sequence,
                        ciphertext,
                    } => (Self::TRANSPORT_PATH_CHUNK, session, sequence, ciphertext),
                    Self::TransportPathChunkRequest {
                        session,
                        sequence,
                        ciphertext,
                    } => (
                        Self::TRANSPORT_PATH_CHUNK_REQUEST,
                        session,
                        sequence,
                        ciphertext,
                    ),
                    Self::TransportEdge {
                        session,
                        sequence,
                        ciphertext,
                    } => (Self::TRANSPORT_EDGE, session, sequence, ciphertext),
                    Self::TransportEdgeRequest {
                        session,
                        sequence,
                        ciphertext,
                    } => (Self::TRANSPORT_EDGE_REQUEST, session, sequence, ciphertext),
                    _ => unreachable!(),
                };
                output.put_u8(kind);
                output.put_u32_le(session.0);
                output.put_u32_le(*sequence);
                output.put_slice(ciphertext);
            }
        }

        output
    }

    pub fn from_bytes(mut input: &[u8]) -> Option<Self> {
        match input.try_get_u8().ok()? {
            Self::ANNOUNCE => {
                let mut public_key = [0; PublicKey::LEN];
                input.try_copy_to_slice(&mut public_key).ok()?;
                let public_key = PublicKey::try_from(public_key).ok()?;
                (!input.has_remaining()).then_some(Self::Announce { public_key })
            }
            Self::HANDSHAKE_INIT => {
                let mut recipient = [0; PublicKey::LEN];
                input.try_copy_to_slice(&mut recipient).ok()?;
                Some(Self::HandshakeInit {
                    recipient: PublicKey::try_from(recipient).ok()?,
                    message: input.to_vec(),
                })
            }
            Self::HANDSHAKE_RESP => {
                let session = SessionId(input.try_get_u32_le().ok()?);
                let mut recipient = [0; PublicKey::LEN];
                input.try_copy_to_slice(&mut recipient).ok()?;
                Some(Self::HandshakeResp {
                    session,
                    recipient: PublicKey::try_from(recipient).ok()?,
                    message: input.to_vec(),
                })
            }
            kind @ (Self::TRANSPORT_ACCEPT
            | Self::TRANSPORT_CONFIRM
            | Self::TRANSPORT_DATAGRAM
            | Self::TRANSPORT_ROUTE
            | Self::TRANSPORT_ROUTE_REQUEST
            | Self::TRANSPORT_PATH_CHUNK
            | Self::TRANSPORT_PATH_CHUNK_REQUEST
            | Self::TRANSPORT_EDGE
            | Self::TRANSPORT_EDGE_REQUEST) => {
                let session = SessionId(input.try_get_u32_le().ok()?);
                let sequence = input.try_get_u32_le().ok()?;
                let ciphertext = input.to_vec();
                Some(match kind {
                    Self::TRANSPORT_ACCEPT => Self::TransportAccept {
                        session,
                        sequence,
                        ciphertext,
                    },
                    Self::TRANSPORT_CONFIRM => Self::TransportConfirm {
                        session,
                        sequence,
                        ciphertext,
                    },
                    Self::TRANSPORT_DATAGRAM => Self::TransportDatagram {
                        session,
                        sequence,
                        ciphertext,
                    },
                    Self::TRANSPORT_ROUTE => Self::TransportRoute {
                        session,
                        sequence,
                        ciphertext,
                    },
                    Self::TRANSPORT_ROUTE_REQUEST => Self::TransportRouteRequest {
                        session,
                        sequence,
                        ciphertext,
                    },
                    Self::TRANSPORT_PATH_CHUNK => Self::TransportPathChunk {
                        session,
                        sequence,
                        ciphertext,
                    },
                    Self::TRANSPORT_PATH_CHUNK_REQUEST => Self::TransportPathChunkRequest {
                        session,
                        sequence,
                        ciphertext,
                    },
                    Self::TRANSPORT_EDGE => Self::TransportEdge {
                        session,
                        sequence,
                        ciphertext,
                    },
                    Self::TRANSPORT_EDGE_REQUEST => Self::TransportEdgeRequest {
                        session,
                        sequence,
                        ciphertext,
                    },
                    _ => unreachable!(),
                })
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LinkSessionFrame {
    Accept(Box<Edge>, Signature),
    Confirm(EdgeId, Signature),
    Gossip(Gossip),
    Datagram(Datagram),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gossip {
    Route(ChunkId),
    RouteRequest(PublicKey),
    PathChunk(PathChunk),
    PathChunkRequest(ChunkId),
    Edge(Box<SignedEdge>),
    EdgeRequest(EdgeId),
}

impl LinkSessionFrame {
    fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();

        match self {
            Self::Accept(edge, signature) => {
                output.put_slice(&edge.to_bytes());
                output.put_slice(&signature.to_bytes());
            }
            Self::Confirm(edge, signature) => {
                output.put_slice(edge.as_bytes());
                output.put_slice(&signature.to_bytes());
            }
            Self::Gossip(Gossip::Route(root)) => {
                output.put_slice(root.as_bytes());
            }
            Self::Gossip(Gossip::RouteRequest(destination)) => {
                output.put_slice(&destination.to_bytes());
            }
            Self::Gossip(Gossip::PathChunk(chunk)) => {
                output.put_slice(&chunk.to_bytes());
            }
            Self::Gossip(Gossip::PathChunkRequest(chunk)) => {
                output.put_slice(chunk.as_bytes());
            }
            Self::Gossip(Gossip::Edge(edge)) => {
                output.put_slice(&edge.to_bytes());
            }
            Self::Gossip(Gossip::EdgeRequest(edge)) => {
                output.put_slice(edge.as_bytes());
            }
            Self::Datagram(datagram) => {
                output.put_slice(&datagram.to_bytes());
            }
        }

        output
    }

    fn from_bytes(kind: u8, mut input: &[u8]) -> Option<Self> {
        let frame = match kind {
            LinkFrame::TRANSPORT_ACCEPT => {
                let mut edge = [0; Edge::LEN];
                let mut signature = [0; Signature::LEN];
                input.try_copy_to_slice(&mut edge).ok()?;
                input.try_copy_to_slice(&mut signature).ok()?;
                Self::Accept(
                    Box::new(Edge::from_bytes(&edge)?),
                    Signature::try_from(signature).ok()?,
                )
            }
            LinkFrame::TRANSPORT_CONFIRM => {
                let mut edge = [0; EdgeId::LEN];
                let mut signature = [0; Signature::LEN];
                input.try_copy_to_slice(&mut edge).ok()?;
                input.try_copy_to_slice(&mut signature).ok()?;
                Self::Confirm(EdgeId(edge), Signature::try_from(signature).ok()?)
            }
            LinkFrame::TRANSPORT_DATAGRAM => {
                return Datagram::from_bytes(input).map(Self::Datagram);
            }
            LinkFrame::TRANSPORT_ROUTE => {
                let mut root = [0; ChunkId::LEN];
                input.try_copy_to_slice(&mut root).ok()?;
                Self::Gossip(Gossip::Route(ChunkId(root)))
            }
            LinkFrame::TRANSPORT_ROUTE_REQUEST => {
                let mut destination = [0; PublicKey::LEN];
                input.try_copy_to_slice(&mut destination).ok()?;
                Self::Gossip(Gossip::RouteRequest(PublicKey::try_from(destination).ok()?))
            }
            LinkFrame::TRANSPORT_PATH_CHUNK => {
                return PathChunk::from_bytes(input)
                    .map(Gossip::PathChunk)
                    .map(Self::Gossip);
            }
            LinkFrame::TRANSPORT_PATH_CHUNK_REQUEST => {
                let mut chunk = [0; ChunkId::LEN];
                input.try_copy_to_slice(&mut chunk).ok()?;
                Self::Gossip(Gossip::PathChunkRequest(ChunkId(chunk)))
            }
            LinkFrame::TRANSPORT_EDGE => {
                let mut edge = [0; SignedEdge::LEN];
                input.try_copy_to_slice(&mut edge).ok()?;
                Self::Gossip(Gossip::Edge(Box::new(SignedEdge::from_bytes(&edge)?)))
            }
            LinkFrame::TRANSPORT_EDGE_REQUEST => {
                let mut edge = [0; EdgeId::LEN];
                input.try_copy_to_slice(&mut edge).ok()?;
                Self::Gossip(Gossip::EdgeRequest(EdgeId(edge)))
            }
            _ => return None,
        };

        (!input.has_remaining()).then_some(frame)
    }
}
