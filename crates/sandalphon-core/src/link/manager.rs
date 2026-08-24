use alloc::{boxed::Box, vec, vec::Vec};

use rand_core::CryptoRng;

use crate::{
    crypto::{IkHandshake, NoiseSession, PrivateKey, PublicKey, SessionId, Signature},
    edge::{ChunkId, Edge, EdgeId, Offer, Path, PathChunk, SignedEdge},
    link::{Gossip, LinkEffect, LinkFrame, LinkSessionFrame, SESSION_OVERHEAD},
    network::Datagram,
    storage::{StorageProvider, TableMap, TableSet},
};

const NEGOTIATION_TIMEOUT_MS: u64 = 30_000;
const CHUNK_RETRY_MS: u64 = 5_000;
const CHUNK_CACHE_TTL_MS: u64 = 300_000;
const ROUTE_ASSEMBLY_TIMEOUT_MS: u64 = 60_000;
const HANDSHAKE_CONTEXT: &[u8] = b"sandalphon/link/v1";

enum LinkSession {
    AwaitingHandshake {
        peer: PublicKey,
        handshake: IkHandshake,
        offer: Offer,
        expires_ms: u64,
    },
    AwaitingAccept {
        peer: PublicKey,
        noise: NoiseSession,
        edge: Edge,
        signature: Signature,
        expires_ms: u64,
    },
    AwaitingConfirm {
        peer: PublicKey,
        noise: NoiseSession,
        edge: Edge,
        signature: Signature,
        expires_ms: u64,
    },
    Open {
        peer: PublicKey,
        noise: NoiseSession,
        edge: SignedEdge,
    },
}

impl LinkSession {
    fn peer(&self) -> PublicKey {
        match self {
            Self::AwaitingHandshake { peer, .. }
            | Self::AwaitingAccept { peer, .. }
            | Self::AwaitingConfirm { peer, .. }
            | Self::Open { peer, .. } => *peer,
        }
    }

    fn expires_ms(&self) -> u64 {
        match self {
            Self::AwaitingHandshake { expires_ms, .. }
            | Self::AwaitingAccept { expires_ms, .. }
            | Self::AwaitingConfirm { expires_ms, .. } => *expires_ms,
            Self::Open { edge, .. } => edge.edge.expires_ms,
        }
    }

    fn incomplete(&self) -> bool {
        !matches!(self, Self::Open { .. })
    }
}

struct SessionStore<P: StorageProvider> {
    sessions: P::LinkSessions<SessionId, LinkSession>,
    incomplete: P::LinkIncomplete<(u64, SessionId)>,
    expirations: P::LinkExpirations<(u64, SessionId)>,
    edges: P::LinkEdges<EdgeId, Vec<SessionId>>,
    incomplete_limit: usize,
}

struct ChunkStore<P: StorageProvider> {
    chunks: P::LinkChunks<ChunkId, PathChunk>,
    chunk_deadlines: P::LinkChunkDeadlines<ChunkId, u64>,
    routes: P::LinkRoutes<(EdgeId, ChunkId), u64>,
    requested: P::LinkRequested<(EdgeId, ChunkId), u64>,
}

impl<P: StorageProvider> SessionStore<P> {
    fn insert(&mut self, id: SessionId, session: LinkSession) -> Result<bool, &'static str> {
        if self.sessions.contains_key(&id) || !self.sessions.can_insert(&id) {
            return Err("link sessions");
        }
        let expires_ms = session.expires_ms();
        let incomplete = session.incomplete();
        if incomplete && !self.incomplete.can_insert(&(expires_ms, id)) {
            return Err("link incomplete sessions");
        }
        if !self.expirations.can_insert(&(expires_ms, id)) {
            return Err("link expirations");
        }
        let edge_id = match &session {
            LinkSession::Open { edge, .. } => Some(edge.edge.id()),
            _ => None,
        };
        if edge_id.is_some_and(|edge| !self.edges.can_insert(&edge)) {
            return Err("link edges");
        }

        self.sessions
            .try_insert(id, session)
            .map_err(|_| "link sessions")?;
        if incomplete && self.incomplete.try_insert((expires_ms, id)).is_err() {
            self.sessions.remove(&id);
            return Err("link incomplete sessions");
        }
        if self.expirations.try_insert((expires_ms, id)).is_err() {
            if incomplete {
                self.incomplete.remove(&(expires_ms, id));
            }
            self.sessions.remove(&id);
            return Err("link expirations");
        }
        let opened = if let Some(edge) = edge_id {
            if let Some(candidates) = self.edges.get_mut(&edge) {
                candidates.push(id);
                false
            } else if self.edges.try_insert(edge, vec![id]).is_ok() {
                true
            } else {
                self.expirations.remove(&(expires_ms, id));
                if incomplete {
                    self.incomplete.remove(&(expires_ms, id));
                }
                self.sessions.remove(&id);
                return Err("link edges");
            }
        } else {
            false
        };
        Ok(opened)
    }

    fn remove(&mut self, id: SessionId) -> Option<(LinkSession, Option<EdgeId>)> {
        let session = self.sessions.remove(&id)?;
        let expires_ms = session.expires_ms();
        self.expirations.remove(&(expires_ms, id));
        if session.incomplete() {
            self.incomplete.remove(&(expires_ms, id));
        }

        let closed = if let LinkSession::Open { edge, .. } = &session {
            let edge = edge.edge.id();
            let candidates = self.edges.get_mut(&edge).expect("open edge is indexed");
            candidates.retain(|candidate| *candidate != id);
            candidates.is_empty().then_some(edge)
        } else {
            None
        };
        if let Some(edge) = closed {
            self.edges.remove(&edge);
        }

        Some((session, closed))
    }

    fn session_for_peer(&self, peer: PublicKey) -> Option<(SessionId, &LinkSession)> {
        self.sessions
            .iter()
            .find(|(_, session)| session.peer() == peer)
            .map(|(id, session)| (*id, session))
    }
}

pub struct LinkManager<P: StorageProvider> {
    private_key: PrivateKey,
    identity: PrivateKey,
    datagram_mtu: u16,
    minimum_mtu: u16,
    expires_ms: u64,
    now_ms: u64,
    sessions: SessionStore<P>,
    chunks: ChunkStore<P>,
}

impl<P: StorageProvider> LinkManager<P> {
    pub fn new<R: CryptoRng>(
        private_key: PrivateKey,
        mtu: u16,
        minimum_mtu: u16,
        expires_ms: u64,
        incomplete_limit: usize,
        rng: &mut R,
    ) -> Self {
        assert!(incomplete_limit > 0);
        assert!(mtu > minimum_mtu);
        assert!(usize::from(mtu) > SESSION_OVERHEAD);
        let datagram_mtu = u16::try_from(usize::from(mtu) - SESSION_OVERHEAD)
            .expect("link MTU exceeds its framing overhead");

        Self {
            private_key,
            identity: PrivateKey::generate(rng),
            datagram_mtu,
            minimum_mtu,
            expires_ms,
            now_ms: 0,
            sessions: SessionStore {
                sessions: Default::default(),
                incomplete: Default::default(),
                expirations: Default::default(),
                edges: Default::default(),
                incomplete_limit,
            },
            chunks: ChunkStore {
                chunks: Default::default(),
                chunk_deadlines: Default::default(),
                routes: Default::default(),
                requested: Default::default(),
            },
        }
    }

    pub fn announce(&self) -> LinkEffect {
        LinkEffect::Transmit {
            frame: LinkFrame::Announce {
                public_key: self.identity.public(),
            },
        }
    }

    pub fn receive<R: CryptoRng>(
        &mut self,
        frame: LinkFrame,
        now_ms: u64,
        rng: &mut R,
    ) -> Vec<LinkEffect> {
        let mut events = self.expire(now_ms);

        match frame {
            LinkFrame::Announce { public_key } => {
                events.extend(self.receive_announce(public_key, now_ms, rng));
            }
            LinkFrame::HandshakeInit { recipient, message }
                if recipient == self.identity.public() =>
            {
                events.extend(self.receive_handshake_init(message, now_ms, rng));
            }
            LinkFrame::HandshakeResp {
                session,
                recipient,
                message,
            } if recipient == self.identity.public() => {
                events.extend(self.receive_handshake_response(session, message, now_ms));
            }
            LinkFrame::TransportAccept {
                session,
                sequence,
                ciphertext,
            } => events.extend(self.receive_transport(
                session,
                sequence,
                &ciphertext,
                LinkFrame::TRANSPORT_ACCEPT,
            )),
            LinkFrame::TransportConfirm {
                session,
                sequence,
                ciphertext,
            } => events.extend(self.receive_transport(
                session,
                sequence,
                &ciphertext,
                LinkFrame::TRANSPORT_CONFIRM,
            )),
            LinkFrame::TransportDatagram {
                session,
                sequence,
                ciphertext,
            } => events.extend(self.receive_transport(
                session,
                sequence,
                &ciphertext,
                LinkFrame::TRANSPORT_DATAGRAM,
            )),
            LinkFrame::TransportRoute {
                session,
                sequence,
                ciphertext,
            } => events.extend(self.receive_transport(
                session,
                sequence,
                &ciphertext,
                LinkFrame::TRANSPORT_ROUTE,
            )),
            LinkFrame::TransportRouteRequest {
                session,
                sequence,
                ciphertext,
            } => events.extend(self.receive_transport(
                session,
                sequence,
                &ciphertext,
                LinkFrame::TRANSPORT_ROUTE_REQUEST,
            )),
            LinkFrame::TransportPathChunk {
                session,
                sequence,
                ciphertext,
            } => events.extend(self.receive_transport(
                session,
                sequence,
                &ciphertext,
                LinkFrame::TRANSPORT_PATH_CHUNK,
            )),
            LinkFrame::TransportPathChunkRequest {
                session,
                sequence,
                ciphertext,
            } => events.extend(self.receive_transport(
                session,
                sequence,
                &ciphertext,
                LinkFrame::TRANSPORT_PATH_CHUNK_REQUEST,
            )),
            LinkFrame::TransportEdge {
                session,
                sequence,
                ciphertext,
            } => events.extend(self.receive_transport(
                session,
                sequence,
                &ciphertext,
                LinkFrame::TRANSPORT_EDGE,
            )),
            LinkFrame::TransportEdgeRequest {
                session,
                sequence,
                ciphertext,
            } => events.extend(self.receive_transport(
                session,
                sequence,
                &ciphertext,
                LinkFrame::TRANSPORT_EDGE_REQUEST,
            )),
            LinkFrame::HandshakeInit { .. } | LinkFrame::HandshakeResp { .. } => {}
        }

        events
    }

    pub fn send(&mut self, edge: EdgeId, datagram: Datagram) -> LinkEffect {
        self.transmit(edge, LinkSessionFrame::Datagram(datagram))
    }

    pub fn gossip(&mut self, edge: EdgeId, gossip: Gossip) -> LinkEffect {
        if !self.sessions.edges.contains_key(&edge) {
            return LinkEffect::UnknownEdge(edge);
        }
        if let Gossip::PathChunk(chunk) = &gossip
            && let Err(resource) = self.cache_chunk(chunk.clone())
        {
            return LinkEffect::Capacity { resource };
        }
        self.transmit(edge, LinkSessionFrame::Gossip(gossip))
    }

    fn cache_chunk(&mut self, chunk: PathChunk) -> Result<(), &'static str> {
        let id = chunk.id();
        if !self.chunks.chunks.can_insert(&id) {
            return Err("link chunks");
        }
        if !self.chunks.chunk_deadlines.can_insert(&id) {
            return Err("link chunk deadlines");
        }
        let previous = self
            .chunks
            .chunk_deadlines
            .try_insert(id, self.now_ms.saturating_add(CHUNK_CACHE_TTL_MS))
            .map_err(|_| "link chunk deadlines")?;
        if self.chunks.chunks.try_insert(id, chunk).is_err() {
            if let Some(previous) = previous {
                self.chunks.chunk_deadlines.insert(id, previous);
            } else {
                self.chunks.chunk_deadlines.remove(&id);
            }
            return Err("link chunks");
        }
        Ok(())
    }

    fn transmit(&mut self, edge: EdgeId, frame: LinkSessionFrame) -> LinkEffect {
        let Some(session) = self
            .sessions
            .edges
            .get(&edge)
            .and_then(|sessions| sessions.first())
            .copied()
        else {
            return LinkEffect::UnknownEdge(edge);
        };
        let Some(LinkSession::Open { noise, edge, .. }) = self.sessions.sessions.get_mut(&session)
        else {
            return LinkEffect::UnknownEdge(edge);
        };
        let plaintext = frame.to_bytes();
        let kind = match &frame {
            LinkSessionFrame::Accept(..) => LinkFrame::TRANSPORT_ACCEPT,
            LinkSessionFrame::Confirm(..) => LinkFrame::TRANSPORT_CONFIRM,
            LinkSessionFrame::Datagram(..) => LinkFrame::TRANSPORT_DATAGRAM,
            LinkSessionFrame::Gossip(Gossip::Route(..)) => LinkFrame::TRANSPORT_ROUTE,
            LinkSessionFrame::Gossip(Gossip::RouteRequest(..)) => {
                LinkFrame::TRANSPORT_ROUTE_REQUEST
            }
            LinkSessionFrame::Gossip(Gossip::PathChunk(..)) => LinkFrame::TRANSPORT_PATH_CHUNK,
            LinkSessionFrame::Gossip(Gossip::PathChunkRequest(..)) => {
                LinkFrame::TRANSPORT_PATH_CHUNK_REQUEST
            }
            LinkSessionFrame::Gossip(Gossip::Edge(..)) => LinkFrame::TRANSPORT_EDGE,
            LinkSessionFrame::Gossip(Gossip::EdgeRequest(..)) => LinkFrame::TRANSPORT_EDGE_REQUEST,
        };
        assert!(
            plaintext.len() <= usize::from(edge.edge.mtu),
            "link session frame exceeds the edge MTU"
        );
        let (sequence, ciphertext) = noise
            .seal(&transport_context(session, kind), &plaintext)
            .expect("link session nonce is available");

        LinkEffect::Transmit {
            frame: match frame {
                LinkSessionFrame::Accept(..) => LinkFrame::TransportAccept {
                    session,
                    sequence,
                    ciphertext,
                },
                LinkSessionFrame::Confirm(..) => LinkFrame::TransportConfirm {
                    session,
                    sequence,
                    ciphertext,
                },
                LinkSessionFrame::Datagram(..) => LinkFrame::TransportDatagram {
                    session,
                    sequence,
                    ciphertext,
                },
                LinkSessionFrame::Gossip(Gossip::Route(..)) => LinkFrame::TransportRoute {
                    session,
                    sequence,
                    ciphertext,
                },
                LinkSessionFrame::Gossip(Gossip::RouteRequest(..)) => {
                    LinkFrame::TransportRouteRequest {
                        session,
                        sequence,
                        ciphertext,
                    }
                }
                LinkSessionFrame::Gossip(Gossip::PathChunk(..)) => LinkFrame::TransportPathChunk {
                    session,
                    sequence,
                    ciphertext,
                },
                LinkSessionFrame::Gossip(Gossip::PathChunkRequest(..)) => {
                    LinkFrame::TransportPathChunkRequest {
                        session,
                        sequence,
                        ciphertext,
                    }
                }
                LinkSessionFrame::Gossip(Gossip::Edge(..)) => LinkFrame::TransportEdge {
                    session,
                    sequence,
                    ciphertext,
                },
                LinkSessionFrame::Gossip(Gossip::EdgeRequest(..)) => {
                    LinkFrame::TransportEdgeRequest {
                        session,
                        sequence,
                        ciphertext,
                    }
                }
            },
        }
    }

    pub fn expire(&mut self, now_ms: u64) -> Vec<LinkEffect> {
        self.now_ms = now_ms;
        let mut closed = Vec::new();

        while let Some(&(expires_ms, session)) = self.sessions.expirations.first() {
            if expires_ms > now_ms {
                break;
            }
            if let Some((_, Some(edge))) = self.sessions.remove(session) {
                self.chunks
                    .routes
                    .retain(|(candidate, _), _| *candidate != edge);
                self.chunks
                    .requested
                    .retain(|(candidate, _), _| *candidate != edge);
                closed.push(LinkEffect::Closed(edge));
            }
        }

        let expired_chunks = self
            .chunks
            .chunk_deadlines
            .iter()
            .filter_map(|(id, deadline)| (*deadline <= now_ms).then_some(*id))
            .collect::<Vec<_>>();
        for id in &expired_chunks {
            self.chunks.chunk_deadlines.remove(id);
            self.chunks.chunks.remove(id);
        }
        self.chunks
            .requested
            .retain(|(_, id), _| !expired_chunks.contains(id));
        self.chunks.routes.retain(|_, deadline| *deadline > now_ms);
        self.chunks
            .requested
            .retain(|_, deadline| *deadline > now_ms);
        let roots = self
            .chunks
            .routes
            .iter()
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        for (edge, root) in roots {
            closed.extend(self.collect_route(edge, root));
        }
        closed
    }

    pub fn reject_edge(&mut self, edge: EdgeId) {
        let sessions: Vec<_> = self
            .sessions
            .sessions
            .iter()
            .filter_map(|(id, state)| match state {
                LinkSession::AwaitingAccept {
                    edge: candidate, ..
                }
                | LinkSession::AwaitingConfirm {
                    edge: candidate, ..
                } if candidate.id() == edge => Some(*id),
                LinkSession::Open {
                    edge: candidate, ..
                } if candidate.edge.id() == edge => Some(*id),
                _ => None,
            })
            .collect();
        for session in sessions {
            self.sessions.remove(session);
        }
        self.chunks
            .routes
            .retain(|(candidate, _), _| *candidate != edge);
        self.chunks
            .requested
            .retain(|(candidate, _), _| *candidate != edge);
    }

    fn restore_session(&mut self, id: SessionId, session: LinkSession) -> Vec<LinkEffect> {
        match self.sessions.insert(id, session) {
            Ok(_) => Vec::new(),
            Err(resource) => vec![LinkEffect::Capacity { resource }],
        }
    }

    pub fn close(self) -> Vec<LinkEffect> {
        self.sessions
            .edges
            .iter()
            .map(|(id, _)| *id)
            .map(LinkEffect::Closed)
            .collect()
    }

    fn receive_announce<R: CryptoRng>(
        &mut self,
        peer: PublicKey,
        now_ms: u64,
        rng: &mut R,
    ) -> Vec<LinkEffect> {
        if peer == self.identity.public() || self.sessions.session_for_peer(peer).is_some() {
            return Vec::new();
        }
        if self.sessions.incomplete.len() >= self.sessions.incomplete_limit {
            return vec![LinkEffect::Capacity {
                resource: "link incomplete sessions",
            }];
        }

        let offer = Offer::new(
            self.private_key.public(),
            self.datagram_mtu,
            self.expires_ms,
        );
        let (handshake, message) = IkHandshake::initiate(
            self.identity.clone(),
            peer,
            HANDSHAKE_CONTEXT,
            &offer.to_bytes(),
            rng,
        )
        .expect("offer fits in an IK handshake");
        let session = handshake.session_id();
        if self.sessions.sessions.contains_key(&session) {
            return Vec::new();
        }
        if let Err(resource) = self.sessions.insert(
            session,
            LinkSession::AwaitingHandshake {
                peer,
                handshake,
                offer,
                expires_ms: now_ms + NEGOTIATION_TIMEOUT_MS,
            },
        ) {
            return vec![LinkEffect::Capacity { resource }];
        }
        vec![LinkEffect::Transmit {
            frame: LinkFrame::HandshakeInit {
                recipient: peer,
                message,
            },
        }]
    }

    fn receive_handshake_init<R: CryptoRng>(
        &mut self,
        message: Vec<u8>,
        now_ms: u64,
        rng: &mut R,
    ) -> Vec<LinkEffect> {
        let Ok((handshake, sender, payload)) =
            IkHandshake::respond(&self.identity, HANDSHAKE_CONTEXT, &message)
        else {
            return Vec::new();
        };
        if sender == self.identity.public() {
            return Vec::new();
        }
        let session = handshake.session_id();
        let salt = handshake.edge_salt();

        if let Some((existing, state)) = self.sessions.session_for_peer(sender) {
            if !matches!(state, LinkSession::AwaitingHandshake { .. })
                || self.identity.public() < sender
            {
                return Vec::new();
            }
            self.sessions.remove(existing);
        }
        if self.sessions.sessions.contains_key(&session) {
            return Vec::new();
        }
        if self.sessions.incomplete.len() >= self.sessions.incomplete_limit {
            return vec![LinkEffect::Capacity {
                resource: "link incomplete sessions",
            }];
        }

        let Some(remote_offer) = payload
            .as_slice()
            .try_into()
            .ok()
            .and_then(Offer::from_bytes)
        else {
            return Vec::new();
        };
        let offer = Offer::new(
            self.private_key.public(),
            self.datagram_mtu,
            self.expires_ms,
        );
        let Some(edge) = offer.edge(&remote_offer, salt).filter(|edge| {
            usize::from(edge.mtu) + SESSION_OVERHEAD > usize::from(self.minimum_mtu)
                && edge.expires_ms > now_ms
        }) else {
            return Vec::new();
        };
        let signature = self.private_key.sign(&edge.to_bytes());
        let Ok((message, noise)) = handshake.write_response(&offer.to_bytes(), rng) else {
            return Vec::new();
        };

        if let Err(resource) = self.sessions.insert(
            session,
            LinkSession::AwaitingAccept {
                peer: sender,
                noise,
                edge,
                signature,
                expires_ms: now_ms + NEGOTIATION_TIMEOUT_MS,
            },
        ) {
            return vec![LinkEffect::Capacity { resource }];
        }
        vec![LinkEffect::Transmit {
            frame: LinkFrame::HandshakeResp {
                session,
                recipient: sender,
                message,
            },
        }]
    }

    fn receive_handshake_response(
        &mut self,
        session: SessionId,
        message: Vec<u8>,
        now_ms: u64,
    ) -> Vec<LinkEffect> {
        let Some((state, _)) = self.sessions.remove(session) else {
            return Vec::new();
        };
        let LinkSession::AwaitingHandshake {
            peer,
            handshake,
            offer,
            expires_ms,
        } = state
        else {
            return self.restore_session(session, state);
        };
        let salt = handshake.edge_salt();
        let Ok((payload, mut noise)) = handshake.read_response(&message) else {
            return Vec::new();
        };
        let Some(remote_offer) = payload
            .as_slice()
            .try_into()
            .ok()
            .and_then(Offer::from_bytes)
        else {
            return Vec::new();
        };
        let Some(edge) = offer.edge(&remote_offer, salt).filter(|edge| {
            usize::from(edge.mtu) + SESSION_OVERHEAD > usize::from(self.minimum_mtu)
                && edge.expires_ms > now_ms
        }) else {
            return Vec::new();
        };
        let signature = self.private_key.sign(&edge.to_bytes());
        let (sequence, ciphertext) = noise
            .seal(
                &transport_context(session, LinkFrame::TRANSPORT_ACCEPT),
                &LinkSessionFrame::Accept(Box::new(edge), signature).to_bytes(),
            )
            .expect("link session nonce is available");

        if let Err(resource) = self.sessions.insert(
            session,
            LinkSession::AwaitingConfirm {
                peer,
                noise,
                edge,
                signature,
                expires_ms,
            },
        ) {
            return vec![LinkEffect::Capacity { resource }];
        }
        vec![LinkEffect::Transmit {
            frame: LinkFrame::TransportAccept {
                session,
                sequence,
                ciphertext,
            },
        }]
    }

    fn receive_transport(
        &mut self,
        session: SessionId,
        sequence: u32,
        ciphertext: &[u8],
        kind: u8,
    ) -> Vec<LinkEffect> {
        if let Some(LinkSession::Open { noise, edge, .. }) =
            self.sessions.sessions.get_mut(&session)
        {
            let Some(plaintext) =
                noise.open(sequence, &transport_context(session, kind), ciphertext)
            else {
                return Vec::new();
            };
            let Some(frame) = LinkSessionFrame::from_bytes(kind, &plaintext) else {
                return Vec::new();
            };
            let edge_id = edge.edge.id();

            return match frame {
                LinkSessionFrame::Gossip(gossip) => self.receive_gossip(edge_id, gossip),
                LinkSessionFrame::Datagram(datagram) => vec![LinkEffect::Datagram {
                    ingress: edge.edge.id(),
                    datagram,
                }],
                _ => Vec::new(),
            };
        }

        let Some((state, _)) = self.sessions.remove(session) else {
            return Vec::new();
        };
        match state {
            LinkSession::AwaitingAccept {
                peer,
                mut noise,
                edge,
                signature,
                expires_ms,
            } => {
                let Some(frame) = noise
                    .open(sequence, &transport_context(session, kind), ciphertext)
                    .and_then(|plaintext| LinkSessionFrame::from_bytes(kind, &plaintext))
                else {
                    return self.restore_session(
                        session,
                        LinkSession::AwaitingAccept {
                            peer,
                            noise,
                            edge,
                            signature,
                            expires_ms,
                        },
                    );
                };
                let LinkSessionFrame::Accept(candidate, remote_signature) = frame else {
                    return Vec::new();
                };
                if *candidate != edge
                    || !remote_signature_valid(&edge, &self.private_key, &remote_signature)
                {
                    return Vec::new();
                }

                let (sequence, ciphertext) = noise
                    .seal(
                        &transport_context(session, LinkFrame::TRANSPORT_CONFIRM),
                        &LinkSessionFrame::Confirm(edge.id(), signature).to_bytes(),
                    )
                    .expect("link session nonce is available");
                let transmit = LinkEffect::Transmit {
                    frame: LinkFrame::TransportConfirm {
                        session,
                        sequence,
                        ciphertext,
                    },
                };

                let edge =
                    signed_edge(edge, self.private_key.public(), signature, remote_signature);
                let opened = match self
                    .sessions
                    .insert(session, LinkSession::Open { peer, noise, edge })
                {
                    Ok(opened) => opened,
                    Err(resource) => return vec![LinkEffect::Capacity { resource }],
                };
                [transmit]
                    .into_iter()
                    .chain(opened.then_some(LinkEffect::Opened(Box::new(edge))))
                    .collect()
            }
            LinkSession::AwaitingConfirm {
                peer,
                mut noise,
                edge,
                signature,
                expires_ms,
            } => {
                let Some(frame) = noise
                    .open(sequence, &transport_context(session, kind), ciphertext)
                    .and_then(|plaintext| LinkSessionFrame::from_bytes(kind, &plaintext))
                else {
                    return self.restore_session(
                        session,
                        LinkSession::AwaitingConfirm {
                            peer,
                            noise,
                            edge,
                            signature,
                            expires_ms,
                        },
                    );
                };
                let LinkSessionFrame::Confirm(candidate, remote_signature) = frame else {
                    return Vec::new();
                };
                if candidate != edge.id()
                    || !remote_signature_valid(&edge, &self.private_key, &remote_signature)
                {
                    return Vec::new();
                }

                let edge =
                    signed_edge(edge, self.private_key.public(), signature, remote_signature);
                let opened = match self
                    .sessions
                    .insert(session, LinkSession::Open { peer, noise, edge })
                {
                    Ok(opened) => opened,
                    Err(resource) => return vec![LinkEffect::Capacity { resource }],
                };
                opened
                    .then_some(LinkEffect::Opened(Box::new(edge)))
                    .into_iter()
                    .collect()
            }
            state => self.restore_session(session, state),
        }
    }

    fn receive_gossip(&mut self, edge: EdgeId, gossip: Gossip) -> Vec<LinkEffect> {
        match gossip {
            Gossip::Route(root) => {
                if self
                    .chunks
                    .routes
                    .try_insert(
                        (edge, root),
                        self.now_ms.saturating_add(ROUTE_ASSEMBLY_TIMEOUT_MS),
                    )
                    .is_err()
                {
                    return vec![LinkEffect::Capacity {
                        resource: "link routes",
                    }];
                }
                self.collect_route(edge, root)
            }
            Gossip::PathChunk(chunk) => {
                let id = chunk.id();
                if let Err(resource) = self.cache_chunk(chunk) {
                    // Do not suppress a future request if capacity is freed.
                    self.chunks.requested.remove(&(edge, id));
                    return vec![LinkEffect::Capacity { resource }];
                }
                self.chunks.requested.remove(&(edge, id));
                self.chunks
                    .routes
                    .iter()
                    .filter_map(|(&(candidate, root), _)| {
                        (candidate == edge).then_some((edge, root))
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .flat_map(|(edge, root)| self.collect_route(edge, root))
                    .collect()
            }
            Gossip::PathChunkRequest(id) => self
                .chunks
                .chunks
                .get(&id)
                .cloned()
                .map(|chunk| {
                    self.transmit(edge, LinkSessionFrame::Gossip(Gossip::PathChunk(chunk)))
                })
                .into_iter()
                .collect(),
            Gossip::EdgeRequest(requested) => {
                let signed = self
                    .sessions
                    .edges
                    .get(&requested)
                    .map(|sessions| sessions[0])
                    .and_then(|session| self.sessions.sessions.get(&session))
                    .and_then(|session| match session {
                        LinkSession::Open { edge, .. } => Some(*edge),
                        _ => None,
                    });
                match signed {
                    Some(signed) => vec![self.transmit(
                        edge,
                        LinkSessionFrame::Gossip(Gossip::Edge(Box::new(signed))),
                    )],
                    None => vec![LinkEffect::EdgeRequest {
                        ingress: edge,
                        requested,
                    }],
                }
            }
            Gossip::RouteRequest(destination) => vec![LinkEffect::RouteRequest {
                ingress: edge,
                destination,
            }],
            Gossip::Edge(signed) => vec![LinkEffect::Edge(signed)],
        }
    }

    fn collect_route(&mut self, edge: EdgeId, root: ChunkId) -> Vec<LinkEffect> {
        let mut events = Vec::new();
        let mut current = Some(root);
        while let Some(id) = current {
            if self.chunks.chunks.contains_key(&id) {
                current = self.chunks.chunks.get(&id).expect("stored chunk").next();
                continue;
            }
            if self.chunks.requested.contains_key(&(edge, id)) {
                return events;
            }
            match self
                .chunks
                .requested
                .try_insert((edge, id), self.now_ms.saturating_add(CHUNK_RETRY_MS))
            {
                Ok(_) => events.push(
                    self.transmit(edge, LinkSessionFrame::Gossip(Gossip::PathChunkRequest(id))),
                ),
                Err(_) => events.push(LinkEffect::Capacity {
                    resource: "link requested chunks",
                }),
            }
            return events;
        }
        self.chunks.routes.remove(&(edge, root));
        if let Some(path) = Path::from_chunks(root, &self.chunks.chunks) {
            events.push(LinkEffect::Route {
                ingress: edge,
                path,
            });
        }
        events
    }
}

fn transport_context(session: SessionId, kind: u8) -> Vec<u8> {
    let mut context = HANDSHAKE_CONTEXT.to_vec();
    context.extend(session.0.to_le_bytes());
    context.push(kind);
    context
}

fn remote_signature_valid(edge: &Edge, private_key: &PrivateKey, signature: &Signature) -> bool {
    edge.other(private_key.public())
        .expect("negotiated edge contains the local key")
        .verify(&edge.to_bytes(), signature)
}

fn signed_edge(
    edge: Edge,
    local: PublicKey,
    local_signature: Signature,
    remote_signature: Signature,
) -> SignedEdge {
    SignedEdge {
        edge,
        signatures: if edge.endpoints()[0] == local {
            (local_signature, remote_signature)
        } else {
            (remote_signature, local_signature)
        },
    }
}
