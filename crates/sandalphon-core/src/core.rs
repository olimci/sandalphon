use alloc::{boxed::Box, vec::Vec};

use rand_core::CryptoRng;

use crate::{
    crypto::{CryptoError, PrivateKey, PublicKey, SessionId},
    edge::{EdgeId, Path, PathId, SignedEdge},
    link::{Gossip, LinkEffect, LinkFrame},
    network::{Datagram, NetworkEffect, NetworkError, Router, RouterInsertError, TransitGroupId},
    session::{ProtocolId, SessionEffect, SessionError, SessionManager, SessionStartError},
    storage::{StorageError, StorageProvider, TableMap, TableSet},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkAction {
    Transmit { frame: LinkFrame },
    Send { edge: EdgeId, datagram: Datagram },
    Gossip { edge: EdgeId, gossip: Gossip },
    RejectEdge { edge: EdgeId },
}

#[derive(Debug)]
pub enum CoreOperationError {
    Crypto(CryptoError),
    Storage(StorageError),
}

impl From<CryptoError> for CoreOperationError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<StorageError> for CoreOperationError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<SessionStartError> for CoreOperationError {
    fn from(error: SessionStartError) -> Self {
        match error {
            SessionStartError::Crypto(error) => Self::Crypto(error),
            SessionStartError::Storage(error) => Self::Storage(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    Network(NetworkError),
    Session(SessionError),
    UnknownEdge {
        edge: EdgeId,
    },
    WrongLink {
        edge: EdgeId,
        expected: LinkId,
        actual: LinkId,
    },
    EdgeAlreadyOwned {
        edge: EdgeId,
        owner: LinkId,
    },
    InvalidLink {
        edge: EdgeId,
    },
    InvalidEdge {
        edge: EdgeId,
    },
    InvalidRoute,
    InvalidSessionPacket,
    RouteCannotBeAdvertised {
        edge: EdgeId,
    },
    StorageFull {
        resource: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreEffect {
    Link {
        link: LinkId,
        action: LinkAction,
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
    Error(CoreError),
}

pub struct SandalphonCore<P: StorageProvider> {
    router: Router<P>,
    sessions: SessionManager<P>,
    pending_routes: P::CorePendingRoutes<(EdgeId, PathId), PendingRoute>,
    edge_links: P::CoreEdgeLinks<EdgeId, LinkId>,
    link_edges: P::CoreLinkEdges<LinkId, P::CoreLinkEdgeSet<EdgeId>>,
    link_transit_groups: P::CoreLinkTransitGroups<LinkId, P::CoreTransitGroupSet<TransitGroupId>>,
}

const ROUTE_PROOF_TIMEOUT_MS: u64 = 60_000;
const ROUTE_PROOF_RETRY_MS: u64 = 5_000;

struct PendingRoute {
    path: Path,
    expires_ms: u64,
    next_request_ms: u64,
}

impl<P: StorageProvider> SandalphonCore<P> {
    pub fn new(private_key: PrivateKey, route_candidates: usize) -> Self {
        let public_key = private_key.public();
        Self {
            router: Router::new(public_key, route_candidates),
            sessions: SessionManager::new(private_key),
            pending_routes: Default::default(),
            edge_links: Default::default(),
            link_edges: Default::default(),
            link_transit_groups: Default::default(),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.sessions.public_key()
    }

    pub fn listen(&mut self, protocol: ProtocolId) -> Result<bool, StorageError> {
        self.sessions.listen(protocol)
    }

    pub fn unlisten(&mut self, protocol: ProtocolId) -> bool {
        self.sessions.unlisten(protocol)
    }

    pub fn initiate<R: CryptoRng>(
        &mut self,
        destination: PublicKey,
        protocol: ProtocolId,
        data: &[u8],
        rng: &mut R,
    ) -> Result<(SessionId, Vec<CoreEffect>), CoreOperationError> {
        let (session, effect) = self.sessions.initiate(destination, protocol, data, rng)?;
        let mut output = Vec::new();
        self.handle_session_effect(effect, &mut output);
        Ok((session, output))
    }

    pub fn accept<R: CryptoRng>(
        &mut self,
        session: SessionId,
        data: &[u8],
        rng: &mut R,
    ) -> Result<Vec<CoreEffect>, CryptoError> {
        let effect = self.sessions.accept(session, data, rng)?;
        let mut output = Vec::new();
        self.handle_session_effect(effect, &mut output);
        Ok(output)
    }

    pub fn reject(&mut self, session: SessionId) -> bool {
        self.sessions.reject(session)
    }

    pub fn send(
        &mut self,
        session: SessionId,
        payload: &[u8],
    ) -> Result<Vec<CoreEffect>, CryptoError> {
        let effect = self.sessions.send(session, payload)?;
        let mut output = Vec::new();
        self.handle_session_effect(effect, &mut output);
        Ok(output)
    }

    pub fn remove_session(&mut self, session: SessionId) -> bool {
        self.sessions.remove(session)
    }

    pub fn max_payload_len(&self, destination: PublicKey) -> Option<usize> {
        self.router
            .max_payload_len(destination)
            .and_then(|length| length.checked_sub(crate::session::Packet::TRANSPORT_OVERHEAD))
    }

    pub fn request_routes(&self, destination: PublicKey) -> Vec<CoreEffect> {
        self.edge_links
            .iter()
            .map(|(&edge, &link)| CoreEffect::Link {
                link,
                action: LinkAction::Gossip {
                    edge,
                    gossip: Gossip::RouteRequest(destination),
                },
            })
            .collect()
    }

    pub fn link_effect(
        &mut self,
        link: LinkId,
        effect: LinkEffect,
        now_ms: u64,
    ) -> Vec<CoreEffect> {
        let mut output = Vec::new();
        match effect {
            LinkEffect::UnknownEdge(edge) => {
                output.push(CoreEffect::Error(CoreError::UnknownEdge { edge }));
            }
            LinkEffect::Capacity { resource } => {
                output.push(CoreEffect::Error(CoreError::StorageFull { resource }));
            }
            LinkEffect::Transmit { frame } => output.push(CoreEffect::Link {
                link,
                action: LinkAction::Transmit { frame },
            }),
            LinkEffect::Opened(edge) => self.open_link(link, *edge, now_ms, &mut output),
            LinkEffect::Closed(edge) => self.close_link(link, edge, &mut output),
            LinkEffect::Route { ingress, path } => {
                if self.ensure_owner(link, ingress, &mut output) {
                    self.accept_route(ingress, path, now_ms, &mut output);
                }
            }
            LinkEffect::RouteRequest {
                ingress,
                destination,
            } => {
                if self.ensure_owner(link, ingress, &mut output) {
                    self.advertise_routes(link, ingress, destination, &mut output);
                }
            }
            LinkEffect::Edge(edge) => {
                let id = edge.edge.id();
                match self.router.insert_edge(*edge, now_ms) {
                    Ok(_) => self.retry_pending_routes(now_ms, &mut output),
                    Err(error) => output.push(CoreEffect::Error(match error {
                        RouterInsertError::Invalid => CoreError::InvalidEdge { edge: id },
                        RouterInsertError::StorageFull(resource) => {
                            CoreError::StorageFull { resource }
                        }
                    })),
                }
            }
            LinkEffect::EdgeRequest { ingress, requested } => {
                if self.ensure_owner(link, ingress, &mut output)
                    && let Some(edge) = self.router.edge(requested)
                {
                    output.push(CoreEffect::Link {
                        link,
                        action: LinkAction::Gossip {
                            edge: ingress,
                            gossip: Gossip::Edge(Box::new(*edge)),
                        },
                    });
                }
            }
            LinkEffect::Datagram { ingress, datagram } => {
                if self.ensure_owner(link, ingress, &mut output) {
                    let effect = self.router.receive(ingress, datagram);
                    self.handle_network_effect(effect, &mut output);
                }
            }
        }
        output
    }

    pub fn set_link_transit_groups(
        &mut self,
        link: LinkId,
        transit_groups: impl IntoIterator<Item = TransitGroupId>,
    ) -> Result<bool, StorageError> {
        let mut groups = P::CoreTransitGroupSet::<TransitGroupId>::default();
        for group in transit_groups {
            groups.try_insert(group).map_err(|_| StorageError {
                resource: "link transit group members",
            })?;
        }
        let transit_groups = groups;
        if self
            .link_transit_groups
            .get(&link)
            .is_some_and(|current| current.same_members(&transit_groups))
            || (transit_groups.is_empty() && !self.link_transit_groups.contains_key(&link))
        {
            return Ok(false);
        }
        if !transit_groups.is_empty() && !self.link_transit_groups.can_insert(&link) {
            return Err(StorageError {
                resource: "link transit groups",
            });
        }
        if !self
            .router
            .can_store_transit_groups(transit_groups.iter().copied())
        {
            return Err(StorageError {
                resource: "router transit group members",
            });
        }

        if let Some(edges) = self.link_edges.get(&link) {
            for edge in edges.iter() {
                self.router
                    .set_transit_groups(*edge, transit_groups.iter().copied());
            }
        }
        if transit_groups.is_empty() {
            self.link_transit_groups.remove(&link);
        } else {
            self.link_transit_groups.insert(link, transit_groups);
        }
        Ok(true)
    }

    pub fn remove_link(&mut self, link: LinkId) -> bool {
        let removed_groups = self.link_transit_groups.remove(&link).is_some();
        let Some(edges) = self.link_edges.remove(&link) else {
            return removed_groups;
        };
        for edge in edges.iter() {
            self.edge_links.remove(edge);
            self.router.remove_edge(*edge);
        }
        self.pending_routes
            .retain(|(ingress, _), _| !edges.contains(ingress));
        true
    }

    pub fn tick(&mut self, now_ms: u64) -> Vec<CoreEffect> {
        for edge in self.router.expire(now_ms) {
            if let Some(link) = self.edge_links.remove(&edge)
                && let Some(edges) = self.link_edges.get_mut(&link)
            {
                edges.remove(&edge);
                if edges.is_empty() {
                    self.link_edges.remove(&link);
                }
            }
        }
        let mut output = Vec::new();
        let due = self
            .pending_routes
            .iter()
            .filter_map(|(key, pending)| {
                (pending.next_request_ms <= now_ms && pending.expires_ms > now_ms).then_some(*key)
            })
            .collect::<Vec<_>>();
        for key in due {
            if let Some(pending) = self.pending_routes.get_mut(&key) {
                pending.next_request_ms = now_ms.saturating_add(ROUTE_PROOF_RETRY_MS);
            }
            self.request_missing_edges(key, &mut output);
        }
        self.pending_routes.retain(|(ingress, _), pending| {
            pending.expires_ms > now_ms && self.edge_links.contains_key(ingress)
        });
        output
    }

    fn accept_route(
        &mut self,
        ingress: EdgeId,
        path: Path,
        now_ms: u64,
        output: &mut Vec<CoreEffect>,
    ) {
        if path
            .edges()
            .iter()
            .all(|edge| self.router.edge(*edge).is_some())
        {
            self.insert_advertised_route(ingress, path, now_ms, output);
            return;
        }

        let key = (ingress, path.id());
        if let Some(pending) = self.pending_routes.get_mut(&key) {
            if pending.expires_ms <= now_ms {
                pending.path = path;
                pending.expires_ms = now_ms.saturating_add(ROUTE_PROOF_TIMEOUT_MS);
            } else if pending.next_request_ms > now_ms {
                return;
            }
            pending.next_request_ms = now_ms.saturating_add(ROUTE_PROOF_RETRY_MS);
        } else if self
            .pending_routes
            .try_insert(
                key,
                PendingRoute {
                    path,
                    expires_ms: now_ms.saturating_add(ROUTE_PROOF_TIMEOUT_MS),
                    next_request_ms: now_ms.saturating_add(ROUTE_PROOF_RETRY_MS),
                },
            )
            .is_err()
        {
            output.push(CoreEffect::Error(CoreError::StorageFull {
                resource: "pending routes",
            }));
            return;
        }
        self.request_missing_edges(key, output);
    }

    fn request_missing_edges(&self, key: (EdgeId, PathId), output: &mut Vec<CoreEffect>) {
        let Some(&link) = self.edge_links.get(&key.0) else {
            return;
        };
        let Some(pending) = self.pending_routes.get(&key) else {
            return;
        };
        for &requested in pending.path.edges() {
            if self.router.edge(requested).is_none() {
                output.push(CoreEffect::Link {
                    link,
                    action: LinkAction::Gossip {
                        edge: key.0,
                        gossip: Gossip::EdgeRequest(requested),
                    },
                });
            }
        }
    }

    fn retry_pending_routes(&mut self, now_ms: u64, output: &mut Vec<CoreEffect>) {
        let ready = self
            .pending_routes
            .iter()
            .filter_map(|(key, pending)| {
                (pending.expires_ms > now_ms
                    && pending
                        .path
                        .edges()
                        .iter()
                        .all(|edge| self.router.edge(*edge).is_some()))
                .then_some(*key)
            })
            .collect::<Vec<_>>();
        for key in ready {
            let pending = self
                .pending_routes
                .remove(&key)
                .expect("ready route remains pending");
            if self.edge_links.contains_key(&key.0) {
                self.insert_advertised_route(key.0, pending.path, now_ms, output);
            }
        }
    }

    fn insert_advertised_route(
        &mut self,
        ingress: EdgeId,
        path: Path,
        now_ms: u64,
        output: &mut Vec<CoreEffect>,
    ) {
        if let Err(error) = self.router.insert_route(ingress, path, now_ms) {
            output.push(CoreEffect::Error(match error {
                RouterInsertError::Invalid => CoreError::InvalidRoute,
                RouterInsertError::StorageFull(resource) => CoreError::StorageFull { resource },
            }));
        }
    }

    fn open_link(
        &mut self,
        link: LinkId,
        edge: SignedEdge,
        now_ms: u64,
        output: &mut Vec<CoreEffect>,
    ) {
        let id = edge.edge.id();
        if let Some(&owner) = self.edge_links.get(&id) {
            if owner == link {
                return;
            }
            Self::reject_open(
                link,
                id,
                CoreError::EdgeAlreadyOwned { edge: id, owner },
                output,
            );
            return;
        }
        let resource = if !self.edge_links.can_insert(&id) {
            Some("core edge owners")
        } else if !self.link_edges.can_insert(&link) {
            Some("core link edges")
        } else if let Some(edges) = self.link_edges.get(&link) {
            (!edges.can_insert(&id)).then_some("core link edge members")
        } else {
            let edges = P::CoreLinkEdgeSet::<EdgeId>::default();
            (!edges.can_insert(&id)).then_some("core link edge members")
        };
        if let Some(resource) = resource {
            Self::reject_open(link, id, CoreError::StorageFull { resource }, output);
            return;
        }
        let transit_groups = self
            .link_transit_groups
            .get(&link)
            .map(TableSet::clone_set)
            .unwrap_or_default();
        if let Err(error) = self
            .router
            .insert_link(edge, transit_groups.iter().copied(), now_ms)
        {
            Self::reject_open(
                link,
                id,
                match error {
                    RouterInsertError::Invalid => CoreError::InvalidLink { edge: id },
                    RouterInsertError::StorageFull(resource) => CoreError::StorageFull { resource },
                },
                output,
            );
            return;
        }
        self.edge_links.insert(id, link);
        self.link_edges.get_or_insert_default(link).insert(id);
    }

    fn reject_open(link: LinkId, edge: EdgeId, error: CoreError, output: &mut Vec<CoreEffect>) {
        output.push(CoreEffect::Error(error));
        output.push(CoreEffect::Link {
            link,
            action: LinkAction::RejectEdge { edge },
        });
    }

    fn close_link(&mut self, link: LinkId, edge: EdgeId, output: &mut Vec<CoreEffect>) {
        if !self.edge_links.contains_key(&edge) {
            return;
        }
        if !self.ensure_owner(link, edge, output) {
            return;
        }
        self.edge_links.remove(&edge);
        let edges = self
            .link_edges
            .get_mut(&link)
            .expect("owned edges are indexed by link");
        edges.remove(&edge);
        if edges.is_empty() {
            self.link_edges.remove(&link);
        }
        self.router.remove_edge(edge);
        self.pending_routes
            .retain(|(ingress, _), _| *ingress != edge);
    }

    fn ensure_owner(&self, link: LinkId, edge: EdgeId, output: &mut Vec<CoreEffect>) -> bool {
        match self.edge_links.get(&edge) {
            Some(owner) if *owner == link => true,
            Some(owner) => {
                output.push(CoreEffect::Error(CoreError::WrongLink {
                    edge,
                    expected: *owner,
                    actual: link,
                }));
                false
            }
            None => {
                output.push(CoreEffect::Error(CoreError::UnknownEdge { edge }));
                false
            }
        }
    }

    fn advertise_routes(
        &self,
        link: LinkId,
        ingress: EdgeId,
        destination: PublicKey,
        output: &mut Vec<CoreEffect>,
    ) {
        let mtu = usize::from(
            self.router
                .edge(ingress)
                .expect("an owned edge is present in the router")
                .edge
                .mtu,
        );
        for path in self.router.routes_for_ingress(ingress, destination) {
            output.extend(path.edges().iter().map(|edge| {
                CoreEffect::Link {
                    link,
                    action: LinkAction::Gossip {
                        edge: ingress,
                        gossip: Gossip::Edge(Box::new(
                            *self
                                .router
                                .edge(*edge)
                                .expect("advertised path edges remain available"),
                        )),
                    },
                }
            }));
            let Some(chunks) = path.chunks(mtu) else {
                output.push(CoreEffect::Error(CoreError::RouteCannotBeAdvertised {
                    edge: ingress,
                }));
                continue;
            };
            let root = chunks[0].id();
            output.extend(chunks.into_vec().into_iter().map(|chunk| CoreEffect::Link {
                link,
                action: LinkAction::Gossip {
                    edge: ingress,
                    gossip: Gossip::PathChunk(chunk),
                },
            }));
            output.push(CoreEffect::Link {
                link,
                action: LinkAction::Gossip {
                    edge: ingress,
                    gossip: Gossip::Route(root),
                },
            });
        }
    }

    fn handle_session_effect(&mut self, effect: SessionEffect, output: &mut Vec<CoreEffect>) {
        match effect {
            SessionEffect::Transmit {
                destination,
                packet,
            } => {
                let effect = self.router.send_to(destination, packet.to_bytes());
                self.handle_network_effect(effect, output);
            }
            SessionEffect::Incoming {
                session,
                peer,
                protocol,
                data,
            } => output.push(CoreEffect::Incoming {
                session,
                peer,
                protocol,
                data,
            }),
            SessionEffect::Established {
                session,
                peer,
                protocol,
                data,
            } => output.push(CoreEffect::Established {
                session,
                peer,
                protocol,
                data,
            }),
            SessionEffect::Deliver {
                session,
                peer,
                protocol,
                payload,
            } => output.push(CoreEffect::Deliver {
                session,
                peer,
                protocol,
                payload,
            }),
            SessionEffect::Error(error) => {
                output.push(CoreEffect::Error(CoreError::Session(error)));
            }
        }
    }

    fn handle_network_effect(&mut self, effect: NetworkEffect, output: &mut Vec<CoreEffect>) {
        match effect {
            NetworkEffect::Transmit { edge, datagram } => {
                let Some(&link) = self.edge_links.get(&edge) else {
                    output.push(CoreEffect::Error(CoreError::UnknownEdge { edge }));
                    return;
                };
                output.push(CoreEffect::Link {
                    link,
                    action: LinkAction::Send { edge, datagram },
                });
            }
            NetworkEffect::Deliver(payload) => {
                let Some(packet) = crate::session::Packet::from_bytes(&payload) else {
                    output.push(CoreEffect::Error(CoreError::InvalidSessionPacket));
                    return;
                };
                for effect in self.sessions.receive(packet) {
                    self.handle_session_effect(effect, output);
                }
            }
            NetworkEffect::Error(error) => {
                output.push(CoreEffect::Error(CoreError::Network(error)));
            }
        }
    }
}
