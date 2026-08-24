use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::cmp::Reverse;

use crate::{
    crypto::PublicKey,
    edge::{EdgeId, Path, PathId, SignedEdge},
    network::{Datagram, NetworkEffect, NetworkError, TransitGroupId},
    storage::{StorageProvider, TableMap, TableSet},
};

#[derive(Clone, Copy)]
struct ForwardingEntry {
    egress: EdgeId,
    next: PathId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouterInsertError {
    Invalid,
    StorageFull(&'static str),
}

pub(crate) struct Router<P: StorageProvider> {
    public_key: PublicKey,

    routes: P::RouterRoutes<PublicKey, Vec<PathId>>,
    candidates: usize,
    forwarding: P::RouterForwarding<PathId, ForwardingEntry>,
    paths: P::RouterPaths<PathId, Path>,
    path_expirations: P::RouterPathExpirations<(u64, PathId)>,

    edges: P::RouterEdges<EdgeId, SignedEdge>,
    edge_expirations: P::RouterEdgeExpirations<(u64, EdgeId)>,
    transit_groups: P::RouterTransitGroups<EdgeId, P::RouterTransitGroupSet<TransitGroupId>>,
}

impl<P: StorageProvider> Router<P> {
    pub(crate) fn new(public_key: PublicKey, candidates: usize) -> Self {
        assert!(candidates > 0);

        Self {
            public_key,
            routes: Default::default(),
            candidates,
            forwarding: Default::default(),
            paths: Default::default(),
            path_expirations: Default::default(),
            edges: Default::default(),
            edge_expirations: Default::default(),
            transit_groups: Default::default(),
        }
    }

    pub(crate) fn insert_edge(
        &mut self,
        edge: SignedEdge,
        now_ms: u64,
    ) -> Result<EdgeId, RouterInsertError> {
        if edge.edge.expires_ms <= now_ms {
            return Err(RouterInsertError::Invalid);
        }

        let id = edge.edge.id();
        self.can_insert_edge(id, edge.edge.expires_ms)?;
        self.edge_expirations.insert((edge.edge.expires_ms, id));
        self.edges.insert(id, edge);
        Ok(id)
    }

    fn can_insert_edge(&self, id: EdgeId, expires_ms: u64) -> Result<(), RouterInsertError> {
        if !self.edges.can_insert(&id) {
            return Err(RouterInsertError::StorageFull("router edges"));
        }
        if !self.edge_expirations.can_insert(&(expires_ms, id)) {
            return Err(RouterInsertError::StorageFull("router edge expirations"));
        }
        Ok(())
    }

    pub(crate) fn insert_link(
        &mut self,
        edge: SignedEdge,
        transit_groups: impl IntoIterator<Item = TransitGroupId>,
        now_ms: u64,
    ) -> Result<EdgeId, RouterInsertError> {
        let destination = *edge
            .edge
            .other(self.public_key)
            .ok_or(RouterInsertError::Invalid)?;
        let id = edge.edge.id();
        let path = Path::new(vec![id].into_boxed_slice()).unwrap();
        let expires_ms = edge.edge.expires_ms;
        if expires_ms <= now_ms {
            return Err(RouterInsertError::Invalid);
        }
        if !self.transit_groups.can_insert(&id) {
            return Err(RouterInsertError::StorageFull("router transit groups"));
        }
        self.can_insert_edge(id, expires_ms)?;
        self.can_insert_path(path.id(), destination, expires_ms)?;
        let mut groups = P::RouterTransitGroupSet::<TransitGroupId>::default();
        for group in transit_groups {
            groups
                .try_insert(group)
                .map_err(|_| RouterInsertError::StorageFull("router transit group members"))?;
        }
        self.insert_edge(edge, now_ms)?;
        self.transit_groups.insert(id, groups);
        self.insert_path(path, now_ms)
            .expect("open edges are incident to the local peer");
        Ok(id)
    }

    pub(crate) fn insert_path(
        &mut self,
        path: Path,
        now_ms: u64,
    ) -> Result<PathId, RouterInsertError> {
        let destination = path
            .validate(self.public_key, &self.edges)
            .ok_or(RouterInsertError::Invalid)?;
        self.insert_validated_path(path, destination, now_ms)
    }

    pub(crate) fn insert_route(
        &mut self,
        ingress: EdgeId,
        advertised: Path,
        now_ms: u64,
    ) -> Result<PathId, RouterInsertError> {
        let mut edges = Vec::with_capacity(advertised.edges().len() + 1);
        edges.push(ingress);
        edges.extend_from_slice(advertised.edges());
        let path = Path::new(edges.into_boxed_slice()).ok_or(RouterInsertError::Invalid)?;
        let destination = path
            .validate(self.public_key, &self.edges)
            .ok_or(RouterInsertError::Invalid)?;

        self.insert_validated_path(path, destination, now_ms)
    }

    fn insert_validated_path(
        &mut self,
        path: Path,
        destination: PublicKey,
        now_ms: u64,
    ) -> Result<PathId, RouterInsertError> {
        let expires_ms = path
            .expires_at_ms(&self.edges)
            .ok_or(RouterInsertError::Invalid)?;
        if expires_ms <= now_ms {
            return Err(RouterInsertError::Invalid);
        }

        let id = path.id();
        if self.paths.contains_key(&id) {
            return Ok(id);
        }
        self.can_insert_path(id, destination, expires_ms)?;
        let (egress, next) = path.next();
        self.path_expirations.insert((expires_ms, id));
        self.paths.insert(id, path);
        self.forwarding.insert(id, ForwardingEntry { egress, next });
        let routes = self.routes.get_or_insert_default(destination);
        routes.retain(|route| *route != id);
        routes.push(id);
        self.rank(destination);
        Ok(id)
    }

    fn can_insert_path(
        &self,
        id: PathId,
        destination: PublicKey,
        expires_ms: u64,
    ) -> Result<(), RouterInsertError> {
        for (allowed, name) in [
            (self.paths.can_insert(&id), "router paths"),
            (self.forwarding.can_insert(&id), "router forwarding"),
            (
                self.path_expirations.can_insert(&(expires_ms, id)),
                "router path expirations",
            ),
            (self.routes.can_insert(&destination), "router destinations"),
        ] {
            if !allowed {
                return Err(RouterInsertError::StorageFull(name));
            }
        }
        Ok(())
    }

    pub(crate) fn remove_path(&mut self, id: PathId) -> Option<Path> {
        let path = self.paths.remove(&id)?;
        self.forwarding.remove(&id);
        let destination = path
            .validate(self.public_key, &self.edges)
            .expect("stored path edges remain available");
        self.path_expirations.remove(&(
            path.expires_at_ms(&self.edges)
                .expect("stored path edges remain available"),
            id,
        ));
        let routes = self
            .routes
            .get_mut(&destination)
            .expect("stored paths are indexed by destination");
        routes.retain(|route| *route != id);
        if routes.is_empty() {
            self.routes.remove(&destination);
        } else {
            self.rank(destination);
        }
        Some(path)
    }

    pub(crate) fn routes_for_ingress(&self, ingress: EdgeId, destination: PublicKey) -> Vec<&Path> {
        let Some(routes) = self.routes.get(&destination) else {
            return Vec::new();
        };
        let eligible = routes
            .iter()
            .copied()
            .filter(|id| {
                let egress = self.paths.get(id).expect("stored path").edges()[0];
                ingress != egress && self.can_transit(ingress, egress)
            })
            .collect();

        self.rank_candidates(eligible)
            .into_iter()
            .take(self.candidates)
            .map(|id| self.paths.get(&id).expect("stored path"))
            .collect()
    }

    pub(crate) fn edge(&self, id: EdgeId) -> Option<&SignedEdge> {
        self.edges.get(&id)
    }

    pub(crate) fn can_store_transit_groups(
        &self,
        groups: impl IntoIterator<Item = TransitGroupId>,
    ) -> bool {
        let mut table = P::RouterTransitGroupSet::<TransitGroupId>::default();
        groups
            .into_iter()
            .all(|group| table.try_insert(group).is_ok())
    }

    pub(crate) fn set_transit_groups(
        &mut self,
        edge: EdgeId,
        transit_groups: impl IntoIterator<Item = TransitGroupId>,
    ) -> bool {
        let mut groups = P::RouterTransitGroupSet::<TransitGroupId>::default();
        for group in transit_groups {
            if groups.try_insert(group).is_err() {
                return false;
            }
        }
        let Some(current) = self.transit_groups.get_mut(&edge) else {
            return false;
        };
        if current.same_members(&groups) {
            return false;
        }

        *current = groups;
        true
    }

    pub(crate) fn remove_edge(&mut self, id: EdgeId) -> Option<SignedEdge> {
        let expires_ms = self.edges.get(&id)?.edge.expires_ms;
        let paths = self
            .paths
            .iter()
            .filter_map(|(path_id, path)| path.edges().contains(&id).then_some(*path_id))
            .collect::<Vec<_>>();
        for path in paths {
            self.remove_path(path);
        }

        self.edge_expirations.remove(&(expires_ms, id));
        self.transit_groups.remove(&id);
        self.edges.remove(&id)
    }

    pub(crate) fn expire(&mut self, now_ms: u64) -> Vec<EdgeId> {
        while let Some(&(expires_ms, path)) = self.path_expirations.first() {
            if expires_ms > now_ms {
                break;
            }
            self.remove_path(path)
                .expect("path expiration index contains stored paths");
        }

        let mut expired = Vec::new();
        while let Some(&(expires_ms, edge)) = self.edge_expirations.first() {
            if expires_ms > now_ms {
                break;
            }
            self.remove_edge(edge)
                .expect("edge expiration index contains stored edges");
            expired.push(edge);
        }
        expired
    }

    pub(crate) fn max_payload_len(&self, destination: PublicKey) -> Option<usize> {
        if destination == self.public_key {
            return Some(usize::MAX);
        }

        self.routes
            .get(&destination)?
            .iter()
            .filter_map(|id| {
                usize::from(self.paths.get(id)?.mtu(&self.edges)?).checked_sub(Datagram::OVERHEAD)
            })
            .max()
    }

    pub(crate) fn send(&self, path: PathId, payload: Vec<u8>) -> NetworkEffect {
        let Some(path) = self.paths.get(&path) else {
            return NetworkEffect::Error(NetworkError::UnknownPath { path });
        };
        let mtu = path
            .mtu(&self.edges)
            .expect("stored path edges remain available");
        let maximum = usize::from(mtu).saturating_sub(Datagram::OVERHEAD);
        if payload.len() > maximum {
            return NetworkEffect::Error(NetworkError::PayloadTooLarge {
                maximum,
                actual: payload.len(),
            });
        }
        let (edge, next) = path.next();
        NetworkEffect::Transmit {
            edge,
            datagram: Datagram {
                path: next,
                payload,
            },
        }
    }

    pub(crate) fn send_to(&self, destination: PublicKey, payload: Vec<u8>) -> NetworkEffect {
        if destination == self.public_key {
            return NetworkEffect::Deliver(payload);
        }
        let Some(routes) = self.routes.get(&destination) else {
            return NetworkEffect::Error(NetworkError::NoRoute { destination });
        };
        let Some(path) = routes.iter().find(|id| {
            usize::from(
                self.paths
                    .get(id)
                    .expect("stored path")
                    .mtu(&self.edges)
                    .expect("stored path edges remain available"),
            ) >= Datagram::OVERHEAD + payload.len()
        }) else {
            let maximum = routes
                .iter()
                .map(|id| {
                    usize::from(
                        self.paths
                            .get(id)
                            .expect("stored path")
                            .mtu(&self.edges)
                            .expect("stored path edges remain available"),
                    )
                    .saturating_sub(Datagram::OVERHEAD)
                })
                .max()
                .expect("destinations have at least one route");
            return NetworkEffect::Error(NetworkError::PayloadTooLarge {
                maximum,
                actual: payload.len(),
            });
        };
        self.send(*path, payload)
    }

    pub(crate) fn receive(&self, ingress: EdgeId, datagram: Datagram) -> NetworkEffect {
        if datagram.path == PathId::EMPTY {
            return NetworkEffect::Deliver(datagram.payload);
        }
        let Some(&ForwardingEntry { egress, next }) = self.forwarding.get(&datagram.path) else {
            return NetworkEffect::Error(NetworkError::UnknownPath {
                path: datagram.path,
            });
        };
        if self
            .edges
            .get(&ingress)
            .and_then(|edge| edge.edge.endpoint(self.public_key))
            .is_none()
        {
            return NetworkEffect::Error(NetworkError::UnknownIngress { edge: ingress });
        }
        let egress_edge = &self
            .edges
            .get(&egress)
            .expect("stored path edges remain available")
            .edge;
        if !self.can_transit(ingress, egress) {
            return NetworkEffect::Error(NetworkError::TransitDenied { ingress, egress });
        }
        let maximum = usize::from(egress_edge.mtu).saturating_sub(Datagram::OVERHEAD);
        if datagram.payload.len() > maximum {
            return NetworkEffect::Error(NetworkError::PayloadTooLarge {
                maximum,
                actual: datagram.payload.len(),
            });
        }

        NetworkEffect::Transmit {
            edge: egress,
            datagram: Datagram {
                path: next,
                payload: datagram.payload,
            },
        }
    }

    fn rank(&mut self, destination: PublicKey) {
        let candidates = self
            .routes
            .remove(&destination)
            .expect("destination has route candidates");
        let ranked = self.rank_candidates(candidates);
        self.routes.insert(destination, ranked);
    }

    fn rank_candidates(&self, mut candidates: Vec<PathId>) -> Vec<PathId> {
        if candidates.is_empty() {
            return candidates;
        }

        candidates.sort_by_key(|id| {
            let path = self.paths.get(id).expect("stored path");
            (
                path.edges().len(),
                Reverse(
                    path.mtu(&self.edges)
                        .expect("stored path edges remain available"),
                ),
                Reverse(
                    path.expires_at_ms(&self.edges)
                        .expect("stored path edges remain available"),
                ),
                *id,
            )
        });

        let mut ranked = Vec::with_capacity(candidates.len());
        let primary = candidates.remove(0);
        let primary_edges = self.paths.get(&primary).expect("stored path").edges();
        let mut edge_load = BTreeMap::<EdgeId, usize>::new();
        for edge in primary_edges {
            edge_load.insert(*edge, 1);
        }
        ranked.push(primary);

        while !candidates.is_empty() {
            let current_max = edge_load.values().copied().max().unwrap_or(0);
            let index = candidates
                .iter()
                .enumerate()
                .min_by_key(|(_, id)| {
                    let path = self.paths.get(id).expect("stored path");
                    let max_load = path
                        .edges()
                        .iter()
                        .map(|edge| edge_load.get(edge).copied().unwrap_or(0) + 1)
                        .max()
                        .expect("paths contain at least one edge")
                        .max(current_max);
                    let overlap = path
                        .edges()
                        .iter()
                        .map(|edge| edge_load.get(edge).copied().unwrap_or(0))
                        .sum::<usize>();

                    (
                        max_load,
                        overlap,
                        path.edges().len(),
                        Reverse(
                            path.mtu(&self.edges)
                                .expect("stored path edges remain available"),
                        ),
                        Reverse(
                            path.expires_at_ms(&self.edges)
                                .expect("stored path edges remain available"),
                        ),
                        **id,
                    )
                })
                .map(|(index, _)| index)
                .expect("route candidates remain");
            let route = candidates.remove(index);
            for edge in self.paths.get(&route).expect("stored path").edges() {
                *edge_load.entry(*edge).or_default() += 1;
            }
            ranked.push(route);
        }

        ranked
    }

    fn can_transit(&self, ingress: EdgeId, egress: EdgeId) -> bool {
        let Some(ingress) = self.transit_groups.get(&ingress) else {
            return false;
        };
        let Some(egress) = self.transit_groups.get(&egress) else {
            return false;
        };

        !ingress.is_disjoint(egress)
    }
}
