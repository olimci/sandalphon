use alloc::{boxed::Box, collections::BTreeSet, vec, vec::Vec};

use bytes::{Buf, BufMut};
use sha2::{Digest, Sha256};

use crate::{
    crypto::PublicKey,
    edge::{EdgeId, SignedEdge},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PathId(pub [u8; PathId::LEN]);

impl PathId {
    pub const LEN: usize = 16;
    pub const EMPTY: Self = Self([0; Self::LEN]);

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn from_path(path: &Path) -> Self {
        Self::from_edges(&path.edges)
    }

    fn from_edges(edges: &[EdgeId]) -> Self {
        edges.iter().rev().fold(Self::EMPTY, |next, edge| {
            let mut digest = Sha256::new();
            digest.update(edge.as_bytes());
            digest.update(next.as_bytes());
            let full: [u8; 32] = digest.finalize().into();

            Self(full[..Self::LEN].try_into().unwrap())
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChunkId(pub [u8; ChunkId::LEN]);

impl ChunkId {
    pub const LEN: usize = 16;

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathChunk {
    edges: Box<[EdgeId]>,
    next: Option<ChunkId>,
}

impl PathChunk {
    const BASE_LEN: usize = size_of::<u16>();
    const LINKED: u16 = 1 << 15;

    fn new(edges: Box<[EdgeId]>, next: Option<ChunkId>) -> Option<Self> {
        if edges.is_empty() || edges.len() > (u16::MAX >> 1) as usize {
            return None;
        }

        Some(Self { edges, next })
    }

    pub fn id(&self) -> ChunkId {
        let full: [u8; 32] = Sha256::digest(self.to_bytes()).into();
        ChunkId(full[..ChunkId::LEN].try_into().unwrap())
    }

    fn edges(&self) -> &[EdgeId] {
        &self.edges
    }

    pub(crate) fn next(&self) -> Option<ChunkId> {
        self.next
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(
            Self::BASE_LEN + self.edges.len() * EdgeId::LEN + self.next.map_or(0, |_| ChunkId::LEN),
        );
        output.put_u16_le(
            u16::try_from(self.edges.len()).expect("path chunk count fits in 15 bits")
                | self.next.map_or(0, |_| Self::LINKED),
        );
        for edge in &self.edges {
            output.put_slice(edge.as_bytes());
        }
        if let Some(next) = self.next {
            output.put_slice(next.as_bytes());
        }

        output
    }

    pub(crate) fn from_bytes(mut input: &[u8]) -> Option<Self> {
        let header = input.try_get_u16_le().ok()?;
        let count = usize::from(header & !Self::LINKED);
        if count == 0
            || input.remaining()
                != count * EdgeId::LEN + usize::from(header & Self::LINKED != 0) * ChunkId::LEN
        {
            return None;
        }

        let mut edges = Vec::with_capacity(count);
        for _ in 0..count {
            let mut edge = [0; EdgeId::LEN];
            input.try_copy_to_slice(&mut edge).ok()?;
            edges.push(EdgeId(edge));
        }
        let next = match header & Self::LINKED {
            0 => None,
            _ => {
                let mut next = [0; ChunkId::LEN];
                input.copy_to_slice(&mut next);
                Some(ChunkId(next))
            }
        };

        (!input.has_remaining()).then(|| Self {
            edges: edges.into_boxed_slice(),
            next,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    edges: Box<[EdgeId]>,
}

impl Path {
    pub fn new(edges: Box<[EdgeId]>) -> Option<Self> {
        if edges.is_empty() || edges.iter().collect::<BTreeSet<_>>().len() != edges.len() {
            return None;
        }

        Some(Self { edges })
    }

    pub fn id(&self) -> PathId {
        PathId::from_path(self)
    }

    pub(crate) fn edges(&self) -> &[EdgeId] {
        &self.edges
    }

    pub(crate) fn next(&self) -> (EdgeId, PathId) {
        (self.edges[0], PathId::from_edges(&self.edges[1..]))
    }

    pub(crate) fn chunks(&self, max_bytes: usize) -> Option<Box<[PathChunk]>> {
        let terminal_capacity = (max_bytes.checked_sub(PathChunk::BASE_LEN)? / EdgeId::LEN)
            .min((u16::MAX >> 1) as usize);
        if terminal_capacity == 0 {
            return None;
        }

        let mut start = self.edges.len().saturating_sub(terminal_capacity);
        let terminal = PathChunk::new(self.edges[start..].into(), None).unwrap();
        let mut chunks = vec![terminal];
        while start > 0 {
            let linked_capacity = (max_bytes.checked_sub(PathChunk::BASE_LEN + ChunkId::LEN)?
                / EdgeId::LEN)
                .min((u16::MAX >> 1) as usize);
            if linked_capacity == 0 {
                return None;
            }
            let next = chunks.last().unwrap().id();
            let chunk_start = start.saturating_sub(linked_capacity);
            chunks.push(PathChunk::new(self.edges[chunk_start..start].into(), Some(next)).unwrap());
            start = chunk_start;
        }
        chunks.reverse();

        Some(chunks.into_boxed_slice())
    }

    pub(crate) fn from_chunks(
        root: ChunkId,
        chunks: &impl crate::storage::TableMap<ChunkId, PathChunk>,
    ) -> Option<Self> {
        let mut current = Some(root);
        let mut visited = BTreeSet::new();
        let mut edges = Vec::new();

        while let Some(id) = current {
            if !visited.insert(id) {
                return None;
            }
            let chunk = chunks.get(&id)?;
            if chunk.id() != id {
                return None;
            }
            edges.extend_from_slice(chunk.edges());
            current = chunk.next();
        }

        Self::new(edges.into_boxed_slice())
    }

    pub(crate) fn validate(
        &self,
        source: PublicKey,
        edges: &impl crate::storage::TableMap<EdgeId, SignedEdge>,
    ) -> Option<PublicKey> {
        let mut visited = BTreeSet::from([source]);
        let mut current = source;
        for edge_id in &self.edges {
            let edge = &edges.get(edge_id)?.edge;
            let next = *edge.other(current)?;
            if !visited.insert(next) {
                return None;
            }
            current = next;
        }

        Some(current)
    }

    pub(crate) fn mtu(
        &self,
        edges: &impl crate::storage::TableMap<EdgeId, SignedEdge>,
    ) -> Option<u16> {
        self.edges.iter().try_fold(u16::MAX, |mtu, edge| {
            Some(mtu.min(edges.get(edge)?.edge.mtu))
        })
    }

    pub(crate) fn expires_at_ms(
        &self,
        edges: &impl crate::storage::TableMap<EdgeId, SignedEdge>,
    ) -> Option<u64> {
        self.edges.iter().try_fold(None, |min, edge_id| {
            let expires = edges.get(edge_id)?.edge.expires_ms;

            Some(Some(min.map_or(expires, |min: u64| min.min(expires))))
        })?
    }
}
