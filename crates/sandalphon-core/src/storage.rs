pub mod bounded;
pub use bounded::{BoundedMap, BoundedSet};

#[cfg(feature = "btree-storage")]
pub mod btree;
#[cfg(feature = "btree-storage")]
pub use btree::BTreeStorage;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageError {
    pub resource: &'static str,
}

pub trait TableMap<K, V>: Default {
    type Iter<'a>: Iterator<Item = (&'a K, &'a V)>
    where
        Self: 'a,
        K: 'a,
        V: 'a;

    fn get(&self, key: &K) -> Option<&V>;
    fn get_mut(&mut self, key: &K) -> Option<&mut V>;
    fn can_insert(&self, key: &K) -> bool;
    fn try_insert(&mut self, key: K, value: V) -> Result<Option<V>, (K, V)>;
    fn remove(&mut self, key: &K) -> Option<V>;
    fn iter(&self) -> Self::Iter<'_>;
    fn retain(&mut self, keep: impl FnMut(&K, &mut V) -> bool);

    fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.try_insert(key, value)
            .unwrap_or_else(|_| panic!("table capacity exceeded"))
    }

    fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    fn try_get_or_insert_default(&mut self, key: K) -> Option<&mut V>
    where
        K: Clone,
        V: Default,
    {
        if self.get(&key).is_none() {
            self.try_insert(key.clone(), V::default()).ok()?;
        }
        self.get_mut(&key)
    }

    fn get_or_insert_default(&mut self, key: K) -> &mut V
    where
        K: Clone,
        V: Default,
    {
        self.try_get_or_insert_default(key)
            .expect("table capacity exceeded")
    }
}

pub trait TableSet<K>: Default {
    type Iter<'a>: Iterator<Item = &'a K>
    where
        Self: 'a,
        K: 'a;

    fn try_insert(&mut self, key: K) -> Result<bool, K>;
    fn can_insert(&self, key: &K) -> bool;
    fn insert(&mut self, key: K) -> bool {
        self.try_insert(key)
            .unwrap_or_else(|_| panic!("table capacity exceeded"))
    }
    fn remove(&mut self, key: &K) -> bool;
    fn contains(&self, key: &K) -> bool;
    fn iter(&self) -> Self::Iter<'_>;
    fn first(&self) -> Option<&K>;
    fn retain(&mut self, keep: impl FnMut(&K) -> bool);
    fn is_empty(&self) -> bool;
    fn len(&self) -> usize;
    fn clone_set(&self) -> Self
    where
        K: Clone,
    {
        let mut copy = Self::default();
        for key in self.iter() {
            copy.insert(key.clone());
        }
        copy
    }
    fn is_disjoint(&self, other: &Self) -> bool {
        !self.iter().any(|key| other.contains(key))
    }
    fn same_members(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().all(|key| other.contains(key))
    }
}
pub trait StorageProvider {
    type CoreEdgeLinks<K: Ord, V>: TableMap<K, V>;
    type CoreLinkEdges<K: Ord, V>: TableMap<K, V>;
    type CoreLinkTransitGroups<K: Ord, V>: TableMap<K, V>;
    type CorePendingRoutes<K: Ord, V>: TableMap<K, V>;
    type CoreLinkEdgeSet<K: Ord>: TableSet<K>;
    type CoreTransitGroupSet<K: Ord>: TableSet<K>;

    type RouterRoutes<K: Ord, V>: TableMap<K, V>;
    type RouterForwarding<K: Ord, V>: TableMap<K, V>;
    type RouterPaths<K: Ord, V>: TableMap<K, V>;
    type RouterEdges<K: Ord, V>: TableMap<K, V>;
    type RouterTransitGroups<K: Ord, V>: TableMap<K, V>;
    type RouterPathExpirations<K: Ord>: TableSet<K>;
    type RouterEdgeExpirations<K: Ord>: TableSet<K>;
    type RouterTransitGroupSet<K: Ord>: TableSet<K>;

    type SessionListeners<K: Ord>: TableSet<K>;
    type SessionSessions<K: Ord, V>: TableMap<K, V>;

    type LinkSessions<K: Ord, V>: TableMap<K, V>;
    type LinkIncomplete<K: Ord>: TableSet<K>;
    type LinkExpirations<K: Ord>: TableSet<K>;
    type LinkEdges<K: Ord, V>: TableMap<K, V>;
    type LinkChunks<K: Ord, V>: TableMap<K, V>;
    type LinkChunkDeadlines<K: Ord, V>: TableMap<K, V>;
    type LinkRoutes<K: Ord, V>: TableMap<K, V>;
    type LinkRequested<K: Ord, V>: TableMap<K, V>;
}
