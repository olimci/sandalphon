use alloc::collections::{BTreeMap, BTreeSet, btree_map, btree_set};

use super::{StorageProvider, TableMap, TableSet};

pub struct BTreeStorage;

impl StorageProvider for BTreeStorage {
    type CoreEdgeLinks<K: Ord, V> = BTreeMap<K, V>;
    type CoreLinkEdges<K: Ord, V> = BTreeMap<K, V>;
    type CoreLinkTransitGroups<K: Ord, V> = BTreeMap<K, V>;
    type CorePendingRoutes<K: Ord, V> = BTreeMap<K, V>;
    type CoreLinkEdgeSet<K: Ord> = BTreeSet<K>;
    type CoreTransitGroupSet<K: Ord> = BTreeSet<K>;

    type RouterRoutes<K: Ord, V> = BTreeMap<K, V>;
    type RouterForwarding<K: Ord, V> = BTreeMap<K, V>;
    type RouterPaths<K: Ord, V> = BTreeMap<K, V>;
    type RouterEdges<K: Ord, V> = BTreeMap<K, V>;
    type RouterTransitGroups<K: Ord, V> = BTreeMap<K, V>;
    type RouterPathExpirations<K: Ord> = BTreeSet<K>;
    type RouterEdgeExpirations<K: Ord> = BTreeSet<K>;
    type RouterTransitGroupSet<K: Ord> = BTreeSet<K>;

    type SessionListeners<K: Ord> = BTreeSet<K>;
    type SessionSessions<K: Ord, V> = BTreeMap<K, V>;

    type LinkSessions<K: Ord, V> = BTreeMap<K, V>;
    type LinkIncomplete<K: Ord> = BTreeSet<K>;
    type LinkExpirations<K: Ord> = BTreeSet<K>;
    type LinkEdges<K: Ord, V> = BTreeMap<K, V>;
    type LinkChunks<K: Ord, V> = BTreeMap<K, V>;
    type LinkChunkDeadlines<K: Ord, V> = BTreeMap<K, V>;
    type LinkRoutes<K: Ord, V> = BTreeMap<K, V>;
    type LinkRequested<K: Ord, V> = BTreeMap<K, V>;
}

impl<K: Ord, V> TableMap<K, V> for BTreeMap<K, V> {
    type Iter<'a>
        = btree_map::Iter<'a, K, V>
    where
        K: 'a,
        V: 'a;

    fn get(&self, key: &K) -> Option<&V> {
        self.get(key)
    }
    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.get_mut(key)
    }
    fn can_insert(&self, _key: &K) -> bool {
        true
    }
    fn try_insert(&mut self, key: K, value: V) -> Result<Option<V>, (K, V)> {
        Ok(self.insert(key, value))
    }
    fn remove(&mut self, key: &K) -> Option<V> {
        self.remove(key)
    }
    fn iter(&self) -> Self::Iter<'_> {
        self.iter()
    }
    fn retain(&mut self, keep: impl FnMut(&K, &mut V) -> bool) {
        self.retain(keep)
    }
}

impl<K: Ord> TableSet<K> for BTreeSet<K> {
    type Iter<'a>
        = btree_set::Iter<'a, K>
    where
        K: 'a;

    fn can_insert(&self, _key: &K) -> bool {
        true
    }
    fn try_insert(&mut self, key: K) -> Result<bool, K> {
        Ok(self.insert(key))
    }
    fn remove(&mut self, key: &K) -> bool {
        self.remove(key)
    }
    fn contains(&self, key: &K) -> bool {
        self.contains(key)
    }
    fn iter(&self) -> Self::Iter<'_> {
        self.iter()
    }
    fn first(&self) -> Option<&K> {
        self.first()
    }
    fn retain(&mut self, keep: impl FnMut(&K) -> bool) {
        self.retain(keep)
    }
    fn is_empty(&self) -> bool {
        self.is_empty()
    }
    fn len(&self) -> usize {
        self.len()
    }
}
