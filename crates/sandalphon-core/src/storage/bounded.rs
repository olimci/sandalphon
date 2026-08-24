use super::{TableMap, TableSet};

fn insert_at<T, const N: usize>(
    entries: &mut [Option<T>; N],
    len: &mut usize,
    index: usize,
    item: T,
) {
    for i in (index..*len).rev() {
        entries[i + 1] = entries[i].take();
    }
    entries[index] = Some(item);
    *len += 1;
}

fn remove_at<T, const N: usize>(entries: &mut [Option<T>; N], len: &mut usize, index: usize) -> T {
    let item = entries[index].take().expect("occupied bounded table slot");
    for i in index + 1..*len {
        entries[i - 1] = entries[i].take();
    }
    *len -= 1;
    item
}

fn map_entry<K, V>(slot: &Option<(K, V)>) -> (&K, &V) {
    let (key, value) = slot.as_ref().expect("occupied bounded map slot");
    (key, value)
}

fn set_entry<K>(slot: &Option<K>) -> &K {
    slot.as_ref().expect("occupied bounded set slot")
}

pub struct BoundedMap<K, V, const N: usize> {
    entries: [Option<(K, V)>; N],
    len: usize,
}

impl<K, V, const N: usize> Default for BoundedMap<K, V, N> {
    fn default() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            len: 0,
        }
    }
}

impl<K: Ord, V, const N: usize> BoundedMap<K, V, N> {
    fn position(&self, key: &K) -> Result<usize, usize> {
        self.entries[..self.len]
            .binary_search_by(|slot| slot.as_ref().expect("occupied bounded map slot").0.cmp(key))
    }

    pub fn try_insert(&mut self, key: K, value: V) -> Result<Option<V>, (K, V)> {
        match self.position(&key) {
            Ok(index) => {
                let old = &mut self.entries[index]
                    .as_mut()
                    .expect("occupied bounded map slot")
                    .1;
                Ok(Some(core::mem::replace(old, value)))
            }
            Err(index) if self.len < N => {
                insert_at(&mut self.entries, &mut self.len, index, (key, value));
                Ok(None)
            }
            Err(_) => Err((key, value)),
        }
    }
}

impl<K: Ord, V, const N: usize> TableMap<K, V> for BoundedMap<K, V, N> {
    type Iter<'a>
        = core::iter::Map<core::slice::Iter<'a, Option<(K, V)>>, fn(&Option<(K, V)>) -> (&K, &V)>
    where
        K: 'a,
        V: 'a;

    fn get(&self, key: &K) -> Option<&V> {
        self.position(key).ok().map(|index| {
            &self.entries[index]
                .as_ref()
                .expect("occupied bounded map slot")
                .1
        })
    }

    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.position(key).ok().map(|index| {
            &mut self.entries[index]
                .as_mut()
                .expect("occupied bounded map slot")
                .1
        })
    }

    fn can_insert(&self, key: &K) -> bool {
        self.len < N || self.position(key).is_ok()
    }

    fn try_insert(&mut self, key: K, value: V) -> Result<Option<V>, (K, V)> {
        BoundedMap::try_insert(self, key, value)
    }

    fn remove(&mut self, key: &K) -> Option<V> {
        self.position(key)
            .ok()
            .map(|index| remove_at(&mut self.entries, &mut self.len, index).1)
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.entries[..self.len]
            .iter()
            .map(map_entry::<K, V> as fn(&Option<(K, V)>) -> (&K, &V))
    }

    fn retain(&mut self, mut keep: impl FnMut(&K, &mut V) -> bool) {
        let mut index = 0;
        while index < self.len {
            let (key, value) = self.entries[index]
                .as_mut()
                .expect("occupied bounded map slot");
            if keep(key, value) {
                index += 1;
            } else {
                remove_at(&mut self.entries, &mut self.len, index);
            }
        }
    }
}

pub struct BoundedSet<K, const N: usize> {
    entries: [Option<K>; N],
    len: usize,
}

impl<K, const N: usize> Default for BoundedSet<K, N> {
    fn default() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            len: 0,
        }
    }
}

impl<K: Ord, const N: usize> BoundedSet<K, N> {
    fn position(&self, key: &K) -> Result<usize, usize> {
        self.entries[..self.len]
            .binary_search_by(|slot| slot.as_ref().expect("occupied bounded set slot").cmp(key))
    }

    pub fn try_insert(&mut self, key: K) -> Result<bool, K> {
        match self.position(&key) {
            Ok(_) => Ok(false),
            Err(index) if self.len < N => {
                insert_at(&mut self.entries, &mut self.len, index, key);
                Ok(true)
            }
            Err(_) => Err(key),
        }
    }
}

impl<K: Ord, const N: usize> TableSet<K> for BoundedSet<K, N> {
    type Iter<'a>
        = core::iter::Map<core::slice::Iter<'a, Option<K>>, fn(&Option<K>) -> &K>
    where
        K: 'a;

    fn can_insert(&self, key: &K) -> bool {
        self.len < N || self.position(key).is_ok()
    }

    fn try_insert(&mut self, key: K) -> Result<bool, K> {
        BoundedSet::try_insert(self, key)
    }

    fn remove(&mut self, key: &K) -> bool {
        match self.position(key) {
            Ok(index) => {
                remove_at(&mut self.entries, &mut self.len, index);
                true
            }
            Err(_) => false,
        }
    }

    fn contains(&self, key: &K) -> bool {
        self.position(key).is_ok()
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.entries[..self.len]
            .iter()
            .map(set_entry::<K> as fn(&Option<K>) -> &K)
    }

    fn first(&self) -> Option<&K> {
        self.entries.first().and_then(Option::as_ref)
    }

    fn retain(&mut self, mut keep: impl FnMut(&K) -> bool) {
        let mut index = 0;
        while index < self.len {
            if keep(
                self.entries[index]
                    .as_ref()
                    .expect("occupied bounded set slot"),
            ) {
                index += 1;
            } else {
                remove_at(&mut self.entries, &mut self.len, index);
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn len(&self) -> usize {
        self.len
    }
}
