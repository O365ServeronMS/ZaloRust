//! Small insertion-ordered bounded containers (R1, batch 4 review).
//!
//! The clear-all eviction they replace killed LIVE capture state twice:
//! - `capture.rs::ws_created` cleared the whole `ws_ids` set at
//!   `WS_IDS_CAP` — the live Zalo socket's id went with it and
//!   `ws_frames` dropped every later frame of that socket for the rest
//!   of the session (permanent silent capture loss).
//! - `runtime.rs` (flusher) drained the whole per-connection key map at
//!   `WS_KEYS_CAP` — and a WS key is sent ONCE per connection
//!   (cmd=1 subCmd=1 at connect), so an evicted connection stays
//!   undecoded until it reconnects.
//!
//! Both containers evict the OLDEST entry only, in insertion order —
//! never the newest, never the whole store. Inserting an existing key
//! refreshes nothing else (its position in the order is untouched);
//! `remove` takes the key out of both the store and the order so a
//! closed connection can never be "evicted" later. The containers count
//! nothing themselves: callers bump the eviction counters in `ws_stats`
//! and zeroize whatever evicted value they get back.
//!
//! Pure data structures, no I/O: unit-tested directly.

use std::borrow::Borrow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;

/// The smallest sane cap: 0 would evict the entry being inserted, and
/// the newest entry must never be evicted.
fn sane_cap(cap: usize) -> usize {
    cap.max(1)
}

/// Insertion-ordered bounded set (R1). Evicts the OLDEST key only.
#[derive(Debug, Clone)]
pub struct BoundedSet<K> {
    order: VecDeque<K>,
    set: HashSet<K>,
    cap: usize,
}

impl<K: Eq + Hash + Clone> BoundedSet<K> {
    pub fn new(cap: usize) -> Self {
        Self {
            order: VecDeque::new(),
            set: HashSet::new(),
            cap: sane_cap(cap),
        }
    }

    /// Insert `key`. An existing key changes nothing (no eviction, no
    /// reorder). A NEW key at capacity evicts the OLDEST entry first —
    /// the key being inserted is not in the order yet, so the newest
    /// entry can never evict itself. Returns the evicted key, if any.
    pub fn insert(&mut self, key: K) -> Option<K> {
        if self.set.contains(&key) {
            return None;
        }
        let evicted = if self.set.len() >= self.cap {
            self.order.pop_front()
        } else {
            None
        };
        if let Some(old) = &evicted {
            self.set.remove(old);
        }
        self.set.insert(key.clone());
        self.order.push_back(key);
        evicted
    }

    pub fn contains<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.set.contains(key)
    }

    /// Remove `key` from both the set and the order (a closed
    /// connection leaves entirely — it can never be evicted later).
    pub fn remove<Q>(&mut self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        if !self.set.remove(key) {
            return false;
        }
        if let Some(pos) = self.order.iter().position(|k| k.borrow() == key) {
            self.order.remove(pos);
        }
        true
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

/// What one [`BoundedMap::insert`] displaced. At most one of these:
/// an existing key never triggers an eviction, and an eviction only
/// happens for a NEW key.
#[derive(Debug)]
pub enum Inserted<K, V> {
    /// Nothing left the map (room was available, or the key was new
    /// below capacity).
    Kept,
    /// The key existed: its value was replaced IN PLACE — no reorder,
    /// no eviction. The old value is returned for the caller to
    /// zeroize.
    Replaced(V),
    /// The OLDEST entry was evicted to make room (returned for the
    /// caller to zeroize). The inserted key is the newest, never the
    /// evicted one.
    Evicted(K, V),
}

/// Insertion-ordered bounded map (R1). Evicts the OLDEST entry only.
#[derive(Debug, Clone)]
pub struct BoundedMap<K, V> {
    order: VecDeque<K>,
    map: HashMap<K, V>,
    cap: usize,
}

impl<K: Eq + Hash + Clone, V> BoundedMap<K, V> {
    pub fn new(cap: usize) -> Self {
        Self {
            order: VecDeque::new(),
            map: HashMap::new(),
            cap: sane_cap(cap),
        }
    }

    /// Insert `key -> value`:
    /// - an existing key replaces the value IN PLACE — its position in
    ///   the order is untouched, nothing else moves or leaves;
    /// - a NEW key at capacity evicts the OLDEST entry first, so the
    ///   newest entry (the one being inserted) is never evicted.
    pub fn insert(&mut self, key: K, value: V) -> Inserted<K, V> {
        if let Some(old) = self.map.insert(key.clone(), value) {
            return Inserted::Replaced(old);
        }
        let evicted = if self.map.len() > self.cap {
            // The new key is already in `map` but NOT in `order` yet,
            // so `pop_front` can never return it.
            self.order.pop_front()
        } else {
            None
        };
        let out = match evicted {
            Some(old) => match self.map.remove(&old) {
                Some(v) => Inserted::Evicted(old, v),
                // Unreachable: order and map move together.
                None => Inserted::Kept,
            },
            None => Inserted::Kept,
        };
        self.order.push_back(key);
        out
    }

    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.map.get(key)
    }

    /// Remove `key` from both the map and the order. The value is
    /// returned for the caller to zeroize.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        let value = self.map.remove(key)?;
        if let Some(pos) = self.order.iter().position(|k| k.borrow() == key) {
            self.order.remove(pos);
        }
        Some(value)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Consume the map (shutdown path): every entry is handed back for
/// the caller to zeroize.
impl<K: Eq + Hash, V> IntoIterator for BoundedMap<K, V> {
    type Item = (K, V);
    type IntoIter = std::collections::hash_map::IntoIter<K, V>;
    fn into_iter(self) -> Self::IntoIter {
        self.map.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("c{i}")).collect()
    }

    #[test]
    fn set_evicts_oldest_only_never_the_newest() {
        let mut s = BoundedSet::new(3);
        for k in keys(3) {
            assert!(s.insert(k).is_none(), "below capacity nothing evicts");
        }
        // At capacity: exactly the oldest leaves, the rest stay.
        assert_eq!(s.insert("c3".into()).as_deref(), Some("c0"));
        assert!(s.contains("c1") && s.contains("c2") && s.contains("c3"));
        assert_eq!(s.len(), 3);
        assert_eq!(s.insert("c4".into()).as_deref(), Some("c1"));
        // The newest is never the evicted one.
        assert!(s.contains("c4"));
        assert!(!s.contains("c0") && !s.contains("c1"));
    }

    #[test]
    fn set_existing_key_insert_refreshes_nothing() {
        let mut s = BoundedSet::new(3);
        for k in keys(3) {
            s.insert(k);
        }
        // Re-inserting an existing key: no eviction, no reorder — the
        // NEXT eviction still takes c0 (original insertion order).
        assert!(s.insert("c0".into()).is_none());
        assert_eq!(s.len(), 3);
        assert_eq!(s.insert("c3".into()).as_deref(), Some("c0"));
        assert!(!s.contains("c0"));
        assert!(s.contains("c1") && s.contains("c2") && s.contains("c3"));
    }

    #[test]
    fn set_remove_leaves_the_order_too() {
        let mut s = BoundedSet::new(3);
        for k in keys(3) {
            s.insert(k);
        }
        assert!(s.remove("c1"));
        assert!(!s.contains("c1"));
        assert_eq!(s.len(), 2);
        // Room below cap: the next insert evicts nothing.
        assert!(s.insert("c3".into()).is_none());
        // At cap again: the eviction takes c0 — the OLDEST still in
        // the order. If the removed c1 had stayed behind in the
        // order, this would hand back a phantom c1 instead.
        assert_eq!(s.insert("c4".into()).as_deref(), Some("c0"));
        assert!(s.contains("c2") && s.contains("c3") && s.contains("c4"));
        // Removing an absent key is a no-op.
        assert!(!s.remove("c1"));
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn set_cap_one_still_never_evicts_the_newest() {
        let mut s = BoundedSet::<String>::new(0); // clamped to 1
        assert!(s.insert("a".into()).is_none());
        assert_eq!(s.insert("b".into()).as_deref(), Some("a"));
        assert!(s.contains("b"));
        assert_eq!(s.len(), 1);
        // An explicit remove on a cap-1 set empties it cleanly.
        assert!(s.remove("b"));
        assert!(s.is_empty());
    }

    #[test]
    fn map_evicts_oldest_pair_and_hands_it_back() {
        let mut m: BoundedMap<String, [u8; 2]> = BoundedMap::new(3);
        for (i, k) in keys(3).into_iter().enumerate() {
            assert!(matches!(m.insert(k, [i as u8, 0]), Inserted::Kept));
        }
        // At capacity: the OLDEST pair is evicted and returned (for
        // the caller to zeroize), never the newest.
        match m.insert("c3".into(), [3, 0]) {
            Inserted::Evicted(k, v) => {
                assert_eq!(k, "c0");
                assert_eq!(v, [0, 0]);
            }
            other => panic!("expected Evicted, got {other:?}"),
        }
        assert_eq!(m.len(), 3);
        assert!(m.get("c3").is_some());
        assert!(m.get("c0").is_none());
        assert_eq!(
            m.insert("c4".into(), [4, 0]).map_evicted(),
            Some(("c1".to_string(), [1, 0]))
        );
        assert!(m.get("c4").is_some());
    }

    #[test]
    fn map_existing_key_replaces_in_place_without_eviction() {
        let mut m: BoundedMap<String, u8> = BoundedMap::new(3);
        for (i, k) in keys(3).into_iter().enumerate() {
            m.insert(k, i as u8);
        }
        // Replace: old value returned, nothing evicted, order kept.
        match m.insert("c0".into(), 9) {
            Inserted::Replaced(v) => assert_eq!(v, 0),
            other => panic!("expected Replaced, got {other:?}"),
        }
        assert_eq!(m.len(), 3);
        assert_eq!(m.get("c0"), Some(&9));
        // The order still ends at c0: the next eviction is c0, not
        // the refreshed entry moved to the back.
        assert_eq!(
            m.insert("c3".into(), 3).map_evicted(),
            Some(("c0".to_string(), 9))
        );
    }

    #[test]
    fn map_remove_returns_the_value_and_leaves_the_order() {
        let mut m: BoundedMap<String, u8> = BoundedMap::new(3);
        for (i, k) in keys(3).into_iter().enumerate() {
            m.insert(k, i as u8);
        }
        assert_eq!(m.remove("c1"), Some(1));
        assert!(m.get("c1").is_none());
        assert_eq!(m.len(), 2);
        // Room below cap: no eviction.
        assert!(matches!(m.insert("c3".into(), 3), Inserted::Kept));
        // At cap again: the eviction takes c0 — the OLDEST still in
        // the order. If the removed c1 had stayed behind in the
        // order, this would hand back a phantom c1 instead.
        assert_eq!(
            m.insert("c4".into(), 4).map_evicted(),
            Some(("c0".to_string(), 0))
        );
        assert!(m.get("c4").is_some());
        assert_eq!(m.remove("c1"), None, "absent key: no value");
    }

    #[test]
    fn map_into_iterator_yields_every_entry() {
        let mut m: BoundedMap<String, u8> = BoundedMap::new(3);
        for (i, k) in keys(3).into_iter().enumerate() {
            m.insert(k, i as u8);
        }
        let mut seen: Vec<(String, u8)> = m.into_iter().collect();
        seen.sort();
        assert_eq!(
            seen,
            vec![("c0".into(), 0), ("c1".into(), 1), ("c2".into(), 2)]
        );
    }

    /// Test-only helper: the evicted pair of an insert, if any.
    trait MapEvicted {
        type K;
        type V;
        fn map_evicted(self) -> Option<(Self::K, Self::V)>;
    }
    impl<K, V> MapEvicted for Inserted<K, V> {
        type K = K;
        type V = V;
        fn map_evicted(self) -> Option<(K, V)> {
            match self {
                Inserted::Evicted(k, v) => Some((k, v)),
                _ => None,
            }
        }
    }
}
