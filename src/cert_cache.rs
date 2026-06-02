use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum ProviderFamily {
    Google,
    Meta,
    Fastly,
    Generic,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum CertAlg {
    EcdsaP256,
    Rsa2048,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct CertCacheKey {
    pub san_group: String,
    pub provider_family: ProviderFamily,
    pub alg: CertAlg,
}

#[derive(Clone, Debug)]
pub struct CertCacheEntry {
    pub cert_der: Arc<[u8]>,
    pub key_id: String,
    pub created_ms: u64,
    pub last_used_ms: u64,
    pub expires_at_ms: u64,
    pub hits: u64,
}

#[derive(Clone, Debug)]
pub struct NegativeCacheEntry {
    pub reason: String,
    pub expires_at_ms: u64,
}

pub struct CertCache {
    max_entries: usize,
    max_entries_per_provider: usize,
    entries: HashMap<CertCacheKey, CertCacheEntry>,
    negative: HashMap<String, NegativeCacheEntry>,
}

impl CertCache {
    pub fn new(max_entries: usize, max_entries_per_provider: usize) -> Self {
        Self {
            max_entries,
            max_entries_per_provider,
            entries: HashMap::new(),
            negative: HashMap::new(),
        }
    }

    pub fn get(&mut self, key: &CertCacheKey, now_ms: u64) -> Option<CertCacheEntry> {
        let entry = self.entries.get_mut(key)?;
        if entry.expires_at_ms <= now_ms {
            self.entries.remove(key);
            return None;
        }
        entry.last_used_ms = now_ms;
        entry.hits = entry.hits.saturating_add(1);
        Some(entry.clone())
    }

    pub fn insert(
        &mut self,
        key: CertCacheKey,
        cert_der: Vec<u8>,
        key_id: String,
        now_ms: u64,
        ttl_ms: u64,
    ) {
        let expires_at_ms = now_ms.saturating_add(ttl_ms);
        let entry = CertCacheEntry {
            cert_der: Arc::from(cert_der),
            key_id,
            created_ms: now_ms,
            last_used_ms: now_ms,
            expires_at_ms,
            hits: 1,
        };
        self.entries.insert(key, entry);
        self.evict_expired(now_ms);
        self.evict_for_provider_cap();
        self.evict_for_global_cap();
    }

    pub fn mark_denied(&mut self, domain: &str, reason: &str, now_ms: u64, ttl_ms: u64) {
        self.negative.insert(
            domain.to_ascii_lowercase(),
            NegativeCacheEntry {
                reason: reason.to_string(),
                expires_at_ms: now_ms.saturating_add(ttl_ms),
            },
        );
    }

    pub fn denied_reason(&mut self, domain: &str, now_ms: u64) -> Option<String> {
        let key = domain.to_ascii_lowercase();
        match self.negative.get(&key) {
            Some(entry) if entry.expires_at_ms > now_ms => Some(entry.reason.clone()),
            Some(_) => {
                self.negative.remove(&key);
                None
            }
            None => None,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn evict_expired(&mut self, now_ms: u64) {
        self.entries.retain(|_, entry| entry.expires_at_ms > now_ms);
        self.negative
            .retain(|_, entry| entry.expires_at_ms > now_ms);
    }

    fn evict_for_provider_cap(&mut self) {
        if self.max_entries_per_provider == 0 {
            return;
        }
        loop {
            let over_provider = self.find_provider_over_cap();
            let Some(provider) = over_provider else { break };
            if let Some(oldest_key) = self.find_oldest_for_provider(&provider) {
                self.entries.remove(&oldest_key);
            } else {
                break;
            }
        }
    }

    fn evict_for_global_cap(&mut self) {
        while self.entries.len() > self.max_entries {
            if let Some(oldest_key) = self.find_oldest_key() {
                self.entries.remove(&oldest_key);
            } else {
                break;
            }
        }
    }

    fn find_provider_over_cap(&self) -> Option<ProviderFamily> {
        let mut counts: HashMap<ProviderFamily, usize> = HashMap::new();
        for key in self.entries.keys() {
            *counts.entry(key.provider_family.clone()).or_insert(0) += 1;
        }
        counts
            .into_iter()
            .find(|(_, count)| *count > self.max_entries_per_provider)
            .map(|(provider, _)| provider)
    }

    fn find_oldest_for_provider(&self, provider: &ProviderFamily) -> Option<CertCacheKey> {
        self.entries
            .iter()
            .filter(|(key, _)| &key.provider_family == provider)
            .min_by(|(k1, v1), (k2, v2)| (v1.last_used_ms, k1).cmp(&(v2.last_used_ms, k2)))
            .map(|(key, _)| key.clone())
    }

    fn find_oldest_key(&self) -> Option<CertCacheKey> {
        self.entries
            .iter()
            .min_by(|(k1, v1), (k2, v2)| (v1.last_used_ms, k1).cmp(&(v2.last_used_ms, k2)))
            .map(|(key, _)| key.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str, provider: ProviderFamily) -> CertCacheKey {
        CertCacheKey {
            san_group: name.to_string(),
            provider_family: provider,
            alg: CertAlg::EcdsaP256,
        }
    }

    #[test]
    fn cache_hit_updates_entry() {
        let mut cache = CertCache::new(16, 16);
        let k = key("*.googlevideo.com", ProviderFamily::Google);
        cache.insert(
            k.clone(),
            vec![1, 2, 3],
            "google-k1".to_string(),
            1000,
            60_000,
        );
        let first = cache.get(&k, 1200).expect("first hit");
        let second = cache.get(&k, 1300).expect("second hit");
        assert!(second.hits > first.hits);
        assert!(second.last_used_ms >= first.last_used_ms);
    }

    #[test]
    fn evicts_oldest_when_global_capacity_exceeded() {
        let mut cache = CertCache::new(2, 2);
        let k1 = key("a.example", ProviderFamily::Google);
        let k2 = key("b.example", ProviderFamily::Google);
        let k3 = key("c.example", ProviderFamily::Google);
        cache.insert(k1.clone(), vec![1], "k1".to_string(), 1000, 60_000);
        cache.insert(k2.clone(), vec![2], "k2".to_string(), 1001, 60_000);
        cache.insert(k3.clone(), vec![3], "k3".to_string(), 1002, 60_000);
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&k1, 2000).is_none());
        assert!(cache.get(&k2, 2000).is_some());
        assert!(cache.get(&k3, 2000).is_some());
    }

    #[test]
    fn negative_cache_expires() {
        let mut cache = CertCache::new(4, 4);
        cache.mark_denied("blocked.example", "policy deny", 100, 50);
        assert_eq!(
            cache.denied_reason("blocked.example", 120).as_deref(),
            Some("policy deny")
        );
        assert_eq!(cache.denied_reason("blocked.example", 151), None);
    }

    #[test]
    fn eviction_tie_break_is_deterministic() {
        // When multiple entries share the same timestamp, eviction should be
        // deterministic (tie-break on key) rather than depending on HashMap
        // iteration order.
        let mut cache = CertCache::new(2, 2);
        let k1 = key("a.example", ProviderFamily::Google);
        let k2 = key("b.example", ProviderFamily::Google);
        let k3 = key("c.example", ProviderFamily::Google);
        cache.insert(k2.clone(), vec![2], "k2".to_string(), 1000, 60_000);
        cache.insert(k1.clone(), vec![1], "k1".to_string(), 1000, 60_000);
        cache.insert(k3.clone(), vec![3], "k3".to_string(), 1001, 60_000);

        // Both k1 and k2 have last_used_ms=1000; smallest key should be evicted
        // consistently (k1).
        assert!(cache.get(&k1, 2000).is_none());
        assert!(cache.get(&k2, 2000).is_some());
        assert!(cache.get(&k3, 2000).is_some());
    }
}
