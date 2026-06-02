use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::cert_cache::ProviderFamily;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2SessionContext {
    pub session_id: u64,
    pub provider_family: ProviderFamily,
    pub authorities: HashSet<String>,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoalescingError {
    ProviderMismatch {
        session_provider: ProviderFamily,
        requested_provider: ProviderFamily,
    },
    EmptyAuthority,
}

impl fmt::Display for CoalescingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoalescingError::ProviderMismatch {
                session_provider,
                requested_provider,
            } => write!(
                f,
                "HTTP/2 provider mismatch: session={:?} requested={:?}",
                session_provider, requested_provider
            ),
            CoalescingError::EmptyAuthority => write!(f, "HTTP/2 authority is empty"),
        }
    }
}

impl std::error::Error for CoalescingError {}

pub struct CoalescingController {
    max_sessions: usize,
    sessions: HashMap<u64, H2SessionContext>,
}

impl CoalescingController {
    pub fn new(max_sessions: usize) -> Self {
        Self {
            max_sessions: max_sessions.max(1),
            sessions: HashMap::new(),
        }
    }

    pub fn assert_authority(
        &mut self,
        session_id: u64,
        authority: &str,
        inferred_provider: ProviderFamily,
        now_ms: u64,
    ) -> Result<(), CoalescingError> {
        let normalized = normalize_authority(authority)?;
        if let Some(session) = self.sessions.get_mut(&session_id) {
            if session.provider_family != inferred_provider {
                return Err(CoalescingError::ProviderMismatch {
                    session_provider: session.provider_family.clone(),
                    requested_provider: inferred_provider,
                });
            }
            session.authorities.insert(normalized);
            session.last_seen_ms = now_ms;
            return Ok(());
        }

        self.evict_if_needed();
        let mut authorities = HashSet::new();
        authorities.insert(normalized);
        self.sessions.insert(
            session_id,
            H2SessionContext {
                session_id,
                provider_family: inferred_provider,
                authorities,
                last_seen_ms: now_ms,
            },
        );
        Ok(())
    }

    pub fn session(&self, session_id: u64) -> Option<&H2SessionContext> {
        self.sessions.get(&session_id)
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    fn evict_if_needed(&mut self) {
        if self.sessions.len() < self.max_sessions {
            return;
        }
        if let Some(oldest) = self
            .sessions
            .iter()
            .min_by(|(k1, v1), (k2, v2)| (v1.last_seen_ms, k1).cmp(&(v2.last_seen_ms, k2)))
            .map(|(session_id, _)| *session_id)
        {
            self.sessions.remove(&oldest);
        }
    }
}

pub fn normalize_authority(authority: &str) -> Result<String, CoalescingError> {
    let value = authority.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Err(CoalescingError::EmptyAuthority);
    }
    // IPv6 literal: keep the bracketed host but strip an optional `:port` suffix
    // so `[::1]:443` and `[::1]:8443` normalize to the same origin host, matching
    // the port-stripping behavior of the hostname/IPv4 path below.
    if value.starts_with('[') {
        let Some(close) = value.find(']') else {
            return Err(CoalescingError::EmptyAuthority);
        };
        let host = &value[..=close];
        // Anything after `]` must be empty or a valid `:port`.
        let rest = &value[close + 1..];
        if !rest.is_empty() {
            match rest.strip_prefix(':') {
                Some(port) if port.parse::<u16>().is_ok() => {}
                _ => return Err(CoalescingError::EmptyAuthority),
            }
        }
        if host.len() <= 2 {
            // "[]" has no host between the brackets.
            return Err(CoalescingError::EmptyAuthority);
        }
        return Ok(host.to_string());
    }
    // If a port suffix is present, require it to be a valid u16. This mirrors
    // the strictness of the IPv6 branch above and prevents oddities like
    // `example.com:` (empty port) from being treated as a distinct origin key.
    let host = match value.rsplit_once(':') {
        Some((host, port)) => {
            if port.parse::<u16>().is_ok() {
                host
            } else {
                return Err(CoalescingError::EmptyAuthority);
            }
        }
        None => &value,
    };
    if host.is_empty() {
        return Err(CoalescingError::EmptyAuthority);
    }
    Ok(host.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_authority_case_and_port() {
        assert_eq!(
            normalize_authority("Example.COM:443").expect("authority"),
            "example.com"
        );
    }

    #[test]
    fn host_without_port_is_unchanged() {
        assert_eq!(
            normalize_authority("example.com").expect("authority"),
            "example.com"
        );
    }

    #[test]
    fn rejects_malformed_port_suffix() {
        assert!(normalize_authority("example.com:").is_err());
        assert!(normalize_authority("example.com:99999").is_err());
        assert!(normalize_authority(":99999").is_err());
    }

    #[test]
    fn normalizes_ipv6_authority_and_strips_port() {
        assert_eq!(
            normalize_authority("[::1]:443").expect("authority"),
            "[::1]"
        );
        assert_eq!(
            normalize_authority("[2001:DB8::1]").expect("authority"),
            "[2001:db8::1]"
        );
        // Same IPv6 host on different ports must coalesce to one origin host.
        assert_eq!(
            normalize_authority("[::1]:443").unwrap(),
            normalize_authority("[::1]:8443").unwrap()
        );
    }

    #[test]
    fn rejects_malformed_ipv6_authority() {
        assert!(matches!(
            normalize_authority("[::1"),
            Err(CoalescingError::EmptyAuthority)
        ));
        assert!(matches!(
            normalize_authority("[]"),
            Err(CoalescingError::EmptyAuthority)
        ));
        assert!(matches!(
            normalize_authority("[::1]:notaport"),
            Err(CoalescingError::EmptyAuthority)
        ));
    }

    #[test]
    fn rejects_cross_provider_coalescing() {
        let mut controller = CoalescingController::new(8);
        controller
            .assert_authority(1, "video.google.com", ProviderFamily::Google, 100)
            .expect("first authority");
        let err = controller
            .assert_authority(1, "www.facebook.com", ProviderFamily::Meta, 110)
            .expect_err("provider mismatch");
        assert!(matches!(err, CoalescingError::ProviderMismatch { .. }));
    }

    #[test]
    fn evicts_oldest_session_at_capacity() {
        let mut controller = CoalescingController::new(1);
        controller
            .assert_authority(1, "a.example", ProviderFamily::Fastly, 100)
            .expect("first session");
        controller
            .assert_authority(2, "b.example", ProviderFamily::Fastly, 200)
            .expect("second session");
        assert!(controller.session(1).is_none());
        assert!(controller.session(2).is_some());
    }
}
