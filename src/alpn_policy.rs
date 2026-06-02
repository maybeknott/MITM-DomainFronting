use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpnMode {
    /// Mirror whatever the upstream negotiated, as long as the client offered it
    /// and provider policy allows it.
    CloneUpstream,
    ForceHttp11,
    ForceH2,
    /// Strictest mode: like [`AlpnMode::CloneUpstream`], but additionally fails
    /// closed when the upstream selection diverges from the client's most
    /// preferred (first-offered) protocol. This prevents the MITM from silently
    /// downgrading the client's top ALPN preference, an observable divergence
    /// that weakens evasion/fingerprint fidelity.
    RejectMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlpnLockInput {
    pub client_offered: Vec<Vec<u8>>,
    pub provider_allowed: Vec<Vec<u8>>,
    pub upstream_selected: Option<Vec<u8>>,
    pub mode: AlpnMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedAlpn {
    pub selected: Vec<u8>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlpnError {
    NoUpstreamSelection,
    ClientDidNotOffer(Vec<u8>),
    ProviderDisallows(Vec<u8>),
    UpstreamMismatch {
        selected: Vec<u8>,
        required: Vec<u8>,
    },
    /// `RejectMismatch` mode: the upstream selected a protocol other than the
    /// client's most-preferred (first-offered) one.
    ClientPreferenceDowngraded {
        selected: Vec<u8>,
        client_preferred: Vec<u8>,
    },
}

impl fmt::Display for AlpnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlpnError::NoUpstreamSelection => write!(f, "upstream did not select ALPN"),
            AlpnError::ClientDidNotOffer(value) => write!(
                f,
                "client did not offer required ALPN {}",
                String::from_utf8_lossy(value)
            ),
            AlpnError::ProviderDisallows(value) => write!(
                f,
                "provider policy disallows ALPN {}",
                String::from_utf8_lossy(value)
            ),
            AlpnError::UpstreamMismatch { selected, required } => write!(
                f,
                "upstream selected {} but policy required {}",
                String::from_utf8_lossy(selected),
                String::from_utf8_lossy(required)
            ),
            AlpnError::ClientPreferenceDowngraded {
                selected,
                client_preferred,
            } => write!(
                f,
                "upstream selected {} but client preferred {} (reject_mismatch)",
                String::from_utf8_lossy(selected),
                String::from_utf8_lossy(client_preferred)
            ),
        }
    }
}

impl std::error::Error for AlpnError {}

pub fn lock_alpn(input: &AlpnLockInput) -> Result<LockedAlpn, AlpnError> {
    let selected = match input.mode {
        AlpnMode::CloneUpstream | AlpnMode::RejectMismatch => input
            .upstream_selected
            .clone()
            .ok_or(AlpnError::NoUpstreamSelection)?,
        AlpnMode::ForceHttp11 => b"http/1.1".to_vec(),
        AlpnMode::ForceH2 => b"h2".to_vec(),
    };

    if !contains_protocol(&input.client_offered, &selected) {
        return Err(AlpnError::ClientDidNotOffer(selected));
    }
    if !contains_protocol(&input.provider_allowed, &selected) {
        return Err(AlpnError::ProviderDisallows(selected));
    }

    if matches!(input.mode, AlpnMode::ForceHttp11 | AlpnMode::ForceH2) {
        if let Some(upstream) = &input.upstream_selected {
            if upstream != &selected {
                return Err(AlpnError::UpstreamMismatch {
                    selected: upstream.clone(),
                    required: selected,
                });
            }
        }
    }

    if input.mode == AlpnMode::RejectMismatch {
        // The client's most-preferred protocol is the first non-empty entry it
        // offered. Failing closed here keeps the locked ALPN aligned with what a
        // genuine client of this browser would have used.
        if let Some(client_preferred) = input.client_offered.iter().find(|item| !item.is_empty()) {
            if client_preferred.as_slice() != selected.as_slice() {
                return Err(AlpnError::ClientPreferenceDowngraded {
                    selected,
                    client_preferred: client_preferred.clone(),
                });
            }
        }
    }

    Ok(LockedAlpn {
        reason: format!("mode={:?}", input.mode),
        selected,
    })
}

fn contains_protocol(protocols: &[Vec<u8>], target: &[u8]) -> bool {
    protocols.iter().any(|item| item.as_slice() == target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn protocols(values: &[&[u8]]) -> Vec<Vec<u8>> {
        values.iter().map(|item| item.to_vec()).collect()
    }

    #[test]
    fn clones_upstream_selection_when_client_and_provider_allow_it() {
        let result = lock_alpn(&AlpnLockInput {
            client_offered: protocols(&[b"h2", b"http/1.1"]),
            provider_allowed: protocols(&[b"h2"]),
            upstream_selected: Some(b"h2".to_vec()),
            mode: AlpnMode::CloneUpstream,
        })
        .expect("lock");
        assert_eq!(result.selected, b"h2");
    }

    #[test]
    fn rejects_provider_disallowed_selection() {
        let err = lock_alpn(&AlpnLockInput {
            client_offered: protocols(&[b"h2", b"http/1.1"]),
            provider_allowed: protocols(&[b"http/1.1"]),
            upstream_selected: Some(b"h2".to_vec()),
            mode: AlpnMode::CloneUpstream,
        })
        .expect_err("must reject provider policy mismatch");
        assert!(matches!(err, AlpnError::ProviderDisallows(_)));
    }

    #[test]
    fn reject_mismatch_accepts_when_upstream_matches_client_preference() {
        let result = lock_alpn(&AlpnLockInput {
            client_offered: protocols(&[b"h2", b"http/1.1"]),
            provider_allowed: protocols(&[b"h2", b"http/1.1"]),
            upstream_selected: Some(b"h2".to_vec()),
            mode: AlpnMode::RejectMismatch,
        })
        .expect("lock when upstream honours client's top preference");
        assert_eq!(result.selected, b"h2");
    }

    #[test]
    fn reject_mismatch_fails_closed_on_client_preference_downgrade() {
        let err = lock_alpn(&AlpnLockInput {
            client_offered: protocols(&[b"h2", b"http/1.1"]),
            provider_allowed: protocols(&[b"h2", b"http/1.1"]),
            upstream_selected: Some(b"http/1.1".to_vec()),
            mode: AlpnMode::RejectMismatch,
        })
        .expect_err("reject_mismatch must not silently downgrade the client's top ALPN");
        match err {
            AlpnError::ClientPreferenceDowngraded {
                selected,
                client_preferred,
            } => {
                assert_eq!(selected, b"http/1.1");
                assert_eq!(client_preferred, b"h2");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn reject_mismatch_still_requires_upstream_selection() {
        let err = lock_alpn(&AlpnLockInput {
            client_offered: protocols(&[b"h2"]),
            provider_allowed: protocols(&[b"h2"]),
            upstream_selected: None,
            mode: AlpnMode::RejectMismatch,
        })
        .expect_err("reject_mismatch cannot lock without an upstream selection");
        assert!(matches!(err, AlpnError::NoUpstreamSelection));
    }

    #[test]
    fn forced_mode_requires_upstream_match_when_available() {
        let err = lock_alpn(&AlpnLockInput {
            client_offered: protocols(&[b"h2", b"http/1.1"]),
            provider_allowed: protocols(&[b"http/1.1"]),
            upstream_selected: Some(b"h2".to_vec()),
            mode: AlpnMode::ForceHttp11,
        })
        .expect_err("forced mode must not hide upstream mismatch");
        assert!(matches!(err, AlpnError::UpstreamMismatch { .. }));
    }
}
