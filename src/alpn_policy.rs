use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpnMode {
    CloneUpstream,
    ForceHttp11,
    ForceH2,
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
