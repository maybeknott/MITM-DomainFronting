use std::fmt;

use crate::alpn_policy::{lock_alpn, AlpnError, AlpnLockInput, AlpnMode, LockedAlpn};
use crate::cert_cache::ProviderFamily;
use crate::parser::ClientHelloInfo;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePlan {
    pub provider_family: ProviderFamily,
    pub upstream_front_sni: String,
    pub provider_allowed_alpn: Vec<Vec<u8>>,
    pub mode: AlpnMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsFallbackMode {
    FailClosed,
    ForceHttp11IfPossible,
    BypassWithoutMitm,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsOrchestrationInput {
    pub route: RoutePlan,
    pub fallback_mode: TlsFallbackMode,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsOrchestrationOutcome {
    Locked {
        locked: LockedAlpn,
        provider_family: ProviderFamily,
        upstream_front_sni: String,
    },
    Bypassed {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsOrchestrationError {
    UpstreamNegotiationFailed(String),
    AlpnPolicy(AlpnError),
    LocalCommitFailed(String),
}

impl fmt::Display for TlsOrchestrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsOrchestrationError::UpstreamNegotiationFailed(reason) => {
                write!(f, "upstream negotiation failed: {}", reason)
            }
            TlsOrchestrationError::AlpnPolicy(err) => write!(f, "alpn policy error: {}", err),
            TlsOrchestrationError::LocalCommitFailed(reason) => {
                write!(f, "local commit failed: {}", reason)
            }
        }
    }
}

impl std::error::Error for TlsOrchestrationError {}

pub trait UpstreamTlsNegotiator {
    fn negotiate_alpn(
        &mut self,
        route: &RoutePlan,
        client_hello: &ClientHelloInfo,
        timeout_ms: u64,
    ) -> Result<Option<Vec<u8>>, TlsOrchestrationError>;
}

pub trait LocalTlsEndpoint {
    fn commit_locked_alpn(&mut self, selected: &[u8]) -> Result<(), TlsOrchestrationError>;
    fn bypass_without_mitm(&mut self, reason: &str) -> Result<(), TlsOrchestrationError>;
}

pub fn orchestrate_tls_session(
    input: &TlsOrchestrationInput,
    client_hello: &ClientHelloInfo,
    upstream: &mut dyn UpstreamTlsNegotiator,
    local: &mut dyn LocalTlsEndpoint,
) -> Result<TlsOrchestrationOutcome, TlsOrchestrationError> {
    let client_offered = client_offered_alpn(client_hello);
    let upstream_selected =
        match upstream.negotiate_alpn(&input.route, client_hello, input.timeout_ms) {
            Ok(selected) => selected,
            Err(err) => {
                return apply_upstream_error_fallback(input, err, client_offered, local);
            }
        };

    let lock_input = AlpnLockInput {
        client_offered: client_offered.clone(),
        provider_allowed: input.route.provider_allowed_alpn.clone(),
        upstream_selected: upstream_selected.clone(),
        mode: input.route.mode,
    };
    match lock_alpn(&lock_input) {
        Ok(locked) => {
            local.commit_locked_alpn(&locked.selected)?;
            Ok(TlsOrchestrationOutcome::Locked {
                locked,
                provider_family: input.route.provider_family.clone(),
                upstream_front_sni: input.route.upstream_front_sni.clone(),
            })
        }
        Err(primary_error) => apply_fallback(
            input,
            primary_error,
            client_offered,
            upstream_selected,
            local,
        ),
    }
}

fn apply_upstream_error_fallback(
    input: &TlsOrchestrationInput,
    upstream_error: TlsOrchestrationError,
    client_offered: Vec<Vec<u8>>,
    local: &mut dyn LocalTlsEndpoint,
) -> Result<TlsOrchestrationOutcome, TlsOrchestrationError> {
    match input.fallback_mode {
        TlsFallbackMode::FailClosed => Err(upstream_error),
        TlsFallbackMode::ForceHttp11IfPossible => {
            let fallback_attempt = lock_alpn(&AlpnLockInput {
                client_offered,
                provider_allowed: input.route.provider_allowed_alpn.clone(),
                upstream_selected: None,
                mode: AlpnMode::ForceHttp11,
            })
            .map_err(TlsOrchestrationError::AlpnPolicy)?;
            local.commit_locked_alpn(&fallback_attempt.selected)?;
            Ok(TlsOrchestrationOutcome::Locked {
                locked: fallback_attempt,
                provider_family: input.route.provider_family.clone(),
                upstream_front_sni: input.route.upstream_front_sni.clone(),
            })
        }
        TlsFallbackMode::BypassWithoutMitm => {
            let reason = format!("upstream_negotiation_failed: {}", upstream_error);
            local.bypass_without_mitm(&reason)?;
            Ok(TlsOrchestrationOutcome::Bypassed { reason })
        }
    }
}

fn apply_fallback(
    input: &TlsOrchestrationInput,
    primary_error: AlpnError,
    client_offered: Vec<Vec<u8>>,
    upstream_selected: Option<Vec<u8>>,
    local: &mut dyn LocalTlsEndpoint,
) -> Result<TlsOrchestrationOutcome, TlsOrchestrationError> {
    match input.fallback_mode {
        TlsFallbackMode::FailClosed => Err(TlsOrchestrationError::AlpnPolicy(primary_error)),
        TlsFallbackMode::ForceHttp11IfPossible => {
            let fallback_attempt = lock_alpn(&AlpnLockInput {
                client_offered,
                provider_allowed: input.route.provider_allowed_alpn.clone(),
                upstream_selected,
                mode: AlpnMode::ForceHttp11,
            })
            .map_err(TlsOrchestrationError::AlpnPolicy)?;
            local.commit_locked_alpn(&fallback_attempt.selected)?;
            Ok(TlsOrchestrationOutcome::Locked {
                locked: fallback_attempt,
                provider_family: input.route.provider_family.clone(),
                upstream_front_sni: input.route.upstream_front_sni.clone(),
            })
        }
        TlsFallbackMode::BypassWithoutMitm => {
            let reason = format!("alpn_lock_failed: {}", primary_error);
            local.bypass_without_mitm(&reason)?;
            Ok(TlsOrchestrationOutcome::Bypassed { reason })
        }
    }
}

fn client_offered_alpn(client_hello: &ClientHelloInfo) -> Vec<Vec<u8>> {
    if client_hello.alpn.is_empty() {
        vec![b"http/1.1".to_vec()]
    } else {
        client_hello.alpn.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StaticUpstream {
        selected: Option<Vec<u8>>,
    }

    impl UpstreamTlsNegotiator for StaticUpstream {
        fn negotiate_alpn(
            &mut self,
            _route: &RoutePlan,
            _client_hello: &ClientHelloInfo,
            _timeout_ms: u64,
        ) -> Result<Option<Vec<u8>>, TlsOrchestrationError> {
            Ok(self.selected.clone())
        }
    }

    struct FailingUpstream;

    impl UpstreamTlsNegotiator for FailingUpstream {
        fn negotiate_alpn(
            &mut self,
            _route: &RoutePlan,
            _client_hello: &ClientHelloInfo,
            _timeout_ms: u64,
        ) -> Result<Option<Vec<u8>>, TlsOrchestrationError> {
            Err(TlsOrchestrationError::UpstreamNegotiationFailed(
                "dial failed".to_string(),
            ))
        }
    }

    #[derive(Default)]
    struct RecordingLocal {
        selected: Option<Vec<u8>>,
        bypass_reason: Option<String>,
    }

    impl LocalTlsEndpoint for RecordingLocal {
        fn commit_locked_alpn(&mut self, selected: &[u8]) -> Result<(), TlsOrchestrationError> {
            self.selected = Some(selected.to_vec());
            Ok(())
        }

        fn bypass_without_mitm(&mut self, reason: &str) -> Result<(), TlsOrchestrationError> {
            self.bypass_reason = Some(reason.to_string());
            Ok(())
        }
    }

    fn hello_with_alpn(protocols: &[&[u8]]) -> ClientHelloInfo {
        ClientHelloInfo {
            sni: Some("example.com".to_string()),
            alpn: protocols.iter().map(|item| item.to_vec()).collect(),
            supported_versions: vec![0x0304],
            signature_algorithms: vec![0x0403],
            supported_groups: vec![0x001d],
            extension_order: Vec::new(),
            cipher_suites: Vec::new(),
            ec_point_formats: Vec::new(),
            raw_len: 42,
        }
    }

    fn base_route() -> RoutePlan {
        RoutePlan {
            provider_family: ProviderFamily::Google,
            upstream_front_sni: "www.google.com".to_string(),
            provider_allowed_alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            mode: AlpnMode::CloneUpstream,
        }
    }

    #[test]
    fn locks_when_upstream_selection_matches_policy() {
        let input = TlsOrchestrationInput {
            route: base_route(),
            fallback_mode: TlsFallbackMode::FailClosed,
            timeout_ms: 1_000,
        };
        let hello = hello_with_alpn(&[b"h2", b"http/1.1"]);
        let mut upstream = StaticUpstream {
            selected: Some(b"h2".to_vec()),
        };
        let mut local = RecordingLocal::default();
        let outcome =
            orchestrate_tls_session(&input, &hello, &mut upstream, &mut local).expect("must lock");
        match outcome {
            TlsOrchestrationOutcome::Locked { locked, .. } => assert_eq!(locked.selected, b"h2"),
            _ => panic!("unexpected outcome"),
        }
        assert_eq!(local.selected, Some(b"h2".to_vec()));
        assert_eq!(local.bypass_reason, None);
    }

    #[test]
    fn force_http11_fallback_rejects_conflicting_upstream_alpn() {
        let mut route = base_route();
        route.mode = AlpnMode::CloneUpstream;
        let input = TlsOrchestrationInput {
            route,
            fallback_mode: TlsFallbackMode::ForceHttp11IfPossible,
            timeout_ms: 1_000,
        };
        let hello = hello_with_alpn(&[b"http/1.1"]);
        let mut upstream = StaticUpstream {
            selected: Some(b"h2".to_vec()),
        };
        let mut local = RecordingLocal::default();
        let err = orchestrate_tls_session(&input, &hello, &mut upstream, &mut local)
            .expect_err("must preserve upstream mismatch");
        assert!(matches!(err, TlsOrchestrationError::AlpnPolicy(_)));
    }

    #[test]
    fn bypass_fallback_preserves_service_availability() {
        let mut route = base_route();
        route.provider_allowed_alpn = vec![b"h2".to_vec()];
        let input = TlsOrchestrationInput {
            route,
            fallback_mode: TlsFallbackMode::BypassWithoutMitm,
            timeout_ms: 1_000,
        };
        let hello = hello_with_alpn(&[b"http/1.1"]);
        let mut upstream = StaticUpstream {
            selected: Some(b"http/1.1".to_vec()),
        };
        let mut local = RecordingLocal::default();
        let outcome = orchestrate_tls_session(&input, &hello, &mut upstream, &mut local)
            .expect("must bypass on policy failure");
        match outcome {
            TlsOrchestrationOutcome::Bypassed { reason } => {
                assert!(reason.contains("alpn_lock_failed"))
            }
            _ => panic!("unexpected outcome"),
        }
        assert_eq!(local.selected, None);
        assert!(local
            .bypass_reason
            .as_deref()
            .unwrap_or_default()
            .contains("alpn_lock_failed"));
    }

    #[test]
    fn fail_closed_returns_policy_error() {
        let mut route = base_route();
        route.provider_allowed_alpn = vec![b"h2".to_vec()];
        let input = TlsOrchestrationInput {
            route,
            fallback_mode: TlsFallbackMode::FailClosed,
            timeout_ms: 1_000,
        };
        let hello = hello_with_alpn(&[b"http/1.1"]);
        let mut upstream = StaticUpstream {
            selected: Some(b"http/1.1".to_vec()),
        };
        let mut local = RecordingLocal::default();
        let err = orchestrate_tls_session(&input, &hello, &mut upstream, &mut local)
            .expect_err("must fail closed");
        assert!(matches!(err, TlsOrchestrationError::AlpnPolicy(_)));
    }

    #[test]
    fn bypass_mode_handles_upstream_negotiation_failure() {
        let input = TlsOrchestrationInput {
            route: base_route(),
            fallback_mode: TlsFallbackMode::BypassWithoutMitm,
            timeout_ms: 1_000,
        };
        let hello = hello_with_alpn(&[b"http/1.1"]);
        let mut upstream = FailingUpstream;
        let mut local = RecordingLocal::default();
        let outcome = orchestrate_tls_session(&input, &hello, &mut upstream, &mut local)
            .expect("bypass should preserve service");
        match outcome {
            TlsOrchestrationOutcome::Bypassed { reason } => {
                assert!(reason.contains("upstream_negotiation_failed"))
            }
            _ => panic!("unexpected outcome"),
        }
        assert!(local
            .bypass_reason
            .as_deref()
            .unwrap_or_default()
            .contains("upstream_negotiation_failed"));
    }

    #[test]
    fn force_http11_can_recover_without_upstream_signal() {
        let input = TlsOrchestrationInput {
            route: base_route(),
            fallback_mode: TlsFallbackMode::ForceHttp11IfPossible,
            timeout_ms: 1_000,
        };
        let hello = hello_with_alpn(&[b"http/1.1"]);
        let mut upstream = FailingUpstream;
        let mut local = RecordingLocal::default();
        let outcome = orchestrate_tls_session(&input, &hello, &mut upstream, &mut local)
            .expect("should recover with forced http/1.1");
        match outcome {
            TlsOrchestrationOutcome::Locked { locked, .. } => {
                assert_eq!(locked.selected, b"http/1.1")
            }
            _ => panic!("unexpected outcome"),
        }
        assert_eq!(local.selected, Some(b"http/1.1".to_vec()));
    }
}
