use crate::parser::ClientHelloInfo;
use crate::tls_orchestrator::{
    LocalTlsEndpoint, RoutePlan, TlsOrchestrationError, UpstreamTlsNegotiator,
};

pub struct PolicyAwareTlsBackend {
    pub observed_upstream_alpn: Option<Vec<u8>>,
    pub allow_inference_without_upstream: bool,
    pub committed_local_alpn: Option<Vec<u8>>,
    pub bypass_reason: Option<String>,
}

impl PolicyAwareTlsBackend {
    pub fn new(
        observed_upstream_alpn: Option<Vec<u8>>,
        allow_inference_without_upstream: bool,
    ) -> Self {
        Self {
            observed_upstream_alpn,
            allow_inference_without_upstream,
            committed_local_alpn: None,
            bypass_reason: None,
        }
    }
}

impl UpstreamTlsNegotiator for PolicyAwareTlsBackend {
    fn negotiate_alpn(
        &mut self,
        route: &RoutePlan,
        client_hello: &ClientHelloInfo,
        _timeout_ms: u64,
    ) -> Result<Option<Vec<u8>>, TlsOrchestrationError> {
        if self.observed_upstream_alpn.is_some() {
            return Ok(self.observed_upstream_alpn.clone());
        }
        if !self.allow_inference_without_upstream {
            return Err(TlsOrchestrationError::UpstreamNegotiationFailed(
                "upstream TLS backend unavailable".to_string(),
            ));
        }

        for client_offered in &client_hello.alpn {
            if route
                .provider_allowed_alpn
                .iter()
                .any(|allowed| allowed == client_offered)
            {
                return Ok(Some(client_offered.clone()));
            }
        }
        Ok(None)
    }
}

impl LocalTlsEndpoint for PolicyAwareTlsBackend {
    fn commit_locked_alpn(&mut self, selected: &[u8]) -> Result<(), TlsOrchestrationError> {
        self.committed_local_alpn = Some(selected.to_vec());
        Ok(())
    }

    fn bypass_without_mitm(&mut self, reason: &str) -> Result<(), TlsOrchestrationError> {
        self.bypass_reason = Some(reason.to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::alpn_policy::AlpnMode;
    use crate::cert_cache::ProviderFamily;
    use crate::tls_orchestrator::{
        orchestrate_tls_session, LocalTlsEndpoint, TlsFallbackMode, TlsOrchestrationError,
        TlsOrchestrationInput, TlsOrchestrationOutcome,
    };

    use super::*;

    fn route_plan() -> RoutePlan {
        RoutePlan {
            provider_family: ProviderFamily::Generic,
            upstream_front_sni: "front.example".to_string(),
            provider_allowed_alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            mode: AlpnMode::CloneUpstream,
        }
    }

    fn hello(protocols: &[&[u8]]) -> ClientHelloInfo {
        ClientHelloInfo {
            sni: Some("target.example".to_string()),
            alpn: protocols.iter().map(|value| value.to_vec()).collect(),
            supported_versions: vec![0x0304],
            signature_algorithms: vec![0x0403],
            supported_groups: vec![0x001d],
            raw_len: 64,
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

    #[test]
    fn inference_mode_locks_supported_alpn_without_upstream_signal() {
        let input = TlsOrchestrationInput {
            route: route_plan(),
            fallback_mode: TlsFallbackMode::FailClosed,
            timeout_ms: 1000,
        };
        let mut backend = PolicyAwareTlsBackend::new(None, true);
        let mut local = RecordingLocal::default();
        let result = orchestrate_tls_session(
            &input,
            &hello(&[b"h2", b"http/1.1"]),
            &mut backend,
            &mut local,
        )
        .expect("lock");
        match result {
            TlsOrchestrationOutcome::Locked { locked, .. } => assert_eq!(locked.selected, b"h2"),
            _ => panic!("expected locked outcome"),
        }
        assert_eq!(local.selected, Some(b"h2".to_vec()));
    }

    #[test]
    fn unavailable_upstream_is_bypassed_when_policy_allows() {
        let input = TlsOrchestrationInput {
            route: route_plan(),
            fallback_mode: TlsFallbackMode::BypassWithoutMitm,
            timeout_ms: 1000,
        };
        let mut backend = PolicyAwareTlsBackend::new(None, false);
        let mut local = RecordingLocal::default();
        let result =
            orchestrate_tls_session(&input, &hello(&[b"http/1.1"]), &mut backend, &mut local)
                .expect("should bypass");
        match result {
            TlsOrchestrationOutcome::Bypassed { reason } => {
                assert!(reason.contains("upstream_negotiation_failed"))
            }
            _ => panic!("expected bypass outcome"),
        }
    }

    #[test]
    fn bypass_mode_survives_alpn_policy_failure() {
        let mut route = route_plan();
        route.provider_allowed_alpn = vec![b"h2".to_vec()];
        let input = TlsOrchestrationInput {
            route,
            fallback_mode: TlsFallbackMode::BypassWithoutMitm,
            timeout_ms: 1000,
        };
        let mut backend = PolicyAwareTlsBackend::new(Some(b"http/1.1".to_vec()), false);
        let mut local = RecordingLocal::default();
        let result =
            orchestrate_tls_session(&input, &hello(&[b"http/1.1"]), &mut backend, &mut local)
                .expect("bypass");
        match result {
            TlsOrchestrationOutcome::Bypassed { reason } => {
                assert!(reason.contains("alpn_lock_failed"));
            }
            _ => panic!("expected bypass outcome"),
        }
        assert!(local
            .bypass_reason
            .as_deref()
            .unwrap_or_default()
            .contains("alpn_lock_failed"));
    }
}
