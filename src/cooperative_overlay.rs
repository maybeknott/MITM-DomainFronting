use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId([u8; 16]);

impl SessionId {
    pub fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    UdpPreferred,
    TcpFallback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlaySession {
    pub id: SessionId,
    pub endpoint: SocketAddr,
    pub mode: TransportMode,
    pub next_sequence: u64,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenSessionRequest<'a> {
    pub session_id: SessionId,
    pub endpoint: SocketAddr,
    pub auth_token: &'a [u8],
    pub now_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownstreamChunk<'a> {
    pub session_id: SessionId,
    pub sequence: u64,
    pub payload: &'a [u8],
    pub auth_token: &'a [u8],
    pub now_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedChunk {
    pub mode: TransportMode,
    pub sequence: u64,
    pub payload_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlayError {
    SessionAlreadyExists,
    UnknownSession,
    AuthFailed,
    PayloadTooLarge { limit: usize, actual: usize },
    ReplayDetected { expected: u64, received: u64 },
    OutOfOrder { expected: u64, received: u64 },
}

impl fmt::Display for OverlayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OverlayError::SessionAlreadyExists => write!(f, "overlay session already exists"),
            OverlayError::UnknownSession => write!(f, "overlay session is unknown"),
            OverlayError::AuthFailed => write!(f, "overlay authentication failed"),
            OverlayError::PayloadTooLarge { limit, actual } => {
                write!(
                    f,
                    "overlay payload exceeds limit {} (got {})",
                    limit, actual
                )
            }
            OverlayError::ReplayDetected { expected, received } => write!(
                f,
                "overlay replay detected (expected sequence {}, got {})",
                expected, received
            ),
            OverlayError::OutOfOrder { expected, received } => write!(
                f,
                "overlay out-of-order sequence (expected {}, got {})",
                expected, received
            ),
        }
    }
}

impl std::error::Error for OverlayError {}

pub trait OverlayAuthenticator {
    fn verify_open(&self, session_id: SessionId, token: &[u8]) -> bool;
    fn verify_chunk(&self, session_id: SessionId, sequence: u64, token: &[u8]) -> bool;
}

pub struct CooperativeOverlay {
    max_sessions: usize,
    idle_ttl_ms: u64,
    max_payload_len: usize,
    sessions: HashMap<SessionId, OverlaySession>,
}

impl CooperativeOverlay {
    pub fn new(max_sessions: usize, idle_ttl_ms: u64, max_payload_len: usize) -> Self {
        Self {
            max_sessions: max_sessions.max(1),
            idle_ttl_ms: idle_ttl_ms.max(1),
            max_payload_len: max_payload_len.max(1),
            sessions: HashMap::new(),
        }
    }

    pub fn open_session<A: OverlayAuthenticator>(
        &mut self,
        request: OpenSessionRequest<'_>,
        authenticator: &A,
    ) -> Result<(), OverlayError> {
        if !authenticator.verify_open(request.session_id, request.auth_token) {
            return Err(OverlayError::AuthFailed);
        }
        if self.sessions.contains_key(&request.session_id) {
            return Err(OverlayError::SessionAlreadyExists);
        }
        self.evict_if_needed(request.now_ms);
        self.sessions.insert(
            request.session_id,
            OverlaySession {
                id: request.session_id,
                endpoint: request.endpoint,
                mode: TransportMode::UdpPreferred,
                next_sequence: 0,
                last_seen_ms: request.now_ms,
            },
        );
        Ok(())
    }

    pub fn accept_chunk<A: OverlayAuthenticator>(
        &mut self,
        chunk: DownstreamChunk<'_>,
        authenticator: &A,
    ) -> Result<AcceptedChunk, OverlayError> {
        // Authenticate before revealing anything about session state or limits.
        // `verify_chunk` only needs the session id, sequence, and token (not an
        // existing session), so checking it first means an unauthenticated peer
        // always sees `AuthFailed` and cannot probe which session ids exist
        // (UnknownSession) or learn the payload limit (PayloadTooLarge). This
        // keeps the unauthenticated attack/probing surface minimal (fail-closed).
        if !authenticator.verify_chunk(chunk.session_id, chunk.sequence, chunk.auth_token) {
            return Err(OverlayError::AuthFailed);
        }
        if chunk.payload.len() > self.max_payload_len {
            return Err(OverlayError::PayloadTooLarge {
                limit: self.max_payload_len,
                actual: chunk.payload.len(),
            });
        }
        let Some(session) = self.sessions.get_mut(&chunk.session_id) else {
            return Err(OverlayError::UnknownSession);
        };
        if chunk.sequence < session.next_sequence {
            return Err(OverlayError::ReplayDetected {
                expected: session.next_sequence,
                received: chunk.sequence,
            });
        }
        if chunk.sequence > session.next_sequence {
            return Err(OverlayError::OutOfOrder {
                expected: session.next_sequence,
                received: chunk.sequence,
            });
        }

        session.next_sequence = session.next_sequence.saturating_add(1);
        session.last_seen_ms = chunk.now_ms;
        Ok(AcceptedChunk {
            mode: session.mode,
            sequence: chunk.sequence,
            payload_len: chunk.payload.len(),
        })
    }

    pub fn mark_udp_path_failed(
        &mut self,
        session_id: SessionId,
        now_ms: u64,
    ) -> Result<(), OverlayError> {
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return Err(OverlayError::UnknownSession);
        };
        session.mode = TransportMode::TcpFallback;
        session.last_seen_ms = now_ms;
        Ok(())
    }

    pub fn mark_udp_path_validated(
        &mut self,
        session_id: SessionId,
        now_ms: u64,
    ) -> Result<(), OverlayError> {
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return Err(OverlayError::UnknownSession);
        };
        session.mode = TransportMode::UdpPreferred;
        session.last_seen_ms = now_ms;
        Ok(())
    }

    pub fn prune_stale(&mut self, now_ms: u64) -> usize {
        let before = self.sessions.len();
        self.sessions
            .retain(|_, session| now_ms.saturating_sub(session.last_seen_ms) <= self.idle_ttl_ms);
        before.saturating_sub(self.sessions.len())
    }

    pub fn session(&self, session_id: SessionId) -> Option<&OverlaySession> {
        self.sessions.get(&session_id)
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    fn evict_if_needed(&mut self, now_ms: u64) {
        let _ = self.prune_stale(now_ms);
        while self.sessions.len() >= self.max_sessions {
            let oldest = self
                .sessions
                .iter()
                .min_by(|(k1, v1), (k2, v2)| (v1.last_seen_ms, k1).cmp(&(v2.last_seen_ms, k2)))
                .map(|(session_id, _)| *session_id);
            if let Some(session_id) = oldest {
                self.sessions.remove(&session_id);
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StaticAuthenticator;

    impl OverlayAuthenticator for StaticAuthenticator {
        fn verify_open(&self, _session_id: SessionId, token: &[u8]) -> bool {
            token == b"open-ok"
        }

        fn verify_chunk(&self, _session_id: SessionId, sequence: u64, token: &[u8]) -> bool {
            token == b"chunk-ok" && sequence < 1_000_000
        }
    }

    fn session_id(value: u8) -> SessionId {
        SessionId::new([value; 16])
    }

    fn endpoint(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().expect("endpoint")
    }

    #[test]
    fn requires_authentication_to_open_session() {
        let mut overlay = CooperativeOverlay::new(8, 5_000, 4_096);
        let auth = StaticAuthenticator;
        let err = overlay
            .open_session(
                OpenSessionRequest {
                    session_id: session_id(1),
                    endpoint: endpoint(9001),
                    auth_token: b"wrong",
                    now_ms: 100,
                },
                &auth,
            )
            .expect_err("open should fail without auth");
        assert_eq!(err, OverlayError::AuthFailed);
    }

    #[test]
    fn unauthenticated_chunk_reveals_nothing_about_session_state() {
        // An unauthenticated peer must always see AuthFailed first, never the
        // more revealing UnknownSession or PayloadTooLarge, so it cannot probe
        // which session ids exist or learn the payload limit.
        let mut overlay = CooperativeOverlay::new(8, 5_000, 4);
        let auth = StaticAuthenticator;

        // Unknown session + bad token => AuthFailed, not UnknownSession.
        let unknown = overlay
            .accept_chunk(
                DownstreamChunk {
                    session_id: session_id(99),
                    sequence: 0,
                    payload: b"x",
                    auth_token: b"wrong",
                    now_ms: 100,
                },
                &auth,
            )
            .expect_err("unauthenticated chunk must fail");
        assert_eq!(unknown, OverlayError::AuthFailed);

        // Oversized payload + bad token => AuthFailed, not PayloadTooLarge.
        let oversized = overlay
            .accept_chunk(
                DownstreamChunk {
                    session_id: session_id(99),
                    sequence: 0,
                    payload: b"way too long",
                    auth_token: b"wrong",
                    now_ms: 100,
                },
                &auth,
            )
            .expect_err("unauthenticated oversized chunk must fail");
        assert_eq!(oversized, OverlayError::AuthFailed);
    }

    #[test]
    fn accepts_in_order_chunk_and_updates_sequence() {
        let mut overlay = CooperativeOverlay::new(8, 5_000, 4_096);
        let auth = StaticAuthenticator;
        let sid = session_id(2);
        overlay
            .open_session(
                OpenSessionRequest {
                    session_id: sid,
                    endpoint: endpoint(9002),
                    auth_token: b"open-ok",
                    now_ms: 100,
                },
                &auth,
            )
            .expect("open");
        let accepted = overlay
            .accept_chunk(
                DownstreamChunk {
                    session_id: sid,
                    sequence: 0,
                    payload: b"hello",
                    auth_token: b"chunk-ok",
                    now_ms: 120,
                },
                &auth,
            )
            .expect("chunk");
        assert_eq!(accepted.sequence, 0);
        let session = overlay.session(sid).expect("session");
        assert_eq!(session.next_sequence, 1);
    }

    #[test]
    fn rejects_replay_and_out_of_order_sequences() {
        let mut overlay = CooperativeOverlay::new(8, 5_000, 4_096);
        let auth = StaticAuthenticator;
        let sid = session_id(3);
        overlay
            .open_session(
                OpenSessionRequest {
                    session_id: sid,
                    endpoint: endpoint(9003),
                    auth_token: b"open-ok",
                    now_ms: 100,
                },
                &auth,
            )
            .expect("open");
        overlay
            .accept_chunk(
                DownstreamChunk {
                    session_id: sid,
                    sequence: 0,
                    payload: b"a",
                    auth_token: b"chunk-ok",
                    now_ms: 110,
                },
                &auth,
            )
            .expect("first");

        let replay_err = overlay
            .accept_chunk(
                DownstreamChunk {
                    session_id: sid,
                    sequence: 0,
                    payload: b"b",
                    auth_token: b"chunk-ok",
                    now_ms: 120,
                },
                &auth,
            )
            .expect_err("replay");
        assert!(matches!(replay_err, OverlayError::ReplayDetected { .. }));

        let order_err = overlay
            .accept_chunk(
                DownstreamChunk {
                    session_id: sid,
                    sequence: 2,
                    payload: b"c",
                    auth_token: b"chunk-ok",
                    now_ms: 130,
                },
                &auth,
            )
            .expect_err("out of order");
        assert!(matches!(order_err, OverlayError::OutOfOrder { .. }));
    }

    #[test]
    fn switches_to_tcp_fallback_after_udp_failure() {
        let mut overlay = CooperativeOverlay::new(8, 5_000, 4_096);
        let auth = StaticAuthenticator;
        let sid = session_id(4);
        overlay
            .open_session(
                OpenSessionRequest {
                    session_id: sid,
                    endpoint: endpoint(9004),
                    auth_token: b"open-ok",
                    now_ms: 100,
                },
                &auth,
            )
            .expect("open");
        overlay.mark_udp_path_failed(sid, 130).expect("mark failed");
        assert_eq!(
            overlay.session(sid).expect("session").mode,
            TransportMode::TcpFallback
        );
        overlay
            .mark_udp_path_validated(sid, 200)
            .expect("mark validated");
        assert_eq!(
            overlay.session(sid).expect("session").mode,
            TransportMode::UdpPreferred
        );
    }

    #[test]
    fn prunes_stale_sessions() {
        let mut overlay = CooperativeOverlay::new(8, 50, 4_096);
        let auth = StaticAuthenticator;
        overlay
            .open_session(
                OpenSessionRequest {
                    session_id: session_id(5),
                    endpoint: endpoint(9005),
                    auth_token: b"open-ok",
                    now_ms: 10,
                },
                &auth,
            )
            .expect("open");
        overlay
            .open_session(
                OpenSessionRequest {
                    session_id: session_id(6),
                    endpoint: endpoint(9006),
                    auth_token: b"open-ok",
                    now_ms: 30,
                },
                &auth,
            )
            .expect("open");
        let removed = overlay.prune_stale(70);
        assert_eq!(removed, 1);
        assert!(overlay.session(session_id(5)).is_none());
        assert!(overlay.session(session_id(6)).is_some());
    }

    #[test]
    fn session_eviction_tie_break_is_deterministic() {
        // When multiple sessions share the same last_seen_ms, eviction should
        // deterministically remove the smallest SessionId (tie-break), not
        // depend on HashMap iteration order.
        let mut overlay = CooperativeOverlay::new(2, 5_000, 4_096);
        let auth = StaticAuthenticator;

        let s1 = session_id(1);
        let s2 = session_id(2);
        let s3 = session_id(3);

        overlay
            .open_session(
                OpenSessionRequest {
                    session_id: s2,
                    endpoint: endpoint(9002),
                    auth_token: b"open-ok",
                    now_ms: 100,
                },
                &auth,
            )
            .expect("open s2");
        overlay
            .open_session(
                OpenSessionRequest {
                    session_id: s1,
                    endpoint: endpoint(9001),
                    auth_token: b"open-ok",
                    now_ms: 100,
                },
                &auth,
            )
            .expect("open s1");

        // Adding a third forces eviction; s1 and s2 are tied, so s1 (smallest)
        // should be removed.
        overlay
            .open_session(
                OpenSessionRequest {
                    session_id: s3,
                    endpoint: endpoint(9003),
                    auth_token: b"open-ok",
                    now_ms: 200,
                },
                &auth,
            )
            .expect("open s3");

        assert!(overlay.session(s1).is_none());
        assert!(overlay.session(s2).is_some());
        assert!(overlay.session(s3).is_some());
    }
}
