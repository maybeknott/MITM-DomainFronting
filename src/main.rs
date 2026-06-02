use std::error::Error;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use mitm_stream_core::alpn_policy::AlpnMode;
use mitm_stream_core::backend_runtime::{
    build_runtime_backend, BackendPreference, BackendRuntimeOptions,
};
use mitm_stream_core::cert_cache::ProviderFamily;
use mitm_stream_core::ingress::StreamIngress;
use mitm_stream_core::parser::{read_client_hello_info, ParserError};
use mitm_stream_core::tls_orchestrator::{
    orchestrate_tls_session, RoutePlan, TlsFallbackMode, TlsOrchestrationInput,
};
use mitm_stream_core::tls_orchestrator_backend::PolicyAwareTlsBackend;

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:10808";
const MAX_CLIENT_HELLO_BYTES: usize = 64 * 1024;
/// Upper bound on how long a connection may take to deliver its full
/// ClientHello before the worker abandons it. Without this, an idle or slow
/// client could pin a worker thread indefinitely (slow-loris style), since the
/// parser's `read_exact` calls block. Configurable via
/// `MITM_STREAM_HANDSHAKE_TIMEOUT_MS` (0 disables the timeout).
const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 10_000;
/// Backoff applied after an `accept_flow` error so a persistent failure (e.g.
/// file-descriptor exhaustion returning `EMFILE`/`ENFILE` on every call) does
/// not turn the accept loop into a CPU-pegging busy loop that also floods
/// stderr. The delay is capped so recovery stays prompt once the transient
/// condition clears.
const ACCEPT_ERROR_BACKOFF_MS: u64 = 50;

/// Parse a `u64` millisecond value from an env var, warning (and falling back)
/// when the value is present but not a valid integer so misconfiguration is
/// visible rather than silently ignored.
fn env_millis(name: &str, default_ms: u64) -> u64 {
    match std::env::var(name) {
        Ok(value) => match parse_millis(&value) {
            Ok(parsed) => parsed,
            Err(()) => {
                eprintln!(
                    "warning: {} is not a valid integer ({:?}); using default {}",
                    name, value, default_ms
                );
                default_ms
            }
        },
        Err(_) => default_ms,
    }
}

/// Pure millisecond parser shared by `env_millis`; trims surrounding whitespace
/// and rejects anything that is not a non-negative integer.
fn parse_millis(value: &str) -> Result<u64, ()> {
    value.trim().parse::<u64>().map_err(|_| ())
}

/// Resolve a boolean-flavored env var, treating `true`/`1`/`yes`/`on`
/// (case-insensitive) as true, `false`/`0`/`no`/`off` as false, and warning on
/// anything else before falling back to `default`.
fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(value) => {
            let trimmed = value.trim();
            match trimmed.to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" | "on" => true,
                "false" | "0" | "no" | "off" => false,
                _ => {
                    eprintln!(
                        "warning: {} is not a recognized boolean ({:?}); using default {}",
                        name, value, default
                    );
                    default
                }
            }
        }
        Err(_) => default,
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let listen_addr =
        std::env::var("MITM_STREAM_LISTEN").unwrap_or_else(|_| DEFAULT_LISTEN_ADDR.to_string());
    let preference = match std::env::var("MITM_STREAM_BACKEND") {
        Ok(value) if !value.trim().is_empty() => BackendPreference::from_env(&value)
            .unwrap_or_else(|| {
                eprintln!(
                    "warning: MITM_STREAM_BACKEND={:?} is not recognized; using auto \
                     (valid: auto, loopback, android_tun, gateway_xdp)",
                    value
                );
                BackendPreference::Auto
            }),
        _ => BackendPreference::Auto,
    };
    let handshake_timeout_ms = env_millis(
        "MITM_STREAM_HANDSHAKE_TIMEOUT_MS",
        DEFAULT_HANDSHAKE_TIMEOUT_MS,
    );
    let android_tun_fd = std::env::var("MITM_STREAM_ANDROID_TUN_FD")
        .ok()
        .and_then(|value| value.parse::<i32>().ok());
    let xdp_interface = std::env::var("MITM_STREAM_XDP_IFACE").ok();

    let mut runtime = build_runtime_backend(BackendRuntimeOptions {
        listen_addr: listen_addr.clone(),
        preference,
        android_tun_fd,
        xdp_interface,
        ..BackendRuntimeOptions::default()
    })?;
    println!(
        "mitm_stream_core baseline listening on {} ({})",
        listen_addr,
        runtime.summary()
    );

    loop {
        match runtime.stream_ingress.accept_flow() {
            Ok((meta, socket)) => {
                thread::spawn(move || {
                    if let Err(err) = handle_client(socket, handshake_timeout_ms) {
                        eprintln!("flow parse error from {}: {}", meta.source, err);
                    }
                });
            }
            Err(err) => {
                eprintln!(
                    "accept error: {} (backing off {}ms)",
                    err, ACCEPT_ERROR_BACKOFF_MS
                );
                thread::sleep(Duration::from_millis(ACCEPT_ERROR_BACKOFF_MS));
            }
        }
    }
}

fn handle_client(mut socket: TcpStream, handshake_timeout_ms: u64) -> Result<(), ParserError> {
    // Bound how long we wait for the client's ClientHello so a slow or idle peer
    // cannot pin this worker thread indefinitely. A zero value disables it.
    if handshake_timeout_ms > 0 {
        let timeout = Duration::from_millis(handshake_timeout_ms);
        if let Err(err) = socket.set_read_timeout(Some(timeout)) {
            eprintln!("warning: could not set handshake read timeout: {}", err);
        }
    }
    let mut raw = Vec::new();
    let info = read_client_hello_info(&mut socket, &mut raw, MAX_CLIENT_HELLO_BYTES)?;
    let alpn_display = if info.alpn.is_empty() {
        "<none>".to_string()
    } else {
        info.alpn
            .iter()
            .map(|item| String::from_utf8_lossy(item).into_owned())
            .collect::<Vec<String>>()
            .join(",")
    };
    println!(
        "clienthello parsed sni={} alpn={} versions={:?} sigalgs={} groups={} raw_len={}",
        info.sni.as_deref().unwrap_or("<none>"),
        alpn_display,
        info.supported_versions,
        info.signature_algorithms.len(),
        info.supported_groups.len(),
        info.raw_len
    );

    let route = RoutePlan {
        provider_family: parse_provider_family(),
        upstream_front_sni: std::env::var("MITM_STREAM_FRONT_SNI")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| info.sni.clone())
            .unwrap_or_else(|| "example.com".to_string()),
        provider_allowed_alpn: parse_allowed_alpn(),
        mode: parse_alpn_mode(),
    };

    let input = TlsOrchestrationInput {
        route,
        fallback_mode: parse_fallback_mode(),
        timeout_ms: env_millis("MITM_STREAM_TIMEOUT_MS", 5_000),
    };

    let observed_upstream_alpn = std::env::var("MITM_STREAM_UPSTREAM_ALPN")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.into_bytes());
    let allow_inference_without_upstream = env_bool("MITM_STREAM_ALLOW_POLICY_INFERENCE", true);

    let mut upstream =
        PolicyAwareTlsBackend::new(observed_upstream_alpn, allow_inference_without_upstream);
    let mut local = PolicyAwareTlsBackend::new(None, true);

    match orchestrate_tls_session(&input, &info, &mut upstream, &mut local) {
        Ok(outcome) => {
            println!("tls orchestration outcome: {:?}", outcome);
        }
        Err(err) => {
            eprintln!("tls orchestration fail-closed: {}", err);
        }
    }

    Ok(())
}

fn parse_provider_family() -> ProviderFamily {
    match std::env::var("MITM_STREAM_PROVIDER_FAMILY")
        .unwrap_or_else(|_| "generic".to_string())
        .to_ascii_lowercase()
        .as_str()
    {
        "google" => ProviderFamily::Google,
        "meta" => ProviderFamily::Meta,
        "fastly" => ProviderFamily::Fastly,
        _ => ProviderFamily::Generic,
    }
}

fn parse_allowed_alpn() -> Vec<Vec<u8>> {
    let raw =
        std::env::var("MITM_STREAM_ALLOWED_ALPN").unwrap_or_else(|_| "h2,http/1.1".to_string());
    let parsed: Vec<Vec<u8>> = raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| item.as_bytes().to_vec())
        .collect();
    if parsed.is_empty() {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        parsed
    }
}

fn parse_alpn_mode() -> AlpnMode {
    match std::env::var("MITM_STREAM_ALPN_MODE")
        .unwrap_or_else(|_| "clone_upstream".to_string())
        .to_ascii_lowercase()
        .as_str()
    {
        "force_http11" | "force-http11" => AlpnMode::ForceHttp11,
        "force_h2" | "force-h2" => AlpnMode::ForceH2,
        "reject_mismatch" | "reject-mismatch" => AlpnMode::RejectMismatch,
        _ => AlpnMode::CloneUpstream,
    }
}

fn parse_fallback_mode() -> TlsFallbackMode {
    match std::env::var("MITM_STREAM_TLS_FALLBACK")
        .unwrap_or_else(|_| "bypass".to_string())
        .to_ascii_lowercase()
        .as_str()
    {
        "fail_closed" | "fail-closed" => TlsFallbackMode::FailClosed,
        "force_http11" | "force-http11" => TlsFallbackMode::ForceHttp11IfPossible,
        _ => TlsFallbackMode::BypassWithoutMitm,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_millis_accepts_trimmed_integers() {
        assert_eq!(parse_millis("0"), Ok(0));
        assert_eq!(parse_millis("  5000 "), Ok(5000));
    }

    #[test]
    fn parse_millis_rejects_non_integers() {
        assert!(parse_millis("").is_err());
        assert!(parse_millis("abc").is_err());
        assert!(parse_millis("-1").is_err());
        assert!(parse_millis("1.5").is_err());
    }

    #[test]
    fn backend_preference_round_trips_known_aliases() {
        assert_eq!(
            BackendPreference::from_env("gateway-xdp"),
            Some(BackendPreference::GatewayXdp)
        );
        assert_eq!(
            BackendPreference::from_env("AUTO"),
            Some(BackendPreference::Auto)
        );
        assert_eq!(BackendPreference::from_env("typo"), None);
        assert_eq!(BackendPreference::from_env(""), None);
    }
}
