use std::error::Error;
use std::net::TcpStream;
use std::thread;

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

fn main() -> Result<(), Box<dyn Error>> {
    let listen_addr =
        std::env::var("MITM_STREAM_LISTEN").unwrap_or_else(|_| DEFAULT_LISTEN_ADDR.to_string());
    let preference = std::env::var("MITM_STREAM_BACKEND")
        .ok()
        .and_then(|value| BackendPreference::from_env(&value))
        .unwrap_or(BackendPreference::Auto);
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
                    if let Err(err) = handle_client(socket) {
                        eprintln!("flow parse error from {}: {}", meta.source, err);
                    }
                });
            }
            Err(err) => {
                eprintln!("accept error: {}", err);
            }
        }
    }
}

fn handle_client(mut socket: TcpStream) -> Result<(), ParserError> {
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
        timeout_ms: std::env::var("MITM_STREAM_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(5_000),
    };

    let observed_upstream_alpn = std::env::var("MITM_STREAM_UPSTREAM_ALPN")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.into_bytes());
    let allow_inference_without_upstream = std::env::var("MITM_STREAM_ALLOW_POLICY_INFERENCE")
        .ok()
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(true);

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
