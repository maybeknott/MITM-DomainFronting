use std::fmt;
use std::net::SocketAddr;

use crate::ingress::IngressError;
use crate::ingress_android_tun::{AndroidTunAvailability, AndroidTunIngress, AndroidTunOptions};
use crate::ingress_loopback::DesktopLoopbackIngress;
use crate::ingress_xdp_gateway::{
    LinuxGatewayXdpIngress, XdpGatewayAvailability, XdpGatewayOptions,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendPreference {
    Auto,
    Loopback,
    AndroidTun,
    GatewayXdp,
}

impl BackendPreference {
    pub fn from_env(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" => None,
            "auto" => Some(Self::Auto),
            "loopback" => Some(Self::Loopback),
            "android_tun" | "android-tun" => Some(Self::AndroidTun),
            "gateway_xdp" | "gateway-xdp" | "xdp_gateway" | "xdp-gateway" => Some(Self::GatewayXdp),
            _ => None,
        }
    }
}

impl fmt::Display for BackendPreference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendPreference::Auto => write!(f, "auto"),
            BackendPreference::Loopback => write!(f, "loopback"),
            BackendPreference::AndroidTun => write!(f, "android_tun"),
            BackendPreference::GatewayXdp => write!(f, "gateway_xdp"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendRuntimeOptions {
    pub listen_addr: String,
    pub destination_hint: Option<SocketAddr>,
    pub preference: BackendPreference,
    pub android_tun_fd: Option<i32>,
    pub xdp_interface: Option<String>,
}

impl Default for BackendRuntimeOptions {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:10808".to_string(),
            destination_hint: None,
            preference: BackendPreference::Auto,
            android_tun_fd: None,
            xdp_interface: None,
        }
    }
}

pub enum RuntimePacketBackend {
    AndroidTun(AndroidTunIngress),
    GatewayXdp(LinuxGatewayXdpIngress),
}

pub struct RuntimeBackend {
    pub stream_ingress: DesktopLoopbackIngress,
    pub packet_backend: Option<RuntimePacketBackend>,
    pub selected: BackendPreference,
    pub notes: Vec<String>,
}

impl RuntimeBackend {
    pub fn summary(&self) -> String {
        let mut parts = vec![format!("selected_backend={}", self.selected)];
        if self.packet_backend.is_some() {
            parts.push("packet_backend=active".to_string());
        } else {
            parts.push("packet_backend=none".to_string());
        }
        if !self.notes.is_empty() {
            parts.push(format!("notes={}", self.notes.join("; ")));
        }
        parts.join(" ")
    }
}

pub fn build_runtime_backend(
    options: BackendRuntimeOptions,
) -> Result<RuntimeBackend, IngressError> {
    let stream_ingress =
        DesktopLoopbackIngress::bind(&options.listen_addr, options.destination_hint)?;
    let mut selected = BackendPreference::Loopback;
    let mut packet_backend = None;
    let mut notes = Vec::new();

    match options.preference {
        BackendPreference::Loopback => {}
        BackendPreference::AndroidTun => {
            let backend = AndroidTunIngress::new(AndroidTunOptions {
                enabled: true,
                tun_fd: options.android_tun_fd,
                max_packet_size: 2_048,
            });
            match backend.availability() {
                AndroidTunAvailability::Enabled => {
                    selected = BackendPreference::AndroidTun;
                    packet_backend = Some(RuntimePacketBackend::AndroidTun(backend));
                }
                _ => {
                    notes.push(format!(
                        "requested android_tun but falling back to loopback: {}",
                        backend.fallback_reason().unwrap_or("unknown")
                    ));
                }
            }
        }
        BackendPreference::GatewayXdp => {
            let backend = LinuxGatewayXdpIngress::new(XdpGatewayOptions {
                enabled: true,
                interface_name: options.xdp_interface,
                max_packet_size: 2_048,
            });
            match backend.availability() {
                XdpGatewayAvailability::Enabled => {
                    selected = BackendPreference::GatewayXdp;
                    packet_backend = Some(RuntimePacketBackend::GatewayXdp(backend));
                }
                _ => {
                    notes.push(format!(
                        "requested gateway_xdp but falling back to loopback: {}",
                        backend.fallback_reason().unwrap_or("unknown")
                    ));
                }
            }
        }
        BackendPreference::Auto => {
            if let Some(fd) = options.android_tun_fd {
                let backend = AndroidTunIngress::new(AndroidTunOptions {
                    enabled: true,
                    tun_fd: Some(fd),
                    max_packet_size: 2_048,
                });
                if matches!(backend.availability(), AndroidTunAvailability::Enabled) {
                    selected = BackendPreference::AndroidTun;
                    packet_backend = Some(RuntimePacketBackend::AndroidTun(backend));
                } else {
                    notes.push(format!(
                        "auto skipped android_tun backend: {}",
                        backend.fallback_reason().unwrap_or("unknown")
                    ));
                }
            }
            if packet_backend.is_none() && options.xdp_interface.is_some() {
                let backend = LinuxGatewayXdpIngress::new(XdpGatewayOptions {
                    enabled: true,
                    interface_name: options.xdp_interface,
                    max_packet_size: 2_048,
                });
                if matches!(backend.availability(), XdpGatewayAvailability::Enabled) {
                    selected = BackendPreference::GatewayXdp;
                    packet_backend = Some(RuntimePacketBackend::GatewayXdp(backend));
                } else {
                    notes.push(format!(
                        "auto skipped gateway_xdp backend: {}",
                        backend.fallback_reason().unwrap_or("unknown")
                    ));
                }
            }
        }
    }

    Ok(RuntimeBackend {
        stream_ingress,
        packet_backend,
        selected,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_loopback_mode_uses_stream_backend_only() {
        let runtime = build_runtime_backend(BackendRuntimeOptions {
            listen_addr: "127.0.0.1:0".to_string(),
            preference: BackendPreference::Loopback,
            ..BackendRuntimeOptions::default()
        })
        .expect("runtime");
        assert_eq!(runtime.selected, BackendPreference::Loopback);
        assert!(runtime.packet_backend.is_none());
    }

    #[test]
    fn requested_android_tun_falls_back_cleanly_without_fd() {
        let runtime = build_runtime_backend(BackendRuntimeOptions {
            listen_addr: "127.0.0.1:0".to_string(),
            preference: BackendPreference::AndroidTun,
            android_tun_fd: None,
            ..BackendRuntimeOptions::default()
        })
        .expect("runtime");
        assert_eq!(runtime.selected, BackendPreference::Loopback);
        assert!(runtime.packet_backend.is_none());
        assert!(runtime
            .notes
            .iter()
            .any(|note| note.contains("falling back to loopback")));
    }

    #[test]
    fn requested_xdp_falls_back_cleanly_without_interface() {
        let runtime = build_runtime_backend(BackendRuntimeOptions {
            listen_addr: "127.0.0.1:0".to_string(),
            preference: BackendPreference::GatewayXdp,
            xdp_interface: None,
            ..BackendRuntimeOptions::default()
        })
        .expect("runtime");
        assert_eq!(runtime.selected, BackendPreference::Loopback);
        assert!(runtime.packet_backend.is_none());
    }
}
