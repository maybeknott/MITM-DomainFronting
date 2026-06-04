//! Model/fixture for an XDP-style batch packet ingress.
//!
//! Offline tests use in-memory batch buffers. When the production loader
//! (`scripts/ebpf_xdp_loader.py`) records kernel or simulated attach in
//! `.local-state/ebpf-xdp-loader.json`, or `MITM_EBPF_ATTACHED=1` is set, this
//! backend is enabled for ingress telemetry coordination — Xray remains the live
//! TLS/data plane (ADR-0007).

use crate::ingress::{BatchPacketBuffer, IngressError, PacketIngress, PacketRef};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpGatewayAvailability {
    Enabled,
    Disabled,
    UnsupportedPlatform,
    MissingInterface,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdpGatewayOptions {
    pub enabled: bool,
    pub interface_name: Option<String>,
    pub max_packet_size: usize,
}

impl Default for XdpGatewayOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            interface_name: None,
            max_packet_size: 2_048,
        }
    }
}

pub struct LinuxGatewayXdpIngress {
    availability: XdpGatewayAvailability,
    interface_name: Option<String>,
    buffer: BatchPacketBuffer,
    production_attach: bool,
}

fn ebpf_consent_granted() -> bool {
    std::env::var("MITM_EBPF_CONSENT")
        .ok()
        .is_some_and(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
}

/// True when the operator ran the production eBPF loader or set `MITM_EBPF_ATTACHED=1`.
pub fn production_attach_active() -> bool {
    if std::env::var("MITM_EBPF_ATTACHED")
        .ok()
        .is_some_and(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
    {
        return ebpf_consent_granted();
    }
    ebpf_consent_granted() && loader_state_reports_attached()
}

fn loader_state_reports_attached() -> bool {
    let path = std::env::var("MITM_EBPF_STATE_FILE")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .unwrap_or_else(|| ".local-state/ebpf-xdp-loader.json".to_string());
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    text.contains("\"attached\": true") || text.contains("\"attached\":true")
}

impl LinuxGatewayXdpIngress {
    pub fn new(options: XdpGatewayOptions) -> Self {
        let production_attach = production_attach_active();
        let effective_enabled = options.enabled || production_attach;
        let has_interface = options
            .interface_name
            .as_ref()
            .is_some_and(|value| !value.trim().is_empty());
        let availability = if !effective_enabled {
            XdpGatewayAvailability::Disabled
        } else if !cfg!(target_os = "linux") {
            XdpGatewayAvailability::UnsupportedPlatform
        } else if !has_interface {
            XdpGatewayAvailability::MissingInterface
        } else {
            XdpGatewayAvailability::Enabled
        };
        Self {
            availability,
            interface_name: options.interface_name,
            buffer: BatchPacketBuffer::new(options.max_packet_size),
            production_attach,
        }
    }

    pub fn production_attach(&self) -> bool {
        self.production_attach
    }

    pub fn availability(&self) -> XdpGatewayAvailability {
        self.availability
    }

    pub fn fallback_reason(&self) -> Option<&'static str> {
        match self.availability {
            XdpGatewayAvailability::Enabled => None,
            XdpGatewayAvailability::Disabled => Some("xdp_gateway backend disabled"),
            XdpGatewayAvailability::UnsupportedPlatform => {
                Some("xdp_gateway requires linux gateway runtime")
            }
            XdpGatewayAvailability::MissingInterface => {
                Some("xdp_gateway requires interface name (e.g. eth0)")
            }
        }
    }

    pub fn interface_name(&self) -> Option<&str> {
        self.interface_name.as_deref()
    }

    pub fn inject_rx_packet_for_test(&mut self, packet: Vec<u8>) -> Result<(), IngressError> {
        self.buffer.push_rx(packet)
    }

    pub fn take_tx_packet_for_test(&mut self) -> Option<Vec<u8>> {
        self.buffer.pop_tx()
    }

    fn ensure_enabled(&self) -> Result<(), IngressError> {
        if let Some(reason) = self.fallback_reason() {
            return Err(IngressError::Unsupported(reason));
        }
        Ok(())
    }

    //
    // Note: packet reference validation and batching lives in `BatchPacketBuffer`
    // so all datagram ingress backends share identical semantics.
}

impl PacketIngress for LinuxGatewayXdpIngress {
    fn recv_batch(&mut self, out: &mut [PacketRef]) -> Result<usize, IngressError> {
        self.ensure_enabled()?;
        self.buffer.fill_batch(out)
    }

    fn send_batch(&mut self, packets: &[PacketRef]) -> Result<usize, IngressError> {
        self.ensure_enabled()?;
        self.buffer.send_batch(packets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xdp_backend_requires_explicit_enablement() {
        let _guard = ProductionAttachEnv::clear();
        let ingress = LinuxGatewayXdpIngress::new(XdpGatewayOptions::default());
        assert_eq!(
            ingress.fallback_reason(),
            Some("xdp_gateway backend disabled")
        );
    }

    #[test]
    fn production_attach_env_enables_without_options_enabled() {
        let _guard = ProductionAttachEnv::set("1");
        let ingress = LinuxGatewayXdpIngress::new(XdpGatewayOptions {
            enabled: false,
            interface_name: Some("eth0".to_string()),
            max_packet_size: 2048,
        });
        if cfg!(target_os = "linux") {
            assert!(ingress.production_attach());
            assert_eq!(ingress.availability(), XdpGatewayAvailability::Enabled);
        }
    }

    struct ProductionAttachEnv {
        previous_attached: Option<String>,
        previous_consent: Option<String>,
    }

    impl ProductionAttachEnv {
        fn set(value: &str) -> Self {
            let previous_attached = std::env::var("MITM_EBPF_ATTACHED").ok();
            let previous_consent = std::env::var("MITM_EBPF_CONSENT").ok();
            std::env::set_var("MITM_EBPF_ATTACHED", value);
            std::env::set_var("MITM_EBPF_CONSENT", "1");
            Self {
                previous_attached,
                previous_consent,
            }
        }

        fn clear() -> Self {
            let previous_attached = std::env::var("MITM_EBPF_ATTACHED").ok();
            let previous_consent = std::env::var("MITM_EBPF_CONSENT").ok();
            std::env::remove_var("MITM_EBPF_ATTACHED");
            std::env::remove_var("MITM_EBPF_CONSENT");
            let _ = std::fs::remove_file(".local-state/ebpf-xdp-loader.json");
            Self {
                previous_attached,
                previous_consent,
            }
        }
    }

    impl Drop for ProductionAttachEnv {
        fn drop(&mut self) {
            match &self.previous_attached {
                Some(value) => std::env::set_var("MITM_EBPF_ATTACHED", value),
                None => std::env::remove_var("MITM_EBPF_ATTACHED"),
            }
            match &self.previous_consent {
                Some(value) => std::env::set_var("MITM_EBPF_CONSENT", value),
                None => std::env::remove_var("MITM_EBPF_CONSENT"),
            }
        }
    }

    #[test]
    fn xdp_batch_roundtrip_works_when_enabled() {
        let mut ingress = LinuxGatewayXdpIngress::new(XdpGatewayOptions {
            enabled: true,
            interface_name: Some("eth0".to_string()),
            max_packet_size: 2048,
        });
        ingress.availability = XdpGatewayAvailability::Enabled;
        ingress
            .inject_rx_packet_for_test(vec![9, 8, 7, 6])
            .expect("inject");

        let mut refs = [PacketRef { offset: 0, len: 1 }; 4];
        let count = ingress.recv_batch(&mut refs).expect("recv");
        assert_eq!(count, 1);
        assert_eq!(refs[0].len, 4);

        let sent = ingress.send_batch(&refs[..count]).expect("send");
        assert_eq!(sent, 1);
        assert_eq!(ingress.take_tx_packet_for_test(), Some(vec![9, 8, 7, 6]));
    }
}
