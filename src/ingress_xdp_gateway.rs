//! Model/fixture for an XDP-style batch packet ingress.
//!
//! NOTE: This is a validation model, not a loaded eBPF/XDP program on the live
//! egress path. The Rust core is a validation library, not the data plane — see
//! `docs/adr/0007-rust-core-is-validation-not-data-plane.md` and ADR-0001. Do
//! not wire raw-packet manipulation or kernel programs in here; the data plane
//! is Xray.

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
}

impl LinuxGatewayXdpIngress {
    pub fn new(options: XdpGatewayOptions) -> Self {
        let has_interface = options
            .interface_name
            .as_ref()
            .is_some_and(|value| !value.trim().is_empty());
        let availability = if !options.enabled {
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
        }
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
        let ingress = LinuxGatewayXdpIngress::new(XdpGatewayOptions::default());
        assert_eq!(
            ingress.fallback_reason(),
            Some("xdp_gateway backend disabled")
        );
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
