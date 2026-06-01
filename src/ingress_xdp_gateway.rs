use std::collections::VecDeque;

use crate::ingress::{IngressError, PacketIngress, PacketRef};

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
    max_packet_size: usize,
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
    last_batch: Vec<Vec<u8>>,
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
            max_packet_size: options.max_packet_size.max(256),
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            last_batch: Vec::new(),
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
        if packet.is_empty() || packet.len() > self.max_packet_size {
            return Err(IngressError::Unsupported(
                "xdp_gateway packet size is invalid for configured MTU budget",
            ));
        }
        self.rx_queue.push_back(packet);
        Ok(())
    }

    pub fn take_tx_packet_for_test(&mut self) -> Option<Vec<u8>> {
        self.tx_queue.pop_front()
    }

    fn ensure_enabled(&self) -> Result<(), IngressError> {
        if let Some(reason) = self.fallback_reason() {
            return Err(IngressError::Unsupported(reason));
        }
        Ok(())
    }

    fn packet_from_last_batch(&self, packet: PacketRef) -> Result<&[u8], IngressError> {
        let index = packet.offset / self.max_packet_size;
        if index >= self.last_batch.len() {
            return Err(IngressError::Unsupported(
                "packet reference is outside batch window",
            ));
        }
        let data = &self.last_batch[index];
        if data.len() != packet.len {
            return Err(IngressError::Unsupported(
                "packet reference length mismatch in xdp_gateway batch",
            ));
        }
        Ok(data)
    }
}

impl PacketIngress for LinuxGatewayXdpIngress {
    fn recv_batch(&mut self, out: &mut [PacketRef]) -> Result<usize, IngressError> {
        self.ensure_enabled()?;
        if out.is_empty() {
            return Ok(0);
        }
        self.last_batch.clear();
        let mut count = 0_usize;
        while count < out.len() {
            let Some(packet) = self.rx_queue.pop_front() else {
                break;
            };
            let offset = count * self.max_packet_size;
            out[count] = PacketRef::new(offset, packet.len())?;
            self.last_batch.push(packet);
            count += 1;
        }
        Ok(count)
    }

    fn send_batch(&mut self, packets: &[PacketRef]) -> Result<usize, IngressError> {
        self.ensure_enabled()?;
        let mut sent = 0_usize;
        for packet in packets {
            let bytes = self.packet_from_last_batch(*packet)?;
            self.tx_queue.push_back(bytes.to_vec());
            sent += 1;
        }
        Ok(sent)
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
