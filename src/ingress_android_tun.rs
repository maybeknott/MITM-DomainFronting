use std::collections::VecDeque;

use crate::ingress::{IngressError, PacketIngress, PacketRef};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AndroidTunAvailability {
    Enabled,
    Disabled,
    UnsupportedPlatform,
    MissingFileDescriptor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidTunOptions {
    pub enabled: bool,
    pub tun_fd: Option<i32>,
    pub max_packet_size: usize,
}

impl Default for AndroidTunOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            tun_fd: None,
            max_packet_size: 2_048,
        }
    }
}

pub struct AndroidTunIngress {
    availability: AndroidTunAvailability,
    tun_fd: Option<i32>,
    max_packet_size: usize,
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
    last_batch: Vec<Vec<u8>>,
}

impl AndroidTunIngress {
    pub fn new(options: AndroidTunOptions) -> Self {
        let availability = if !options.enabled {
            AndroidTunAvailability::Disabled
        } else if !cfg!(target_os = "android") {
            AndroidTunAvailability::UnsupportedPlatform
        } else if options.tun_fd.is_none_or(|fd| fd < 0) {
            AndroidTunAvailability::MissingFileDescriptor
        } else {
            AndroidTunAvailability::Enabled
        };
        Self {
            availability,
            tun_fd: options.tun_fd,
            max_packet_size: options.max_packet_size.max(256),
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            last_batch: Vec::new(),
        }
    }

    pub fn availability(&self) -> AndroidTunAvailability {
        self.availability
    }

    pub fn fallback_reason(&self) -> Option<&'static str> {
        match self.availability {
            AndroidTunAvailability::Enabled => None,
            AndroidTunAvailability::Disabled => Some("android_tun backend disabled"),
            AndroidTunAvailability::UnsupportedPlatform => {
                Some("android_tun requires android runtime")
            }
            AndroidTunAvailability::MissingFileDescriptor => {
                Some("android_tun requires a valid VpnService TUN fd")
            }
        }
    }

    pub fn tun_fd(&self) -> Option<i32> {
        self.tun_fd
    }

    pub fn inject_rx_packet_for_test(&mut self, packet: Vec<u8>) -> Result<(), IngressError> {
        if packet.is_empty() || packet.len() > self.max_packet_size {
            return Err(IngressError::Unsupported(
                "android_tun packet size is invalid for configured MTU budget",
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
                "packet reference length mismatch in android_tun batch",
            ));
        }
        Ok(data)
    }
}

impl PacketIngress for AndroidTunIngress {
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
    fn disabled_backend_reports_fallback_reason() {
        let ingress = AndroidTunIngress::new(AndroidTunOptions::default());
        assert_eq!(
            ingress.fallback_reason(),
            Some("android_tun backend disabled")
        );
    }

    #[test]
    fn batch_roundtrip_works_when_backend_enabled() {
        let mut ingress = AndroidTunIngress::new(AndroidTunOptions {
            enabled: true,
            tun_fd: Some(10),
            max_packet_size: 1024,
        });
        ingress.availability = AndroidTunAvailability::Enabled;
        ingress
            .inject_rx_packet_for_test(vec![1, 2, 3, 4])
            .expect("inject");

        let mut refs = [PacketRef { offset: 0, len: 1 }; 2];
        let count = ingress.recv_batch(&mut refs).expect("recv");
        assert_eq!(count, 1);
        assert_eq!(refs[0].len, 4);

        let sent = ingress.send_batch(&refs[..count]).expect("send");
        assert_eq!(sent, 1);
        assert_eq!(ingress.take_tx_packet_for_test(), Some(vec![1, 2, 3, 4]));
    }
}
