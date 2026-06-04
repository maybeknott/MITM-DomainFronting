use crate::ingress::{BatchPacketBuffer, IngressError, PacketIngress, PacketRef};

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
    buffer: BatchPacketBuffer,
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
            buffer: BatchPacketBuffer::new(options.max_packet_size),
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

impl PacketIngress for AndroidTunIngress {
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

    /// D9 harness: after send_batch drains injected RX, no stale TX remains and a
    /// second recv returns zero packets (buffer lifecycle sanity — optional CI LSan
    /// can wrap `cargo test -Z sanitizer=leak` on Android targets separately).
    #[test]
    fn batch_buffer_does_not_retain_stale_packets() {
        let mut ingress = AndroidTunIngress::new(AndroidTunOptions {
            enabled: true,
            tun_fd: Some(11),
            max_packet_size: 512,
        });
        ingress.availability = AndroidTunAvailability::Enabled;
        ingress
            .inject_rx_packet_for_test(vec![9, 8, 7])
            .expect("inject");
        let mut refs = [PacketRef { offset: 0, len: 0 }; 4];
        let count = ingress.recv_batch(&mut refs).expect("recv");
        assert_eq!(count, 1);
        let sent = ingress.send_batch(&refs[..count]).expect("send");
        assert_eq!(sent, 1);
        assert_eq!(ingress.take_tx_packet_for_test(), Some(vec![9, 8, 7]));
        assert!(ingress.take_tx_packet_for_test().is_none());
        let again = ingress.recv_batch(&mut refs).expect("recv again");
        assert_eq!(again, 0);
    }
}
