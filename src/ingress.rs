use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressKind {
    DesktopLoopback,
    AndroidTun,
    LinuxGatewayXdp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowMeta {
    pub source: SocketAddr,
    pub destination: Option<SocketAddr>,
    pub ingress_kind: IngressKind,
}

#[derive(Debug)]
pub enum IngressError {
    Io(io::Error),
    Unsupported(&'static str),
}

impl fmt::Display for IngressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IngressError::Io(err) => write!(f, "io error: {}", err),
            IngressError::Unsupported(reason) => write!(f, "unsupported ingress: {}", reason),
        }
    }
}

impl std::error::Error for IngressError {}

impl From<io::Error> for IngressError {
    fn from(value: io::Error) -> Self {
        IngressError::Io(value)
    }
}

pub trait StreamIngress {
    type Stream: io::Read + io::Write;

    fn accept_flow(&mut self) -> Result<(FlowMeta, Self::Stream), IngressError>;
}

pub trait PacketIngress {
    fn recv_batch(&mut self, out: &mut [PacketRef]) -> Result<usize, IngressError>;
    fn send_batch(&mut self, packets: &[PacketRef]) -> Result<usize, IngressError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketRef {
    pub offset: usize,
    pub len: usize,
}

impl PacketRef {
    pub fn new(offset: usize, len: usize) -> Result<Self, IngressError> {
        if len == 0 {
            return Err(IngressError::Unsupported(
                "empty packet references are not valid",
            ));
        }
        Ok(Self { offset, len })
    }
}

/// Shared batch-oriented packet buffer used by the datagram ingress backends
/// (`AndroidTunIngress`, `LinuxGatewayXdpIngress`). It owns the receive/transmit
/// queues plus the "last batch" window that `PacketRef`s point into, and is the
/// single place that validates `PacketRef`s on the send path.
///
/// Centralising this logic removes drift-prone duplicated code that previously
/// lived in each backend and guarantees both backends share identical (and
/// identically hardened) validation semantics.
#[derive(Debug)]
pub struct BatchPacketBuffer {
    /// MTU budget; offsets in `PacketRef`s emitted by `fill_batch` are exact
    /// multiples of this value, so a non-multiple offset is provably malformed.
    max_packet_size: usize,
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
    last_batch: Vec<Vec<u8>>,
}

impl BatchPacketBuffer {
    /// Minimum MTU budget. Anything below this is almost certainly a
    /// misconfiguration and would make even small packets unrepresentable.
    pub const MIN_MAX_PACKET_SIZE: usize = 256;

    pub fn new(max_packet_size: usize) -> Self {
        Self {
            max_packet_size: max_packet_size.max(Self::MIN_MAX_PACKET_SIZE),
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            last_batch: Vec::new(),
        }
    }

    pub fn max_packet_size(&self) -> usize {
        self.max_packet_size
    }

    /// Queue an inbound packet, rejecting empty packets and anything that
    /// exceeds the configured MTU budget so malformed input fails closed.
    pub fn push_rx(&mut self, packet: Vec<u8>) -> Result<(), IngressError> {
        if packet.is_empty() || packet.len() > self.max_packet_size {
            return Err(IngressError::Unsupported(
                "packet size is invalid for configured MTU budget",
            ));
        }
        self.rx_queue.push_back(packet);
        Ok(())
    }

    /// Pop the oldest transmitted packet (used by tests / drain paths).
    pub fn pop_tx(&mut self) -> Option<Vec<u8>> {
        self.tx_queue.pop_front()
    }

    /// Drain up to `out.len()` queued receive packets into `out`, returning the
    /// number of `PacketRef`s written. Offsets are exact multiples of
    /// `max_packet_size`, which lets the send path validate alignment cheaply.
    pub fn fill_batch(&mut self, out: &mut [PacketRef]) -> Result<usize, IngressError> {
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

    /// Resolve a `PacketRef` against the most recently received batch.
    ///
    /// Hardening over the previous implementation: offsets that are not exact
    /// multiples of `max_packet_size` are *rejected* rather than silently
    /// floored to a slot index. Because `fill_batch` only ever emits aligned
    /// offsets, a misaligned offset is provably forged/corrupt; flooring it
    /// could re-transmit the wrong packet on a data plane, which is both a
    /// correctness and an integrity hazard.
    fn slot_for(&self, packet: PacketRef) -> Result<&[u8], IngressError> {
        if !packet.offset.is_multiple_of(self.max_packet_size) {
            return Err(IngressError::Unsupported(
                "packet reference offset is not aligned to the batch stride",
            ));
        }
        let index = packet.offset / self.max_packet_size;
        let data = self.last_batch.get(index).ok_or(IngressError::Unsupported(
            "packet reference is outside batch window",
        ))?;
        if data.len() != packet.len {
            return Err(IngressError::Unsupported(
                "packet reference length mismatch in ingress batch",
            ));
        }
        Ok(data)
    }

    /// Validate every `PacketRef` against the last batch and enqueue the
    /// corresponding bytes for transmission. Returns the number of packets
    /// queued. Fails closed (and queues nothing further) on the first invalid
    /// reference so a malformed batch cannot partially leak the wrong bytes.
    pub fn send_batch(&mut self, packets: &[PacketRef]) -> Result<usize, IngressError> {
        // Resolve-then-stage: collect validated payloads first so a malformed
        // reference mid-batch leaves the tx queue untouched (all-or-nothing).
        let mut staged: Vec<Vec<u8>> = Vec::with_capacity(packets.len());
        for packet in packets {
            staged.push(self.slot_for(*packet)?.to_vec());
        }
        let sent = staged.len();
        for bytes in staged {
            self.tx_queue.push_back(bytes);
        }
        Ok(sent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_ref_rejects_empty_packet() {
        let err = PacketRef::new(0, 0).expect_err("empty packet is invalid");
        assert!(matches!(err, IngressError::Unsupported(_)));
    }

    #[test]
    fn flow_meta_can_represent_unknown_destination() {
        let source: SocketAddr = "127.0.0.1:10808".parse().expect("source");
        let meta = FlowMeta {
            source,
            destination: None,
            ingress_kind: IngressKind::DesktopLoopback,
        };
        assert_eq!(meta.destination, None);
        assert_eq!(meta.ingress_kind, IngressKind::DesktopLoopback);
    }

    #[test]
    fn batch_buffer_enforces_minimum_mtu() {
        let buffer = BatchPacketBuffer::new(16);
        assert_eq!(
            buffer.max_packet_size(),
            BatchPacketBuffer::MIN_MAX_PACKET_SIZE
        );
    }

    #[test]
    fn batch_buffer_rejects_oversized_and_empty_rx() {
        let mut buffer = BatchPacketBuffer::new(512);
        assert!(buffer.push_rx(Vec::new()).is_err());
        assert!(buffer.push_rx(vec![0_u8; 513]).is_err());
        assert!(buffer.push_rx(vec![1, 2, 3]).is_ok());
    }

    #[test]
    fn batch_buffer_roundtrips_packets() {
        let mut buffer = BatchPacketBuffer::new(1024);
        buffer.push_rx(vec![1, 2, 3, 4]).expect("rx");
        let mut refs = [PacketRef { offset: 0, len: 1 }; 2];
        let count = buffer.fill_batch(&mut refs).expect("fill");
        assert_eq!(count, 1);
        assert_eq!(refs[0].offset, 0);
        assert_eq!(refs[0].len, 4);
        let sent = buffer.send_batch(&refs[..count]).expect("send");
        assert_eq!(sent, 1);
        assert_eq!(buffer.pop_tx(), Some(vec![1, 2, 3, 4]));
        assert_eq!(buffer.pop_tx(), None);
    }

    #[test]
    fn batch_buffer_rejects_misaligned_offset() {
        let mut buffer = BatchPacketBuffer::new(1024);
        buffer.push_rx(vec![1, 2, 3, 4]).expect("rx");
        let mut refs = [PacketRef { offset: 0, len: 1 }; 1];
        buffer.fill_batch(&mut refs).expect("fill");

        let misaligned = PacketRef { offset: 5, len: 4 };
        let err = buffer
            .send_batch(&[misaligned])
            .expect_err("misaligned offset must be rejected");
        assert!(matches!(err, IngressError::Unsupported(_)));
        assert_eq!(buffer.pop_tx(), None);
    }

    #[test]
    fn batch_buffer_send_is_all_or_nothing() {
        let mut buffer = BatchPacketBuffer::new(1024);
        buffer.push_rx(vec![1, 2, 3, 4]).expect("rx");
        let mut refs = [PacketRef { offset: 0, len: 1 }; 1];
        buffer.fill_batch(&mut refs).expect("fill");
        let good = refs[0];
        let bad = PacketRef {
            offset: 1024 * 9,
            len: 4,
        };

        let err = buffer
            .send_batch(&[good, bad])
            .expect_err("out-of-window ref must fail the batch");
        assert!(matches!(err, IngressError::Unsupported(_)));
        assert_eq!(buffer.pop_tx(), None, "no partial transmission on failure");
    }

    #[test]
    fn batch_buffer_rejects_length_mismatch() {
        let mut buffer = BatchPacketBuffer::new(1024);
        buffer.push_rx(vec![1, 2, 3, 4]).expect("rx");
        let mut refs = [PacketRef { offset: 0, len: 1 }; 1];
        buffer.fill_batch(&mut refs).expect("fill");

        let wrong_len = PacketRef { offset: 0, len: 3 };
        assert!(buffer.send_batch(&[wrong_len]).is_err());
    }
}
