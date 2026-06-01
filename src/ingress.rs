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
}
