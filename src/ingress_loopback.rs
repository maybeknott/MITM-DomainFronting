use std::net::{SocketAddr, TcpListener, TcpStream};

use crate::ingress::{FlowMeta, IngressError, IngressKind, StreamIngress};

pub struct DesktopLoopbackIngress {
    listener: TcpListener,
    destination_hint: Option<SocketAddr>,
}

impl DesktopLoopbackIngress {
    pub fn bind(
        bind_addr: &str,
        destination_hint: Option<SocketAddr>,
    ) -> Result<Self, IngressError> {
        let listener = TcpListener::bind(bind_addr)?;
        Ok(Self {
            listener,
            destination_hint,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, IngressError> {
        Ok(self.listener.local_addr()?)
    }
}

impl StreamIngress for DesktopLoopbackIngress {
    type Stream = TcpStream;

    fn accept_flow(&mut self) -> Result<(FlowMeta, Self::Stream), IngressError> {
        let (stream, source) = self.listener.accept()?;
        let meta = FlowMeta {
            source,
            destination: self.destination_hint,
            ingress_kind: IngressKind::DesktopLoopback,
        };
        Ok((meta, stream))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::thread;

    use super::*;

    #[test]
    fn accepts_loopback_flow_with_metadata() {
        let mut ingress = DesktopLoopbackIngress::bind("127.0.0.1:0", None).expect("bind ingress");
        let bind_addr = ingress.local_addr().expect("local addr");

        let join = thread::spawn(move || {
            let mut client = TcpStream::connect(bind_addr).expect("connect");
            client.write_all(b"ping").expect("write");
            client.flush().expect("flush");
        });

        let (meta, mut stream) = ingress.accept_flow().expect("accept flow");
        let mut buf = [0_u8; 4];
        stream.read_exact(&mut buf).expect("read");
        assert_eq!(&buf, b"ping");
        assert_eq!(meta.ingress_kind, IngressKind::DesktopLoopback);
        assert_eq!(meta.destination, None);
        join.join().expect("join");
    }
}
