use std::fmt;
use std::io::{self, Read};

const TLS_HANDSHAKE_RECORD_TYPE: u8 = 0x16;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloInfo {
    pub sni: Option<String>,
    pub alpn: Vec<Vec<u8>>,
    pub supported_versions: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub raw_len: usize,
}

#[derive(Debug)]
pub enum ParserError {
    Io(io::Error),
    NotHandshakeRecord,
    UnexpectedRecordType(u8),
    ClientHelloTooLarge(usize),
    Invalid(&'static str),
    InvalidSniUtf8,
}

impl fmt::Display for ParserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParserError::Io(err) => write!(f, "io error: {}", err),
            ParserError::NotHandshakeRecord => write!(f, "not a TLS handshake record"),
            ParserError::UnexpectedRecordType(kind) => {
                write!(f, "unexpected TLS record type {:#x} while collecting ClientHello", kind)
            }
            ParserError::ClientHelloTooLarge(limit) => {
                write!(f, "client hello exceeds configured limit ({} bytes)", limit)
            }
            ParserError::Invalid(reason) => write!(f, "invalid client hello: {}", reason),
            ParserError::InvalidSniUtf8 => write!(f, "invalid utf-8 server name"),
        }
    }
}

impl std::error::Error for ParserError {}

impl From<io::Error> for ParserError {
    fn from(value: io::Error) -> Self {
        ParserError::Io(value)
    }
}

#[derive(Debug)]
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Result<u8, ParserError> {
        if self.remaining() < 1 {
            return Err(ParserError::Invalid("unexpected end of data"));
        }
        let value = self.data[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, ParserError> {
        if self.remaining() < 2 {
            return Err(ParserError::Invalid("unexpected end of data"));
        }
        let value = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(value)
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], ParserError> {
        if self.remaining() < len {
            return Err(ParserError::Invalid("unexpected end of data"));
        }
        let start = self.pos;
        let end = start + len;
        self.pos = end;
        Ok(&self.data[start..end])
    }

    fn skip(&mut self, len: usize) -> Result<(), ParserError> {
        let _ = self.read_slice(len)?;
        Ok(())
    }
}

pub fn read_client_hello_info<R: Read>(
    reader: &mut R,
    raw_out: &mut Vec<u8>,
    max_client_hello_bytes: usize,
) -> Result<ClientHelloInfo, ParserError> {
    if max_client_hello_bytes < 4 {
        return Err(ParserError::ClientHelloTooLarge(max_client_hello_bytes));
    }

    raw_out.clear();

    let mut first_header = [0_u8; 5];
    reader.read_exact(&mut first_header)?;
    raw_out.extend_from_slice(&first_header);

    if first_header[0] != TLS_HANDSHAKE_RECORD_TYPE {
        return Err(ParserError::NotHandshakeRecord);
    }

    let first_len = u16::from_be_bytes([first_header[3], first_header[4]]) as usize;
    let mut first_payload = vec![0_u8; first_len];
    reader.read_exact(&mut first_payload)?;
    raw_out.extend_from_slice(&first_payload);

    if first_payload.len() < 4 {
        return Err(ParserError::Invalid("handshake fragment too short"));
    }
    if first_payload[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(ParserError::Invalid("first handshake message is not ClientHello"));
    }

    let hello_len = ((first_payload[1] as usize) << 16)
        | ((first_payload[2] as usize) << 8)
        | (first_payload[3] as usize);
    let needed = 4 + hello_len;
    if needed > max_client_hello_bytes {
        return Err(ParserError::ClientHelloTooLarge(needed));
    }

    let mut handshake_bytes = first_payload;
    while handshake_bytes.len() < needed {
        let mut header = [0_u8; 5];
        reader.read_exact(&mut header)?;
        raw_out.extend_from_slice(&header);
        if header[0] != TLS_HANDSHAKE_RECORD_TYPE {
            return Err(ParserError::UnexpectedRecordType(header[0]));
        }
        let fragment_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut fragment = vec![0_u8; fragment_len];
        reader.read_exact(&mut fragment)?;
        raw_out.extend_from_slice(&fragment);

        handshake_bytes.extend_from_slice(&fragment);
        if handshake_bytes.len() > max_client_hello_bytes {
            return Err(ParserError::ClientHelloTooLarge(handshake_bytes.len()));
        }
    }

    parse_client_hello_handshake(&handshake_bytes[..needed])
}

pub fn parse_client_hello_handshake(handshake: &[u8]) -> Result<ClientHelloInfo, ParserError> {
    if handshake.len() < 4 {
        return Err(ParserError::Invalid("handshake header too short"));
    }
    if handshake[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(ParserError::Invalid("handshake is not ClientHello"));
    }
    let declared_len = ((handshake[1] as usize) << 16)
        | ((handshake[2] as usize) << 8)
        | (handshake[3] as usize);
    if handshake.len() < 4 + declared_len {
        return Err(ParserError::Invalid("truncated ClientHello body"));
    }
    let body = &handshake[4..(4 + declared_len)];

    let mut reader = Reader::new(body);
    let _legacy_version = reader.read_u16()?;
    reader.skip(32)?; // random

    let session_id_len = reader.read_u8()? as usize;
    reader.skip(session_id_len)?;

    let cipher_suites_len = reader.read_u16()? as usize;
    if cipher_suites_len % 2 != 0 {
        return Err(ParserError::Invalid("cipher suite vector length must be even"));
    }
    reader.skip(cipher_suites_len)?;

    let compression_methods_len = reader.read_u8()? as usize;
    reader.skip(compression_methods_len)?;

    let mut sni: Option<String> = None;
    let mut alpn: Vec<Vec<u8>> = Vec::new();
    let mut supported_versions: Vec<u16> = Vec::new();
    let mut signature_algorithms: Vec<u16> = Vec::new();
    let mut supported_groups: Vec<u16> = Vec::new();

    if reader.remaining() > 0 {
        let extensions_len = reader.read_u16()? as usize;
        let extensions = reader.read_slice(extensions_len)?;
        let mut ext_reader = Reader::new(extensions);
        while ext_reader.remaining() > 0 {
            if ext_reader.remaining() < 4 {
                return Err(ParserError::Invalid("truncated extension header"));
            }
            let ext_type = ext_reader.read_u16()?;
            let ext_len = ext_reader.read_u16()? as usize;
            let ext_payload = ext_reader.read_slice(ext_len)?;
            match ext_type {
                0x0000 => {
                    if sni.is_none() {
                        sni = parse_sni(ext_payload)?;
                    }
                }
                0x0010 => {
                    alpn = parse_alpn(ext_payload)?;
                }
                0x002b => {
                    supported_versions = parse_u16_vector_with_u8_len(ext_payload)?;
                }
                0x000d => {
                    signature_algorithms = parse_u16_vector_with_u16_len(ext_payload)?;
                }
                0x000a => {
                    supported_groups = parse_u16_vector_with_u16_len(ext_payload)?;
                }
                _ => {}
            }
        }
    }

    Ok(ClientHelloInfo {
        sni,
        alpn,
        supported_versions,
        signature_algorithms,
        supported_groups,
        raw_len: 4 + declared_len,
    })
}

fn parse_sni(data: &[u8]) -> Result<Option<String>, ParserError> {
    let mut reader = Reader::new(data);
    let list_len = reader.read_u16()? as usize;
    let list = reader.read_slice(list_len)?;
    let mut list_reader = Reader::new(list);

    while list_reader.remaining() > 0 {
        let name_type = list_reader.read_u8()?;
        let name_len = list_reader.read_u16()? as usize;
        let name = list_reader.read_slice(name_len)?;
        if name_type == 0 {
            return String::from_utf8(name.to_vec())
                .map(Some)
                .map_err(|_| ParserError::InvalidSniUtf8);
        }
    }
    Ok(None)
}

fn parse_alpn(data: &[u8]) -> Result<Vec<Vec<u8>>, ParserError> {
    let mut reader = Reader::new(data);
    let list_len = reader.read_u16()? as usize;
    let list = reader.read_slice(list_len)?;
    let mut list_reader = Reader::new(list);
    let mut protocols = Vec::new();
    while list_reader.remaining() > 0 {
        let len = list_reader.read_u8()? as usize;
        let value = list_reader.read_slice(len)?;
        protocols.push(value.to_vec());
    }
    Ok(protocols)
}

fn parse_u16_vector_with_u16_len(data: &[u8]) -> Result<Vec<u16>, ParserError> {
    let mut reader = Reader::new(data);
    let len = reader.read_u16()? as usize;
    if len % 2 != 0 {
        return Err(ParserError::Invalid("u16 vector length must be even"));
    }
    let list = reader.read_slice(len)?;
    let mut list_reader = Reader::new(list);
    let mut out = Vec::new();
    while list_reader.remaining() > 0 {
        out.push(list_reader.read_u16()?);
    }
    Ok(out)
}

fn parse_u16_vector_with_u8_len(data: &[u8]) -> Result<Vec<u16>, ParserError> {
    let mut reader = Reader::new(data);
    let len = reader.read_u8()? as usize;
    if len % 2 != 0 {
        return Err(ParserError::Invalid("u16 vector length must be even"));
    }
    let list = reader.read_slice(len)?;
    let mut list_reader = Reader::new(list);
    let mut out = Vec::new();
    while list_reader.remaining() > 0 {
        out.push(list_reader.read_u16()?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_sample_client_hello(host: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0_u8; 32]); // random
        body.push(0x00); // session_id_len
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[0x01, 0x00]); // one compression method: null

        let mut extensions = Vec::new();

        // SNI extension
        let host_bytes = host.as_bytes();
        let sni_name_len = host_bytes.len() as u16;
        let sni_list_len = 1_u16 + 2 + sni_name_len;
        let sni_ext_len = 2_u16 + sni_list_len;
        extensions.extend_from_slice(&0x0000_u16.to_be_bytes());
        extensions.extend_from_slice(&sni_ext_len.to_be_bytes());
        extensions.extend_from_slice(&sni_list_len.to_be_bytes());
        extensions.push(0x00);
        extensions.extend_from_slice(&sni_name_len.to_be_bytes());
        extensions.extend_from_slice(host_bytes);

        // ALPN extension: h2, http/1.1
        let alpn_list = b"\x02h2\x08http/1.1";
        let alpn_ext_len = 2 + alpn_list.len() as u16;
        extensions.extend_from_slice(&0x0010_u16.to_be_bytes());
        extensions.extend_from_slice(&alpn_ext_len.to_be_bytes());
        extensions.extend_from_slice(&(alpn_list.len() as u16).to_be_bytes());
        extensions.extend_from_slice(alpn_list);

        // supported_versions: TLS 1.3 and 1.2
        extensions.extend_from_slice(&0x002b_u16.to_be_bytes());
        extensions.extend_from_slice(&0x0005_u16.to_be_bytes());
        extensions.extend_from_slice(&[0x04, 0x03, 0x04, 0x03, 0x03]);

        // signature_algorithms
        extensions.extend_from_slice(&0x000d_u16.to_be_bytes());
        extensions.extend_from_slice(&0x0006_u16.to_be_bytes());
        extensions.extend_from_slice(&[0x00, 0x04, 0x04, 0x03, 0x08, 0x04]);

        // supported_groups
        extensions.extend_from_slice(&0x000a_u16.to_be_bytes());
        extensions.extend_from_slice(&0x0006_u16.to_be_bytes());
        extensions.extend_from_slice(&[0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);

        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut hello = Vec::new();
        hello.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        hello.push(((body.len() >> 16) & 0xff) as u8);
        hello.push(((body.len() >> 8) & 0xff) as u8);
        hello.push((body.len() & 0xff) as u8);
        hello.extend_from_slice(&body);
        hello
    }

    #[test]
    fn parses_client_hello_extensions() {
        let hello = build_sample_client_hello("example.com");
        let parsed = parse_client_hello_handshake(&hello).expect("parse client hello");
        assert_eq!(parsed.sni.as_deref(), Some("example.com"));
        assert_eq!(parsed.alpn, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        assert_eq!(parsed.supported_versions, vec![0x0304, 0x0303]);
        assert_eq!(parsed.signature_algorithms, vec![0x0403, 0x0804]);
        assert_eq!(parsed.supported_groups, vec![0x001d, 0x0017]);
        assert_eq!(parsed.raw_len, hello.len());
    }

    #[test]
    fn rejects_truncated_hello() {
        let hello = vec![0x01, 0x00, 0x00, 0x05, 0x03];
        let err = parse_client_hello_handshake(&hello).expect_err("must reject truncated");
        assert!(matches!(err, ParserError::Invalid(_)));
    }
}

