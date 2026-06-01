use std::error::Error;
use std::net::{TcpListener, TcpStream};
use std::thread;

use mitm_stream_core::parser::{read_client_hello_info, ParserError};

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:10808";
const MAX_CLIENT_HELLO_BYTES: usize = 64 * 1024;

fn main() -> Result<(), Box<dyn Error>> {
    let listen_addr =
        std::env::var("MITM_STREAM_LISTEN").unwrap_or_else(|_| DEFAULT_LISTEN_ADDR.to_string());
    let listener = TcpListener::bind(&listen_addr)?;
    println!(
        "mitm_stream_core baseline listening on {} (parse-only, no MITM relay yet)",
        listen_addr
    );

    for stream in listener.incoming() {
        match stream {
            Ok(socket) => {
                thread::spawn(move || {
                    if let Err(err) = handle_client(socket) {
                        eprintln!("flow parse error: {}", err);
                    }
                });
            }
            Err(err) => eprintln!("accept error: {}", err),
        }
    }
    Ok(())
}

fn handle_client(mut socket: TcpStream) -> Result<(), ParserError> {
    let mut raw = Vec::new();
    let info = read_client_hello_info(&mut socket, &mut raw, MAX_CLIENT_HELLO_BYTES)?;
    let alpn_display = if info.alpn.is_empty() {
        "<none>".to_string()
    } else {
        info.alpn
            .iter()
            .map(|item| String::from_utf8_lossy(item).into_owned())
            .collect::<Vec<String>>()
            .join(",")
    };
    println!(
        "clienthello parsed sni={} alpn={} versions={:?} sigalgs={} groups={} raw_len={}",
        info.sni.as_deref().unwrap_or("<none>"),
        alpn_display,
        info.supported_versions,
        info.signature_algorithms.len(),
        info.supported_groups.len(),
        info.raw_len
    );
    Ok(())
}
