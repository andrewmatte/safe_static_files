use openssl::pkcs12::Pkcs12;
use openssl::ssl::{SslAcceptor, SslMethod, SslStream};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

fn handle_client(mut stream: SslStream<TcpStream>) {
    let response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!";
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn main() {
    // Load PKCS#12 file
    let mut file = File::open("identity.pfx").expect("Failed to open identity.pfx");
    let mut pkcs12 = vec![];
    file.read_to_end(&mut pkcs12).expect("Failed to read PFX file");

    let pkcs12 = Pkcs12::from_der(&pkcs12).expect("Failed to parse PKCS#12");
    let identity = pkcs12.parse2("password123").expect("Failed to decrypt PKCS#12");

    // Configure SSL acceptor
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).expect("Failed to create SSL acceptor");
    acceptor.set_private_key(&identity.pkey.unwrap()).expect("Failed to set private key");
    acceptor.set_certificate(&identity.cert.unwrap()).expect("Failed to set certificate");
    let acceptor = Arc::new(acceptor.build());

    // Start TCP listener
    let listener = TcpListener::bind("0.0.0.0:8443").expect("Failed to bind to port 8443");
    println!("Listening on https://0.0.0.0:8443");

    // Accept incoming connections
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let acceptor = Arc::clone(&acceptor);
                thread::spawn(move || {
                    match acceptor.accept(stream) {
                        Ok(ssl_stream) => handle_client(ssl_stream),
                        Err(e) => eprintln!("TLS handshake failed: {}", e),
                    }
                });
            }
            Err(e) => eprintln!("Connection failed: {}", e),
        }
    }
}
