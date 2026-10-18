//! `janus-mailbox <addr> [cert-file]`: runs a development mailbox and writes its self-signed
//! certificate (DER, `mailbox.der` by default) for clients to pin. Blocks live in memory only,
//! so a restart starts empty, under a new certificate.

use std::net::TcpListener;
use std::{env, fs, io, process};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let (addr, cert_file) = match &args[..] {
        [addr] => (addr.as_str(), "mailbox.der"),
        [addr, file] => (addr.as_str(), file.as_str()),
        _ => {
            eprintln!("usage: janus-mailbox <addr> [cert-file]");
            process::exit(2);
        }
    };
    if let Err(e) = run(addr, cert_file) {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

fn run(addr: &str, cert_file: &str) -> io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    let (cert, key) = janus_mailbox::self_signed();
    fs::write(cert_file, &cert)?;
    println!("mailbox on {addr}; clients pin the certificate in {cert_file}");
    janus_mailbox::serve(listener, cert, key)
}
