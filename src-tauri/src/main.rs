// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::str::FromStr;
use std::{env, net, ptr::null, sync::Arc};

use rustls::OwnedTrustAnchor;

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![showstr])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[tauri::command]
fn showstr(url: &str) -> String {
    let unparsed = url;

    let mut withouthttp = String::from(
        unparsed
            .split("//")
            .last()
            .unwrap()
            .split("/")
            .next()
            .unwrap_or("google.com"),
    );

    let k = withouthttp.clone();

    println!("{}", &withouthttp);

    withouthttp.push_str(":443");

    println!("{}", &withouthttp);

    let mut ip_of_arg = net::ToSocketAddrs::to_socket_addrs(&withouthttp).unwrap();
    let ip = ip_of_arg.next().unwrap();

    let mut st = String::new();

    let mut it1 = &mut unparsed.split("//");
    it1.next();

    let path_unparsed = it1.next().unwrap();

    let mut it2 = path_unparsed.split("/");
    it2.next();

    it2.for_each(|a| {
        st.push_str("/");
        st.push_str(a)
    });

    return create_socket(&ip, &st, k);
}

fn create_socket(s: &SocketAddr, path: &String, hostname: String) -> String {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject.to_vec(),
            ta.subject_public_key_info.to_vec(),
            ta.name_constraints.as_ref().map(|a| a.to_vec()),
        )
    }));

    //root_store.add(collectedroots);

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    // Allow using SSLKEYLOGFILE.

    let server_name = hostname.as_str().try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();

    println!("{}", &s.ip());

    let mut socket = net::TcpStream::connect(s).unwrap();

    let sendt = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: OCaml\r\nConnection: close\r\n\r\n",
        path, hostname
    )
    .to_string();

    println!("{}", &sendt);

    //socket.write(&sendt.as_bytes()).unwrap();

    let mut tls = rustls::Stream::new(&mut conn, &mut socket);
    tls.write_all(&sendt.as_bytes()).unwrap();

    let mut plaintext = String::new();
    tls.read_to_string(&mut plaintext).unwrap();

    println!(
        "{}",
        String::from(plaintext.split("\r\n\r\n").last().unwrap())
    );

    return String::from(plaintext.split("\r\n\r\n").last().unwrap());
}
