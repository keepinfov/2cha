//! goreality runtime test: drives a real REALITY handshake through the FFI —
//! server (gor_server_new + gor_server_handshake, borrowing a local TLS Dest) and
//! client (gor_client_handshake, ported uTLS auth) — then passes application bytes
//! both ways through the decrypted socketpair streams. Proves the tunnel works,
//! not just that it links.

use std::ffi::CString;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::raw::c_char;
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;
use std::thread;

extern "C" {
    fn gor_x25519_keygen(out_priv: *mut u8, out_pub: *mut u8) -> i32;
    fn gor_test_start_tls_dest() -> i32;
    fn gor_server_new(
        private_key: *const u8,
        dest: *const c_char,
        server_names_csv: *const c_char,
        short_ids_csv: *const c_char,
        max_time_diff_ms: i64,
        err: *mut c_char,
        errlen: i32,
    ) -> i64;
    fn gor_server_handshake(
        server_handle: i64,
        tcp_fd: i32,
        out_fd: *mut i32,
        err: *mut c_char,
        errlen: i32,
    ) -> i64;
    fn gor_client_handshake(
        tcp_fd: i32,
        server_name: *const c_char,
        public_key: *const u8,
        short_id: *const u8,
        fingerprint: *const c_char,
        out_fd: *mut i32,
        err: *mut c_char,
        errlen: i32,
    ) -> i64;
    fn gor_close(handle: i64);
}

fn errstr(buf: &[c_char]) -> String {
    let bytes: Vec<u8> = buf.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn main() {
    // Server X25519 keypair (client uses the public half).
    let (mut priv_k, mut pub_k) = ([0u8; 32], [0u8; 32]);
    assert_eq!(unsafe { gor_x25519_keygen(priv_k.as_mut_ptr(), pub_k.as_mut_ptr()) }, 0);

    // Hermetic Dest the REALITY server borrows a certificate from.
    let dest_port = unsafe { gor_test_start_tls_dest() };
    assert!(dest_port > 0, "dest server failed to start");
    let dest = CString::new(format!("127.0.0.1:{dest_port}")).unwrap();

    let names = CString::new("example.com").unwrap();
    let short_hex = CString::new("0123456789abcdef").unwrap();
    let short_bytes: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

    let mut err = [0 as c_char; 256];
    let sh = unsafe {
        gor_server_new(priv_k.as_ptr(), dest.as_ptr(), names.as_ptr(), short_hex.as_ptr(), 0,
            err.as_mut_ptr(), 256)
    };
    assert!(sh >= 0, "gor_server_new failed: {}", errstr(&err));

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    // Server side: accept, run the REALITY server handshake, echo one message.
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let fd = tcp.into_raw_fd();
        let (mut out, mut e) = (0i32, [0 as c_char; 256]);
        let ch = unsafe { gor_server_handshake(sh, fd, &mut out, e.as_mut_ptr(), 256) };
        assert!(ch >= 0, "gor_server_handshake rc={ch}: {}", errstr(&e));
        let mut s = unsafe { UnixStream::from_raw_fd(out) };
        let mut buf = [0u8; 128];
        let n = s.read(&mut buf).unwrap();
        s.write_all(&buf[..n]).unwrap();
        ch
    });

    // Client side: connect, run the REALITY client handshake, round-trip a payload.
    let name = CString::new("example.com").unwrap();
    let fp = CString::new("chrome").unwrap();
    let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let fd = tcp.into_raw_fd();
    let (mut out, mut e) = (0i32, [0 as c_char; 256]);
    let ch = unsafe {
        gor_client_handshake(fd, name.as_ptr(), pub_k.as_ptr(), short_bytes.as_ptr(), fp.as_ptr(),
            &mut out, e.as_mut_ptr(), 256)
    };
    assert!(ch >= 0, "gor_client_handshake rc={ch}: {}", errstr(&e));

    let mut s = unsafe { UnixStream::from_raw_fd(out) };
    let msg = b"tunnel-payload-through-reality";
    s.write_all(msg).unwrap();
    let mut buf = vec![0u8; msg.len()];
    s.read_exact(&mut buf).unwrap();
    assert_eq!(&buf[..], &msg[..], "tunnel round-trip mismatch");

    let server_ch = server.join().unwrap();
    unsafe {
        gor_close(ch);
        gor_close(server_ch);
    }
    println!("goreality handshake OK: authenticated REALITY tunnel round-trip works");
}
