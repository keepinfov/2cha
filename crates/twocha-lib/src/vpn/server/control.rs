//! # Control Socket
//!
//! Unix-socket IPC for runtime peer management. The server polls the
//! listener fd in its single-threaded event loop, so requests mutate
//! server state directly without locking.
//!
//! Protocol: one whitespace-separated request line per connection,
//! followed by a text response, then the server closes the stream.
//!
//! ```text
//! -> peer-add <base64-key> [name]
//! <- ok added <key>
//!
//! -> peer-remove <base64-key>
//! <- ok removed <key>
//!
//! -> peer-list
//! <- ok 2 peers
//! <- peer <base64-key> <name|-> online endpoint=1.2.3.4:5678 last_recv_secs=3
//! <- peer <base64-key> <name|-> offline
//! ```
//!
//! Errors are reported as `err <message>`.

use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use twocha_core::decode_public_key;
use twocha_protocol::{Result, VpnError};

/// Where the control socket may live, best location first.
/// Mirrors the pidfile strategy: /run for root, then the user runtime dir.
pub fn control_socket_candidates() -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from("/run/2cha-ctl.sock")];
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            v.push(PathBuf::from(dir).join("2cha-ctl.sock"));
        }
    }
    v.push(PathBuf::from("/tmp/2cha-ctl.sock"));
    v
}

/// Pick a bindable control socket path (first candidate with a writable parent)
fn control_socket_path() -> PathBuf {
    for candidate in control_socket_candidates() {
        if let Some(parent) = candidate.parent() {
            if parent.is_dir()
                && !parent
                    .metadata()
                    .map(|m| m.permissions().readonly())
                    .unwrap_or(true)
            {
                return candidate;
            }
        }
    }
    PathBuf::from("/tmp/2cha-ctl.sock")
}

/// Locate an existing control socket (for the CLI client side)
pub fn find_control_socket() -> Option<PathBuf> {
    control_socket_candidates().into_iter().find(|p| p.exists())
}

/// A parsed control request
#[derive(Debug, PartialEq, Eq)]
pub enum CtlRequest {
    PeerAdd { key: String, name: Option<String> },
    PeerRemove { key: String },
    PeerList,
}

/// Parse one request line
pub fn parse_request(line: &str) -> std::result::Result<CtlRequest, String> {
    let mut parts = line.split_whitespace();
    let cmd = parts.next().ok_or("empty request")?;
    match cmd {
        "peer-add" => {
            let key = parts.next().ok_or("peer-add requires a public key")?;
            decode_public_key(key).map_err(|e| e.to_string())?;
            let name = parts.next().map(str::to_string);
            if parts.next().is_some() {
                return Err("too many arguments".into());
            }
            Ok(CtlRequest::PeerAdd {
                key: key.to_string(),
                name,
            })
        }
        "peer-remove" => {
            let key = parts.next().ok_or("peer-remove requires a public key")?;
            decode_public_key(key).map_err(|e| e.to_string())?;
            if parts.next().is_some() {
                return Err("too many arguments".into());
            }
            Ok(CtlRequest::PeerRemove {
                key: key.to_string(),
            })
        }
        "peer-list" => Ok(CtlRequest::PeerList),
        other => Err(format!("unknown command '{}'", other)),
    }
}

/// Nonblocking control-socket listener, polled by the server event loop
pub struct ControlListener {
    listener: UnixListener,
    path: PathBuf,
}

impl ControlListener {
    /// Bind the control socket, replacing a stale one from a dead server
    pub fn bind() -> Result<Self> {
        let path = control_socket_path();
        if path.exists() {
            // A connectable socket means another server is alive
            if UnixStream::connect(&path).is_ok() {
                return Err(VpnError::Config(format!(
                    "control socket {} is in use (another server running?)",
                    path.display()
                )));
            }
            let _ = std::fs::remove_file(&path);
        }
        let listener = UnixListener::bind(&path)
            .map_err(|e| VpnError::Config(format!("cannot bind {}: {}", path.display(), e)))?;
        listener.set_nonblocking(true)?;

        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));

        log::info!("control socket: {}", path.display());
        Ok(ControlListener { listener, path })
    }

    pub fn fd(&self) -> RawFd {
        self.listener.as_raw_fd()
    }

    /// Accept pending connections and answer each with `respond`.
    /// Requests are tiny, so a short blocking read on the accepted
    /// stream is acceptable in the single-threaded loop.
    pub fn process(&self, mut respond: impl FnMut(CtlRequest) -> String) {
        loop {
            let stream = match self.listener.accept() {
                Ok((stream, _)) => stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    log::warn!("control socket accept failed: {}", e);
                    break;
                }
            };
            if let Err(e) = handle_stream(stream, &mut respond) {
                log::warn!("control request failed: {}", e);
            }
        }
    }
}

fn handle_stream(
    mut stream: UnixStream,
    respond: &mut impl FnMut(CtlRequest) -> String,
) -> std::io::Result<()> {
    use std::io::{BufRead, BufReader, Write};

    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;

    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line)?;

    let reply = match parse_request(line.trim()) {
        Ok(req) => respond(req),
        Err(e) => format!("err {}", e),
    };
    stream.write_all(reply.as_bytes())?;
    if !reply.ends_with('\n') {
        stream.write_all(b"\n")?;
    }
    Ok(())
}

impl Drop for ControlListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Send one request to a running server and return its raw response
pub fn send_request(socket: &Path, request: &str) -> Result<String> {
    use std::io::{Read, Write};

    let mut stream = UnixStream::connect(socket)
        .map_err(|e| VpnError::Config(format!("cannot connect to {}: {}", socket.display(), e)))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(request.as_bytes())?;
    stream.write_all(b"\n")?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";

    #[test]
    fn test_parse_request() {
        assert_eq!(
            parse_request(&format!("peer-add {} laptop", KEY)).unwrap(),
            CtlRequest::PeerAdd {
                key: KEY.into(),
                name: Some("laptop".into())
            }
        );
        assert_eq!(
            parse_request(&format!("peer-add {}", KEY)).unwrap(),
            CtlRequest::PeerAdd {
                key: KEY.into(),
                name: None
            }
        );
        assert_eq!(
            parse_request(&format!("peer-remove {}", KEY)).unwrap(),
            CtlRequest::PeerRemove { key: KEY.into() }
        );
        assert_eq!(parse_request("peer-list").unwrap(), CtlRequest::PeerList);

        assert!(parse_request("").is_err());
        assert!(parse_request("peer-add").is_err());
        assert!(parse_request("peer-add not-a-key").is_err());
        assert!(parse_request("bogus").is_err());
        assert!(parse_request(&format!("peer-add {} a b", KEY)).is_err());
    }

    #[test]
    fn test_listener_roundtrip() {
        // Use a private path to avoid clashing with a real server
        let path = std::env::temp_dir().join(format!("2cha-ctl-test-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let ctl = ControlListener {
            listener,
            path: path.clone(),
        };

        let handle = {
            let path = path.clone();
            std::thread::spawn(move || send_request(&path, "peer-list").unwrap())
        };

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut served = false;
        while std::time::Instant::now() < deadline && !served {
            ctl.process(|req| {
                assert_eq!(req, CtlRequest::PeerList);
                served = true;
                "ok 0 peers".to_string()
            });
            std::thread::sleep(Duration::from_millis(10));
        }

        let response = handle.join().unwrap();
        assert_eq!(response.trim(), "ok 0 peers");
        drop(ctl);
        assert!(!path.exists(), "socket removed on drop");
    }
}
