// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

/// A body without length information is bounded by the open-ended
/// timeout (ProjectDefaults.json connections.timeouts). (Moved from
/// net/types.rs with the traits that use it, L8 #38.)
pub const OPEN_ENDED_RESPONSE_TIMEOUT_MS: u64 = 10000;

pub trait ResponseRead: Read {
    /// The read timeout from now on (idle time allowed between reads).
    fn set_read_timeout_ms(&self, ms: u64) -> std::io::Result<()>;
    /// A body without length information is bounded by the open-ended
    /// timeout (ProjectDefaults.json connections.timeouts).
    fn set_open_ended_timeout(&self) -> std::io::Result<()> {
        self.set_read_timeout_ms(OPEN_ENDED_RESPONSE_TIMEOUT_MS)
    }
}

impl ResponseRead for TcpStream {
    fn set_read_timeout_ms(&self, ms: u64) -> std::io::Result<()> {
        self.set_read_timeout(Some(Duration::from_millis(ms)))
    }
}

impl ResponseRead for rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    fn set_read_timeout_ms(&self, ms: u64) -> std::io::Result<()> {
        self.get_ref()
            .set_read_timeout(Some(Duration::from_millis(ms)))
    }
}

pub trait ProxyIo: Read + Write {
    fn set_nonblocking_io(&self, nonblocking: bool) -> std::io::Result<()>;
    /// The peer closed the connection (checked without consuming data).
    fn peer_closed(&self) -> bool {
        false
    }
}

/// EOF or a hard error on a (non-blocking) socket, seen with a peek that
/// consumes nothing.
pub fn tcp_closed(s: &TcpStream) -> bool {
    let mut b = [0u8; 1];
    match s.peek(&mut b) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => !matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::Interrupted
                | std::io::ErrorKind::TimedOut
        ),
    }
}

impl ProxyIo for TcpStream {
    fn set_nonblocking_io(&self, nonblocking: bool) -> std::io::Result<()> {
        self.set_nonblocking(nonblocking)
    }
    fn peer_closed(&self) -> bool {
        tcp_closed(self)
    }
}

impl ProxyIo for rustls::StreamOwned<rustls::ServerConnection, TcpStream> {
    fn set_nonblocking_io(&self, nonblocking: bool) -> std::io::Result<()> {
        self.get_ref().set_nonblocking(nonblocking)
    }
    fn peer_closed(&self) -> bool {
        tcp_closed(self.get_ref())
    }
}

impl ProxyIo for rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    fn set_nonblocking_io(&self, nonblocking: bool) -> std::io::Result<()> {
        self.get_ref().set_nonblocking(nonblocking)
    }
    fn peer_closed(&self) -> bool {
        tcp_closed(self.get_ref())
    }
}
