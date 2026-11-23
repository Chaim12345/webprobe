//! Wait for listener readiness, not a fixed sleep after an empty accept queue.
//! The timeout bounds restart-flag latency while connections wake immediately.
use polling::{Event, Events, Poller};
use std::{io, net::TcpListener, time::Duration};

pub(super) struct Readiness<'a> {
    poller: Poller,
    listener: &'a TcpListener,
    events: Events,
}

impl<'a> Readiness<'a> {
    pub(super) fn new(listener: &'a TcpListener) -> io::Result<Self> {
        let poller = Poller::new()?;
        // SAFETY: the borrow keeps the listener alive for this registration.
        // Drop unregisters it; the poller is also destroyed before the borrow
        // can end, including when delete reports an OS error.
        unsafe {
            poller.add(listener, Event::readable(0))?;
        }
        Ok(Self {
            poller,
            listener,
            events: Events::new(),
        })
    }

    pub(super) fn wait(&mut self, timeout: Duration) -> io::Result<usize> {
        // One-shot readiness must be rearmed after every delivered event.
        // Recheck readiness in the OS, avoiding a lost connection between
        // accept(WouldBlock) and this registration update.
        self.poller.modify(self.listener, Event::readable(0))?;
        self.events.clear();
        match self.poller.wait(&mut self.events, Some(timeout)) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(0),
            result => result,
        }
    }
}

impl Drop for Readiness<'_> {
    fn drop(&mut self) {
        let _ = self.poller.delete(self.listener);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;

    #[test]
    fn idle_wait_times_out_and_can_rearm_for_later_clients() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut ready = Readiness::new(&listener).unwrap();
        assert_eq!(ready.wait(Duration::from_millis(2)).unwrap(), 0);
        for _ in 0..3 {
            let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            assert!(ready.wait(Duration::from_secs(2)).unwrap() > 0);
            let _accepted = listener.accept().unwrap();
            assert_eq!(ready.wait(Duration::from_millis(2)).unwrap(), 0);
        }
    }

    #[test]
    fn drop_unregisters_without_closing_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        {
            let _ready = Readiness::new(&listener).unwrap();
        }
        let mut ready = Readiness::new(&listener).unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        assert!(ready.wait(Duration::from_secs(2)).unwrap() > 0);
        listener.accept().unwrap();
    }
}
