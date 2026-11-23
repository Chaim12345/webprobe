//! Local benchmark process. No public targets, extensions, OAST or scanner.
use std::{
    io::{self, Write},
    sync::atomic::Ordering,
};
use webprobe_core::net;
fn main() {
    let shared = net::Shared::new();
    shared.intercept_on.store(false, Ordering::SeqCst);
    let port = if std::env::args().any(|arg| arg == "--main") {
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        shared.proxy_port.store(port, Ordering::SeqCst);
        net::start_proxy(shared.clone());
        let start = std::time::Instant::now();
        while !shared.listener_running.load(Ordering::SeqCst) {
            assert!(start.elapsed().as_secs() < 5, "proxy start timed out");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        port
    } else {
        net::browser_listener(&shared).expect("local listener")
    };
    println!("{port}");
    io::stdout().flush().unwrap();
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
}
