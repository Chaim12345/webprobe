//! Headless proxy process for load measurement (perf lane, 2026-11-22).
//!
//! Boots the engine's proxy listener on a fresh in-memory project, prints
//! `READY <port>` once the listener accepts connections, then idles until
//! killed. The harness in qa/perf-load drives traffic through it; no UI, no
//! MCP, no disk project.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use webprobe_core::net::{start_proxy, Shared};

fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(18080);
    let shared = Shared::new();
    shared.proxy_port.store(port, Ordering::SeqCst);
    start_proxy(Arc::clone(&shared));
    for _ in 0..500 {
        if shared.listener_running.load(Ordering::SeqCst) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !shared.listener_running.load(Ordering::SeqCst) {
        eprintln!("listener failed to start on 127.0.0.1:{port}");
        std::process::exit(1);
    }
    println!("READY {port}");
    // Idle until the harness kills the process.
    loop {
        std::thread::park();
    }
}
