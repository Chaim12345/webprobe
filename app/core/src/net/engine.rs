// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

use super::*;

/// The embedded browser's own listener. Burp's browser does not use the
/// user's proxy listener: it gets a private one on a random loopback port
/// (its process runs with --proxy-server=localhost:<random>), so it works
/// even when the configured port (8080) is taken by another tool and could
/// otherwise reach that tool instead. Traffic takes the same path as the main
/// listener (history, interception, scanner).
pub fn browser_listener(shared: &Arc<Shared>) -> Result<u16, NetError> {
    let p = shared.browser_port.load(Ordering::SeqCst);
    if p != 0 {
        return Ok(p);
    }
    let l = TcpListener::bind("127.0.0.1:0")
        .map_err(|source| NetError::BrowserListenerBind { source })?;
    let port = l
        .local_addr()
        .map_err(|source| NetError::BrowserListenerAddr { source })?
        .port();
    if let Err(existing) =
        shared
            .browser_port
            .compare_exchange(0, port, Ordering::SeqCst, Ordering::SeqCst)
    {
        return Ok(existing);
    }
    let sh = shared.clone();
    crate::util::spawn_contained("net", move || {
        for stream in l.incoming().flatten() {
            let sh = sh.clone();
            spawn_connection(sh, stream);
        }
    });
    shared.log(&format!("Browser listener started on 127.0.0.1:{port}"));
    Ok(port)
}

pub fn start_proxy(shared: Arc<Shared>) {
    start_extra_listeners(shared.clone());
    crate::util::spawn_contained("net", move || loop {
        shared.listener_restart.store(false, Ordering::SeqCst);
        let addr = format!("127.0.0.1:{}", shared.proxy_port.load(Ordering::SeqCst));
        let listener = TcpListener::bind(&addr);
        match listener {
            Ok(l) => {
                shared.listener_running.store(true, Ordering::SeqCst);
                shared.log(&format!(
                    "Proxy listener started on {addr}, intercept is {}",
                    {
                        if shared.intercept_on.load(Ordering::SeqCst) {
                            "on"
                        } else {
                            "off"
                        }
                    }
                ));
                // Non-blocking accept, so a restart (port change, restored
                // project) takes effect at once; a blocking accept only saw
                // the flag after the next client connected.
                let _ = l.set_nonblocking(true);
                loop {
                    if shared.listener_restart.load(Ordering::SeqCst) {
                        break;
                    }
                    match l.accept() {
                        Ok((stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let sh = shared.clone();
                            spawn_connection(sh, stream);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(50))
                        }
                        Err(_) => continue,
                    }
                }
                shared.listener_running.store(false, Ordering::SeqCst);
                shared.log("Proxy listener stopped for restart");
                // fall through and rebind below (flag cleared at loop top via check)
            }
            Err(e) => {
                shared.listener_running.store(false, Ordering::SeqCst);
                shared.log(&format!(
                    "Proxy listener bind failed on {addr}: {e}; waiting for restart command"
                ));
                // Burp alerts on this; a silent failure leaves the user
                // browsing through nothing.
                crate::notice::toast(
                    crate::notice::Level::Error,
                    format!("Failed to start proxy service on {addr}. Check whether another service is already using this port. ({e})"),
                );
                // wait for a restart command instead of exiting
                while !shared.listener_restart.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        }
        // Short delay so the old socket closes before rebinding on the next pass;
        // the loop top clears the restart flag.
        std::thread::sleep(Duration::from_millis(250));
    });
}

/// Replace the extra listener set. Validates entries (non-empty bind, port
/// 1..=65535, no duplicate bind:port). Returns an error message on rejection.
pub fn set_listeners(shared: &Arc<Shared>, specs: Vec<ListenerSpec>) -> Result<(), NetError> {
    let mut seen = std::collections::HashSet::new();
    for s in &specs {
        if s.bind.trim().is_empty() {
            return Err(NetError::EmptyBind);
        }
        if s.port == 0 {
            return Err(NetError::InvalidPort);
        }
        if !seen.insert((s.bind.clone(), s.port)) {
            return Err(NetError::DuplicateListener {
                bind: s.bind.clone(),
                port: s.port,
            });
        }
    }
    *shared.listeners.lock().unwrap() = specs
        .into_iter()
        .map(|s| Arc::new(ListenerState::new(s)))
        .collect();
    // Bump the generation so the supervisor spawns workers for the new set and
    // the old workers exit. History and in-flight connections are untouched.
    shared.listener_generation.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

/// The extra listeners' configuration, for editing and re-applying with
/// `set_listeners`.
pub fn listener_specs(shared: &Arc<Shared>) -> Vec<ListenerSpec> {
    shared
        .listeners
        .lock()
        .unwrap()
        .iter()
        .map(|l| ListenerSpec {
            http2: l.http2.load(Ordering::SeqCst),
            ..l.spec.clone()
        })
        .collect()
}

/// "Support HTTP/2" of the listener on `port`: an extra listener's own
/// option, else the primary listener's (also the embedded browser's).
pub fn listener_supports_http2(shared: &Shared, port: Option<u16>) -> bool {
    let extra = port.and_then(|p| {
        shared
            .listeners
            .lock()
            .unwrap()
            .iter()
            .find(|l| l.spec.port == p)
            .map(|l| l.http2.load(Ordering::SeqCst))
    });
    extra.unwrap_or_else(|| shared.listener_http2.load(Ordering::SeqCst))
}

/// Set "Support HTTP/2" of the listener shown at `row` of the listener
/// table (0 = primary, 1.. = extra listeners).
pub fn set_listener_http2(shared: &Shared, row: usize, on: bool) {
    if row == 0 {
        shared.listener_http2.store(on, Ordering::SeqCst);
    } else if let Some(l) = shared.listeners.lock().unwrap().get(row - 1) {
        l.http2.store(on, Ordering::SeqCst);
    }
}

/// Listener status for the UI: primary listener plus extras, each as
/// (address, running, last error).
pub fn listener_status(shared: &Arc<Shared>) -> Vec<(String, bool, Option<String>)> {
    let mut out = vec![(
        format!("127.0.0.1:{}", shared.proxy_port.load(Ordering::SeqCst)),
        shared.listener_running.load(Ordering::SeqCst),
        None,
    )];
    for l in shared.listeners.lock().unwrap().iter() {
        out.push((
            format!("{}:{}", l.spec.bind, l.spec.port),
            l.running.load(Ordering::SeqCst),
            l.error.lock().unwrap().clone(),
        ));
    }
    out
}

pub fn listener_worker(shared: Arc<Shared>, state: Arc<ListenerState>, gen: u64) {
    loop {
        if shared.listener_generation.load(Ordering::SeqCst) != gen {
            break;
        }
        let addr = format!("{}:{}", state.spec.bind, state.spec.port);
        match TcpListener::bind(&addr) {
            Ok(l) => {
                let _ = l.set_nonblocking(true);
                state.running.store(true, Ordering::SeqCst);
                *state.error.lock().unwrap() = None;
                shared.log(&format!("Proxy listener started on {addr}"));
                loop {
                    if shared.listener_generation.load(Ordering::SeqCst) != gen {
                        break;
                    }
                    match l.accept() {
                        Ok((stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let _ = stream
                                .set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));
                            let sh = shared.clone();
                            spawn_connection(sh, stream);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(100));
                            continue;
                        }
                        Err(_) => continue,
                    }
                }
                state.running.store(false, Ordering::SeqCst);
            }
            Err(e) => {
                state.running.store(false, Ordering::SeqCst);
                *state.error.lock().unwrap() = Some(e.to_string());
                shared.log(&format!("Proxy listener bind failed on {addr}: {e}"));
                crate::notice::toast(
                    crate::notice::Level::Error,
                    format!("Listener {addr} failed: {e}"),
                );
                // Wait for a configuration change before retrying.
                while shared.listener_generation.load(Ordering::SeqCst) == gen {
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        }
    }
    state.running.store(false, Ordering::SeqCst);
}

/// Supervisor for the extra listeners: spawns workers for the current set and
/// lets them exit when the generation changes.
pub fn start_extra_listeners(shared: Arc<Shared>) {
    crate::util::spawn_contained("net", move || {
        let mut spawned_gen = u64::MAX;
        loop {
            let gen = shared.listener_generation.load(Ordering::SeqCst);
            if gen != spawned_gen {
                spawned_gen = gen;
                let specs: Vec<Arc<ListenerState>> = shared.listeners.lock().unwrap().clone();
                for st in specs {
                    let sh = shared.clone();
                    crate::util::spawn_contained("net", move || listener_worker(sh, st, gen));
                }
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    });
}

/// Most client connections handled at once, across all listeners. Each one
/// is a thread; beyond this a flood (or a runaway client) would exhaust
/// threads and memory, so further connections get a 503 and are closed.
pub const MAX_CONNECTIONS: usize = 1024;

/// Handle a client connection on its own thread, within [`MAX_CONNECTIONS`].
pub fn spawn_connection(shared: Arc<Shared>, mut stream: TcpStream) {
    let admitted = stream_limit_check(&shared, &mut stream, MAX_CONNECTIONS);
    spawn_connection_limited(shared, admitted, stream);
}

/// Reserve a connection slot; on refusal answer 503 and say so.
pub fn stream_limit_check(shared: &Shared, stream: &mut TcpStream, limit: usize) -> bool {
    let taken = shared.active_connections.fetch_add(1, Ordering::SeqCst);
    if taken >= limit {
        shared.active_connections.fetch_sub(1, Ordering::SeqCst);
        let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
        let _ = stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: 39\r\n\r\nWebProbe: too many connections at once");
        return false;
    }
    true
}

pub fn spawn_connection_limited(shared: Arc<Shared>, admitted: bool, stream: TcpStream) {
    if !admitted {
        shared.log(&format!(
            "Refused a connection: {MAX_CONNECTIONS} already open"
        ));
        return;
    }
    struct Slot(Arc<Shared>);
    impl Drop for Slot {
        fn drop(&mut self) {
            self.0.active_connections.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let counter = shared.clone();
    let spawned = std::thread::Builder::new()
        .name("proxy-conn".into())
        .spawn(move || {
            let _slot = Slot(shared.clone());
            handle_conn(shared, stream);
        });
    if spawned.is_err() {
        // The closure (and its slot) was never run.
        counter.active_connections.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The upstream target for a request on this connection: the listener's
/// redirect when one is set, otherwise the host the request names.
/// The listener port of this thread's connection (history "Listener port"),
/// the main listener when the thread is not serving one.
pub fn listener_port(shared: &Shared) -> u16 {
    LISTENER_PORT
        .with(|p| p.get())
        .unwrap_or_else(|| shared.proxy_port.load(Ordering::SeqCst))
}

pub fn upstream_target(shared: &Shared, host: &str, port: u16) -> (String, u16) {
    LISTENER_PORT
        .with(|p| p.get())
        .and_then(|lp| shared.listener_redirects.lock().unwrap().get(&lp).cloned())
        .unwrap_or_else(|| (host.to_string(), port))
}

pub fn handle_conn(shared: Arc<Shared>, mut stream: TcpStream) {
    LISTENER_PORT.with(|p| p.set(stream.local_addr().ok().map(|a| a.port())));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));
    let _ = stream.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));
    let req = match read_request(&mut stream) {
        Ok(r) if !r.is_empty() => r,
        _ => return,
    };
    let parts = util::parse_http(&req);

    if parts.method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(parts.path.trim(), 443);
        handle_connect(shared, stream, host, port);
        return;
    }

    let (req, req_state) = intercept_request(&shared, req, 80);
    let Some(req) = req else { return };
    let is_ws = util::get_header(&parts.headers, "Upgrade")
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    if is_ws {
        handle_websocket(shared, stream, req);
        return;
    }
    upstream_and_deliver(&shared, &mut stream, req, 80, false, req_state);
}

/// Copy bytes both ways until either direction closes (SSL pass-through tunnel).
pub fn relay_tunnel(client: &TcpStream, upstream: &mut TcpStream) {
    let up_reader = upstream.try_clone();
    let mut client_reader = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let t = crate::util::spawn_contained("net", move || {
        if let Ok(mut up) = up_reader {
            let _ = std::io::copy(&mut up, &mut client_reader);
        }
        let _ = client_reader.shutdown(std::net::Shutdown::Write);
    });
    let mut up_writer = match upstream.try_clone() {
        Ok(u) => u,
        Err(_) => return,
    };
    let mut client_reader = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let _ = std::io::copy(&mut client_reader, &mut up_writer);
    let _ = up_writer.shutdown(std::net::Shutdown::Write);
    let _ = t.join();
    let _ = upstream.shutdown(std::net::Shutdown::Both);
    let _ = client.shutdown(std::net::Shutdown::Both);
}

pub fn handle_connect(shared: Arc<Shared>, mut stream: TcpStream, host: String, port: u16) {
    // SSL pass-through: matching hosts get a byte-relay tunnel, not MITM.
    let bypassed = shared
        .tls_bypass
        .lock()
        .unwrap()
        .iter()
        .any(|pattern| host_matches(pattern, &host));
    if bypassed {
        let config = shared.upstream_for(&host);
        let mut upstream = match crate::upstream::connect_target(&config, &host, port) {
            Ok(s) => s,
            Err(e) => {
                shared.log(&format!(
                    "pass-through connect to {host}:{port} failed: {e}"
                ));
                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
                return;
            }
        };
        if stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .is_err()
        {
            return;
        }
        shared.log(&format!("TLS pass-through tunnel to {host}:{port}"));
        relay_tunnel(&stream, &mut upstream);
        return;
    }
    let config = match shared.mitm.listener_config(
        &host,
        listener_supports_http2(&shared, LISTENER_PORT.with(|p| p.get())),
    ) {
        Ok(config) => config,
        Err(e) => {
            shared.log(&format!("HTTPS certificate for {host} failed: {e}"));
            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
            return;
        }
    };
    if stream
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .is_err()
    {
        return;
    }
    let conn = match rustls::ServerConnection::new(config) {
        Ok(conn) => conn,
        Err(e) => {
            shared.log(&format!("HTTPS server setup for {host}:{port} failed: {e}"));
            return;
        }
    };
    let mut tls = rustls::StreamOwned::new(conn, stream);
    // The client chose HTTP/2 by ALPN: serve the connection's streams.
    let _ = tls.conn.complete_io(&mut tls.sock);
    if tls.conn.alpn_protocol() == Some(b"h2".as_slice()) {
        serve_h2_client(shared, tls, host, port);
        return;
    }
    let req = match read_request(&mut tls) {
        Ok(req) if !req.is_empty() => req,
        Ok(_) => return,
        Err(e) => {
            shared.log(&format!(
                "HTTPS client handshake/request for {host}:{port} failed: {e}"
            ));
            return;
        }
    };
    let (req, req_state) = intercept_request(&shared, req, 443);
    let Some(req) = req else { return };
    let ws_parts = util::parse_http(&req);
    let is_ws = util::get_header(&ws_parts.headers, "Upgrade")
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    if is_ws {
        handle_tls_websocket(shared, tls, req, host, port);
        return;
    }
    upstream_and_deliver(&shared, &mut tls, req, 443, true, req_state);
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

/// An HTTPS client that negotiated h2: every stream runs the proxy's
/// per-request pipeline (intercept, match and replace, extensions,
/// history, streaming) on its own thread; `h2_server` frames the results.
pub fn serve_h2_client(
    shared: Arc<Shared>,
    mut tls: rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
    host: String,
    port: u16,
) {
    if tls.get_ref().set_nonblocking(true).is_err() {
        return;
    }
    shared.log(&format!("HTTP/2 client connection for {host}:{port}"));
    let listener = LISTENER_PORT.with(|p| p.get());
    let pipeline_shared = Arc::clone(&shared);
    let handler: crate::h2_server::Handler = Arc::new(
        move |req: Vec<u8>, mut out: crate::h2_server::ResponseWriter| {
            LISTENER_PORT.with(|p| p.set(listener));
            let (req, state) = intercept_request(&pipeline_shared, req, 443);
            let Some(req) = req else { return };
            upstream_and_deliver(&pipeline_shared, &mut out, req, 443, true, state);
        },
    );
    crate::h2_server::serve(&mut tls, handler);
    tls.conn.send_close_notify();
    let _ = tls.get_ref().set_nonblocking(false);
    let _ = tls.flush();
}

/// What Forward sends for a held message: the original bytes when the text
/// is unchanged from what was shown (a binary body survives exactly, its
/// lossy text view would replace bytes with U+FFFD), else the edited text.
/// Returns the bytes and whether the user changed the message.
pub fn forwarded(original: Vec<u8>, shown: &str, edited: String) -> (Vec<u8>, bool) {
    if edited == shown {
        (original, false)
    } else {
        (edited.into_bytes(), true)
    }
}

/// The Proxy's response sink: a streaming response is written to the
/// client as it arrives, and kept for history in a bounded [`Tee`] when
/// "Store streaming responses" is on.
///
/// [`Tee`]: crate::streaming::Tee
pub struct ProxySink<'a, W: Write> {
    client: &'a mut W,
    url: String,
    settings: crate::streaming::StreamSettings,
    head: Option<Vec<u8>>,
    tee: Option<crate::streaming::Tee>,
    wired: usize,
    complete: bool,
    client_gone: bool,
}

/// A streamed response, for history.
pub struct Streamed {
    head: Vec<u8>,
    message: crate::body::Body,
    note: String,
    stored: bool,
}

impl<'a, W: Write> ProxySink<'a, W> {
    fn new(shared: &Shared, client: &'a mut W, url: &str) -> Self {
        ProxySink {
            client,
            url: url.to_string(),
            settings: shared.streaming.lock().unwrap().clone(),
            head: None,
            tee: None,
            wired: 0,
            complete: false,
            client_gone: false,
        }
    }

    /// The streamed response, when this one was streaming.
    fn finish(self) -> Option<Streamed> {
        let head = self.head?;
        let stored = self.tee.is_some();
        let (message, cut) = match self.tee {
            Some(t) => {
                let cut = t.truncated();
                (t.finish(), cut)
            }
            None => (
                crate::body::Body::from(crate::streaming::unframed_head(&head)),
                false,
            ),
        };
        let mut note = String::from("Streaming response");
        if !stored {
            note.push_str(" (not stored)");
        } else if cut {
            note.push_str(" (stored copy cut at the size limit)");
        }
        if self.client_gone {
            note.push_str("; client closed it");
        } else if !self.complete {
            note.push_str("; ended early");
        }
        Some(Streamed {
            head,
            message,
            note,
            stored,
        })
    }
}

impl<W: Write> crate::streaming::ResponseSink for ProxySink<'_, W> {
    fn head(&mut self, head: &[u8]) -> crate::streaming::BodyMode {
        if crate::streaming::decide(&self.url, head, &self.settings)
            == crate::streaming::Decision::Buffered
        {
            return crate::streaming::BodyMode::Buffer;
        }
        self.head = Some(head.to_vec());
        if self.settings.store {
            let mut tee = crate::streaming::Tee::new();
            tee.push(&if self.settings.strip_chunked {
                crate::streaming::unframed_head(head)
            } else {
                head.to_vec()
            });
            self.tee = Some(tee);
        }
        crate::streaming::BodyMode::Stream
    }

    fn wire(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.wired += 1;
        // Without stripping, the stored copy is the body as it was framed.
        if !self.settings.strip_chunked && self.wired > 1 {
            if let Some(t) = self.tee.as_mut() {
                t.push(bytes);
            }
        }
        let sent = self
            .client
            .write_all(bytes)
            .and_then(|()| self.client.flush());
        self.client_gone = sent.is_err();
        sent
    }

    fn payload(&mut self, bytes: &[u8]) {
        if self.settings.strip_chunked {
            if let Some(t) = self.tee.as_mut() {
                t.push(bytes);
            }
        }
    }

    fn end(&mut self, complete: bool) {
        self.complete = complete;
    }
}

/// A streaming response passes through unmodified, as in Burp: say once
/// per host and reason that response interception, response
/// match-and-replace or extension response handlers did not apply to it.
pub fn report_stream_skips(shared: &Shared, host: &str, url: &str, head: &[u8], st: ReqState) {
    let mut reasons: Vec<&'static str> = Vec::new();
    if shared.intercept_on.load(Ordering::SeqCst) {
        let p = util::parse_http(head);
        let ct = util::get_header(&p.headers, "Content-Type").unwrap_or_default();
        let status = p.status.split_whitespace().next().unwrap_or("").to_string();
        let rules = shared.response_rules.lock().unwrap().clone();
        if rules.matches(&ct, &status, st, rules.in_scope && in_scope(shared, url)) {
            reasons.push("response interception");
        }
    }
    if shared.mr_response.lock().unwrap().iter().any(|r| r.enabled) {
        reasons.push("response match and replace rules");
    }
    if !shared.ext_host.lock().unwrap().active().is_empty() {
        reasons.push("extension response handlers");
    }
    for reason in reasons {
        if shared
            .stream_skips
            .lock()
            .unwrap()
            .insert((host.to_string(), reason))
        {
            shared.log(&format!("Streaming responses from {host} pass straight through: {reason} did not apply to them"));
        }
    }
}

pub fn upstream_and_deliver<S: ProxyIo>(
    shared: &Shared,
    stream: &mut S,
    req: Vec<u8>,
    default_port: u16,
    use_tls: bool,
    req_state: ReqState,
) {
    let was_edited = req_state.edited;
    let parts = util::parse_http(&req);
    let (host, port) = host_of(&parts, default_port);

    // Burp's "Show response in browser" / "Request in browser" URLs
    // (http://burpsuite/show/N, /repeat/N): WebProbe serves the same under
    // http://webprobe.
    if host.eq_ignore_ascii_case("webprobe") {
        if let Some(resp) = browser_item_response(shared, &path_of(&parts)) {
            let _ = stream.write_all(&resp);
            let _ = stream.flush();
            shared.log(&format!("Served {} for the browser", path_of(&parts)));
            return;
        }
    }
    // Burp answers `http://burpsuite` itself: the browser must already be
    // proxying through the listener, and the page it returns is where the CA
    // certificate is downloaded. WebProbe does the same at http://webprobe.
    if let Some(resp) = crate::setup_page::local_response(
        &host,
        &path_of(&parts),
        shared.proxy_port.load(Ordering::SeqCst),
        shared.mitm.ca_pem(),
        &shared.mitm.ca_der(),
    ) {
        let _ = stream.write_all(&resp);
        let _ = stream.flush();
        let status = String::from_utf8_lossy(&resp)
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        // Not recorded: Burp keeps http://burpsuite out of Proxy history and
        // the scanner (live 52685: history stays empty, live audit 0 issues).
        shared.log(&format!(
            "Served the local setup page for {host} -> {status}"
        ));
        return;
    }
    // Session rules run before match-and-replace, matching Burp's handling chain.
    let req_session = apply_session_rules(shared, &req, default_port);
    let mut req_out = crate::rules::apply_rules(&req_session, &shared.mr_request.lock().unwrap());
    // Extension hooks run after the built-in chain (session rules, M&R);
    // a Drop verdict closes the client connection without a response.
    let mut ann = webprobe_support::ext::Annotations::default();
    if !shared.ext_handle_request(
        &webprobe_support::ext::HttpService::new(&host, port, use_tls),
        &parts.method,
        &path_of(&parts),
        &mut req_out,
        &mut ann,
    ) {
        shared.log("Request dropped by an extension hook");
        return;
    }
    let (up_host, up_port) = upstream_target(shared, &host, port);
    let url = history_host(&HistEntry {
        host: host.clone(),
        port,
        https: use_tls,
        ..Default::default()
    }) + &path_of(&parts);
    // A streaming response (Burp's rule, `streaming::decide`) goes to the
    // client as it arrives, straight from the response reader.
    let mut sink = ProxySink::new(shared, stream, &url);
    let up = if use_tls {
        send_tls_raw_with(shared, &up_host, up_port, &req_out, Some(&mut sink))
    } else {
        send_raw_with(shared, &up_host, up_port, &req_out, Some(&mut sink))
    };
    if let Some(done) = sink.finish() {
        report_stream_skips(shared, &host, &url, &done.head, req_state);
        let status = util::parse_http(&done.head)
            .first
            .split_whitespace()
            .nth(1)
            .unwrap_or("")
            .to_string();
        record_entry(
            shared,
            &req_out,
            Some(done.message),
            Some(done.note),
            default_port,
            use_tls,
            listener_port(shared),
            was_edited,
            &ann,
            done.stored,
        );
        shared.log(&format!(
            "Streamed {} {host}:{port}{} -> {status}",
            parts.method,
            path_of(&parts)
        ));
        return;
    }
    match up.resp {
        Some(resp) => {
            let mut resp = crate::rules::apply_rules(&resp, &shared.mr_response.lock().unwrap());
            if !shared.ext_handle_response(
                &webprobe_support::ext::HttpService::new(&host, port, use_tls),
                &parts.method,
                &path_of(&parts),
                &req_out,
                &mut resp,
                &mut ann,
            ) {
                shared.log("Response dropped by an extension hook");
                return;
            }
            let Some(resp) =
                intercept_response(shared, resp, &host, port, use_tls, &url, req_state)
            else {
                return;
            };
            let status = util::parse_http(&resp)
                .first
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .to_string();
            let _ = stream.write_all(&resp);
            let _ = stream.flush();
            record(
                shared,
                &req_out,
                Some(resp),
                None,
                default_port,
                use_tls,
                listener_port(shared),
                was_edited,
                &ann,
            );
            shared.log(&format!(
                "Proxied {} {host}:{port}{} -> {}{}",
                parts.method,
                path_of(&parts),
                status,
                if use_tls {
                    " via HTTPS interception"
                } else {
                    ""
                }
            ));
        }
        None => {
            let err = up.error.clone().unwrap_or_default();
            let msg = format!("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nWebProbe: upstream failed: {err}");
            let _ = stream.write_all(msg.as_bytes());
            let note = up.error.clone().unwrap_or_else(|| "failed".into());
            record(
                shared,
                &req_out,
                None,
                Some(note),
                default_port,
                use_tls,
                listener_port(shared),
                was_edited,
                &ann,
            );
            shared.log(&format!("Proxy error for {host}:{port}: {err}"));
        }
    }
}
