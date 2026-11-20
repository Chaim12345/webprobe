//! Operational diagnostics are separate from captured traffic (the Logger).
//!
//! Only static labels, counts and flags can be attached. Request/response data,
//! URLs, headers, exception strings and extension output must never enter this
//! channel. Static event codes remain searchable even when wording changes.

/// Safe diagnostic context. Dynamic text is deliberately not supported.
#[derive(Debug, Clone, Copy)]
pub enum Field {
    Count(&'static str, u64),
    Flag(&'static str, bool),
    Label(&'static str, &'static str),
}

#[derive(Debug, Clone, Copy)]
pub enum Level {
    Info,
    Warn,
    Error,
}

/// Emit a structured event. The application owns subscriber installation.
pub fn emit(level: Level, code: &'static str, message: &'static str, fields: &[Field]) {
    match level {
        Level::Info => {
            tracing::info!(target: "webprobe", event_code = code, context = ?fields, message)
        }
        Level::Warn => {
            tracing::warn!(target: "webprobe", event_code = code, context = ?fields, message)
        }
        Level::Error => {
            tracing::error!(target: "webprobe", event_code = code, context = ?fields, message)
        }
    }
}

/// Human-readable summary for the existing bounded UI event list.
pub fn summary(code: &'static str, message: &'static str, fields: &[Field]) -> String {
    let mut out = format!("{code}: {message}");
    for field in fields {
        use std::fmt::Write;
        match field {
            Field::Count(key, value) => {
                let _ = write!(out, " {key}={value}");
            }
            Field::Flag(key, value) => {
                let _ = write!(out, " {key}={value}");
            }
            Field::Label(key, value) => {
                let _ = write!(out, " {key}={value}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_keeps_stable_code_and_safe_context() {
        assert_eq!(
            summary(
                "scan.finished",
                "Scan finished",
                &[
                    Field::Count("issues", 4),
                    Field::Flag("cancelled", false),
                    Field::Label("stage", "active"),
                ]
            ),
            "scan.finished: Scan finished issues=4 cancelled=false stage=active"
        );
    }

    #[test]
    fn empty_context_has_no_debug_or_trailing_noise() {
        assert_eq!(
            summary("scan.failed", "Scan failed", &[]),
            "scan.failed: Scan failed"
        );
    }
}

#[cfg(test)]
mod subscriber_tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn subscriber_receives_codes_levels_and_context_not_traffic() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let sink = Capture(bytes.clone());
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            emit(
                Level::Info,
                "scan.started",
                "Active scan started",
                &[Field::Count("points", 3)],
            );
            emit(Level::Warn, "scan.busy", "Scan already running", &[]);
            emit(Level::Error, "scan.failed", "Scan failed", &[]);
        });
        let out = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        for expected in [
            "INFO",
            "WARN",
            "ERROR",
            "webprobe",
            "event_code=",
            "scan.started",
            "points",
            "3",
            "scan.busy",
            "scan.failed",
        ] {
            assert!(out.contains(expected), "missing {expected} in {out}");
        }
        assert_eq!(out.lines().count(), 3);
    }
}
