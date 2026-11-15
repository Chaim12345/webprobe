//! Proxy HTTP history filter (B-01).
//!
//! Burp's history filter bar has a text/regex box plus method, status code, MIME
//! type and "in scope only" controls (shipped docs:
//! `resources/Documentation/burp/documentation/desktop/tools/proxy/http-history/filters.html`).
//! Everything here is derived from the recorded exchange: the MIME type comes
//! from the response's Content-Type, and "in scope" is the shared scope list the
//! rest of the app already uses, so the filter cannot disagree with Target.

use eframe::egui::{self, RichText, Ui};

use crate::net::{self, HistEntry};
use crate::theme::{self, c};

#[derive(Clone, Default)]
pub struct HistoryFilter {
    pub text: String,
    pub regex: bool,
    pub method: String,
    pub status: String,
    pub mime: String,
    pub in_scope_only: bool,
}

impl HistoryFilter {
    pub fn is_active(&self) -> bool {
        !self.text.trim().is_empty()
            || !self.method.trim().is_empty()
            || !self.status.trim().is_empty()
            || !self.mime.trim().is_empty()
            || self.in_scope_only
    }

    /// The Content-Type of the recorded response, reduced to `type/subtype`
    /// (so "json" matches `application/json; charset=utf-8`).
    pub fn mime_of(entry: &HistEntry) -> String {
        let Some(resp) = &entry.resp_raw else { return String::new() };
        let parts = crate::util::parse_http(resp);
        let value = crate::util::get_header(&parts.headers, "Content-Type").unwrap_or_default();
        let essence = value.split(';').next().unwrap_or("").trim().to_lowercase();
        essence
    }

    pub fn matches(&self, entry: &HistEntry, shared: &std::sync::Arc<net::Shared>) -> bool {
        if !self.method.trim().is_empty()
            && !entry.method.eq_ignore_ascii_case(self.method.trim())
        {
            return false;
        }
        if !self.status.trim().is_empty()
            && !entry.status.trim().starts_with(self.status.trim())
        {
            return false;
        }
        if !self.mime.trim().is_empty() {
            let needle = self.mime.trim().to_lowercase();
            let mime = Self::mime_of(entry);
            let hit = if self.regex {
                regex::RegexBuilder::new(&self.mime.trim())
                    .case_insensitive(true)
                    .build()
                    .map(|re| re.is_match(&mime))
                    .unwrap_or(false)
            } else {
                mime.contains(&needle)
            };
            if !hit {
                return false;
            }
        }
        if self.in_scope_only {
            let url = format!("{}://{}{}", if entry.https { "https" } else { "http" }, entry.host, entry.path);
            if !net::in_scope(shared, &url) {
                return false;
            }
        }
        let needle = self.text.trim();
        if needle.is_empty() {
            return true;
        }
        let haystack = format!(
            "{} {} {} {} {} {}",
            entry.id, entry.method, entry.host, entry.port, entry.path, entry.status
        );
        if self.regex {
            // A half-typed expression must not empty the table: an invalid
            // pattern matches nothing and says so instead.
            match regex::RegexBuilder::new(needle).case_insensitive(true).build() {
                Ok(re) => re.is_match(&haystack),
                Err(_) => false,
            }
        } else {
            haystack.to_lowercase().contains(&needle.to_lowercase())
        }
    }

    /// The filter bar. Returns true when the text is a broken regular
    /// expression, so the caller can say so.
    pub fn ui(&mut self, ui: &mut Ui, shared: &std::sync::Arc<net::Shared>, shown: usize, total: usize) -> bool {
        let mut broken = false;
        // The scope list is what the in-scope checkbox reads, so say how many
        // rules it would apply rather than leaving the box unexplained.
        let scope_rules = shared
            .scope
            .lock()
            .map(|rules| rules.iter().filter(|r| r.enabled).count())
            .unwrap_or(0);
        ui.horizontal(|ui| {
            ui.add_sized(
                [44.0, 0.0],
                egui::Label::new(RichText::new("Filter:").size(12.0).color(c(theme::MONO6))),
            );
            let edit = egui::TextEdit::singleline(&mut self.text)
                .desired_width(240.0)
                .font(egui::TextStyle::Monospace)
                .hint_text(if self.regex { "regex…" } else { "any text…" });
            let resp = ui.add(edit).on_hover_text(
                "Matches the entry id, method, host, port, path and status",
            );
            if self.regex && !self.text.trim().is_empty() {
                broken = regex::Regex::new(self.text.trim()).is_err();
            }
            if ui.checkbox(&mut self.regex, "regex").changed() && resp.has_focus() {
                resp.request_focus();
            }
            if ui
                .checkbox(&mut self.in_scope_only, "in scope")
                .on_hover_text("Only requests whose URL matches the Target scope list")
                .changed()
            {}
            if self.is_active() && ui.small_button("Clear").clicked() {
                *self = Self { regex: self.regex, ..Default::default() };
            }
            ui.label(
                RichText::new(format!("{shown} of {total}"))
                    .size(11.5)
                    .color(c(if shown == total { theme::MONO6 } else { theme::ORANGE })),
            );
        });
        ui.horizontal(|ui| {
            // Indented to line the second row up with the filter input above it.
            ui.add_space(44.0);
            ui.label(RichText::new("Method").size(11.0).color(c(theme::MONO4)));
            ui.add(
                egui::TextEdit::singleline(&mut self.method)
                    .desired_width(58.0)
                    .font(egui::TextStyle::Monospace)
                    .hint_text("any"),
            );
            ui.add_space(6.0);
            ui.label(RichText::new("Status").size(11.0).color(c(theme::MONO4)));
            ui.add(
                egui::TextEdit::singleline(&mut self.status)
                    .desired_width(52.0)
                    .font(egui::TextStyle::Monospace)
                    .hint_text("any"),
            );
            ui.add_space(6.0);
            ui.label(RichText::new("MIME").size(11.0).color(c(theme::MONO4)));
            ui.add(
                egui::TextEdit::singleline(&mut self.mime)
                    .desired_width(110.0)
                    .font(egui::TextStyle::Monospace)
                    .hint_text("any"),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new(format!(
                    "{} scope rule{} (Target > Scope)",
                    scope_rules,
                    if scope_rules == 1 { "" } else { "s" }
                ))
                .size(10.5)
                .color(c(theme::MONO4)),
            );
        });
        broken
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(method: &str, host: &str, path: &str, status: &str, content_type: Option<&str>) -> HistEntry {
        let mut resp = Vec::new();
        if let Some(ct) = content_type {
            resp.extend_from_slice(
                format!("HTTP/1.1 {status} OK\r\nContent-Type: {ct}\r\nContent-Length: 0\r\n\r\n").as_bytes(),
            );
        }
        HistEntry {
            id: 1,
            ts: 0,
            method: method.into(),
            host: host.into(),
            port: 80,
            path: path.into(),
            status: status.into(),
            resp_len: 0,
            req_raw: Vec::new(),
            resp_raw: if resp.is_empty() { None } else { Some(resp) },
            https: false,
            note: None,
            params: false,
            edited: false,
            extension: String::new(),
            title: String::new(),
            cookies: String::new(),
            listener_port: 0,
        }
    }

    fn shared() -> std::sync::Arc<net::Shared> {
        net::Shared::new()
    }

    #[test]
    fn mime_is_taken_from_the_recorded_response() {
        let e = entry("GET", "a", "/", "200", Some("application/json; charset=utf-8"));
        assert_eq!(HistoryFilter::mime_of(&e), "application/json");
        let none = entry("GET", "a", "/", "200", None);
        assert_eq!(HistoryFilter::mime_of(&none), "");
    }

    #[test]
    fn method_and_status_filters_match_substrings() {
        let shared = shared();
        let e = entry("GET", "example.com", "/x", "404", Some("text/html"));
        let mut f = HistoryFilter { method: "get".into(), ..Default::default() };
        assert!(f.matches(&e, &shared));
        f.method = "POST".into();
        assert!(!f.matches(&e, &shared));
        f.method.clear();
        f.status = "40".into();
        assert!(f.matches(&e, &shared));
        f.status = "200".into();
        assert!(!f.matches(&e, &shared));
    }

    #[test]
    fn mime_filter_matches_the_essence_not_the_parameters() {
        let shared = shared();
        let e = entry("GET", "a", "/", "200", Some("application/json; charset=utf-8"));
        let mut f = HistoryFilter { mime: "json".into(), ..Default::default() };
        assert!(f.matches(&e, &shared));
        f.mime = "text/html".into();
        assert!(!f.matches(&e, &shared));
        // A regex works too, and a broken one simply matches nothing.
        f.mime = "^application/".into();
        f.regex = true;
        assert!(f.matches(&e, &shared));
        f.mime = "(".into();
        assert!(!f.matches(&e, &shared));
    }

    #[test]
    fn text_filter_can_be_literal_or_regex() {
        let shared = shared();
        let e = entry("GET", "api.example.com", "/v1/users", "200", None);
        let mut f = HistoryFilter { text: "users".into(), ..Default::default() };
        assert!(f.matches(&e, &shared));
        f.text = "/v1/users".into();
        assert!(f.matches(&e, &shared)); // literal substring
        // The haystack is "id method host port path status", so an anchor that
        // only fits the path does not match it.
        f.text = "^/v1/".into();
        f.regex = true;
        assert!(!f.matches(&e, &shared));
        f.text = "/v1/users$".into();
        assert!(!f.matches(&e, &shared), "the haystack ends with the status code");
        f.text = "users\\b".into();
        assert!(f.matches(&e, &shared));
        f.text = "(".into();
        assert!(!f.matches(&e, &shared));
    }

    #[test]
    fn in_scope_uses_the_shared_scope_list() {
        let shared = shared();
        let e = entry("GET", "api.example.com", "/v1", "200", None);
        // An empty scope means "everything is in scope", as in the original.
        let f = HistoryFilter { in_scope_only: true, ..Default::default() };
        assert!(f.matches(&e, &shared));

        // With an include rule, only matching URLs pass.
        shared.scope.lock().unwrap().push(net::ScopeRule {
            enabled: true,
            include: true,
            pattern: "example\\.com".into(),
            is_regex: true,
        });
        let other = entry("GET", "other.test", "/", "200", None);
        assert!(f.matches(&e, &shared));
        assert!(!f.matches(&other, &shared));
    }
}