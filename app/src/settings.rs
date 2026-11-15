//! Target-scope and upstream-proxy settings models.
//!
//! Fields and defaults are grounded in the `burp-re` build 51467 evidence:
//! `ProjectDefaults.json` stores empty `target.scope.include` / `exclude` lists,
//! `project_options.connections.upstream_proxy.servers = []`, and a disabled
//! `socks_proxy` (`use_proxy: false`) with empty host / username / password and
//! port 0. The live jar (build 52685) is newer and was not used here. The actual
//! proxy transport and the suite's shared scope list are parent-owned; these
//! types are additive settings models for the editor.

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

/// Which request component a scope regex is matched against.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeTarget {
    #[default]
    Host,
    Path,
}

impl ScopeTarget {
    pub fn label(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Path => "path",
        }
    }
}

/// One include or exclude regex rule.
///
/// Empty and syntactically invalid patterns never match, so a half-edited row
/// cannot silently alter scope. Host patterns are case-insensitive because DNS
/// hostnames are; path patterns are case-sensitive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRule {
    pub enabled: bool,
    pub target: ScopeTarget,
    pub pattern: String,
}

impl ScopeRule {
    pub fn new(target: ScopeTarget) -> Self {
        Self { enabled: true, target, pattern: String::new() }
    }

    pub fn with_pattern(target: ScopeTarget, pattern: impl Into<String>) -> Self {
        Self { enabled: true, target, pattern: pattern.into() }
    }

    /// Editor-facing validation. Returns `None` for a compilable, non-empty regex.
    pub fn error(&self) -> Option<&'static str> {
        if self.pattern.trim().is_empty() {
            return Some("empty regex");
        }
        match compile_regex(self.target, &self.pattern) {
            Ok(_) => None,
            Err(_) => Some("invalid regex"),
        }
    }

    /// True only for an enabled, valid rule that matches the selected component.
    pub fn matches(&self, host: &str, path: &str) -> bool {
        if !self.enabled || self.pattern.trim().is_empty() {
            return false;
        }
        let text = match self.target {
            ScopeTarget::Host => host,
            ScopeTarget::Path => path,
        };
        match compile_regex(self.target, &self.pattern) {
            Ok(regex) => regex.is_match(text),
            Err(_) => false,
        }
    }
}

fn compile_regex(target: ScopeTarget, pattern: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(pattern)
        .case_insensitive(target == ScopeTarget::Host)
        .build()
}

fn compile_rules(rules: &[ScopeRule], target: ScopeTarget) -> Vec<Regex> {
    rules
        .iter()
        .filter(|rule| {
            rule.enabled && rule.target == target && !rule.pattern.trim().is_empty()
        })
        .filter_map(|rule| compile_regex(target, &rule.pattern).ok())
        .collect()
}

/// Compiled snapshot of a [`ScopeState`]. Build once and reuse for request paths
/// that are checked frequently; [`ScopeState::in_scope`] compiles on each call.
#[derive(Clone, Debug, Default)]
pub struct ScopeMatcher {
    include_host: Vec<Regex>,
    include_path: Vec<Regex>,
    exclude_host: Vec<Regex>,
    exclude_path: Vec<Regex>,
}

impl ScopeMatcher {
    pub fn new(state: &ScopeState) -> Self {
        Self {
            include_host: compile_rules(&state.include, ScopeTarget::Host),
            include_path: compile_rules(&state.include, ScopeTarget::Path),
            exclude_host: compile_rules(&state.exclude, ScopeTarget::Host),
            exclude_path: compile_rules(&state.exclude, ScopeTarget::Path),
        }
    }

    /// Excludes are applied first and always win. Include host and include path
    /// rules are independent constraints: when at least one is present for a
    /// component, that component must match one of them. With no include rules
    /// every location is in scope.
    pub fn in_scope(&self, host: &str, path: &str) -> bool {
        if self.exclude_host.iter().any(|rule| rule.is_match(host)) {
            return false;
        }
        if self.exclude_path.iter().any(|rule| rule.is_match(path)) {
            return false;
        }
        if !self.include_host.is_empty()
            && !self.include_host.iter().any(|rule| rule.is_match(host))
        {
            return false;
        }
        if !self.include_path.is_empty()
            && !self.include_path.iter().any(|rule| rule.is_match(path))
        {
            return false;
        }
        true
    }

    /// No valid enabled include rule restricts the host or path.
    pub fn is_unrestricted(&self) -> bool {
        self.include_host.is_empty() && self.include_path.is_empty()
    }
}

/// Target scope: include/exclude host and path regex rules.
///
/// The reference defaults are empty lists, which means every location is in
/// scope. A matching exclude always removes a location.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeState {
    pub include: Vec<ScopeRule>,
    pub exclude: Vec<ScopeRule>,
}

impl ScopeState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compile the current rules for repeated evaluation.
    pub fn matcher(&self) -> ScopeMatcher {
        ScopeMatcher::new(self)
    }

    /// True when `host`/`path` is in scope. Exclude rules are checked first.
    ///
    /// `host` should be the bare hostname (optionally with a port if that is
    /// what the pattern targets); `path` is the request path, including a query
    /// string only when the caller wants the path regex to see it.
    pub fn in_scope(&self, host: &str, path: &str) -> bool {
        self.matcher().in_scope(host, path)
    }

    pub fn add_include(&mut self, target: ScopeTarget) {
        self.include.push(ScopeRule::new(target));
    }

    pub fn add_exclude(&mut self, target: ScopeTarget) {
        self.exclude.push(ScopeRule::new(target));
    }
}

/// Transport used by an upstream proxy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpstreamKind {
    #[default]
    Http,
    Socks5,
}

impl UpstreamKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Http => "HTTP",
            Self::Socks5 => "SOCKS5",
        }
    }
}

/// Editable upstream-proxy configuration.
///
/// Reference defaults (build 51467 `ProjectDefaults.json`): proxy routing is
/// disabled, host / username / password are empty, and the port is 0 (unset).
/// The parent-owned `crate::upstream::UpstreamConfig` is the transport view of
/// this data; this type is the settings/editor model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamState {
    pub enabled: bool,
    pub kind: UpstreamKind,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

impl Default for UpstreamState {
    fn default() -> Self {
        Self {
            enabled: false,
            kind: UpstreamKind::Http,
            host: String::new(),
            port: 0,
            username: String::new(),
            password: String::new(),
        }
    }
}

impl UpstreamState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether credentials will be sent. Both the parent HTTP and SOCKS5 paths
    /// treat a non-empty username as the trigger for authentication.
    pub fn uses_credentials(&self) -> bool {
        !self.username.is_empty()
    }

    /// `host:port` once both fields are filled in; `None` for an incomplete form.
    pub fn endpoint(&self) -> Option<String> {
        let host = self.host.trim();
        if host.is_empty() || self.port == 0 {
            return None;
        }
        Some(format!("{host}:{}", self.port))
    }

    /// Editor validation. A disabled proxy is valid but inert. Returns a short,
    /// user-facing message for the first problem found.
    pub fn validation_error(&self) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let host = self.host.trim();
        if host.is_empty() {
            return Some("Proxy host is required.".into());
        }
        if host.contains("://") || host.contains('/') {
            return Some("Enter a hostname or IP without a scheme or path.".into());
        }
        if host.chars().any(|ch| ch.is_whitespace()) {
            return Some("Proxy host must not contain whitespace.".into());
        }
        if self.port == 0 {
            return Some("Proxy port must be 1-65535.".into());
        }
        if self.username.is_empty() && !self.password.is_empty() {
            return Some("Enter a username for the proxy password.".into());
        }
        if self.kind == UpstreamKind::Socks5 {
            if self.username.len() > 255 {
                return Some("SOCKS5 username must be at most 255 bytes.".into());
            }
            if self.password.len() > 255 {
                return Some("SOCKS5 password must be at most 255 bytes.".into());
            }
        }
        None
    }

    /// True when the proxy is enabled and has everything the transport needs.
    pub fn ready(&self) -> bool {
        self.enabled && self.validation_error().is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(target: ScopeTarget, pattern: &str) -> ScopeRule {
        ScopeRule::with_pattern(target, pattern)
    }

    #[test]
    fn empty_scope_is_unrestricted() {
        let state = ScopeState::default();
        assert!(state.matcher().is_unrestricted());
        assert!(state.in_scope("example.com", "/anything"));
    }

    #[test]
    fn excludes_override_includes() {
        let mut state = ScopeState::default();
        state.include.push(rule(ScopeTarget::Host, r"^example\.com$"));
        state.exclude.push(rule(ScopeTarget::Path, r"^/admin"));
        assert!(state.in_scope("example.com", "/index"));
        assert!(!state.in_scope("example.com", "/admin/users"));
        assert!(!state.in_scope("other.test", "/index"));
    }

    #[test]
    fn include_host_and_path_are_conjunctive() {
        let mut state = ScopeState::default();
        state.include.push(rule(ScopeTarget::Host, r"^api\.example\.com$"));
        state.include.push(rule(ScopeTarget::Path, r"^/v1/"));
        assert!(state.in_scope("api.example.com", "/v1/items"));
        assert!(state.in_scope("API.EXAMPLE.COM", "/v1/items"));
        assert!(!state.in_scope("api.example.com", "/v2/items"));
        assert!(!state.in_scope("www.example.com", "/v1/items"));
    }

    #[test]
    fn empty_and_invalid_patterns_never_match() {
        let mut state = ScopeState::default();
        state.include.push(rule(ScopeTarget::Host, "("));
        state.include.push(rule(ScopeTarget::Host, ""));
        state.exclude.push(rule(ScopeTarget::Path, "("));
        assert!(state.matcher().is_unrestricted());
        assert!(state.in_scope("example.com", "/"));
    }

    #[test]
    fn upstream_defaults_match_project_defaults() {
        let state = UpstreamState::default();
        assert!(!state.enabled);
        assert_eq!(state.kind, UpstreamKind::Http);
        assert!(state.host.is_empty());
        assert_eq!(state.port, 0);
        assert!(state.username.is_empty());
        assert!(state.password.is_empty());
        assert_eq!(state.validation_error(), None);
    }

    #[test]
    fn upstream_validation_requires_host_and_port_when_enabled() {
        let mut state = UpstreamState { enabled: true, ..UpstreamState::default() };
        assert!(state.validation_error().is_some());

        state.host = "127.0.0.1".into();
        assert!(state.validation_error().is_some());

        state.port = 8080;
        assert_eq!(state.validation_error(), None);
        assert_eq!(state.endpoint().as_deref(), Some("127.0.0.1:8080"));
        assert!(!state.uses_credentials());

        state.password = "secret".into();
        assert!(state.validation_error().is_some());

        state.username = "user".into();
        assert_eq!(state.validation_error(), None);
        assert!(state.uses_credentials());
        assert!(state.ready());
    }
}
