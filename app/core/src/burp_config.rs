//! R-15: Burp's settings JSON for `--config-file` / `--user-config-file` on
//! the command line and for Project / User options export and import.
//!
//! Scope note (agreed on PR #5, 2026-11-18): the scan configuration model
//! (checks, insertion points, crawl limits) belongs to R-11
//! (`scan_config.rs`); this module deliberately does not parse or emit
//! scan-configuration JSON. What is covered here is the rest of Burp's
//! options files: the project options' proxy listener and the user
//! options' REST API section (`user_options.misc.api`, UserDefaults.json
//! shape per the R-15 research document). Settings WebProbe does not
//! support are ignored on import with a note, the same way Burp ignores
//! keys it does not know.

use serde_json::{Map, Value, json};

fn obj(pairs: Vec<(&str, Value)>) -> Value {
    Value::Object(
        pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect::<Map<String, Value>>(),
    )
}

fn get_bool(v: &Map<String, Value>, key: &str) -> Option<bool> {
    v.get(key).and_then(Value::as_bool)
}

fn get_usize(v: &Map<String, Value>, key: &str) -> Option<usize> {
    v.get(key).and_then(Value::as_u64).map(|n| n as usize)
}

/// The proxy listener: Burp's project options `proxy.request_listeners`
/// (Burp > Project options > Save project options).
#[derive(Clone, Debug, PartialEq)]
pub struct ProxyListener {
    pub port: u16,
    pub running: bool,
    /// `loopback_only`, `specific_address` or `all_interfaces`.
    pub listen_mode: String,
}

impl Default for ProxyListener {
    fn default() -> Self {
        // Burp's default listener: 127.0.0.1:8080, running.
        Self {
            port: 8080,
            running: true,
            listen_mode: "loopback_only".to_string(),
        }
    }
}

/// REST API settings: Burp's `user_options.misc.api` (UserDefaults.json).
/// The defaults match Burp's: disabled, loopback only, port 1337, API key
/// required (`insecure_mode` false).
#[derive(Clone, Debug, PartialEq)]
pub struct ApiConfig {
    pub enabled: bool,
    /// `loopback_only` or `all_interfaces`.
    pub listen_mode: String,
    /// Explicit listen address override (`null` = derive from listen_mode).
    pub address: Option<String>,
    pub port: u16,
    /// Burp's `insecure_mode`: serve the API without an API key.
    pub insecure_mode: bool,
    /// API keys (Burp's newer API authenticates with a key in the path).
    pub keys: Vec<String>,
}

/// Keys must be a nonempty, printable single URL path segment. In particular,
/// a blank key would authenticate a double-slash path, and CR/LF or a slash
/// must never be interpolated into a Location response header.
pub fn valid_api_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && !matches!(b, b'/' | b'?' | b'#' | b'\\'))
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_mode: "loopback_only".to_string(),
            address: None,
            port: 1337,
            insecure_mode: false,
            keys: Vec::new(),
        }
    }
}

/// Burp's project options `http` section. Only the fields WebProbe acts on
/// are modelled; unknown keys are left alone on import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpOptions {
    /// `http.http2.enable_http2` (Burp's default: on). With it off the
    /// Hidden HTTP/2 check does not run.
    pub http2_enabled: bool,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            http2_enabled: true,
        }
    }
}

/// Project options JSON, Burp's `proxy.request_listeners` and
/// `http.http2.enable_http2` shapes. WebProbe has one listener, so it is
/// the single array entry.
pub fn export_project_options(listener: &ProxyListener, http: &HttpOptions) -> Value {
    obj(vec![
        (
            "proxy",
            obj(vec![(
                "request_listeners",
                json!([{
                    "certificate_mode": "per_host",
                    "listen_mode": listener.listen_mode,
                    "listener_port": listener.port,
                    "running": listener.running,
                }]),
            )]),
        ),
        (
            "http",
            obj(vec![(
                "http2",
                obj(vec![("enable_http2", Value::Bool(http.http2_enabled))]),
            )]),
        ),
    ])
}

/// The sub-trees of `options` named by dotted `paths` (Burp's
/// `exportProjectOptionsAsJson("proxy.request_listeners")`), nested as in
/// the source. No paths means everything; a path that names nothing is
/// left out.
pub fn select_paths(options: &Value, paths: &[String]) -> Value {
    if paths.is_empty() {
        return options.clone();
    }
    let mut out = Value::Object(serde_json::Map::new());
    for path in paths {
        let keys: Vec<&str> = path.split('.').filter(|k| !k.is_empty()).collect();
        let mut found = options;
        if keys.is_empty()
            || !keys
                .iter()
                .all(|k| found.get(k).map(|v| found = v).is_some())
        {
            continue;
        }
        let mut slot = &mut out;
        for (i, key) in keys.iter().enumerate() {
            let map = slot.as_object_mut().expect("built as objects");
            if i + 1 == keys.len() {
                map.insert((*key).to_string(), found.clone());
                break;
            }
            slot = map
                .entry((*key).to_string())
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            if !slot.is_object() {
                // A longer path under a value already copied whole.
                break;
            }
        }
    }
    out
}

/// Read a project options JSON into `listener` and `http`. Unknown sections
/// and keys are ignored with a note in `notes` (like Burp's "not all
/// settings could be restored" note). Scan-configuration sections
/// (`scanner`, `crawler`) are skipped silently here: R-11's scan
/// configuration model owns them, and the binaries route each
/// --config-file through `scan_library` for those keys.
pub fn apply_project_options(
    json: &Value,
    listener: &mut ProxyListener,
    http: &mut HttpOptions,
    notes: &mut Vec<String>,
) {
    let Some(root) = json.as_object() else {
        notes.push("config file is not a JSON object; ignored".to_string());
        return;
    };
    for section in root.keys() {
        if !matches!(section.as_str(), "proxy" | "scanner" | "crawler" | "http") {
            notes.push(format!("unsupported section `{section}` ignored"));
        }
    }
    if let Some(enable) = root
        .get("http")
        .and_then(Value::as_object)
        .and_then(|h| h.get("http2"))
        .and_then(Value::as_object)
        .and_then(|h2| get_bool(h2, "enable_http2"))
    {
        http.http2_enabled = enable;
    }
    let Some(proxy) = root.get("proxy").and_then(Value::as_object) else {
        return;
    };
    let Some(listeners) = proxy.get("request_listeners").and_then(Value::as_array) else {
        return;
    };
    // WebProbe has one listener: the last entry wins, matching Burp's
    // repeated --config-file last-wins rule.
    for entry in listeners.iter().filter_map(Value::as_object) {
        if let Some(n) = get_usize(entry, "listener_port") {
            if n > 0 && n <= u16::MAX as usize {
                listener.port = n as u16;
            } else {
                notes.push(format!("listener_port {n} out of range; ignored"));
            }
        }
        if let Some(b) = get_bool(entry, "running") {
            listener.running = b;
        }
        if let Some(s) = entry.get("listen_mode").and_then(Value::as_str) {
            if s == "loopback_only" || s == "specific_address" || s == "all_interfaces" {
                listener.listen_mode = s.to_string();
            } else {
                notes.push(format!("unknown listen_mode `{s}` ignored"));
            }
        }
    }
}

/// User options JSON: Burp's `user_options.misc.api` (UserDefaults.json).
/// Mirrors Burp > User options > Save user options.
pub fn export_user_options(api: &ApiConfig) -> Value {
    obj(vec![(
        "user_options",
        obj(vec![(
            "misc",
            obj(vec![(
                "api",
                obj(vec![
                    (
                        "address",
                        api.address.as_ref().map_or(Value::Null, |a| json!(a)),
                    ),
                    ("enabled", Value::Bool(api.enabled)),
                    ("insecure_mode", Value::Bool(api.insecure_mode)),
                    ("keys", json!(api.keys)),
                    ("listen_mode", json!(api.listen_mode)),
                    ("port", json!(api.port)),
                ]),
            )]),
        )]),
    )])
}

/// Read a user options JSON into `api`; unknown sections are noted.
pub fn apply_user_options(json: &Value, api: &mut ApiConfig, notes: &mut Vec<String>) {
    let Some(user_options) = json.get("user_options").and_then(Value::as_object) else {
        notes.push("no `user_options` section; ignored".to_string());
        return;
    };
    for section in user_options.keys() {
        if section != "misc" {
            notes.push(format!(
                "unsupported user_options section `{section}` ignored"
            ));
        }
    }
    let misc = user_options.get("misc").and_then(Value::as_object).cloned();
    let Some(api_obj) = misc
        .as_ref()
        .and_then(|m| m.get("api"))
        .and_then(Value::as_object)
    else {
        return;
    };
    if let Some(b) = get_bool(api_obj, "enabled") {
        api.enabled = b;
    }
    if let Some(s) = api_obj.get("listen_mode").and_then(Value::as_str) {
        if s == "loopback_only" || s == "all_interfaces" {
            api.listen_mode = s.to_string();
        } else {
            notes.push(format!("unknown listen_mode `{s}` ignored"));
        }
    }
    match api_obj.get("address") {
        Some(Value::Null) => api.address = None,
        Some(v) => match v.as_str() {
            Some(s) => api.address = Some(s.to_string()),
            None => notes.push("api address must be a string or null; ignored".to_string()),
        },
        None => {}
    }
    if let Some(n) = get_usize(api_obj, "port") {
        if n > 0 && n <= u16::MAX as usize {
            api.port = n as u16;
        } else {
            notes.push(format!("api port {n} out of range; ignored"));
        }
    }
    if let Some(b) = get_bool(api_obj, "insecure_mode") {
        api.insecure_mode = b;
    }
    if let Some(keys) = api_obj.get("keys").and_then(Value::as_array) {
        api.keys = keys
            .iter()
            .filter_map(Value::as_str)
            .filter(|key| valid_api_key(key))
            .map(str::to_string)
            .collect();
        if api.keys.len() != keys.len() {
            notes.push("invalid API keys ignored (keys must be nonempty URL path segments)".into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_paths_keeps_named_sub_trees_nested() {
        let all = export_project_options(&ProxyListener::default(), &HttpOptions::default());
        assert_eq!(select_paths(&all, &[]), all);
        let one = select_paths(&all, &["http.http2.enable_http2".to_string()]);
        assert_eq!(one, json!({"http": {"http2": {"enable_http2": true}}}));
        let two = select_paths(
            &all,
            &[
                "proxy".to_string(),
                "http.http2".to_string(),
                "no.such".to_string(),
            ],
        );
        assert_eq!(two["proxy"], all["proxy"]);
        assert_eq!(two["http"]["http2"], all["http"]["http2"]);
        assert!(two.get("no").is_none());
    }

    /// The API defaults are Burp's: loopback only, port 1337, API key
    /// required (insecure_mode false).
    #[test]
    fn api_defaults_match_burp() {
        let api = ApiConfig::default();
        assert!(!api.enabled);
        assert_eq!(api.listen_mode, "loopback_only");
        assert_eq!(api.port, 1337);
        assert!(!api.insecure_mode);
    }

    /// The proxy listener defaults are Burp's: 127.0.0.1:8080, running.
    #[test]
    fn proxy_listener_defaults_match_burp() {
        let l = ProxyListener::default();
        assert_eq!(l.port, 8080);
        assert!(l.running);
        assert_eq!(l.listen_mode, "loopback_only");
    }

    /// The project options JSON has Burp's proxy.request_listeners and
    /// http.http2 shapes and round-trips.
    #[test]
    fn project_options_round_trip() {
        let listener = ProxyListener {
            port: 8081,
            running: false,
            listen_mode: "all_interfaces".to_string(),
        };
        let http = HttpOptions {
            http2_enabled: false,
        };
        let json = export_project_options(&listener, &http);
        assert_eq!(
            json["proxy"]["request_listeners"][0]["listener_port"],
            json!(8081)
        );
        assert_eq!(
            json["proxy"]["request_listeners"][0]["running"],
            Value::Bool(false)
        );
        assert_eq!(json["http"]["http2"]["enable_http2"], Value::Bool(false));
        let mut back = ProxyListener::default();
        let mut back_http = HttpOptions::default();
        let mut notes = Vec::new();
        apply_project_options(&json, &mut back, &mut back_http, &mut notes);
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(back, listener);
        assert_eq!(back_http, http);
    }

    /// Burp's project option `http.http2.enable_http2` is read from the
    /// project options JSON (S-05).
    #[test]
    fn http2_enable_setting_is_read_from_project_options() {
        let json = json!({"http": {"http2": {"enable_http2": false}}});
        let mut listener = ProxyListener::default();
        let mut http = HttpOptions::default();
        let mut notes = Vec::new();
        apply_project_options(&json, &mut listener, &mut http, &mut notes);
        assert!(!http.http2_enabled, "off is applied");
        assert!(notes.is_empty(), "http is a supported section: {notes:?}");

        // A file without the key leaves the default (on) alone.
        let mut http = HttpOptions::default();
        apply_project_options(
            &json!({"http": {"http1": {"enable_keep_alive": false}}}),
            &mut listener,
            &mut http,
            &mut notes,
        );
        assert!(http.http2_enabled);
    }

    /// Unknown sections are noted; scan-configuration sections are skipped
    /// without a note (R-11's model owns them).
    #[test]
    fn import_ignores_unknown_and_scan_config_sections() {
        let json = json!({
            "target": {"scope": {"include": []}},
            "scanner": {"issues_reported": {"SQL injection": false}},
            "crawler": {"crawl_limits": {"maximum_unique_locations": 5}},
            "proxy": {"request_listeners": [{"listener_port": 9090}]},
        });
        let mut listener = ProxyListener::default();
        let mut http = HttpOptions::default();
        let mut notes = Vec::new();
        apply_project_options(&json, &mut listener, &mut http, &mut notes);
        assert_eq!(listener.port, 9090);
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("target"));
    }

    /// With several listener entries the last one wins, like repeated
    /// --config-file flags.
    #[test]
    fn last_listener_wins() {
        let json = json!({"proxy": {"request_listeners": [{"listener_port": 8081}, {"listener_port": 8082, "running": false}]}});
        let mut listener = ProxyListener::default();
        let mut http = HttpOptions::default();
        let mut notes = Vec::new();
        apply_project_options(&json, &mut listener, &mut http, &mut notes);
        assert_eq!(listener.port, 8082);
        assert!(!listener.running);
    }

    /// The user options JSON has Burp's user_options.misc.api shape and
    /// round-trips.
    #[test]
    fn user_options_round_trip() {
        let api = ApiConfig {
            enabled: true,
            port: 1338,
            listen_mode: "all_interfaces".to_string(),
            insecure_mode: true,
            keys: vec!["abc".to_string()],
            ..Default::default()
        };
        let json = export_user_options(&api);
        assert_eq!(json["user_options"]["misc"]["api"]["port"], json!(1338));
        assert_eq!(
            json["user_options"]["misc"]["api"]["insecure_mode"],
            Value::Bool(true)
        );
        let mut back = ApiConfig::default();
        let mut notes = Vec::new();
        apply_user_options(&json, &mut back, &mut notes);
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(back, api);
    }

    /// Unknown user option sections are noted, and a bad listen_mode is
    /// ignored.
    #[test]
    fn user_options_unknown_sections_noted() {
        let json = json!({"user_options": {"display": {"theme": "dark"}, "misc": {"api": {"listen_mode": "everywhere"}}}});
        let mut api = ApiConfig::default();
        let mut notes = Vec::new();
        apply_user_options(&json, &mut api, &mut notes);
        assert_eq!(api.listen_mode, "loopback_only");
        assert_eq!(notes.len(), 2, "{notes:?}");
    }

    #[test]
    fn import_rejects_blank_and_invalid_api_keys_without_echoing_them() {
        let input = json!({"user_options": {"misc": {"api": {
            "keys": ["", "   ", "has/slash", "good-key"]
        }}}});
        let mut api = ApiConfig::default();
        let mut notes = Vec::new();
        apply_user_options(&input, &mut api, &mut notes);
        assert_eq!(api.keys, vec!["good-key"]);
        assert!(!notes.is_empty());
        assert!(!notes.join(" ").contains("good-key"));
    }

    /// API keys import and export, but are never logged: the notes carry
    /// file/section names only.
    #[test]
    fn api_keys_round_trip_without_logging() {
        let json =
            json!({"user_options": {"misc": {"api": {"enabled": true, "keys": ["secret-key-1"]}}}});
        let mut api = ApiConfig::default();
        let mut notes = Vec::new();
        apply_user_options(&json, &mut api, &mut notes);
        assert_eq!(api.keys, vec!["secret-key-1".to_string()]);
        assert!(notes.iter().all(|n| !n.contains("secret-key-1")));
        assert_eq!(
            export_user_options(&api)["user_options"]["misc"]["api"]["keys"],
            json!(["secret-key-1"])
        );
    }
}
