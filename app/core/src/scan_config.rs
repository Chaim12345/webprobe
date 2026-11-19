//! Scan configuration: which audit checks run and which insertion point
//! types they attack (Burp's scan configuration "Issues reported" and
//! "Insertion point types" sections). Everything is on by default.

/// The live scan configuration a `Shared` carries (stored in
/// `Shared::tool_state` so net does not name this type). The returned guard
/// shares one mutex across all callers, as the old `Shared::scan_config`
/// field did.
pub fn shared_config(
    shared: &crate::net::Shared,
) -> std::sync::Arc<crate::sync::Mutex<ScanConfig>> {
    shared.tool_state.get_or_insert()
}

use std::collections::BTreeSet;

/// Burp's insertion point types, as (key, label): AuditDefaults.json
/// scanner.insertion_point_types (insert_url_params, insert_body_params,
/// insert_cookies, insert_param_name, insert_http_headers,
/// insert_entire_body, insert_url_path_folders, insert_url_path_filename).
/// A key is stored only when switched off, so a configuration saved before
/// a type existed loads with that type on, as in Burp's defaults.
pub const INSERTION_TYPES: [(&str, &str); 8] = [
    ("url", "URL parameter values"),
    ("body", "Body parameter values"),
    ("cookie", "Cookie parameter values"),
    ("param_name", "Parameter name"),
    ("header", "HTTP headers"),
    ("entire_body", "Entire body"),
    ("folder", "URL path folders"),
    ("filename", "URL path filename"),
];

/// "Use nested insertion points" (AuditDefaults.json
/// scanner.misc_insertion_point_options.use_nested_insertion_points, on by
/// default), kept with the switched-off insertion types under this key.
pub const NESTED_KEY: &str = "nested";
pub const NESTED_LABEL: &str = "Use nested insertion points";

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ScanConfig {
    /// Check ids (see `scan::check_catalogue`) that do not run.
    pub disabled_checks: BTreeSet<String>,
    /// Insertion point type keys (see [`INSERTION_TYPES`]) not attacked.
    pub disabled_insertion: BTreeSet<String>,
    /// Crawl limits for "Crawl and audit" scans.
    pub crawl: CrawlLimits,
    /// "Issues reported" from the scan configuration library (R-11); None
    /// runs every check, as before the library existed.
    pub issues: Option<crate::scan_library::IssueFilter>,
}

/// Burp's crawl settings (CrawlDefaults.json): link depth, unique locations,
/// and whether robots.txt and sitemap.xml are requested.
#[derive(Clone, Debug, PartialEq)]
pub struct CrawlLimits {
    pub max_depth: usize,
    pub max_locations: usize,
    pub robots: bool,
    pub sitemap: bool,
    /// crawl_limits.maximum_crawl_time in minutes (0: no limit).
    pub max_minutes: u64,
    /// crawl_limits.maximum_request_count (0: no limit).
    pub max_requests: usize,
    /// Headless engine for the JavaScript crawl: "" = Chromium over CDP
    /// (the default), or "Lightpanda" / "Obscura" (headless::js_crawl).
    pub engine: String,
}

impl Default for CrawlLimits {
    fn default() -> Self {
        // crawl_optimization.maximum_link_depth = 4,
        // crawl_limits.maximum_unique_locations = 1500,
        // customization.request_robots_txt / request_sitemap = true,
        // crawl_limits.maximum_crawl_time = 150, maximum_request_count = 0.
        Self {
            max_depth: 4,
            max_locations: 1500,
            robots: true,
            sitemap: true,
            max_minutes: 150,
            max_requests: 0,
            engine: String::new(),
        }
    }
}

impl CrawlLimits {
    /// Whether a crawl started at `started` that has made `requests`
    /// requests must stop (maximum crawl time / request count).
    pub fn exhausted(&self, started: std::time::Instant, requests: usize) -> bool {
        (self.max_minutes > 0
            && started.elapsed() >= std::time::Duration::from_secs(self.max_minutes * 60))
            || (self.max_requests > 0 && requests >= self.max_requests)
    }
}

impl ScanConfig {
    pub fn check_enabled(&self, id: &str) -> bool {
        !self.disabled_checks.contains(id)
    }

    /// Whether checks for issue `name` run and report (see
    /// [`crate::scan_library::filter_allows`]).
    pub fn issue_allowed(&self, name: &str, active: bool) -> bool {
        self.issues
            .as_ref()
            .is_none_or(|f| crate::scan_library::filter_allows(f, name, active))
    }

    pub fn insertion_enabled(&self, key: &str) -> bool {
        !self.disabled_insertion.contains(key)
    }
}

impl ScanConfig {
    /// The configuration a project file holds. Ids and keys are kept as
    /// saved (unknown ones are harmless: nothing asks for them), so a check
    /// or insertion type added later loads switched on; crawl limits out of
    /// range are clamped (depth 1..=50, locations 1..=100000) and missing
    /// ones take Burp's defaults.
    pub fn from_saved(s: &crate::project::ProjectScanner) -> Self {
        let d = CrawlLimits::default();
        ScanConfig {
            disabled_checks: s.disabled_checks.iter().cloned().collect(),
            disabled_insertion: s.disabled_insertion_points.iter().cloned().collect(),
            crawl: CrawlLimits {
                max_depth: s.crawl_max_depth.unwrap_or(d.max_depth).clamp(1, 50),
                max_locations: s
                    .crawl_max_locations
                    .unwrap_or(d.max_locations)
                    .clamp(1, 100_000),
                robots: s.crawl_robots.unwrap_or(d.robots),
                sitemap: s.crawl_sitemap.unwrap_or(d.sitemap),
                max_minutes: s.crawl_max_minutes.unwrap_or(d.max_minutes),
                max_requests: s.crawl_max_requests.unwrap_or(d.max_requests),
                engine: s.crawl_engine.clone().unwrap_or_default(),
            },
            issues: s.issues_reported.as_ref().and_then(|ir| {
                crate::scan_library::IssueFilter::from_tree(
                    &serde_json::json!({"scanner": {"issues_reported": ir}}),
                )
            }),
        }
    }

    /// Write this configuration into a project's scanner section.
    pub fn save_into(&self, s: &mut crate::project::ProjectScanner) {
        s.disabled_checks = self.disabled_checks.iter().cloned().collect();
        s.disabled_insertion_points = self.disabled_insertion.iter().cloned().collect();
        s.crawl_max_depth = Some(self.crawl.max_depth);
        s.crawl_max_locations = Some(self.crawl.max_locations);
        s.crawl_robots = Some(self.crawl.robots);
        s.crawl_sitemap = Some(self.crawl.sitemap);
        s.crawl_engine = Some(self.crawl.engine.clone()).filter(|e| !e.is_empty());
        s.crawl_max_minutes = Some(self.crawl.max_minutes);
        s.crawl_max_requests = Some(self.crawl.max_requests);
        s.issues_reported = self.issues.as_ref().and_then(|_| {
            crate::scan_library::get_path(
                &crate::scan_library::config_to_tree(self, 1, 1),
                "scanner.issues_reported",
            )
            .cloned()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::ProjectScanner;

    #[test]
    fn round_trips_through_a_project_file() {
        let mut c = ScanConfig::default();
        c.disabled_checks.insert("passive.ssn-disclosed".into());
        c.disabled_insertion.insert("header".into());
        c.disabled_insertion.insert(NESTED_KEY.into());
        c.crawl = CrawlLimits {
            max_depth: 7,
            max_locations: 200,
            robots: false,
            sitemap: true,
            max_minutes: 10,
            max_requests: 500,
            engine: "Lightpanda".into(),
        };
        let mut saved = ProjectScanner::default();
        c.save_into(&mut saved);
        let json = serde_json::to_string(&saved).unwrap();
        let back: ProjectScanner = serde_json::from_str(&json).unwrap();
        assert_eq!(ScanConfig::from_saved(&back), c);
    }

    #[test]
    fn old_and_odd_files_load_with_defaults_and_clamps() {
        // A file from before crawl limits and insertion switches existed.
        let old: ProjectScanner = serde_json::from_str(
            r#"{"speed":1,"accuracy":1,"extra_checks":false,"disabled_checks":["active.csrf"]}"#,
        )
        .unwrap();
        let c = ScanConfig::from_saved(&old);
        assert_eq!(c.crawl, CrawlLimits::default());
        assert!(!c.check_enabled("active.csrf"));
        assert!(
            c.check_enabled("passive.vulnerable-js-dependency"),
            "checks added later load on"
        );
        assert!(
            INSERTION_TYPES.iter().all(|(k, _)| c.insertion_enabled(k))
                && c.insertion_enabled(NESTED_KEY)
        );
        let odd = ProjectScanner {
            crawl_max_depth: Some(0),
            crawl_max_locations: Some(10_000_000),
            crawl_engine: Some(String::new()),
            ..ProjectScanner::default()
        };
        let c = ScanConfig::from_saved(&odd);
        assert_eq!(
            (
                c.crawl.max_depth,
                c.crawl.max_locations,
                c.crawl.engine.as_str()
            ),
            (1, 100_000, "")
        );
        let mut back = ProjectScanner::default();
        c.save_into(&mut back);
        assert_eq!(back.crawl_engine, None, "the default engine is not written");
    }
}
