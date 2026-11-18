//! Scan configuration: which audit checks run and which insertion point
//! types they attack (Burp's scan configuration "Issues reported" and
//! "Insertion point types" sections). Everything is on by default.

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
}

/// Burp's crawl settings (CrawlDefaults.json): link depth, unique locations,
/// and whether robots.txt and sitemap.xml are requested.
#[derive(Clone, Debug, PartialEq)]
pub struct CrawlLimits {
    pub max_depth: usize,
    pub max_locations: usize,
    pub robots: bool,
    pub sitemap: bool,
    /// Headless engine for the JavaScript crawl: "" = Chromium over CDP
    /// (the default), or "Lightpanda" / "Obscura" (headless::js_crawl).
    pub engine: String,
}

impl Default for CrawlLimits {
    fn default() -> Self {
        // crawl_optimization.maximum_link_depth = 4,
        // crawl_limits.maximum_unique_locations = 1500,
        // customization.request_robots_txt / request_sitemap = true.
        Self { max_depth: 4, max_locations: 1500, robots: true, sitemap: true, engine: String::new() }
    }
}

impl ScanConfig {
    pub fn check_enabled(&self, id: &str) -> bool {
        !self.disabled_checks.contains(id)
    }

    pub fn insertion_enabled(&self, key: &str) -> bool {
        !self.disabled_insertion.contains(key)
    }
}
