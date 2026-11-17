//! Scan configuration: which audit checks run and which insertion point
//! types they attack (Burp's scan configuration "Issues reported" and
//! "Insertion point types" sections). Everything is on by default.

use std::collections::BTreeSet;

/// Burp's insertion point types, as (key, label).
pub const INSERTION_TYPES: [(&str, &str); 6] = [
    ("url", "URL parameter values"),
    ("body", "Body parameter values"),
    ("cookie", "Cookie parameter values"),
    ("header", "HTTP headers"),
    ("folder", "URL path folders"),
    ("filename", "URL path filename"),
];

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
}

impl Default for CrawlLimits {
    fn default() -> Self {
        // crawl_optimization.maximum_link_depth = 4,
        // crawl_limits.maximum_unique_locations = 1500,
        // customization.request_robots_txt / request_sitemap = true.
        Self { max_depth: 4, max_locations: 1500, robots: true, sitemap: true }
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
