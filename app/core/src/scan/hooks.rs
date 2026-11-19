// The scanner's side of the net boundary (issue #38): the ScanHooks impl
// the app registers at startup so net's live crawl, live passive audit
// and issue bookkeeping work without net naming scan.

use std::sync::Arc;

use webprobe_support::hist::HistEntry;
use webprobe_support::issues::ScanIssue;

use super::*;
use crate::net::ScanHooks;

struct LiveHooks;

impl ScanHooks for LiveHooks {
    fn crawl_links(&self, origin: &str, path: &str, resp: &[u8]) -> Vec<String> {
        crawl_links(origin, path, resp)
    }

    fn crawl_max_unique_locations(&self) -> usize {
        CRAWL_MAX_UNIQUE_LOCATIONS
    }

    fn passive_check_live(&self, shared: &Shared, e: &HistEntry) -> Vec<ScanIssue> {
        passive_check_live(shared, e)
    }

    fn add_passive_issues(&self, shared: &Shared, issues: Vec<ScanIssue>) {
        add_passive_issues(shared, issues);
    }

    fn add_issues(&self, shared: &Shared, issues: Vec<ScanIssue>) {
        add_issues(shared, issues);
    }

    fn issue_type_id(&self, name: &str) -> u64 {
        issue_type_id(name)
    }
}

/// Register the scanner with net; call once at app startup before proxy
/// traffic (the live passive crawl and audit run on proxy responses).
pub fn register_scan_hooks() {
    crate::net::set_scan_hooks(Arc::new(LiveHooks));
}
