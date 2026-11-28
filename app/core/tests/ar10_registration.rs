//! AR-10: one start-up registration call for every engine/front-end seam.

#[test]
fn register_runtime_registers_every_seam_and_is_idempotent() {
    webprobe_core::register_runtime();
    webprobe_core::register_runtime();

    // The browser crawl driver is the seam with a public reader.
    assert!(webprobe_core::scan::browser_crawl().is_some());

    // The check catalogue is built from the registries after registration.
    let catalogue = webprobe_core::scan::check_catalogue();
    assert!(
        catalogue
            .iter()
            .any(|c| c.0 == "active.xss-reflected" && c.2 == "per insertion point")
    );
    assert!(
        catalogue
            .iter()
            .any(|c| c.0 == "passive.hsts-missing" && c.2 == "passive, per response")
    );

    // The passive metadata catalogue is derived from the check registry
    // (no second hand-kept list), so it carries every passive issue class.
    let library = webprobe_core::scan::check_library();
    assert!(library.len() >= 36, "{}", library.len());
    assert!(library.iter().all(|c| c.id.starts_with("passive.")));
    assert!(library.iter().any(|c| c.id == "passive.hsts-missing"));
    assert!(library.iter().any(|c| c.id == "passive.csp-not-enforced"));
}
