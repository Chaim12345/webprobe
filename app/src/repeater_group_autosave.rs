//! Exact group/bar dirty state for the existing 60-second autosave decision.
//! No persistence-format or broader request-content dirty-tracking change.
use webprobe_core::send_group::RepGroup;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Snapshot {
    groups: Vec<RepGroup>,
    bar_order: Vec<u64>,
}

impl Snapshot {
    fn new(groups: &[RepGroup], bar_order: Vec<u64>) -> Self {
        Self {
            groups: groups.to_vec(),
            bar_order,
        }
    }
}

pub(crate) fn capture(app: &crate::App) -> Snapshot {
    let order = app
        .shared
        .repeaters
        .lock()
        .unwrap()
        .iter()
        .map(|tab| tab.id)
        .collect();
    Snapshot::new(&app.rep_groups, order)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn groups() -> Vec<RepGroup> {
        vec![
            RepGroup {
                id: 10,
                name: "ab".into(),
                colour: 1,
                tabs: vec![1, 2],
            },
            RepGroup {
                id: 11,
                name: "cd".into(),
                colour: 2,
                tabs: vec![3],
            },
        ]
    }
    #[test]
    fn exact_group_and_bar_changes_are_dirty_without_count_changes() {
        let base = Snapshot::new(&groups(), vec![1, 2, 3]);
        assert_eq!(base, Snapshot::new(&groups(), vec![1, 2, 3]));
        for edit in 0..7 {
            let mut g = groups();
            let mut order = vec![1, 2, 3];
            match edit {
                0 => g[0].name = "xy".into(),
                1 => g[0].colour = 3,
                2 => g[0].tabs = vec![1, 3],
                3 => g[0].tabs.swap(0, 1),
                4 => g.swap(0, 1),
                5 => g.clear(),
                _ => order.swap(0, 1),
            }
            assert_ne!(base, Snapshot::new(&g, order), "edit {edit}");
        }
        assert_ne!(
            Snapshot::new(&groups()[..1], vec![1, 2, 3]),
            Snapshot::new(&[], vec![1, 2, 3])
        );
    }
    #[test]
    fn bar_swap_matters_even_when_serialized_group_positions_match() {
        let before = groups();
        let mut after = before.clone();
        after[0].tabs = vec![2, 1];
        assert_eq!(
            webprobe_core::send_group::to_project(&before, &[1, 2, 3])[0].tabs,
            webprobe_core::send_group::to_project(&after, &[2, 1, 3])[0].tabs
        );
        assert_ne!(
            Snapshot::new(&before, vec![1, 2, 3]),
            Snapshot::new(&after, vec![2, 1, 3])
        );
    }
    #[test]
    fn scheduled_group_only_edit_saves_and_loads_after_interval() {
        use std::time::{Duration, Instant};
        let mut app = crate::App::new(webprobe_core::net::Shared::new());
        let mut data = webprobe_core::project::ProjectData::default();
        data.repeaters
            .push(webprobe_core::project::ProjectRepeater {
                name: "one".into(),
                host: "localhost".into(),
                port: 80,
                https: false,
                request: "GET / HTTP/1.1\r\n\r\n".into(),
                response: None,
                response_b64: None,
                result_line: String::new(),
            });
        data.repeater_groups
            .push(webprobe_core::project::ProjectRepeaterGroup {
                name: "ab".into(),
                colour: 1,
                tabs: vec![0],
            });
        crate::tools::apply_project(&mut app, &data, true);
        let dir = std::env::temp_dir().join(format!(
            "webprobe-group-autosave-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("project.json");
        app.project_path = path.to_string_lossy().into_owned();
        let now = Instant::now();
        app.autosave_at = now;
        app.autosave_sig = crate::autosave_signature(&app);
        app.autosave_groups = capture(&app);
        app.rep_groups[0].name = "xy".into();
        app.rep_groups[0].colour = 4;
        assert!(!app.autosave_if_due(now + Duration::from_secs(59)));
        assert!(!path.exists());
        assert!(app.autosave_if_due(now + Duration::from_secs(60)));
        webprobe_core::project::wait_for_saves();
        let saved = webprobe_core::project::load(&path).unwrap();
        assert_eq!(saved.repeater_groups[0].name, "xy");
        assert_eq!(saved.repeater_groups[0].colour, 4);
        assert!(!app.autosave_if_due(now + Duration::from_secs(120)));
        app.rep_groups.clear();
        assert!(app.autosave_if_due(now + Duration::from_secs(180)));
        webprobe_core::project::wait_for_saves();
        assert!(webprobe_core::project::load(&path)
            .unwrap()
            .repeater_groups
            .is_empty());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}
