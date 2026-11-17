//! Burp-style Organizer: a flat, named collection of saved requests and
//! responses that survives across tools. Items keep their id for their whole
//! lifetime; removing one never renumbers the others.

/// One saved request/response pair with user metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrganizerItem {
    pub id: u64,
    pub name: String,
    pub note: String,
    pub request: String,
    pub response: String,
    pub created: u64,
}

/// Ordered-by-id item store. Ids are monotonic and never reused.
#[derive(Debug, Default)]
pub struct Organizer {
    pub items: Vec<OrganizerItem>,
    pub next_id: u64,
}

impl Organizer {
    pub fn new() -> Self {
        Self { items: Vec::new(), next_id: 1 }
    }

    /// Store a new item and return its id. `now` is the creation timestamp
    /// supplied by the caller (epoch seconds or millis).
    pub fn add(&mut self, name: &str, note: &str, request: &str, response: &str, now: u64) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.items.push(OrganizerItem {
            id,
            name: name.to_string(),
            note: note.to_string(),
            request: request.to_string(),
            response: response.to_string(),
            created: now,
        });
        id
    }

    /// Remove the item with `id`; false when it does not exist.
    pub fn remove(&mut self, id: u64) -> bool {
        let before = self.items.len();
        self.items.retain(|i| i.id != id);
        self.items.len() != before
    }

    pub fn rename(&mut self, id: u64, name: &str) -> bool {
        match self.items.iter_mut().find(|i| i.id == id) {
            Some(item) => {
                item.name = name.to_string();
                true
            }
            None => false,
        }
    }

    pub fn set_note(&mut self, id: u64, note: &str) -> bool {
        match self.items.iter_mut().find(|i| i.id == id) {
            Some(item) => {
                item.note = note.to_string();
                true
            }
            None => false,
        }
    }

    pub fn get(&self, id: u64) -> Option<&OrganizerItem> {
        self.items.iter().find(|i| i.id == id)
    }

    /// All items sorted by id (insertion order, since ids only grow).
    pub fn list(&self) -> Vec<&OrganizerItem> {
        let mut out: Vec<&OrganizerItem> = self.items.iter().collect();
        out.sort_by_key(|i| i.id);
        out
    }

    /// Case-insensitive substring match over name and note.
    pub fn search(&self, text: &str) -> Vec<&OrganizerItem> {
        let needle = text.trim().to_lowercase();
        let mut out: Vec<&OrganizerItem> = if needle.is_empty() {
            self.items.iter().collect()
        } else {
            self.items
                .iter()
                .filter(|i| {
                    i.name.to_lowercase().contains(&needle)
                        || i.note.to_lowercase().contains(&needle)
                })
                .collect()
        };
        out.sort_by_key(|i| i.id);
        out
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn org() -> Organizer {
        let mut o = Organizer::new();
        o.add("Login", "auth flow", "GET /login HTTP/1.1", "200 OK", 10);
        o.add("Upload", "file upload", "POST /up HTTP/1.1", "201 Created", 20);
        o.add("Admin", "admin panel", "GET /admin HTTP/1.1", "403 Forbidden", 30);
        o
    }

    #[test]
    fn add_and_get() {
        let o = org();
        assert_eq!(o.len(), 3);
        let item = o.get(2).expect("item 2");
        assert_eq!(item.name, "Upload");
        assert_eq!(item.note, "file upload");
        assert_eq!(item.request, "POST /up HTTP/1.1");
        assert_eq!(item.response, "201 Created");
        assert_eq!(item.created, 20);
        assert!(o.get(99).is_none());
    }

    #[test]
    fn remove_reports_success() {
        let mut o = org();
        assert!(o.remove(2));
        assert!(!o.remove(2));
        assert_eq!(o.len(), 2);
        assert!(o.get(2).is_none());
    }

    #[test]
    fn rename_and_set_note() {
        let mut o = org();
        assert!(o.rename(1, "Login v2"));
        assert!(o.set_note(1, "updated note"));
        assert!(!o.rename(42, "nope"));
        assert!(!o.set_note(42, "nope"));
        let item = o.get(1).unwrap();
        assert_eq!(item.name, "Login v2");
        assert_eq!(item.note, "updated note");
        // Other items untouched.
        assert_eq!(o.get(2).unwrap().name, "Upload");
    }

    #[test]
    fn search_matches_name_and_note_case_insensitively() {
        let o = org();
        assert_eq!(o.search("login").len(), 1);
        assert_eq!(o.search("LOGIN")[0].id, 1);
        assert_eq!(o.search("file").len(), 1); // note only
        assert_eq!(o.search("panel").len(), 1); // note only
        assert!(o.search("missing").is_empty());
        assert_eq!(o.search("  ").len(), 3); // empty query lists all
    }

    #[test]
    fn ids_stay_stable_after_removal() {
        let mut o = org();
        o.remove(2);
        assert_eq!(o.add("New", "", "GET /new", "", 40), 4);
        let ids: Vec<u64> = o.list().iter().map(|i| i.id).collect();
        assert_eq!(ids, vec![1, 3, 4]);
        assert_eq!(o.get(3).unwrap().name, "Admin");
    }

    #[test]
    fn list_is_sorted_by_id() {
        let mut o = Organizer::new();
        // Insertion order is already id order; list must be stable regardless.
        let a = o.add("a", "", "", "", 1);
        let b = o.add("b", "", "", "", 2);
        let ids: Vec<u64> = o.list().iter().map(|i| i.id).collect();
        assert_eq!(ids, vec![a, b]);
    }
}
