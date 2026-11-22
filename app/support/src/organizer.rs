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
    /// Owning collection id; 0 is the built-in Inbox.
    pub collection: u64,
}

/// A named user collection (Burp's Organizer "New collection").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collection {
    pub id: u64,
    pub name: String,
}

/// Ordered-by-id item store. Ids are monotonic and never reused.
#[derive(Debug, Default)]
pub struct Organizer {
    pub items: Vec<OrganizerItem>,
    pub next_id: u64,
    pub collections: Vec<Collection>,
    pub next_collection_id: u64,
    /// Collection that `add` files new items into (0 = Inbox); the UI keeps it
    /// in sync with the selected collection.
    pub target_collection: u64,
}

impl Organizer {
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            next_id: 1,
            collections: Vec::new(),
            next_collection_id: 1,
            target_collection: 0,
        }
    }

    fn unique_name(&self, name: &str, except: u64) -> String {
        let base = match name.trim() {
            "" => format!("Collection {}", self.collections.len() + 1),
            n => n.to_string(),
        };
        let mut unique = base.clone();
        let mut n = 2;
        while unique.eq_ignore_ascii_case("Inbox")
            || self
                .collections
                .iter()
                .any(|c| c.id != except && c.name == unique)
        {
            unique = format!("{base} {n}");
            n += 1;
        }
        unique
    }

    /// Create a named collection and return its id. A blank name becomes
    /// "Collection N"; a duplicate name (or "Inbox") gets " 2", " 3", ... appended.
    pub fn add_collection(&mut self, name: &str) -> u64 {
        let id = self.next_collection_id;
        self.next_collection_id = self.next_collection_id.saturating_add(1);
        let name = self.unique_name(name, 0);
        self.collections.push(Collection { id, name });
        id
    }

    /// Rename with the same uniqueness rules; blank names are rejected.
    pub fn rename_collection(&mut self, id: u64, name: &str) -> bool {
        if name.trim().is_empty() || !self.collections.iter().any(|c| c.id == id) {
            return false;
        }
        let name = self.unique_name(name, id);
        if let Some(c) = self.collections.iter_mut().find(|c| c.id == id) {
            c.name = name;
        }
        true
    }

    /// Delete a collection; its items move back to the Inbox, nothing is lost.
    pub fn remove_collection(&mut self, id: u64) -> bool {
        let before = self.collections.len();
        self.collections.retain(|c| c.id != id);
        for i in self.items.iter_mut().filter(|i| i.collection == id) {
            i.collection = 0;
        }
        self.collections.len() != before
    }

    /// Point every item whose collection no longer exists back at the Inbox.
    pub fn repair_collections(&mut self) {
        let ids: Vec<u64> = self.collections.iter().map(|c| c.id).collect();
        for i in self.items.iter_mut() {
            if i.collection != 0 && !ids.contains(&i.collection) {
                i.collection = 0;
            }
        }
    }

    pub fn collection_len(&self, id: u64) -> usize {
        self.items.iter().filter(|i| i.collection == id).count()
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
            collection: if self
                .collections
                .iter()
                .any(|c| c.id == self.target_collection)
            {
                self.target_collection
            } else {
                0
            },
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

    /// Move an item into a collection (0 = Inbox).
    pub fn move_item(&mut self, id: u64, collection: u64) -> bool {
        if collection != 0 && !self.collections.iter().any(|c| c.id == collection) {
            return false;
        }
        match self.items.iter_mut().find(|i| i.id == id) {
            Some(i) => {
                i.collection = collection;
                true
            }
            None => false,
        }
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
        o.add(
            "Upload",
            "file upload",
            "POST /up HTTP/1.1",
            "201 Created",
            20,
        );
        o.add(
            "Admin",
            "admin panel",
            "GET /admin HTTP/1.1",
            "403 Forbidden",
            30,
        );
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
    fn new_collection_is_named_and_not_an_inbox_item() {
        let mut o = org();
        let items_before = o.len();
        let a = o.add_collection("");
        let b = o.add_collection("Auth bugs");
        let c = o.add_collection("Auth bugs");
        assert_eq!(o.len(), items_before, "+ New must not add an item");
        assert!(o.items.iter().all(|i| i.name != "New item"));
        assert_eq!(o.collections.len(), 3);
        assert_eq!(o.collections[0].name, "Collection 1");
        assert_eq!(o.collections[1].name, "Auth bugs");
        assert_eq!(o.collections[2].name, "Auth bugs 2");
        assert!(a != b && b != c);
        assert!(o.rename_collection(b, "Renamed"));
        assert!(!o.rename_collection(b, "  "));
        assert!(!o.rename_collection(99, "x"));
        assert_eq!(o.collection_len(0), items_before);
        assert!(o.move_item(1, b));
        assert!(!o.move_item(1, 99));
        assert_eq!(o.collection_len(b), 1);
        assert_eq!(o.collection_len(0), items_before - 1);
        assert!(o.rename_collection(b, "Collection 1"));
        assert_eq!(o.collections[1].name, "Collection 1 2", "rename dedupes");
        assert!(o.rename_collection(b, "inbox"));
        assert_eq!(o.collections[1].name, "inbox 2");
        o.target_collection = b;
        let filed = o.add("sent", "", "GET /", "", 50);
        assert_eq!(
            o.get(filed).unwrap().collection,
            b,
            "send targets selected collection"
        );
        o.target_collection = 99;
        let stray = o.add("stray", "", "GET /", "", 51);
        assert_eq!(
            o.get(stray).unwrap().collection,
            0,
            "missing target falls back to Inbox"
        );
        assert!(o.remove_collection(b));
        assert_eq!(o.get(1).unwrap().collection, 0, "items return to Inbox");
        assert_eq!(o.get(filed).unwrap().collection, 0);
        o.items[0].collection = 77;
        o.repair_collections();
        assert_eq!(o.items[0].collection, 0, "orphans remapped");
        assert!(!o.remove_collection(b));
        assert_eq!(o.add_collection("Inbox"), 4);
        assert_eq!(o.collections.last().unwrap().name, "Inbox 2");
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
