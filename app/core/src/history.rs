//! Proxy history (and the crawl's site map items) as an owned type (N-07).
//!
//! The entries are private: every write goes through a method that moves the
//! bodies into the on-disk store (`HistEntry::spilled`), so a path that
//! forgets to spill no longer compiles. Readers get short, scoped access
//! (`with_rows`, `get`, `snapshot`) and never hold the lock while doing UI or
//! network work.

use crate::net::HistEntry;
use crate::sync::Mutex;

#[derive(Default)]
pub struct ProxyHistory {
    rows: Mutex<Vec<HistEntry>>,
}

impl ProxyHistory {
    /// Append one entry (bodies spilled).
    pub fn push(&self, e: HistEntry) {
        let e = e.spilled();
        self.rows.lock().unwrap().push(e);
    }

    /// Append several entries (bodies spilled), in order.
    pub fn extend(&self, entries: impl IntoIterator<Item = HistEntry>) {
        let entries: Vec<HistEntry> = entries.into_iter().map(HistEntry::spilled).collect();
        self.rows.lock().unwrap().extend(entries);
    }

    /// Replace every entry (project load), bodies spilled.
    pub fn replace_all(&self, entries: impl IntoIterator<Item = HistEntry>) {
        let entries: Vec<HistEntry> = entries.into_iter().map(HistEntry::spilled).collect();
        *self.rows.lock().unwrap() = entries;
    }

    pub fn clear(&self) {
        self.rows.lock().unwrap().clear();
    }

    pub fn len(&self) -> usize {
        self.rows.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// (number of entries, id of the newest): changes whenever entries are
    /// added or removed, for caches keyed on the history.
    pub fn stamp(&self) -> (usize, u64) {
        let rows = self.rows.lock().unwrap();
        (rows.len(), rows.last().map(|e| e.id).unwrap_or(0))
    }

    /// The entry with `id`.
    pub fn get(&self, id: u64) -> Option<HistEntry> {
        self.rows.lock().unwrap().iter().find(|e| e.id == id).cloned()
    }

    /// The newest entry.
    pub fn last(&self) -> Option<HistEntry> {
        self.rows.lock().unwrap().last().cloned()
    }

    /// Every entry, oldest first. Cheap: bodies are shared handles.
    pub fn snapshot(&self) -> Vec<HistEntry> {
        self.rows.lock().unwrap().clone()
    }

    /// Read access for the length of `f`. Keep `f` short: proxy threads
    /// wait for this lock to record traffic.
    pub fn with_rows<R>(&self, f: impl FnOnce(&[HistEntry]) -> R) -> R {
        f(&self.rows.lock().unwrap())
    }

    /// Keep the entries `keep` accepts; returns how many were removed.
    pub fn retain(&self, keep: impl FnMut(&HistEntry) -> bool) -> usize {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(keep);
        before - rows.len()
    }

    /// Change the entry with `id` in place (notes, highlight); false when
    /// there is none. Bodies set by `f` are spilled.
    pub fn update(&self, id: u64, f: impl FnOnce(&mut HistEntry)) -> bool {
        let mut rows = self.rows.lock().unwrap();
        let Some(e) = rows.iter_mut().find(|e| e.id == id) else { return false };
        f(e);
        *e = std::mem::take(e).spilled();
        true
    }

    /// Change every entry `pick` selects; returns how many.
    pub fn update_where(&self, mut pick: impl FnMut(&HistEntry) -> bool, mut f: impl FnMut(&mut HistEntry)) -> usize {
        let mut rows = self.rows.lock().unwrap();
        let mut n = 0;
        for e in rows.iter_mut().filter(|e| pick(e)) {
            f(e);
            *e = std::mem::take(e).spilled();
            n += 1;
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_spill_and_reads_are_scoped() {
        let h = ProxyHistory::default();
        let big = vec![b'x'; 4096];
        h.push(HistEntry { id: 1, resp_raw: Some(big.clone().into()), ..Default::default() });
        h.extend([HistEntry { id: 2, ..Default::default() }, HistEntry { id: 3, ..Default::default() }]);
        assert_eq!(h.stamp(), (3, 3));
        if cfg!(unix) {
            assert!(h.get(1).unwrap().resp_raw.unwrap().is_stored(), "pushed bodies are spilled");
        }
        assert!(h.update(2, |e| e.note = Some("n".into())));
        assert!(!h.update(9, |_| {}));
        assert_eq!(h.get(2).unwrap().note.as_deref(), Some("n"));
        assert_eq!(h.update_where(|e| e.id >= 2, |e| e.highlight = Some(1)), 2);
        assert_eq!(h.retain(|e| e.id != 3), 1);
        assert_eq!(h.with_rows(|r| r.iter().map(|e| e.id).collect::<Vec<_>>()), [1, 2]);
        h.replace_all([HistEntry { id: 7, ..Default::default() }]);
        assert_eq!((h.len(), h.last().map(|e| e.id)), (1, Some(7)));
        h.clear();
        assert!(h.is_empty());
    }
}
