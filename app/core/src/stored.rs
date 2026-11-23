//! Stored input pairing (D-10), after Burp's scanner:
//!
//! * every audited insertion point gets a token that names it (burp.Zi00:
//!   a `Zinn` of task, item, STORED_DATA_REPLACE and point, wrapped as a
//!   Collaborator-style id), injected in place of the value by the
//!   stored-input probe (burp.Zx2y through burp.Zwp0's stage A2);
//! * every response the scan receives is searched for the tokens of
//!   other points (burp.Zhqw.detectAndReport, burp.Zchm / Zwd9 parse the
//!   ids, burp.Zp0f leaves out the probe's own token); a hit records the
//!   pair (injection item, point, retrieval item) (burp.Zml_ -> Zwcz) and
//!   raises "Input returned in response (stored)" once per pair (burp.Zpwn);
//! * after the audit, the stored checks run per pair, each send followed by
//!   the retrieval item's own request (burp.Zwp6 stage A4, burp.Zpqv.Z_).
//!
//! The store lives for one scan run: a single-item scan, or a batch (a task
//! of several items, a crawl and audit), and is cleared when the next one
//! begins. All state is private; the scan reaches it through the methods.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::sync::Mutex;
use webprobe_support::hist::HistEntry;
use webprobe_support::insertion::InsertionPoint;

/// The token prefix: fixed, so one pass over a response finds every token.
/// Burp's tokens are Collaborator ids (net.portswigger.Zwl, found with
/// net.portswigger.Zet); WebProbe has no Collaborator id space to borrow, so
/// a fixed prefix plus a random body stands in for it.
pub const TOKEN_PREFIX: &str = "zwq7";
/// Random characters after the prefix (lowercase letters and digits).
pub const TOKEN_BODY: usize = 12;

/// One audited request.
#[derive(Clone)]
pub struct Item {
    pub entry: HistEntry,
    pub req: String,
    pub host: String,
    pub port: u16,
    pub https: bool,
}

impl Item {
    /// scheme://host[:port]/path?query, as Burp prints item URLs.
    pub fn url(&self) -> String {
        let scheme = if self.https { "https" } else { "http" };
        let default = if self.https { 443 } else { 80 };
        let path = crate::util::parse_http(self.req.as_bytes()).path;
        // An absolute-form request line keeps only its path.
        let path = match path
            .split_once("://")
            .and_then(|(_, rest)| rest.find('/').map(|i| rest[i..].to_string()))
        {
            Some(p) if !path.starts_with('/') => p,
            _ => path,
        };
        if self.port == default {
            format!("{scheme}://{}{path}", self.host)
        } else {
            format!("{scheme}://{}:{}{path}", self.host, self.port)
        }
    }
}

/// A recorded pair: input sent to `point` of item `item` came back in the
/// response to item `retrieval`.
#[derive(Clone)]
pub(crate) struct Pair {
    pub item: Item,
    pub point: InsertionPoint,
    pub retrieval: Item,
    /// The request that carried the token, and its response.
    pub injection: (Vec<u8>, Option<Vec<u8>>),
}

/// (item, point, request bytes, injected value) of one stored token.
type StoredPoint = (usize, InsertionPoint, Vec<u8>, Option<Vec<u8>>);

#[derive(Default)]
struct Inner {
    #[cfg(test)]
    strict: bool,
    #[cfg(test)]
    generation: Option<(
        std::sync::Weak<crate::host_probe_state::AttemptScope>,
        std::sync::Weak<()>,
    )>,
    items: Vec<Item>,
    /// (item, point) of each injected token.
    tokens: HashMap<String, usize>,
    points: Vec<StoredPoint>,
    /// token per (item, point identity), so a point keeps its token.
    by_point: HashMap<(usize, String), String>,
    /// (point index, retrieval item) pairs, in the order found.
    pairs: Vec<(usize, usize)>,
    seen: HashSet<(usize, usize)>,
}

#[derive(Default)]
pub struct StoredInputs {
    inner: Mutex<Inner>,
    /// A batch (task or crawl) holds the store across its items.
    batch: AtomicBool,
}

fn point_key(p: &InsertionPoint) -> String {
    format!(
        "{:?}|{}|{:?}",
        p.kind,
        p.name,
        p.parent.as_ref().map(|q| format!("{:?}{}", q.kind, q.name))
    )
}

impl StoredInputs {
    fn raw_inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        let inner = self.inner.lock().unwrap();
        #[cfg(test)]
        if inner.strict {
            drop(inner);
            panic!("prohibited raw StoredInputs access during strict generation");
        }
        inner
    }
    #[cfg(test)]
    pub(crate) fn set_generation_strict(&self, generation: &StoreGeneration) -> Result<(), ()> {
        let mut inner = self.inner.lock().unwrap();
        generation.validate(&inner).map_err(|_| ())?;
        inner.strict = true;
        Ok(())
    }

    /// Forget everything (a new scan run).
    pub fn clear(&self) {
        *self.raw_inner() = Inner::default();
    }

    /// Start a batch: cleared once here, kept across its items. False when
    /// a batch is already open (the caller then neither clears nor closes).
    pub fn open_batch(&self) -> bool {
        #[cfg(test)]
        {
            let mut inner = self.raw_inner();
            if self.batch.swap(true, Ordering::SeqCst) {
                return false;
            }
            *inner = Inner::default();
            true
        }
        #[cfg(not(test))]
        {
            if self.batch.swap(true, Ordering::SeqCst) {
                return false;
            }
            self.clear();
            true
        }
    }

    pub fn close_batch(&self) {
        #[cfg(test)]
        {
            let _inner = self.raw_inner();
            self.batch.store(false, Ordering::SeqCst);
        }
        #[cfg(not(test))]
        {
            self.batch.store(false, Ordering::SeqCst);
        }
    }

    pub fn in_batch(&self) -> bool {
        #[cfg(test)]
        {
            let _inner = self.raw_inner();
            self.batch.load(Ordering::SeqCst)
        }
        #[cfg(not(test))]
        {
            self.batch.load(Ordering::SeqCst)
        }
    }

    /// Register an audited item; its index names it from now on.
    pub fn add_item(&self, item: Item) -> usize {
        let mut g = self.raw_inner();
        g.items.push(item);
        g.items.len() - 1
    }

    pub fn item(&self, idx: usize) -> Option<Item> {
        self.raw_inner().items.get(idx).cloned()
    }

    /// The token of `point` of item `item` (the same one each time).
    pub(crate) fn token(&self, item: usize, point: &InsertionPoint) -> String {
        let mut g = self.raw_inner();
        let key = (item, point_key(point));
        if let Some(t) = g.by_point.get(&key) {
            return t.clone();
        }
        let token = loop {
            let t = format!(
                "{TOKEN_PREFIX}{}",
                webprobe_support::util::rnd_id(TOKEN_BODY)
            );
            if !g.tokens.contains_key(&t) {
                break t;
            }
        };
        g.points.push((item, point.clone(), Vec::new(), None));
        let idx = g.points.len() - 1;
        g.tokens.insert(token.clone(), idx);
        g.by_point.insert(key, token.clone());
        token
    }

    /// Keep the exchange that first carried `token` (evidence for the
    /// stored-input issue).
    pub(crate) fn note_injection(&self, token: &str, request: &[u8], response: Option<&[u8]>) {
        let mut g = self.raw_inner();
        if let Some(&idx) = g.tokens.get(token) {
            if g.points[idx].2.is_empty() {
                g.points[idx].2 = request.to_vec();
                g.points[idx].3 = response.map(<[u8]>::to_vec);
            }
        }
    }

    /// Search one response to item `retrieval` for tokens of other points
    /// (one pass: every occurrence of the fixed prefix, then a lookup).
    /// Tokens the request itself carries are not stored input (burp.Zp0f).
    /// Returns the pairs seen for the first time.
    pub(crate) fn observe(&self, retrieval: usize, request: &[u8], response: &[u8]) -> Vec<Pair> {
        #[cfg(test)]
        drop(self.raw_inner());

        let found = find_tokens(response);
        if found.is_empty() {
            return Vec::new();
        }
        let own = find_tokens(request);
        let mut g = self.raw_inner();
        let mut new = Vec::new();
        for t in found {
            if own.contains(&t) {
                continue;
            }
            let Some(&pidx) = g.tokens.get(&t) else {
                continue;
            };
            if retrieval >= g.items.len() || !g.seen.insert((pidx, retrieval)) {
                continue;
            }
            g.pairs.push((pidx, retrieval));
            let (item, point, req, resp) = g.points[pidx].clone();
            new.push(Pair {
                item: g.items[item].clone(),
                point,
                retrieval: g.items[retrieval].clone(),
                injection: (req, resp),
            });
        }
        new
    }

    /// Every recorded pair, in the order found.
    pub(crate) fn pairs(&self) -> Vec<Pair> {
        let g = self.raw_inner();
        g.pairs
            .iter()
            .map(|&(pidx, r)| {
                let (item, point, req, resp) = g.points[pidx].clone();
                Pair {
                    item: g.items[item].clone(),
                    point,
                    retrieval: g.items[r].clone(),
                    injection: (req, resp),
                }
            })
            .collect()
    }

    /// Experimental A4 indexed retrieval. Reject before cloning input-owned
    /// bytes. Body handles are Arc-backed; string/point/evidence clones count.
    #[cfg(test)]
    pub(crate) fn pair_bounded(
        &self,
        index: usize,
        max_bytes: usize,
        admit: impl FnOnce(usize) -> bool,
    ) -> Result<Option<Pair>, ()> {
        fn item_size(item: &Item) -> Option<usize> {
            let e = &item.entry;
            [
                item.req.len(),
                item.host.len(),
                e.method.len(),
                e.host.len(),
                e.path.len(),
                e.status.len(),
                e.note.as_ref().map_or(0, String::len),
                e.extension.len(),
                e.title.len(),
                e.cookies.len(),
                e.ip.len(),
            ]
            .into_iter()
            .try_fold(std::mem::size_of::<Item>(), usize::checked_add)
        }
        fn point_size(p: &InsertionPoint, depth: usize) -> Option<usize> {
            if depth >= 16 {
                return None;
            }
            let kind = match &p.kind {
                webprobe_support::insertion::IpKind::Json(v) => {
                    if v.len() > 256 {
                        return None;
                    }
                    v.iter().try_fold(
                        v.len().checked_mul(std::mem::size_of::<String>())?,
                        |n, s| n.checked_add(s.len()),
                    )?
                }
                webprobe_support::insertion::IpKind::Multipart { filename, .. } => {
                    filename.as_ref().map_or(0, String::len)
                }
                _ => 0,
            };
            std::mem::size_of::<InsertionPoint>()
                .checked_add(p.name.len())?
                .checked_add(p.value.len())?
                .checked_add(kind)?
                .checked_add(match &p.parent {
                    Some(p) => point_size(p, depth + 1)?,
                    None => 0,
                })
        }
        let g = self.raw_inner();
        let Some(&(pidx, retrieval)) = g.pairs.get(index) else {
            return Ok(None);
        };
        let Some((item, point, req, resp)) = g.points.get(pidx) else {
            return Err(());
        };
        let Some(injection_item) = g.items.get(*item) else {
            return Err(());
        };
        let Some(retrieval_item) = g.items.get(retrieval) else {
            return Err(());
        };
        let bytes = item_size(injection_item)
            .and_then(|n| n.checked_add(item_size(retrieval_item)?))
            .and_then(|n| n.checked_add(point_size(point, 0)?))
            .and_then(|n| n.checked_add(req.len()))
            .and_then(|n| n.checked_add(resp.as_ref().map_or(0, Vec::len)))
            .ok_or(())?;
        if bytes > max_bytes || !admit(bytes) {
            return Err(());
        }
        Ok(Some(Pair {
            item: injection_item.clone(),
            point: point.clone(),
            retrieval: retrieval_item.clone(),
            injection: (req.clone(), resp.clone()),
        }))
    }

    #[cfg(test)]
    pub(crate) fn has_pair(&self, index: usize) -> bool {
        self.raw_inner().pairs.get(index).is_some()
    }

    pub fn is_empty(&self) -> bool {
        let g = self.raw_inner();
        g.items.is_empty() && g.pairs.is_empty()
    }
}

/// Every distinct token in `bytes`: the prefix, then exactly TOKEN_BODY
/// lowercase letters or digits.
pub fn find_tokens(bytes: &[u8]) -> Vec<String> {
    find_tokens_counted(bytes, &mut 0)
}

/// [`find_tokens`], adding the bytes it examined to `work` (one pass: the
/// count stays within a small constant times the body length).
fn find_tokens_counted(bytes: &[u8], work: &mut usize) -> Vec<String> {
    let p = TOKEN_PREFIX.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i + p.len() + TOKEN_BODY <= bytes.len() {
        // Skip to the next prefix start byte.
        match bytes[i..].iter().position(|&b| b == p[0]) {
            Some(off) => {
                *work += off + 1;
                i += off;
            }
            None => {
                *work += bytes.len() - i;
                break;
            }
        }
        if i + p.len() + TOKEN_BODY > bytes.len() {
            break;
        }
        *work += p.len();
        if &bytes[i..i + p.len()] == p {
            let body = &bytes[i + p.len()..i + p.len() + TOKEN_BODY];
            *work += TOKEN_BODY;
            if body
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            {
                let t = String::from_utf8_lossy(&bytes[i..i + p.len() + TOKEN_BODY]).into_owned();
                if !out.contains(&t) {
                    out.push(t);
                }
                i += p.len() + TOKEN_BODY;
                continue;
            }
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use webprobe_support::insertion::{InsertionPoint, IpKind};

    fn item(path: &str) -> Item {
        Item {
            entry: HistEntry::default(),
            req: format!("GET {path} HTTP/1.1\r\nHost: h\r\n\r\n"),
            host: "h".into(),
            port: 80,
            https: false,
        }
    }

    #[test]
    fn bounded_pair_rejects_many_empty_json_elements_before_clone_and_preserves_next() {
        let s = StoredInputs::default();
        let injection = s.add_item(item("/inject"));
        let retrieval = s.add_item(item("/retrieve"));
        let point = InsertionPoint::new(
            webprobe_support::insertion::IpKind::Json(vec![String::new(); 10000]),
            "x",
            "",
        );
        let token = s.token(injection, &point);
        s.observe(retrieval, b"GET /retrieve", token.as_bytes());
        let admitted = std::cell::Cell::new(false);
        assert!(s
            .pair_bounded(0, 1024 * 1024, |_| {
                admitted.set(true);
                true
            })
            .is_err());
        assert!(!admitted.get());
        let valid = InsertionPoint::new(webprobe_support::insertion::IpKind::Query, "y", "");
        let next = s.token(injection, &valid);
        s.observe(retrieval, b"GET /retrieve", next.as_bytes());
        assert!(s.has_pair(0));
        assert!(s.pair_bounded(1, 1024 * 1024, |_| true).unwrap().is_some());
        assert!(!s.has_pair(2));
    }
    #[test]
    fn tokens_pair_once_and_never_with_their_own_request() {
        let s = StoredInputs::default();
        let a = s.add_item(item("/comment"));
        let b = s.add_item(item("/list"));
        let p = InsertionPoint::new(IpKind::Body, "c", "hi");
        let t = s.token(a, &p);
        assert_eq!(s.token(a, &p), t, "one token per point");
        assert!(t.starts_with(TOKEN_PREFIX) && t.len() == TOKEN_PREFIX.len() + TOKEN_BODY);
        // The probe's own response echoing its token is not stored input.
        assert!(s
            .observe(
                a,
                format!("POST /comment c={t}").as_bytes(),
                format!("<p>{t}</p>").as_bytes()
            )
            .is_empty());
        // Another item showing it is.
        let got = s.observe(
            b,
            b"GET /list",
            format!("<li>{t}</li><li>{t}</li>").as_bytes(),
        );
        assert_eq!(got.len(), 1);
        assert_eq!(
            (
                got[0].item.url(),
                got[0].retrieval.url(),
                got[0].point.name.as_str()
            ),
            ("http://h/comment".into(), "http://h/list".into(), "c")
        );
        assert!(
            s.observe(b, b"GET /list", t.as_bytes()).is_empty(),
            "recorded once"
        );
        // Unknown tokens and near misses are ignored.
        assert!(s
            .observe(b, b"", b"zwq7abcdefghijkl zwq7ABCDEFGHIJKL zwq7short")
            .is_empty());
        assert_eq!(s.pairs().len(), 1);
        s.clear();
        assert!(s.pairs().is_empty() && s.is_empty());
    }

    #[test]
    fn find_tokens_is_one_pass_over_large_bodies() {
        // Worst case: every byte starts the prefix. The bytes examined stay
        // linear in the body (a small constant per byte) and double when
        // the body doubles.
        let work = |n: usize| {
            let mut body = vec![b'z'; n];
            body.extend_from_slice(b"zwq7abc123def456!");
            let mut w = 0;
            assert_eq!(
                find_tokens_counted(&body, &mut w),
                vec!["zwq7abc123def456".to_string()]
            );
            (w, body.len())
        };
        let (small, n) = work(1 << 20);
        let (big, m) = work(4 << 20);
        assert!(
            small <= 8 * n && big <= 8 * m,
            "{small} for {n} bytes, {big} for {m}"
        );
        let ratio = big as f64 / small as f64;
        assert!(
            (3.5..4.5).contains(&ratio),
            "work grew {ratio}x for 4x the body"
        );
    }

    #[test]
    fn a_batch_keeps_the_store_across_items() {
        let s = StoredInputs::default();
        assert!(s.open_batch());
        s.add_item(item("/a"));
        assert!(!s.open_batch(), "already open: no clear");
        assert!(!s.is_empty());
        s.close_batch();
        assert!(s.open_batch(), "a new batch clears");
        assert!(s.is_empty());
    }
}

#[cfg(test)]
impl Inner {
    #[cfg(test)]
    fn pair_bounded(
        &self,
        index: usize,
        max_bytes: usize,
        admit: impl FnOnce(usize) -> bool,
    ) -> Result<Option<Pair>, ()> {
        fn item_size(item: &Item) -> Option<usize> {
            let e = &item.entry;
            [
                item.req.len(),
                item.host.len(),
                e.method.len(),
                e.host.len(),
                e.path.len(),
                e.status.len(),
                e.note.as_ref().map_or(0, String::len),
                e.extension.len(),
                e.title.len(),
                e.cookies.len(),
                e.ip.len(),
            ]
            .into_iter()
            .try_fold(std::mem::size_of::<Item>(), usize::checked_add)
        }
        fn point_size(p: &InsertionPoint, depth: usize) -> Option<usize> {
            if depth >= 16 {
                return None;
            }
            let kind = match &p.kind {
                webprobe_support::insertion::IpKind::Json(v) => {
                    if v.len() > 256 {
                        return None;
                    }
                    v.iter().try_fold(
                        v.len().checked_mul(std::mem::size_of::<String>())?,
                        |n, s| n.checked_add(s.len()),
                    )?
                }
                webprobe_support::insertion::IpKind::Multipart { filename, .. } => {
                    filename.as_ref().map_or(0, String::len)
                }
                _ => 0,
            };
            std::mem::size_of::<InsertionPoint>()
                .checked_add(p.name.len())?
                .checked_add(p.value.len())?
                .checked_add(kind)?
                .checked_add(match &p.parent {
                    Some(p) => point_size(p, depth + 1)?,
                    None => 0,
                })
        }
        let g = self;
        let Some(&(pidx, retrieval)) = g.pairs.get(index) else {
            return Ok(None);
        };
        let Some((item, point, req, resp)) = g.points.get(pidx) else {
            return Err(());
        };
        let Some(injection_item) = g.items.get(*item) else {
            return Err(());
        };
        let Some(retrieval_item) = g.items.get(retrieval) else {
            return Err(());
        };
        let bytes = item_size(injection_item)
            .and_then(|n| n.checked_add(item_size(retrieval_item)?))
            .and_then(|n| n.checked_add(point_size(point, 0)?))
            .and_then(|n| n.checked_add(req.len()))
            .and_then(|n| n.checked_add(resp.as_ref().map_or(0, Vec::len)))
            .ok_or(())?;
        if bytes > max_bytes || !admit(bytes) {
            return Err(());
        }
        Ok(Some(Pair {
            item: injection_item.clone(),
            point: point.clone(),
            retrieval: retrieval_item.clone(),
            injection: (req.clone(), resp.clone()),
        }))
    }

    fn add_item(&mut self, item: Item) -> usize {
        let g = self;
        g.items.push(item);
        g.items.len() - 1
    }
    fn item(&mut self, idx: usize) -> Option<Item> {
        self.items.get(idx).cloned()
    }
    fn token(&mut self, item: usize, point: &InsertionPoint) -> String {
        let g = self;
        let key = (item, point_key(point));
        if let Some(t) = g.by_point.get(&key) {
            return t.clone();
        }
        let token = loop {
            let t = format!(
                "{TOKEN_PREFIX}{}",
                webprobe_support::util::rnd_id(TOKEN_BODY)
            );
            if !g.tokens.contains_key(&t) {
                break t;
            }
        };
        g.points.push((item, point.clone(), Vec::new(), None));
        let idx = g.points.len() - 1;
        g.tokens.insert(token.clone(), idx);
        g.by_point.insert(key, token.clone());
        token
    }
    fn note_injection(&mut self, token: &str, request: &[u8], response: Option<&[u8]>) {
        let g = self;
        if let Some(&idx) = g.tokens.get(token) {
            if g.points[idx].2.is_empty() {
                g.points[idx].2 = request.to_vec();
                g.points[idx].3 = response.map(<[u8]>::to_vec);
            }
        }
    }
    fn observe(&mut self, retrieval: usize, request: &[u8], response: &[u8]) -> Vec<Pair> {
        let found = find_tokens(response);
        if found.is_empty() {
            return Vec::new();
        }
        let own = find_tokens(request);
        let g = self;
        let mut new = Vec::new();
        for t in found {
            if own.contains(&t) {
                continue;
            }
            let Some(&pidx) = g.tokens.get(&t) else {
                continue;
            };
            if retrieval >= g.items.len() || !g.seen.insert((pidx, retrieval)) {
                continue;
            }
            g.pairs.push((pidx, retrieval));
            let (item, point, req, resp) = g.points[pidx].clone();
            new.push(Pair {
                item: g.items[item].clone(),
                point,
                retrieval: g.items[retrieval].clone(),
                injection: (req, resp),
            });
        }
        new
    }
    fn pairs(&mut self) -> Vec<Pair> {
        let g = self;
        g.pairs
            .iter()
            .map(|&(pidx, r)| {
                let (item, point, req, resp) = g.points[pidx].clone();
                Pair {
                    item: g.items[item].clone(),
                    point,
                    retrieval: g.items[r].clone(),
                    injection: (req, resp),
                }
            })
            .collect()
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StoreAccessError {
    StaleGeneration,
    InvalidItem,
    PairLimitOrAdmission,
}
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct StoreGeneration {
    shared: std::sync::Weak<crate::net::Shared>,
    owner: std::sync::Arc<crate::host_probe_state::AttemptScope>,
    identity: std::sync::Arc<()>,
}
#[cfg(test)]
impl StoreGeneration {
    fn validate(&self, inner: &Inner) -> Result<(), StoreAccessError> {
        if inner
            .generation
            .as_ref()
            .is_some_and(|(owner, generation)| {
                owner.ptr_eq(&std::sync::Arc::downgrade(&self.owner))
                    && generation.ptr_eq(&std::sync::Arc::downgrade(&self.identity))
            })
        {
            Ok(())
        } else {
            Err(StoreAccessError::StaleGeneration)
        }
    }
    pub(crate) fn add_item(&self, item: Item) -> Result<usize, StoreAccessError> {
        let shared = self
            .shared
            .upgrade()
            .ok_or(StoreAccessError::StaleGeneration)?;
        let mut inner = shared.stored.inner.lock().unwrap();
        self.validate(&inner)?;
        Ok(inner.add_item(item))
    }
    pub(crate) fn item(&self, idx: usize) -> Result<Option<Item>, StoreAccessError> {
        let shared = self
            .shared
            .upgrade()
            .ok_or(StoreAccessError::StaleGeneration)?;
        let mut inner = shared.stored.inner.lock().unwrap();
        self.validate(&inner)?;
        Ok(inner.item(idx))
    }
    pub(crate) fn token(
        &self,
        item: usize,
        point: &InsertionPoint,
    ) -> Result<String, StoreAccessError> {
        let shared = self
            .shared
            .upgrade()
            .ok_or(StoreAccessError::StaleGeneration)?;
        let mut inner = shared.stored.inner.lock().unwrap();
        self.validate(&inner)?;
        if item >= inner.items.len() {
            return Err(StoreAccessError::InvalidItem);
        }
        Ok(inner.token(item, point))
    }
    pub(crate) fn note_injection(
        &self,
        token: &str,
        request: &[u8],
        response: Option<&[u8]>,
    ) -> Result<(), StoreAccessError> {
        let shared = self
            .shared
            .upgrade()
            .ok_or(StoreAccessError::StaleGeneration)?;
        let mut inner = shared.stored.inner.lock().unwrap();
        self.validate(&inner)?;
        inner.note_injection(token, request, response);
        Ok(())
    }
    pub(crate) fn observe(
        &self,
        retrieval: usize,
        request: &[u8],
        response: &[u8],
    ) -> Result<Vec<Pair>, StoreAccessError> {
        let shared = self
            .shared
            .upgrade()
            .ok_or(StoreAccessError::StaleGeneration)?;
        let mut inner = shared.stored.inner.lock().unwrap();
        self.validate(&inner)?;
        Ok(inner.observe(retrieval, request, response))
    }
    pub(crate) fn pairs(&self) -> Result<Vec<Pair>, StoreAccessError> {
        let shared = self
            .shared
            .upgrade()
            .ok_or(StoreAccessError::StaleGeneration)?;
        let mut inner = shared.stored.inner.lock().unwrap();
        self.validate(&inner)?;
        Ok(inner.pairs())
    }
    pub(crate) fn pair_bounded(
        &self,
        index: usize,
        max_bytes: usize,
    ) -> Result<Option<Pair>, StoreAccessError> {
        let shared = self
            .shared
            .upgrade()
            .ok_or(StoreAccessError::StaleGeneration)?;
        let inner = shared.stored.inner.lock().unwrap();
        self.validate(&inner)?;
        inner
            .pair_bounded(index, max_bytes, |_| true)
            .map_err(|_| StoreAccessError::PairLimitOrAdmission)
    }
    pub(crate) fn has_pair(&self, index: usize) -> Result<bool, StoreAccessError> {
        let shared = self
            .shared
            .upgrade()
            .ok_or(StoreAccessError::StaleGeneration)?;
        let inner = shared.stored.inner.lock().unwrap();
        self.validate(&inner)?;
        Ok(inner.pairs.get(index).is_some())
    }
    pub(crate) fn pair_bounded_admit(
        &self,
        index: usize,
        max_bytes: usize,
        admit: impl FnOnce(usize) -> bool,
    ) -> Result<Option<Pair>, StoreAccessError> {
        let shared = self
            .shared
            .upgrade()
            .ok_or(StoreAccessError::StaleGeneration)?;
        let inner = shared.stored.inner.lock().unwrap();
        self.validate(&inner)?;
        inner
            .pair_bounded(index, max_bytes, admit)
            .map_err(|_| StoreAccessError::PairLimitOrAdmission)
    }
    pub(crate) fn retire_owner(&self) {
        let Some(shared) = self.shared.upgrade() else {
            return;
        };
        let mut inner = shared.stored.inner.lock().unwrap();
        if inner
            .generation
            .as_ref()
            .is_some_and(|(owner, _)| owner.ptr_eq(&std::sync::Arc::downgrade(&self.owner)))
        {
            inner.generation = None;
            inner.strict = false;
            shared.stored.batch.store(false, Ordering::SeqCst);
        }
    }
    pub(crate) fn close(&self) -> Result<(), StoreAccessError> {
        let shared = self
            .shared
            .upgrade()
            .ok_or(StoreAccessError::StaleGeneration)?;
        let mut inner = shared.stored.inner.lock().unwrap();
        self.validate(&inner)?;
        inner.generation = None;
        inner.strict = false;
        Ok(())
    }
}
#[cfg(test)]
impl StoredInputs {
    pub(crate) fn begin_generation(
        &self,
        shared: &std::sync::Arc<crate::net::Shared>,
        owner: std::sync::Arc<crate::host_probe_state::AttemptScope>,
    ) -> StoreGeneration {
        let mut inner = self.inner.lock().unwrap();
        let strict = inner.strict;
        *inner = Inner::default();
        inner.strict = strict;
        let identity = std::sync::Arc::new(());
        inner.generation = Some((
            std::sync::Arc::downgrade(&owner),
            std::sync::Arc::downgrade(&identity),
        ));
        StoreGeneration {
            shared: std::sync::Arc::downgrade(shared),
            owner,
            identity,
        }
    }
}
