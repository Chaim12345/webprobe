//! Message bytes that cost a pointer to clone, and the on-disk store that keeps
//! Proxy history out of RAM (N-06).
//!
//! A [`Body`] is either inline (`Arc<[u8]>`) or a range of a memory-mapped
//! segment file. Proxy history moves every body it keeps into the store
//! ([`spill`]), so an unbounded history costs file-backed pages the kernel can
//! drop and reread, not anonymous memory; and the many places that copy
//! history (site map, reports, scans, project save) copy handles, not bytes.
//!
//! Segments are append-only files under the cache directory, mapped and then
//! unlinked at once: the mapping keeps them alive for the process, and nothing
//! is left on disk after it exits, even after a crash. The project file
//! remains the only durable copy (it is written from these handles).
//! Measured before this change (debug build): 20k items with 4 KB bodies held
//! 95 MB, and a save took 4.3 s on the UI thread.

use std::ops::Deref;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

/// Bytes of one message. Derefs to `[u8]`.
#[derive(Clone)]
pub struct Body(Repr);

#[derive(Clone)]
enum Repr {
    Inline(Arc<[u8]>),
    Stored { seg: Arc<Segment>, off: usize, len: usize },
}

impl Body {
    /// True when the bytes live in the on-disk store.
    pub fn is_stored(&self) -> bool {
        matches!(self.0, Repr::Stored { .. })
    }
}

impl Deref for Body {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match &self.0 {
            Repr::Inline(a) => a,
            // SAFETY: [off, off + len) was written before this Body was
            // created and is never written again (segments are append-only);
            // the Arc keeps the mapping alive.
            Repr::Stored { seg, off, len } => unsafe { std::slice::from_raw_parts(seg.map.as_ptr().add(*off), *len) },
        }
    }
}

impl AsRef<[u8]> for Body {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl Default for Body {
    fn default() -> Self {
        Body(Repr::Inline(Arc::from(&[][..])))
    }
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Body({} bytes{})", self.len(), if self.is_stored() { ", stored" } else { "" })
    }
}

impl PartialEq for Body {
    fn eq(&self, other: &Body) -> bool {
        **self == **other
    }
}
impl Eq for Body {}
impl PartialEq<[u8]> for Body {
    fn eq(&self, other: &[u8]) -> bool {
        **self == *other
    }
}
impl PartialEq<Vec<u8>> for Body {
    fn eq(&self, other: &Vec<u8>) -> bool {
        **self == other[..]
    }
}
impl PartialEq<Body> for Vec<u8> {
    fn eq(&self, other: &Body) -> bool {
        self[..] == **other
    }
}
impl PartialEq<Body> for [u8] {
    fn eq(&self, other: &Body) -> bool {
        *self == **other
    }
}
impl PartialEq<str> for Body {
    fn eq(&self, other: &str) -> bool {
        **self == *other.as_bytes()
    }
}
impl PartialEq<&str> for Body {
    fn eq(&self, other: &&str) -> bool {
        **self == *other.as_bytes()
    }
}

impl From<Vec<u8>> for Body {
    fn from(v: Vec<u8>) -> Self {
        Body(Repr::Inline(Arc::from(v)))
    }
}
impl From<&[u8]> for Body {
    fn from(v: &[u8]) -> Self {
        Body(Repr::Inline(Arc::from(v)))
    }
}
impl<const N: usize> From<&[u8; N]> for Body {
    fn from(v: &[u8; N]) -> Self {
        Body(Repr::Inline(Arc::from(&v[..])))
    }
}
impl From<String> for Body {
    fn from(v: String) -> Self {
        v.into_bytes().into()
    }
}
impl From<&str> for Body {
    fn from(v: &str) -> Self {
        v.as_bytes().into()
    }
}
impl From<&Body> for Body {
    fn from(v: &Body) -> Self {
        v.clone()
    }
}

/// One mapped segment file (already unlinked).
struct Segment {
    map: memmap2::MmapRaw,
}

/// Bodies smaller than this stay inline: a handle costs about as much.
const MIN_SPILL: usize = 256;
/// Segment size; a larger body gets a segment of its own size.
const SEGMENT: usize = 64 << 20;

struct Store {
    dir: Option<PathBuf>,
    current: Option<(Arc<Segment>, usize, usize)>,
    next: u64,
    failed: bool,
}

fn store() -> &'static Mutex<Store> {
    static S: OnceLock<Mutex<Store>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Store { dir: store_dir(), current: None, next: 0, failed: false }))
}

/// `WEBPROBE_BODY_DIR`, else `$XDG_CACHE_HOME/webprobe`, else
/// `~/.cache/webprobe`. Not the temp dir: `/tmp` is often tmpfs, which is RAM.
fn store_dir() -> Option<PathBuf> {
    if !cfg!(unix) {
        return None;
    }
    let env = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    env("WEBPROBE_BODY_DIR")
        .or_else(|| env("XDG_CACHE_HOME").map(|d| d.join("webprobe")))
        .or_else(|| env("HOME").map(|d| d.join(".cache").join("webprobe")))
}

impl Store {
    fn segment(&mut self, need: usize) -> std::io::Result<(Arc<Segment>, usize)> {
        if let Some((seg, used, cap)) = &self.current {
            if cap - used >= need {
                return Ok((seg.clone(), *used));
            }
        }
        let dir = self.dir.clone().ok_or_else(|| std::io::Error::other("no body store directory"))?;
        std::fs::create_dir_all(&dir)?;
        let cap = need.max(SEGMENT);
        let path = dir.join(format!("bodies-{}-{}", std::process::id(), self.next));
        self.next += 1;
        let file = std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(&path)?;
        let mapped = file.set_len(cap as u64).and_then(|()| memmap2::MmapOptions::new().len(cap).map_raw(&file));
        // Unlinked at once: the mapping keeps the data for this process and
        // nothing outlives it.
        let _ = std::fs::remove_file(&path);
        let seg = Arc::new(Segment { map: mapped? });
        self.current = Some((seg.clone(), 0, cap));
        Ok((seg, 0))
    }
}

/// `body` moved into the on-disk store (a clone when it is small, already
/// stored, or the store is unavailable; the first failure is logged and
/// later bodies stay inline).
pub fn spill(body: &Body) -> Body {
    if body.is_stored() || body.len() < MIN_SPILL {
        return body.clone();
    }
    let mut st = store().lock().unwrap();
    if st.failed {
        return body.clone();
    }
    match st.segment(body.len()) {
        Ok((seg, off)) => {
            // SAFETY: [off, off + len) is past every range handed out so far
            // and inside the mapping; no reader can see it until this Body
            // is returned.
            unsafe { std::ptr::copy_nonoverlapping(body.as_ptr(), seg.map.as_mut_ptr().add(off), body.len()) };
            if let Some((_, used, _)) = &mut st.current {
                *used = off + body.len();
            }
            Body(Repr::Stored { seg, off, len: body.len() })
        }
        Err(e) => {
            st.failed = true;
            eprintln!("webprobe: history bodies stay in memory, the body store is unavailable: {e}");
            body.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spilled_bodies_read_back_exactly_and_small_ones_stay_inline() {
        let big: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let b = spill(&Body::from(big.clone()));
        if cfg!(unix) && store_dir().is_some() {
            assert!(b.is_stored());
        }
        assert_eq!(b, big);
        let again = spill(&b);
        assert_eq!(again, big, "spilling a stored body is a clone");
        let small = spill(&Body::from("GET / HTTP/1.1\r\n\r\n"));
        assert!(!small.is_stored());
        assert_eq!(small, "GET / HTTP/1.1\r\n\r\n");
        // A body larger than a segment gets a segment of its own.
        let huge = vec![7u8; SEGMENT + 1];
        assert_eq!(&spill(&Body::from(huge.clone()))[..], &huge[..]);
        assert_eq!(&b[..], &big[..], "earlier bodies are unaffected by new segments");
    }

    #[test]
    fn concurrent_spills_do_not_overlap() {
        let handles: Vec<_> = (0..8u8)
            .map(|t| std::thread::spawn(move || (0..200).map(|i| (t, i, spill(&Body::from(vec![t ^ (i as u8); 300 + i])))).collect::<Vec<_>>()))
            .collect();
        for h in handles {
            for (t, i, b) in h.join().unwrap() {
                assert_eq!(b.len(), 300 + i);
                assert!(b.iter().all(|&x| x == t ^ (i as u8)));
            }
        }
    }
}
