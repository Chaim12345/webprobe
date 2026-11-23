use super::*;
use std::io::Write;

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn stacked_content_encodings_decode_in_reverse_order() {
    let body = b"binary\0payload\xff";
    let inner = gzip(body);
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&inner).unwrap();
    let outer = encoder.finish().unwrap();
    assert_eq!(decode_content(&outer, " GZip , DEFLATE "), body);
    assert_eq!(decode_content(&inner, "x-gzip"), body);
}

#[test]
fn raw_deflate_without_zlib_wrapper_is_supported() {
    let body = b"raw deflate raw deflate raw deflate";
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(body).unwrap();
    assert_eq!(decode_content(&encoder.finish().unwrap(), "deflate"), body);
}

#[test]
fn corrupt_content_and_unknown_outer_encoding_keep_wire_bytes() {
    let invalid = b"this is not a compressed stream";
    for encoding in ["gzip", "deflate", "br", "identity", ""] {
        assert_eq!(decode_content(invalid, encoding), invalid, "{encoding}");
    }
    let compressed = gzip(b"hidden text");
    assert_eq!(decode_content(&compressed, "gzip, unknown"), compressed);
}

#[test]
fn chunk_cursor_emits_each_chunk_once_at_every_split() {
    let framed = b"2;foo=bar\r\nab\r\n3\r\nc\0d\r\n0\r\nX-Trailer: yes\r\n\r\n";
    for split in 0..framed.len() {
        let mut cursor = ChunkCursor::default();
        let mut decoded = Vec::new();
        assert_eq!(
            scan_chunked(&framed[..split], &mut cursor, |d| decoded
                .extend_from_slice(d)),
            Chunked::Partial,
            "split {split}"
        );
        assert_eq!(
            scan_chunked(framed, &mut cursor, |d| decoded.extend_from_slice(d)),
            Chunked::Complete(framed.len()),
            "split {split}"
        );
        assert_eq!(decoded, b"abc\0d", "split {split}");
    }
}

#[test]
fn chunked_consumption_stops_before_next_message() {
    let framed = b"1\r\nx\r\n0\r\n\r\n";
    let mut pipelined = framed.to_vec();
    pipelined.extend_from_slice(b"HTTP/1.1 204 No Content\r\n\r\n");
    assert_eq!(
        decode_chunked(&pipelined).unwrap(),
        (b"x".to_vec(), framed.len())
    );
}

#[test]
fn malformed_chunk_sizes_and_terminators_are_rejected() {
    for body in [
        b"\r\n".as_slice(),
        b"-1\r\nx\r\n0\r\n\r\n",
        b"0x1\r\nx\r\n0\r\n\r\n",
        b"1\r\nx!!0\r\n\r\n",
        b"g\r\n",
    ] {
        assert_eq!(
            scan_chunked(body, &mut ChunkCursor::default(), |_| panic!(
                "invalid chunk must not be emitted"
            )),
            Chunked::Malformed,
            "{body:?}"
        );
        assert!(decode_chunked(body).is_none());
    }
}

#[test]
fn normalize_request_replaces_framing_without_losing_binary_payload() {
    let raw = b"POST /up HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nContent-Length: 999\r\nX-Keep: yes\r\n\r\n3\r\na\0b\r\n0\r\n\r\n";
    let normalized = normalize_request(raw);
    let parts = util::parse_http(&normalized);
    assert_eq!(parts.first, "POST /up HTTP/1.1");
    assert_eq!(
        util::get_header(&parts.headers, "Content-Length").as_deref(),
        Some("3")
    );
    assert!(util::get_header(&parts.headers, "Transfer-Encoding").is_none());
    assert_eq!(
        util::get_header(&parts.headers, "X-Keep").as_deref(),
        Some("yes")
    );
    assert_eq!(&normalized[parts.head_len..], b"a\0b");
}

#[test]
fn normalize_request_leaves_incomplete_and_nonchunked_messages_unchanged() {
    for raw in [
        b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
        b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\na\0b",
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab",
        b"not HTTP",
    ] {
        assert_eq!(normalize_request(raw), raw);
    }
}

#[test]
fn normalized_response_decodes_content_after_transfer_framing() {
    let body = b"compressed\0response";
    let compressed = gzip(body);
    let mut raw = b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\nContent-Length: 999\r\nX-Keep: yes\r\n\r\n".to_vec();
    raw.extend_from_slice(format!("{:x}\r\n", compressed.len()).as_bytes());
    raw.extend_from_slice(&compressed);
    raw.extend_from_slice(b"\r\n0\r\n\r\n");
    let normalized = normalize_response(&raw);
    let parts = util::parse_http(&normalized);
    assert_eq!(&normalized[parts.head_len..], body);
    assert_eq!(
        util::get_header(&parts.headers, "Content-Length").as_deref(),
        Some("19")
    );
    assert_eq!(
        util::get_header(&parts.headers, "X-Keep").as_deref(),
        Some("yes")
    );
    assert!(util::get_header(&parts.headers, "Content-Encoding").is_none());
    assert!(util::get_header(&parts.headers, "Transfer-Encoding").is_none());
}

#[test]
fn normalized_response_ignores_bytes_past_content_length() {
    let normalized = normalize_response(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\na\0bEXTRA");
    let parts = util::parse_http(&normalized);
    assert_eq!(&normalized[parts.head_len..], b"a\0b");
}

#[test]
fn response_framing_rejects_duplicate_lengths_as_pool_boundaries() {
    for lengths in [
        "Content-Length: 3\r\nContent-Length: 3",
        "Content-Length: 3\r\nContent-Length: 5",
        "Content-Length: -1",
        "Content-Length: abc",
    ] {
        let head = format!("HTTP/1.1 200 OK\r\n{lengths}\r\n\r\n");
        assert_eq!(
            response_body_kind(head.as_bytes(), "GET"),
            BodyKind::UntilEof
        );
    }
    assert_eq!(
        response_body_kind(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n", "GET"),
        BodyKind::Length(0)
    );
}

#[test]
fn body_completion_requires_whole_fixed_or_chunked_payload() {
    let head = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n";
    let mut raw = head.to_vec();
    raw.extend_from_slice(b"ab");
    assert!(!body_complete(&raw, "GET"));
    raw.push(b'c');
    assert!(body_complete(&raw, "GET"));
    let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n".to_vec();
    assert!(!body_complete(&raw, "GET"));
    raw.extend_from_slice(b"\r\n");
    assert!(body_complete(&raw, "GET"));
}
