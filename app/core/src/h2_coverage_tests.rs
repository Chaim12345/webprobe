use super::*;
use std::io::Cursor;

#[test]
fn frame_parser_waits_for_every_header_and_payload_byte() {
    let mut wire = Vec::new();
    write_frame(
        &mut wire,
        FRAME_DATA,
        FLAG_END_STREAM,
        0x8000_0001,
        b"binary\0payload",
    )
    .unwrap();
    for end in 0..wire.len() {
        assert!(
            parse_frame(&wire[..end], DEFAULT_MAX_FRAME)
                .unwrap()
                .is_none(),
            "prefix {end}"
        );
    }
    let used = wire.len();
    wire.extend_from_slice(b"next frame");
    let (frame, consumed) = parse_frame(&wire, DEFAULT_MAX_FRAME).unwrap().unwrap();
    assert_eq!(consumed, used);
    assert_eq!(
        (frame.ty, frame.flags, frame.stream),
        (FRAME_DATA, FLAG_END_STREAM, 1)
    );
    assert_eq!(frame.payload, b"binary\0payload");
}

#[test]
fn frame_parser_enforces_limit_before_waiting_for_payload() {
    let mut wire = Vec::new();
    write_frame(&mut wire, FRAME_DATA, 0, 1, &[42; 16]).unwrap();
    assert!(parse_frame(&wire[..9], 15)
        .err()
        .unwrap()
        .contains("SETTINGS_MAX_FRAME_SIZE"));
    let (frame, used) = parse_frame(&wire, 16).unwrap().unwrap();
    assert_eq!(used, 25);
    assert_eq!(frame.payload, [42; 16]);
}

#[test]
fn empty_frame_roundtrips_at_zero_payload_limit() {
    let mut wire = Vec::new();
    write_frame(&mut wire, FRAME_SETTINGS, FLAG_ACK, 0, &[]).unwrap();
    let (frame, used) = parse_frame(&wire, 0).unwrap().unwrap();
    assert_eq!(used, 9);
    assert_eq!(
        (frame.ty, frame.flags, frame.stream),
        (FRAME_SETTINGS, FLAG_ACK, 0)
    );
    assert!(frame.payload.is_empty());
}

#[test]
fn blocking_frame_reader_distinguishes_truncation_and_oversize() {
    let mut wire = Vec::new();
    write_frame(&mut wire, FRAME_DATA, 0, 1, b"abc").unwrap();
    for end in 0..wire.len() {
        let err = read_frame(&mut Cursor::new(&wire[..end])).err().unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }
    let oversized_header = [0, 0x40, 1, FRAME_DATA, 0, 0, 0, 0, 1];
    let err = read_frame(&mut Cursor::new(oversized_header))
        .err()
        .unwrap();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn header_fragment_strips_padding_before_priority_fields() {
    let bytes = [2, 0x80, 0, 0, 3, 16, 0x88, 0xbe, 0, 0];
    assert_eq!(
        header_fragment(FLAG_PADDED | FLAG_PRIORITY, &bytes).unwrap(),
        [0x88, 0xbe]
    );
    assert_eq!(header_fragment(FLAG_PADDED, &[2, 0, 0]).unwrap(), b"");
    assert_eq!(header_fragment(FLAG_PRIORITY, &[0; 5]).unwrap(), b"");
    assert!(header_fragment(FLAG_PADDED | FLAG_PRIORITY, &[1, 0, 0, 0, 0, 0]).is_err());
}

#[test]
fn data_padding_covers_zero_full_and_invalid_lengths() {
    assert_eq!(data_payload(0, &[2, 7, 8]).unwrap(), [2, 7, 8]);
    assert_eq!(data_payload(FLAG_PADDED, &[0, 7, 8]).unwrap(), [7, 8]);
    assert_eq!(data_payload(FLAG_PADDED, &[2, 7, 8]).unwrap(), b"");
    assert!(data_payload(FLAG_PADDED, &[]).is_err());
    assert!(data_payload(FLAG_PADDED, &[3, 7, 8]).is_err());
}

fn request() -> H2Request {
    H2Request {
        method: "POST".into(),
        scheme: "https".into(),
        authority: "example.test:8443".into(),
        path: "/upload?q=1".into(),
        headers: Vec::new(),
        body: b"hi\0".to_vec(),
        connection: None,
    }
}

#[test]
fn hpack_encoding_filters_hop_headers_and_recomputes_length() {
    let mut req = request();
    req.headers = [
        ("Host", "wrong.test"),
        ("Content-Length", "999"),
        ("Connection", "close"),
        ("Proxy-Authorization", "secret"),
        ("Keep-Alive", "timeout=5"),
        ("Transfer-Encoding", "chunked"),
        ("Upgrade", "h2c"),
        ("HTTP2-Settings", "abc"),
        ("TE", "gzip"),
        ("TE", "trailers"),
        ("X-Trace", "yes"),
        ("", "empty"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    let decoded = Decoder::new().decode(&encode_headers(&req)).unwrap();
    let expected: Vec<(Vec<u8>, Vec<u8>)> = [
        (":method", "POST"),
        (":scheme", "https"),
        (":authority", "example.test:8443"),
        (":path", "/upload?q=1"),
        ("te", "trailers"),
        ("x-trace", "yes"),
        ("content-length", "3"),
    ]
    .into_iter()
    .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
    .collect();
    assert_eq!(decoded, expected);
}

#[test]
fn hpack_explicit_connection_override_is_not_silently_removed() {
    let mut req = request();
    req.connection = Some("close".into());
    let decoded = Decoder::new().decode(&encode_headers(&req)).unwrap();
    assert!(decoded.contains(&(b"connection".to_vec(), b"close".to_vec())));
}

#[test]
fn request_headers_set_end_stream_only_without_body() {
    let mut req = request();
    for empty in [false, true] {
        if empty {
            req.body.clear();
        }
        let mut stream = Cursor::new(Vec::new());
        send_request_headers(&mut stream, &req).unwrap();
        let bytes = stream.into_inner();
        let (frame, used) = parse_frame(&bytes, DEFAULT_MAX_FRAME).unwrap().unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(frame.ty, FRAME_HEADERS);
        assert_eq!(frame.stream, 1);
        assert_ne!(frame.flags & FLAG_END_HEADERS, 0);
        assert_eq!(frame.flags & FLAG_END_STREAM != 0, empty);
    }
}

#[test]
fn ping_ack_echoes_payload_and_does_not_ack_an_ack() {
    let mut rx = Rx::new();
    let mut stream = Cursor::new(Vec::new());
    let mut sink = None;
    rx.handle(
        &mut stream,
        Frame {
            ty: FRAME_PING,
            flags: 0,
            stream: 0,
            payload: b"12345678".to_vec(),
        },
        &mut sink,
    )
    .unwrap();
    let (ack, used) = parse_frame(stream.get_ref(), DEFAULT_MAX_FRAME)
        .unwrap()
        .unwrap();
    assert_eq!((ack.ty, ack.flags, ack.stream), (FRAME_PING, FLAG_ACK, 0));
    assert_eq!(ack.payload, b"12345678");
    rx.handle(&mut stream, ack, &mut sink).unwrap();
    assert_eq!(stream.get_ref().len(), used);
}

#[test]
fn goaway_and_reset_retry_classification_preserves_processed_streams() {
    for (ty, stream_id, payload, expected_retry) in [
        (FRAME_GOAWAY, 0, vec![0, 0, 0, 0, 0, 0, 0, 0], true),
        (FRAME_GOAWAY, 0, vec![0, 0, 0, 1, 0, 0, 0, 2], false),
        (FRAME_RST_STREAM, 1, vec![0, 0, 0, 7], true),
        (FRAME_RST_STREAM, 1, vec![0, 0, 0, 8], false),
    ] {
        let err = Rx::new()
            .handle(
                &mut Cursor::new(Vec::new()),
                Frame {
                    ty,
                    flags: 0,
                    stream: stream_id,
                    payload,
                },
                &mut None,
            )
            .unwrap_err();
        assert_eq!(retryable(&err), expected_retry, "{err}");
    }
}

#[test]
fn continuation_cannot_be_interrupted_by_control_or_other_stream() {
    for (ty, stream_id) in [(FRAME_PING, 0), (FRAME_CONTINUATION, 3), (FRAME_DATA, 1)] {
        let mut rx = Rx::new();
        let mut stream = Cursor::new(Vec::new());
        rx.handle(
            &mut stream,
            Frame {
                ty: FRAME_HEADERS,
                flags: 0,
                stream: 1,
                payload: vec![0x88],
            },
            &mut None,
        )
        .unwrap();
        let err = rx
            .handle(
                &mut stream,
                Frame {
                    ty,
                    flags: 0,
                    stream: stream_id,
                    payload: vec![],
                },
                &mut None,
            )
            .unwrap_err();
        assert!(err.contains("interrupted before CONTINUATION"), "{err}");
    }
}

#[test]
fn base64url_handles_short_tails_and_url_safe_alphabet() {
    for (input, expected) in [
        (b"f".as_slice(), "Zg"),
        (b"fo", "Zm8"),
        (b"foo", "Zm9v"),
        (&[0xfb, 0xff, 0xff], "-___"),
    ] {
        assert_eq!(base64url(input), expected);
    }
    assert_eq!(empty_settings_value(), "AAIAAAAA");
}

#[test]
fn raw_request_requires_authority_and_preserves_binary_payload() {
    assert!(request_from_raw(b"GET / HTTP/1.1\r\n\r\n", "https").is_none());
    assert!(request_from_raw(b"GET / HTTP/1.1", "https").is_none());
    let req = request_from_raw(
        b"POST / HTTP/1.1\r\nhOsT: example.test:8080\r\nContent-Length: 3\r\n\r\na\0b",
        "http",
    )
    .unwrap();
    assert_eq!(req.authority, "example.test:8080");
    assert_eq!(req.body, b"a\0b");
    assert_eq!(req.scheme, "http");
}
