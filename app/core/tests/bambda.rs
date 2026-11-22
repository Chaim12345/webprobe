//! Public Bambda compilation/evaluation contract, with a real JVM.
use std::{path::PathBuf, time::Duration};
use webprobe_core::bambda::{Exchange, Kind, Program};

fn runtime() -> (PathBuf, PathBuf) {
    let java = std::env::var_os("WEBPROBE_BAMBDA_TEST_JAVA")
        .expect("set WEBPROBE_BAMBDA_TEST_JAVA to a JDK 17+ java launcher");
    let api = std::env::var_os("WEBPROBE_BAMBDA_TEST_API")
        .expect("set WEBPROBE_BAMBDA_TEST_API to montoya-api.jar");
    (java.into(), api.into())
}
fn rows() -> Vec<Exchange> {
    vec![Exchange {
        id: 7, host: "example.test".into(), port: 443, secure: true,
        request: b"GET /private HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec(),
        response: Some(b"HTTP/1.1 302 Found\r\nServer: fixture\r\nSet-Cookie: session=test\r\nContent-Length: 0\r\n\r\n".to_vec()),
    }, Exchange {
        id: 8, host: "example.test".into(), port: 443, secure: true,
        request: b"GET /pending HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec(), response: None,
    }]
}
const LIMIT: Duration = Duration::from_secs(15);
#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn java_filter_returns_booleans_for_complete_and_pending_exchanges() {
    let (java, api) = runtime();
    let script = r#"if (!requestResponse.hasResponse()) return false;
        var response = requestResponse.response();
        return response.isStatusCodeClass(StatusCodeClass.CLASS_3XX_REDIRECTION)
            && response.hasCookie("session");"#;
    let p = Program::compile(&java, &api, Kind::Filter, script, LIMIT).unwrap();
    let out = p.evaluate(&rows(), LIMIT).unwrap();
    assert_eq!(out[0].value, Some(serde_json::json!(true)), "{out:?}");
    assert_eq!(out[1].value, Some(serde_json::json!(false)));
    assert!(out.iter().all(|r| r.error.is_none()));
}

#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn java_column_guards_missing_responses_and_reads_headers() {
    let (java, api) = runtime();
    let script = r#"if (!requestResponse.hasResponse()) return "";
        var response = requestResponse.response();
        return response.hasHeader("Server") ? response.headerValue("Server") : "";"#;
    let p = Program::compile(&java, &api, Kind::Column, script, LIMIT).unwrap();
    let out = p.evaluate(&rows(), LIMIT).unwrap();
    assert_eq!(out[0].value, Some(serde_json::json!("fixture")));
    assert_eq!(out[1].value, Some(serde_json::json!("")));
}

#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn invalid_java_and_wrong_filter_return_type_produce_compile_diagnostics() {
    let (java, api) = runtime();
    for source in ["return missing_symbol;", "return 123;"] {
        let result = Program::compile(&java, &api, Kind::Filter, source, LIMIT);
        assert!(
            matches!(result, Err(webprobe_core::bambda::Error::Compile(message)) if message.contains("error"))
        );
    }
}

#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn row_exception_does_not_hide_later_results_or_corrupt_output() {
    let (java, api) = runtime();
    let p = Program::compile(
        &java,
        &api,
        Kind::Column,
        r#"System.out.println("not protocol");
        if (requestResponse.id() == 7) throw new IllegalStateException("fixture failure");
        return utilities.base64Utils().encodeToString("ok");"#,
        LIMIT,
    )
    .unwrap();
    let out = p.evaluate(&rows(), LIMIT).unwrap();
    assert!(out[0].error.as_ref().unwrap().contains("fixture failure"));
    assert_eq!(out[1].value, Some(serde_json::json!("b2s=")));
    assert!(out[1].error.is_none());
}

#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn looping_java_is_stopped_and_program_can_be_reused() {
    let (java, api) = runtime();
    let p = Program::compile(
        &java,
        &api,
        Kind::Column,
        "if (requestResponse.hasResponse()) { while (true) {} } return 42;",
        LIMIT,
    )
    .unwrap();
    let start = std::time::Instant::now();
    let out = p.evaluate(&rows(), Duration::from_millis(500));
    assert!(matches!(out, Err(webprobe_core::bambda::Error::Timeout)));
    assert!(start.elapsed() < Duration::from_secs(5));
    let out = p.evaluate(&rows()[1..], LIMIT).unwrap();
    assert_eq!(out[0].value, Some(serde_json::json!(42)));
}

#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn row_identity_is_exact_even_above_javascript_integer_precision() {
    let (java, api) = runtime();
    let p = Program::compile(
        &java,
        &api,
        Kind::Column,
        "return requestResponse.request().path();",
        LIMIT,
    )
    .unwrap();
    let mut input = rows();
    input[0].id = u64::MAX;
    let out = p.evaluate(&input, LIMIT).unwrap();
    assert_eq!(out[0].id, u64::MAX);
    assert_eq!(out[0].value, Some(serde_json::json!("/private")));
}

#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn byte_bodies_and_cookie_overloads_keep_the_recorded_values() {
    let (java, api) = runtime();
    let p = Program::compile(&java, &api, Kind::Filter, r#"
        if (!requestResponse.hasResponse()) return false;
        record Wanted(String name, String value, String domain, String path)
            implements burp.api.montoya.http.message.Cookie {
            public java.util.Optional<java.time.ZonedDateTime> expiration() { return java.util.Optional.empty(); }
        }
        var response = requestResponse.response();
        return requestResponse.request().body().getByte(0) == (byte) 255
            && response.hasCookie("session") && !response.hasCookie("Session")
            && response.hasCookie(new Wanted("session", "test", null, null))
            && !response.hasCookie(new Wanted("session", "wrong", null, null));
    "#, LIMIT).unwrap();
    let mut input = rows();
    input[0].request =
        b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 2\r\n\r\n".to_vec();
    input[0].request.extend_from_slice(&[255, 0]);
    let out = p.evaluate(&input, LIMIT).unwrap();
    assert_eq!(out[0].value, Some(serde_json::json!(true)), "{out:?}");
}

#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn runaway_protocol_output_is_bounded() {
    let (java, api) = runtime();
    let p = Program::compile(
        &java,
        &api,
        Kind::Column,
        r#"
        var output = new java.io.FileOutputStream(java.io.FileDescriptor.out);
        byte[] buffer = new byte[1024 * 1024];
        while (true) output.write(buffer);
    "#,
        LIMIT,
    )
    .unwrap();
    let start = std::time::Instant::now();
    let out = p.evaluate(&rows(), Duration::from_secs(5));
    assert!(
        matches!(out, Err(webprobe_core::bambda::Error::Limit(_))),
        "{out:?}"
    );
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn successful_null_column_is_distinct_from_a_missing_error_value() {
    let (java, api) = runtime();
    let p = Program::compile(
        &java,
        &api,
        Kind::Column,
        "if (requestResponse.hasResponse()) return null; throw new IllegalArgumentException();",
        LIMIT,
    )
    .unwrap();
    let out = p.evaluate(&rows(), LIMIT).unwrap();
    assert_eq!(out[0].value, Some(serde_json::Value::Null));
    assert!(out[0].error.is_none());
    assert!(out[1].value.is_none());
    assert!(out[1].error.is_some());
}
