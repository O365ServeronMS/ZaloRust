//! CDP capture plumbing (Windows/WebView2) + `safe_endpoint` for logs.
//!
//! Transport (setting `shadow.capture = "cdp"`): the WebView2 DevTools
//! protocol. `Network.enable` arms these listeners:
//! - `Network.webSocketCreated` — track the Zalo WSS connection ids.
//! - `Network.webSocketFrameReceived/Sent` — raw binary frames; Rust
//!   decodes them (`wire`) with the per-connection key.
//! - `Network.responseReceived` (URL filter) + `Network.loadingFinished`
//!   + `Network.getResponseBody` — raw REST response bodies for Zalo API
//!   URLs, decoded with the bridge-supplied REST key.
//!
//! Nothing here touches page state; it only observes what the page's own
//! socket carries. On non-Windows the attach is a no-op (capture modes
//! other than `cdp` are future work, see handoff).

/// Log/record-safe endpoint: strips scheme+host+query and collapses long
/// digit runs to `<id>` so no session-scoped identifier lands in logs.
/// The path itself is kept — `normalize_rest` matches on it.
pub fn safe_endpoint(ep: &str) -> String {
    let no_q = ep.split('?').next().unwrap_or("");
    let path = match no_q.find("://") {
        Some(i) => {
            let rest = &no_q[i + 3..];
            match rest.find('/') {
                Some(j) => &rest[j..],
                None => "/",
            }
        }
        None => no_q,
    };
    let mut out = String::with_capacity(path.len());
    let mut digits = String::new();
    for ch in path.chars() {
        if ch.is_ascii_digit() {
            digits.push(ch);
        } else {
            flush_digits(&mut out, &mut digits);
            out.push(ch);
        }
    }
    flush_digits(&mut out, &mut digits);
    out
}

fn flush_digits(out: &mut String, digits: &mut String) {
    if digits.len() >= 10 {
        out.push_str("<id>");
    } else {
        out.push_str(digits);
    }
    digits.clear();
}

/// Split a URL into (host, path-without-leading-slash) on the same
/// parsing `is_api_url` always used. Pure.
fn split_host_path(url: &str) -> Option<(&str, &str)> {
    let rest = url.split_once("://")?.1;
    match rest.split_once('/') {
        Some((h, p)) => Some((h, p)),
        None => Some((rest, "")),
    }
}

/// Which REST URLs are worth storing: Zalo API surfaces, not static assets.
pub fn is_api_url(url: &str) -> bool {
    let Some((host, path)) = split_host_path(url) else {
        return false;
    };
    if !host.ends_with("zalo.me") && !host.ends_with("zadn.vn") {
        return false;
    }
    host.starts_with("wpa.")
        || host.contains("-wpa.api")
        // C3 (batch 3): the real web API hosts are
        // `tt-chat2-wpa.chat.zalo.me`, `tt-group-wpa.chat.zalo.me`,
        // `tt-profile-wpa.chat.zalo.me`, `tt-convers-wpa.chat.zalo.me`
        // with paths under `/api/…` — the old `-wpa.api` clause never
        // matched them, so whole endpoint families were dropped before
        // the counters existed. (`path` carries no leading slash, so
        // URL path `/api/x` is `path = "api/x"` here.)
        || (host.ends_with(".zalo.me")
            && (host.contains("-wpa.") || host.starts_with("wpa."))
            && path.starts_with("api/"))
        || host.starts_with("zcld.")
        || host.starts_with("dl-")
        || path.contains("/a/")
        || path.contains("get-last-msgs")
        || path.contains("getmg")
        || path.contains("getprofiles")
        || path.contains("preloadconvers")
}

/// C2 host bucket (counter only — the host value itself is never
/// logged): true when the url's host ends with `zalo.me` on the same
/// parsing `is_api_url` uses. Counts `*.zalo.me` requests the API
/// predicate rejects, which is how we spot `is_api_url` being too
/// narrow without ever logging a host verbatim.
pub fn host_is_zalo_me(url: &str) -> bool {
    split_host_path(url).is_some_and(|(host, _)| host.ends_with("zalo.me"))
}

/// Why a `Network.getResponseBody` completion produced no body bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyErr {
    /// The completion payload was not valid JSON.
    NotJson,
    /// JSON, but no `body` string on the return object.
    NoBody,
    /// `base64Encoded: true` but the body did not decode.
    BadBase64,
    /// Decoded to zero bytes.
    Empty,
}

/// Parse the completion JSON of a `Network.getResponseBody` CDP call
/// into body bytes (C1, batch 3 — the likely root cause of H2).
///
/// WebView2's `CallDevToolsProtocolMethod` completion handler receives
/// the method's RETURN OBJECT directly as JSON: for `getResponseBody`
/// that is the bare `{"body": "...", "base64Encoded": bool}` with NO
/// `result` wrapper — a `result` key only appears when the method's own
/// return type has one (e.g. `Runtime.evaluate`). The previous code
/// read `v["result"]["body"]`, so EVERY body was dropped and REST
/// capture wrote 0 rows. A `{"result":{...}}` wrapper is still accepted
/// defensively (first `result` object wins) so a WebView2 update that
/// changes the envelope cannot silently drop bodies again.
pub fn parse_get_response_body(json: &str) -> Result<Vec<u8>, BodyErr> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|_| BodyErr::NotJson)?;
    let obj = match v.get("result") {
        Some(r) if r.is_object() => r,
        _ => &v,
    };
    let body = obj
        .get("body")
        .and_then(serde_json::Value::as_str)
        .ok_or(BodyErr::NoBody)?;
    let b64 = obj
        .get("base64Encoded")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let bytes = if b64 {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(body.trim())
            .map_err(|_| BodyErr::BadBase64)?
    } else {
        body.as_bytes().to_vec()
    };
    if bytes.is_empty() {
        return Err(BodyErr::Empty);
    }
    Ok(bytes)
}

#[cfg(windows)]
mod cdp {
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};

    use tauri::AppHandle;

    use super::{host_is_zalo_me, is_api_url, parse_get_response_body, BodyErr};
    use crate::shadow::rest_stats::{self, RestStage};
    use crate::shadow::runtime;

    type Core = webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2;

    /// C4 (batch 3): WebView2's Network domain buffer defaults evict
    /// large response bodies before `Network.getResponseBody` can
    /// read them back (audit H2 risk note). 100 MB total / 20 MB per
    /// resource.
    const NETWORK_ENABLE_PARAMS: &str =
        r#"{"maxTotalBufferSize":104857600,"maxResourceBufferSize":20971520}"#;

    /// C4: `pending` is bounded — entries leave on
    /// loadingFinished/loadingFailed, but a response whose load never
    /// completes (navigation, eviction) must not grow the map forever.
    /// Past the cap it is dropped wholesale: rids are dedupe keys, not
    /// data, so the worst case is a missed body, never a leak.
    const PENDING_CAP: usize = 4096;

    /// C4: `fetched` only exists to dedupe duplicate finished events;
    /// once a rid left `pending` it can go, so the set is capped (and
    /// cleared) rather than pruned precisely.
    const FETCHED_CAP: usize = 4096;

    /// Attach the capture listeners to one account webview. Safe to call
    /// per webview; each gets its own listener set.
    pub fn attach(webview: tauri::webview::PlatformWebview, app: AppHandle) {
        unsafe {
            let controller = webview.controller();
            let core: Core = match controller.CoreWebView2() {
                Ok(c) => c,
                Err(_) => {
                    crate::dlog::log("shadow cdp: no CoreWebView2");
                    return;
                }
            };
            // WS connection ids; REST rids pending a finished body.
            let ws_ids: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
            let pending: Arc<Mutex<HashMap<String, String>>> =
                Arc::new(Mutex::new(HashMap::new()));
            let fetched: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

            // C4: the buffer caps ride on `Network.enable` so big REST
            // bodies are not evicted before getResponseBody.
            let enable_params = windows_core::HSTRING::from(NETWORK_ENABLE_PARAMS);
            let done =
                webview2_com::CallDevToolsProtocolMethodCompletedHandler::create(Box::new(
                    |_, _| Ok(()),
                ));
            if core
                .CallDevToolsProtocolMethod(
                    windows_core::w!("Network.enable"),
                    windows_core::PCWSTR::from_raw(enable_params.as_ptr()),
                    &done,
                )
                .is_err()
            {
                crate::dlog::log("shadow cdp: Network.enable FAILED");
                return;
            }

            ws_created(&core, ws_ids.clone());
            ws_frames(
                &core,
                app.clone(),
                "Network.webSocketFrameReceived",
                "in",
                ws_ids.clone(),
            );
            ws_frames(&core, app.clone(), "Network.webSocketFrameSent", "out", ws_ids);
            rest_received(&core, app.clone(), pending.clone());
            // C4: failed loads release their rid instead of leaking it.
            rest_failed(&core, pending.clone());
            rest_finished(&core, app, pending, fetched);
            crate::dlog::log("shadow cdp: attached");
        }
    }

    fn recv_handler(
        core: &Core,
        event: &'static str,
        f: impl Fn(&serde_json::Value) + 'static,
    ) {
        let handler = webview2_com::DevToolsProtocolEventReceivedEventHandler::create(Box::new(
            move |_, args| {
                let Some(args) = args else { return Ok(()) };
                let json = unsafe {
                    let mut p = windows_core::PWSTR::null();
                    args.ParameterObjectAsJson(&mut p)?;
                    webview2_com::take_pwstr(p)
                };
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
                    f(&v);
                }
                Ok(())
            },
        ));
        let mut token = 0i64;
        // `w!` only accepts literals; the event name is a parameter, so
        // build a null-terminated wide string at runtime.
        let wide = windows_core::HSTRING::from(event);
        unsafe {
            if let Ok(recv) =
                core.GetDevToolsProtocolEventReceiver(windows_core::PCWSTR::from_raw(wide.as_ptr()))
            {
                let _ = recv.add_DevToolsProtocolEventReceived(&handler, &mut token);
            }
        }
    }

    fn ws_created(core: &Core, ws_ids: Arc<Mutex<HashSet<String>>>) {
        recv_handler(core, "Network.webSocketCreated", move |v| {
            if let (Some(rid), Some(url)) = (
                v.get("requestId").and_then(|r| r.as_str()),
                v.get("url").and_then(|u| u.as_str()),
            ) {
                if url.contains("zalo") {
                    ws_ids.lock().map(|mut s| s.insert(rid.to_string())).ok();
                }
            }
        });
    }

    fn ws_frames(
        core: &Core,
        app: AppHandle,
        event: &'static str,
        direction: &'static str,
        ws_ids: Arc<Mutex<HashSet<String>>>,
    ) {
        recv_handler(core, event, move |v| {
            let Some(rid) = v.get("requestId").and_then(|r| r.as_str()) else {
                return;
            };
            if !ws_ids.lock().map(|s| s.contains(rid)).unwrap_or(false) {
                return;
            }
            let payload = v
                .get("response")
                .and_then(|r| r.get("payloadData"))
                .and_then(|p| p.as_str())
                .unwrap_or("");
            use base64::Engine as _;
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(payload) {
                if !bytes.is_empty() {
                    runtime::deliver_ws(&app, bytes, direction);
                }
            }
        });
    }

    fn rest_received(core: &Core, _app: AppHandle, pending: Arc<Mutex<HashMap<String, String>>>) {
        recv_handler(core, "Network.responseReceived", move |v| {
            let Some(rid) = v.get("requestId").and_then(|r| r.as_str()) else {
                return;
            };
            let url = v
                .get("response")
                .and_then(|r| r.get("url"))
                .and_then(|u| u.as_str())
                .unwrap_or("");
            // C2: every response counts, then the two buckets — matched
            // vs. zalo.me-but-unmatched (host bucket, never the host).
            rest_stats::bump(RestStage::ResponseSeen);
            if is_api_url(url) {
                rest_stats::bump(RestStage::ApiMatched);
                // C4: bounded insert — see PENDING_CAP.
                if let Ok(mut m) = pending.lock() {
                    if m.len() >= PENDING_CAP {
                        m.clear();
                    }
                    m.insert(rid.to_string(), url.to_string());
                }
            } else if host_is_zalo_me(url) {
                rest_stats::bump(RestStage::ApiHostUnmatched);
            }
        });
    }

    /// C4 (batch 3): a failed load never yields a body — release the
    /// rid so `pending` cannot grow and the stage stays visible in the
    /// counters instead of dying silently.
    fn rest_failed(core: &Core, pending: Arc<Mutex<HashMap<String, String>>>) {
        recv_handler(core, "Network.loadingFailed", move |v| {
            let Some(rid) = v.get("requestId").and_then(|r| r.as_str()) else {
                return;
            };
            if pending.lock().ok().and_then(|mut m| m.remove(rid)).is_some() {
                rest_stats::bump(RestStage::FailedSeen);
            }
        });
    }

    fn rest_finished(
        core: &Core,
        app: AppHandle,
        pending: Arc<Mutex<HashMap<String, String>>>,
        fetched: Arc<Mutex<HashSet<String>>>,
    ) {
        // The event closure needs the COM pointer at event time; WebView2
        // fires handlers on the UI thread that created them, so an owned
        // clone (AddRef) captured here is safe without Send.
        let core_evt: Core = core.clone();
        recv_handler(core, "Network.loadingFinished", move |v| {
            let Some(rid) = v.get("requestId").and_then(|r| r.as_str()) else {
                return;
            };
            // C4: whatever happens below, this rid is DONE — remove it
            // from `pending` first, so a failed body fetch can never
            // leak the entry (and a duplicate finished event is a no-op).
            let Some(url) = pending.lock().ok().and_then(|mut m| m.remove(rid)) else {
                return;
            };
            rest_stats::bump(RestStage::FinishedSeen);
            {
                let mut f = match fetched.lock() {
                    Ok(f) => f,
                    Err(_) => return,
                };
                // C4: dedupe only — once a rid left `pending` it can
                // go; cap so the set cannot grow forever.
                if f.len() >= FETCHED_CAP {
                    f.clear();
                }
                if !f.insert(rid.to_string()) {
                    return;
                }
            }
            let params = format!(r#"{{"requestId":{}}}"#, serde_json::json!(rid));
            let params_wide = windows_core::HSTRING::from(params.as_str());
            // Per-event clone: `done` is FnOnce, the outer closure is Fn.
            let app_cb = app.clone();
            let done =
                webview2_com::CallDevToolsProtocolMethodCompletedHandler::create(Box::new(
                    move |error: windows_core::Result<()>, json: String| {
                        if error.is_err() {
                            // C2: counted, never logged verbatim (the
                            // error text is transport detail).
                            rest_stats::bump(RestStage::BodyCallErr);
                            return Ok(());
                        }
                        // C1: WebView2 hands the method's return object
                        // directly — NO `result` wrapper for
                        // getResponseBody. `parse_get_response_body`
                        // (pure, unit-tested) accepts the bare shape
                        // and the wrapper defensively.
                        match parse_get_response_body(&json) {
                            Ok(bytes) => {
                                rest_stats::bump(RestStage::BodyOk);
                                runtime::deliver_rest(&app_cb, url.clone(), bytes, "in");
                                rest_stats::bump(RestStage::Delivered);
                            }
                            Err(e) => rest_stats::bump(match e {
                                BodyErr::NotJson => RestStage::BodyErrNotJson,
                                BodyErr::NoBody => RestStage::BodyErrNoBody,
                                BodyErr::BadBase64 => RestStage::BodyErrBadB64,
                                BodyErr::Empty => RestStage::BodyErrEmpty,
                            }),
                        }
                        Ok(())
                    },
                ));
            unsafe {
                if core_evt
                    .CallDevToolsProtocolMethod(
                        windows_core::w!("Network.getResponseBody"),
                        windows_core::PCWSTR::from_raw(params_wide.as_ptr()),
                        &done,
                    )
                    .is_err()
                {
                    rest_stats::bump(RestStage::BodyCallErr);
                }
            }
        });
    }
}

#[cfg(windows)]
pub fn attach(webview: tauri::webview::PlatformWebview, app: tauri::AppHandle) {
    cdp::attach(webview, app);
}

#[cfg(not(windows))]
pub fn attach(_webview: tauri::webview::PlatformWebview, _app: tauri::AppHandle) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_endpoint_collapses_ids() {
        assert_eq!(
            safe_endpoint("https://wpa.chat.zalo.me/a/get-last-msgs?zcid=1234567890123"),
            "/a/get-last-msgs"
        );
        assert_eq!(
            safe_endpoint("https://friend-wpa.api.zalo.me/v2/profile/2294947733392101048/x"),
            "/v2/profile/<id>/x"
        );
        assert_eq!(safe_endpoint("/short/12345"), "/short/12345");
    }

    #[test]
    fn api_url_predicate() {
        assert!(is_api_url("https://wpa.chat.zalo.me/a/preloadconvers/get-last-msgs"));
        assert!(is_api_url("https://group-wpa.api.zalo.me/getmg-v2"));
        assert!(is_api_url("https://zcld.chat.zalo.me/cloudmedia/x"));
        assert!(!is_api_url("https://static.zalo.me/app.css"));
        assert!(!is_api_url("https://example.com/a/get-last-msgs"));
    }

    // --- C3 (batch 3): the real web API host shapes ------------------------

    #[test]
    fn api_url_matches_wpa_chat_hosts() {
        // Real host shapes (audit endpoint list), fake paths: hosts are
        // `tt-*-wpa.chat.zalo.me` with paths under `/api/…`. The old
        // predicate only caught these when a path substring happened
        // to match (`-wpa.api` vs `-wpa.chat`), so whole endpoint
        // families were invisible.
        for ok in [
            "https://tt-chat2-wpa.chat.zalo.me/api/p/get-last-msgs",
            "https://tt-group-wpa.chat.zalo.me/api/group/getmg-v2",
            "https://tt-profile-wpa.chat.zalo.me/api/getprofiles/v2",
            "https://tt-convers-wpa.chat.zalo.me/api/preloadconvers",
            // Widened: ANY /api/ path on a -wpa./wpa. zalo.me host.
            "https://tt-chat2-wpa.chat.zalo.me/api/some/other/call",
            "https://wpa.chat.zalo.me/api/x",
        ] {
            assert!(is_api_url(ok), "{ok}");
        }
        // Static/CDN hosts never match — the body fetch costs a CDP
        // round trip and static bytes are worthless rows.
        for bad in [
            "https://stc-fake.zdn.vn/app.css",          // zdn.vn: not an API host at all
            "https://stc-fake.zadn.vn/media/img.jpg",   // zadn.vn image CDN
            "https://fake.zadn.vn/media/x.jpg",
            "https://tt-chat2-wpa.chat.zalo.me/static/x.js", // wpa host, non-api path
            "https://tt-chat2-wpa.chat.zalo.me/api2/x",      // /api2 is not /api/
        ] {
            assert!(!is_api_url(bad), "{bad}");
        }
    }

    #[test]
    fn host_zalo_me_bucket() {
        // The unmatched bucket counts only *.zalo.me hosts — never the
        // host value itself.
        assert!(host_is_zalo_me("https://tt-chat2-wpa.chat.zalo.me/api/x"));
        assert!(host_is_zalo_me("https://anything.zalo.me/"));
        assert!(!host_is_zalo_me("https://stc-fake.zadn.vn/a.jpg"));
        assert!(!host_is_zalo_me("https://example.com/x"));
        assert!(!host_is_zalo_me("not a url"));
    }

    // --- C1 (batch 3): getResponseBody completion parsing ------------------

    #[test]
    fn get_response_body_bare_and_wrapped() {
        // Bare return object — what WebView2's CallDevToolsProtocolMethod
        // completion actually passes for getResponseBody (no `result`
        // wrapper; the old code read v["result"] and dropped every body).
        assert_eq!(
            parse_get_response_body(r#"{"body":"hello","base64Encoded":false}"#).unwrap(),
            b"hello".to_vec()
        );
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"payload bytes");
        assert_eq!(
            parse_get_response_body(&format!(r#"{{"body":"{b64}","base64Encoded":true}}"#))
                .unwrap(),
            b"payload bytes".to_vec()
        );
        // Defensively: a {"result":{…}} wrapper (Runtime.evaluate
        // shape) is also accepted, both base64 and text.
        assert_eq!(
            parse_get_response_body(&format!(
                r#"{{"result":{{"body":"{b64}","base64Encoded":true}}}}"#
            ))
            .unwrap(),
            b"payload bytes".to_vec()
        );
        assert_eq!(
            parse_get_response_body(r#"{"result":{"body":"x","base64Encoded":false}}"#).unwrap(),
            b"x".to_vec()
        );
        // base64Encoded omitted defaults to text.
        assert_eq!(parse_get_response_body(r#"{"body":"plain"}"#).unwrap(), b"plain".to_vec());
    }

    #[test]
    fn get_response_body_error_variants() {
        assert_eq!(parse_get_response_body("not json"), Err(BodyErr::NotJson));
        assert_eq!(parse_get_response_body(""), Err(BodyErr::NotJson));
        assert_eq!(parse_get_response_body(r#"{"base64Encoded":false}"#), Err(BodyErr::NoBody));
        assert_eq!(parse_get_response_body(r#"{"body":42}"#), Err(BodyErr::NoBody));
        assert_eq!(parse_get_response_body("[]"), Err(BodyErr::NoBody));
        assert_eq!(
            parse_get_response_body(r#"{"body":"!!not-b64!!","base64Encoded":true}"#),
            Err(BodyErr::BadBase64)
        );
        assert_eq!(
            parse_get_response_body(r#"{"body":"","base64Encoded":false}"#),
            Err(BodyErr::Empty)
        );
        assert_eq!(
            parse_get_response_body(r#"{"body":"","base64Encoded":true}"#),
            Err(BodyErr::Empty)
        );
        // A non-object `result` is not the wrapper: fall back to the
        // bare object (which has no body).
        assert_eq!(parse_get_response_body(r#"{"result":5}"#), Err(BodyErr::NoBody));
    }
}
