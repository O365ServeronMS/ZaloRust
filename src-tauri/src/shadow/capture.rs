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

/// Which REST URLs are worth storing: Zalo API surfaces, not static assets.
pub fn is_api_url(url: &str) -> bool {
    let (host, path) = match url.split_once("://") {
        Some((_, rest)) => match rest.split_once('/') {
            Some((h, p)) => (h, p),
            None => (rest, ""),
        },
        None => return false,
    };
    if !host.ends_with("zalo.me") && !host.ends_with("zadn.vn") {
        return false;
    }
    host.starts_with("wpa.")
        || host.contains("-wpa.api")
        || host.starts_with("zcld.")
        || host.starts_with("dl-")
        || path.contains("/a/")
        || path.contains("get-last-msgs")
        || path.contains("getmg")
        || path.contains("getprofiles")
        || path.contains("preloadconvers")
}

#[cfg(windows)]
mod cdp {
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};

    use tauri::AppHandle;

    use super::is_api_url;
    use crate::shadow::runtime;

    type Core = webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2;

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

            let done =
                webview2_com::CallDevToolsProtocolMethodCompletedHandler::create(Box::new(
                    |_, _| Ok(()),
                ));
            if core
                .CallDevToolsProtocolMethod(
                    windows_core::w!("Network.enable"),
                    windows_core::w!("{}"),
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
            if is_api_url(url) {
                pending
                    .lock()
                    .map(|mut m| m.insert(rid.to_string(), url.to_string()))
                    .ok();
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
            let Some(url) = pending.lock().ok().and_then(|m| m.get(rid).cloned())
            else {
                return;
            };
            {
                let mut f = match fetched.lock() {
                    Ok(f) => f,
                    Err(_) => return,
                };
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
                            return Ok(());
                        }
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
                            if let Some(result) = v.get("result") {
                                let body = result.get("body").and_then(|b| b.as_str()).unwrap_or("");
                                let b64 = result
                                    .get("base64Encoded")
                                    .and_then(|b| b.as_bool())
                                    .unwrap_or(false);
                                let bytes = if b64 {
                                    use base64::Engine as _;
                                    base64::engine::general_purpose::STANDARD
                                        .decode(body)
                                        .unwrap_or_default()
                                } else {
                                    body.as_bytes().to_vec()
                                };
                                if !bytes.is_empty() {
                                    runtime::deliver_rest(&app_cb, url.clone(), bytes, "in");
                                }
                            }
                        }
                        Ok(())
                    },
                ));
            unsafe {
                let _ = core_evt.CallDevToolsProtocolMethod(
                    windows_core::w!("Network.getResponseBody"),
                    windows_core::PCWSTR::from_raw(params_wide.as_ptr()),
                    &done,
                );
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
}
