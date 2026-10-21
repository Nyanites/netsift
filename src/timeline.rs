//! HTTP request timeline: every HTTP/1.x (plain or decrypted), HTTP/2 and HTTP/3 exchange as one
//! request with timings, for the waterfall view and HAR export.

use crate::dissect::{fmt_abs_time, is_http_start};
use crate::engine::Engine;
use crate::model::{HttpMsg, StreamKind};
use crate::streams::Conversation;
use crate::tls::pkt_for;
use std::collections::BTreeMap;
use std::net::IpAddr;

const BODY_KEEP: usize = 256 * 1024;

#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub version: u8,
    pub method: String,
    pub scheme: &'static str,
    pub host: String,
    pub path: String,
    pub status: Option<u16>,
    pub req_headers: Vec<(String, String)>,
    pub resp_headers: Vec<(String, String)>,
    pub body_bytes: usize,
    pub body: Vec<u8>,
    /// Request sent (timestamp of the packet carrying its first byte).
    pub start: f64,
    /// First response byte seen.
    pub first_byte: Option<f64>,
    /// Last response byte seen.
    pub end: Option<f64>,
    /// For the first request on a connection: when the connection started (SYN / first packet),
    /// so connection setup and TLS show up in the waterfall.
    pub conn_start: Option<f64>,
    pub conv: (StreamKind, usize),
    pub stream_id: Option<u64>,
    pub req_pkt: usize,
    pub server: (IpAddr, u16),
    pub process: Option<String>,
    pub encrypted: bool,
}

impl HttpRequest {
    pub fn ttfb(&self) -> Option<f64> {
        self.first_byte.map(|f| f - self.start)
    }

    pub fn total(&self) -> Option<f64> {
        self.end.map(|e| e - self.start)
    }

    pub fn url(&self) -> String {
        format!("{}://{}{}", self.scheme, self.host, self.path)
    }

    fn resp_header(&self, n: &str) -> Option<&str> {
        self.resp_headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.as_str())
    }
}

/// Collects all HTTP requests in the capture, sorted by start time.
pub fn requests(eng: &Engine) -> Vec<HttpRequest> {
    let mut out = Vec::new();
    for c in eng.streams.tcp.iter() {
        let before = out.len();
        if !c.http_msgs().is_empty() {
            let client = c.tls.as_ref().and_then(|t| t.client_dir).unwrap_or(0);
            from_msgs(eng, c, client, c.http_msgs(), c.tls.is_some(), &mut out);
        } else if let Some(t) = &c.tls {
            if t.decrypted_records > 0 {
                let client = t.client_dir.unwrap_or(0);
                let d = &t.dirs;
                from_http1(eng, c, [(&d[client].plain, &d[client].plain_chunks), (&d[1 - client].plain, &d[1 - client].plain_chunks)], true, &mut out);
            }
        } else if c.app == "HTTP" {
            let d = &c.dirs;
            from_http1(eng, c, [(&d[0].data, &d[0].chunks), (&d[1].data, &d[1].chunks)], false, &mut out);
        }
        mark_first(&mut out[before..], c);
    }
    for c in eng.streams.udp.iter() {
        if let Some(q) = &c.quic {
            let before = out.len();
            from_msgs(eng, c, q.client_dir.unwrap_or(0), &q.h3.msgs, true, &mut out);
            mark_first(&mut out[before..], c);
        }
    }
    out.sort_by(|a, b| a.start.total_cmp(&b.start));
    out
}

fn mark_first(reqs: &mut [HttpRequest], c: &Conversation) {
    if let Some(first) = reqs.iter_mut().min_by(|a, b| a.start.total_cmp(&b.start)) {
        first.conn_start = Some(c.first_ts);
    }
}

fn base(eng: &Engine, c: &Conversation, client: usize, encrypted: bool, version: u8) -> HttpRequest {
    let server = if client == 0 { c.b } else { c.a };
    HttpRequest {
        version,
        method: String::new(),
        scheme: if encrypted { "https" } else { "http" },
        host: c.host.clone().unwrap_or_else(|| server.0.to_string()),
        path: String::new(),
        status: None,
        req_headers: Vec::new(),
        resp_headers: Vec::new(),
        body_bytes: 0,
        body: Vec::new(),
        start: 0.0,
        first_byte: None,
        end: None,
        conn_start: None,
        conv: (c.kind, c.id),
        stream_id: None,
        req_pkt: 0,
        server,
        process: c.process.map(|i| eng.processes[i as usize].name.clone()),
        encrypted,
    }
}

/// HTTP/2 and HTTP/3: one request per stream.
fn from_msgs(eng: &Engine, c: &Conversation, client: usize, msgs: &[HttpMsg], encrypted: bool, out: &mut Vec<HttpRequest>) {
    let ts = |pkt: usize| eng.packets[pkt].frame.ts;
    let mut streams: BTreeMap<u64, HttpRequest> = BTreeMap::new();
    for m in msgs {
        if m.kind != "HEADERS" && m.kind != "DATA" {
            continue;
        }
        let from_client = m.dir == client;
        if m.kind == "HEADERS" && from_client && m.header(":method").is_some() && !streams.contains_key(&m.stream_id) {
            let mut r = base(eng, c, client, encrypted, m.version);
            r.method = m.header(":method").unwrap_or("").to_string();
            r.path = m.header(":path").unwrap_or("").to_string();
            if let Some(a) = m.header(":authority") {
                r.host = a.to_string();
            }
            r.scheme = if m.header(":scheme") == Some("http") { "http" } else { r.scheme };
            r.req_headers = m.headers.clone();
            r.start = ts(m.pkt);
            r.req_pkt = m.pkt;
            r.stream_id = Some(m.stream_id);
            streams.insert(m.stream_id, r);
            continue;
        }
        let Some(r) = streams.get_mut(&m.stream_id) else { continue };
        if from_client {
            continue;
        }
        let t = ts(m.pkt);
        if m.kind == "HEADERS" {
            let status: Option<u16> = m.header(":status").and_then(|s| s.parse().ok());
            if status.is_some_and(|s| s < 200) {
                continue; // informational (100, 103)
            }
            if r.status.is_none() {
                r.status = status;
                r.resp_headers = m.headers.clone();
            }
        } else {
            r.body_bytes += m.data_len;
            if r.body.len() < BODY_KEEP {
                r.body.extend_from_slice(&m.data[..m.data.len().min(BODY_KEEP - r.body.len())]);
            }
        }
        r.first_byte.get_or_insert(t);
        r.end = Some(r.end.map_or(t, |e: f64| e.max(t)));
    }
    out.extend(streams.into_values());
}

struct H1Msg {
    start: usize,
    end: usize,
    first_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    body_len: usize,
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Splits an HTTP/1.x byte stream into messages. `methods` (for responses) are the request
/// methods in order, so HEAD responses are known to have no body.
fn parse_h1(buf: &[u8], response: bool, methods: &[String]) -> Vec<H1Msg> {
    let mut out = Vec::new();
    let mut pos = 0;
    let mut answered = 0;
    while pos < buf.len() {
        while buf[pos..].starts_with(b"\r\n") {
            pos += 2;
        }
        if !is_http_start(&buf[pos..]) {
            break;
        }
        let Some(h) = find(&buf[pos..], b"\r\n\r\n") else { break };
        let hdr_end = pos + h + 4;
        let text = String::from_utf8_lossy(&buf[pos..hdr_end - 4]).into_owned();
        let mut lines = text.split("\r\n");
        let first_line = lines.next().unwrap_or("").to_string();
        let headers: Vec<(String, String)> =
            lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
        let get = |n: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.as_str());
        let status: Option<u16> = if response { first_line.split(' ').nth(1).and_then(|s| s.parse().ok()) } else { None };
        let informational = status.is_some_and(|s| s < 200);
        let no_body = response
            && (informational || matches!(status, Some(204) | Some(304)) || methods.get(answered).is_some_and(|m| m == "HEAD"));
        let mut body = Vec::new();
        let mut body_len = 0;
        let end;
        if no_body {
            end = hdr_end;
        } else if get("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
            let mut p = hdr_end;
            loop {
                let Some(le) = find(&buf[p..], b"\r\n") else {
                    p = buf.len();
                    break;
                };
                let size_text = String::from_utf8_lossy(&buf[p..p + le]).into_owned();
                let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
                p += le + 2;
                if size == 0 {
                    p = find(&buf[p..], b"\r\n").map(|i| p + i + 2).unwrap_or(buf.len());
                    break;
                }
                let take = size.min(buf.len().saturating_sub(p));
                body_len += take;
                if body.len() < BODY_KEEP {
                    body.extend_from_slice(&buf[p..p + take.min(BODY_KEEP - body.len())]);
                }
                p = (p + size + 2).min(buf.len());
                if p >= buf.len() {
                    break;
                }
            }
            end = p;
        } else if let Some(n) = get("content-length").and_then(|v| v.parse::<usize>().ok()) {
            end = (hdr_end + n).min(buf.len());
            body_len = end - hdr_end;
            body = buf[hdr_end..end.min(hdr_end + BODY_KEEP)].to_vec();
        } else if response {
            end = buf.len(); // delimited by connection close
            body_len = end - hdr_end;
            body = buf[hdr_end..end.min(hdr_end + BODY_KEEP)].to_vec();
        } else {
            end = hdr_end;
        }
        if !informational {
            answered += 1;
            out.push(H1Msg { start: pos, end, first_line, headers, body, body_len });
        }
        if end <= pos {
            break;
        }
        pos = end;
    }
    out
}

/// One direction of a byte stream: (data, (offset, packet) chunks). Client side first.
type DirBytes<'a> = (&'a Vec<u8>, &'a Vec<(usize, usize)>);

fn from_http1(eng: &Engine, c: &Conversation, dirs: [DirBytes; 2], encrypted: bool, out: &mut Vec<HttpRequest>) {
    let ts = |chunks: &[(usize, usize)], off: usize| eng.packets[pkt_for(chunks, off)].frame.ts;
    let (cbuf, cch) = dirs[0];
    let (sbuf, sch) = dirs[1];
    let reqs = parse_h1(cbuf, false, &[]);
    let methods: Vec<String> = reqs.iter().map(|r| r.first_line.split(' ').next().unwrap_or("").to_string()).collect();
    let resps = parse_h1(sbuf, true, &methods);
    let client = if c.tls.as_ref().and_then(|t| t.client_dir) == Some(1) { 1 } else { 0 };
    for (i, rq) in reqs.into_iter().enumerate() {
        let mut r = base(eng, c, client, encrypted, 1);
        let mut parts = rq.first_line.splitn(3, ' ');
        r.method = parts.next().unwrap_or("").to_string();
        r.path = parts.next().unwrap_or("").to_string();
        if let Some(h) = rq.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")) {
            r.host = h.1.clone();
        }
        r.req_headers = rq.headers;
        r.start = ts(cch, rq.start);
        r.req_pkt = pkt_for(cch, rq.start);
        if let Some(rs) = resps.get(i) {
            r.status = rs.first_line.split(' ').nth(1).and_then(|s| s.parse().ok());
            r.resp_headers = rs.headers.clone();
            r.body_bytes = rs.body_len;
            r.body = rs.body.clone();
            r.first_byte = Some(ts(sch, rs.start));
            r.end = Some(ts(sch, rs.end.max(rs.start + 1) - 1));
        }
        out.push(r);
    }
}

// ---------------------------------------------------------------------------------------------
// HAR 1.2 export

fn js(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for ch in s.chars() {
        match ch {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn iso(ts: f64) -> String {
    // fmt_abs_time gives "YYYY-MM-DD HH:MM:SS.uuuuuu UTC".
    let s = fmt_abs_time(ts);
    format!("{}T{}Z", &s[..10], &s[11..23])
}

fn headers_json(h: &[(String, String)]) -> String {
    let items: Vec<String> = h.iter().map(|(n, v)| format!("{{\"name\":{},\"value\":{}}}", js(n), js(v))).collect();
    format!("[{}]", items.join(","))
}

fn ms(x: Option<f64>) -> String {
    x.map(|v| format!("{:.3}", (v * 1000.0).max(0.0))).unwrap_or_else(|| "-1".into())
}

pub fn har(reqs: &[HttpRequest]) -> String {
    let entries: Vec<String> = reqs
        .iter()
        .map(|r| {
            let http_version = match r.version {
                2 => "HTTP/2",
                3 => "HTTP/3",
                _ => "HTTP/1.1",
            };
            let mime = r.resp_header("content-type").unwrap_or("");
            let encoded = r.resp_header("content-encoding").is_some_and(|e| !e.eq_ignore_ascii_case("identity"));
            let text = if !encoded && r.body.len() == r.body_bytes {
                std::str::from_utf8(&r.body).ok().map(|t| format!(",\"text\":{}", js(t))).unwrap_or_default()
            } else {
                String::new()
            };
            let connect = r.conn_start.map(|c| r.start - c);
            let receive = match (r.first_byte, r.end) {
                (Some(f), Some(e)) => Some(e - f),
                _ => None,
            };
            let total = connect.unwrap_or(0.0) + r.total().unwrap_or(0.0);
            format!(
                concat!(
                    "{{\"startedDateTime\":{},\"time\":{:.3},",
                    "\"request\":{{\"method\":{},\"url\":{},\"httpVersion\":\"{}\",\"cookies\":[],\"headers\":{},\"queryString\":[],\"headersSize\":-1,\"bodySize\":-1}},",
                    "\"response\":{{\"status\":{},\"statusText\":\"\",\"httpVersion\":\"{}\",\"cookies\":[],\"headers\":{},",
                    "\"content\":{{\"size\":{},\"mimeType\":{}{}}},\"redirectURL\":\"\",\"headersSize\":-1,\"bodySize\":{}}},",
                    "\"cache\":{{}},\"timings\":{{\"blocked\":-1,\"dns\":-1,\"connect\":{},\"ssl\":-1,\"send\":0,\"wait\":{},\"receive\":{}}},",
                    "\"serverIPAddress\":{},\"connection\":\"{}\",\"comment\":{}}}"
                ),
                js(&iso(r.conn_start.unwrap_or(r.start))),
                total * 1000.0,
                js(&r.method),
                js(&r.url()),
                http_version,
                headers_json(&r.req_headers),
                r.status.unwrap_or(0),
                http_version,
                headers_json(&r.resp_headers),
                r.body_bytes,
                js(mime),
                text,
                r.body_bytes,
                ms(connect),
                ms(r.ttfb()),
                ms(receive),
                js(&r.server.0.to_string()),
                r.conv.1,
                js(&format!("{}captured by NetSift{}", if r.encrypted { "decrypted, " } else { "" }, r.process.as_ref().map(|p| format!(", process {p}")).unwrap_or_default())),
            )
        })
        .collect();
    format!(
        "{{\"log\":{{\"version\":\"1.2\",\"creator\":{{\"name\":\"NetSift\",\"version\":\"{}\"}},\"pages\":[],\"entries\":[\n{}\n]}}}}\n",
        env!("CARGO_PKG_VERSION"),
        entries.join(",\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http1_splitting() {
        let reqs = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nHEAD /b HTTP/1.1\r\nHost: x\r\n\r\nPOST /c HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcGET /d HTTP/1.1\r\n\r\n";
        let r = parse_h1(reqs, false, &[]);
        assert_eq!(r.iter().map(|m| m.first_line.as_str()).collect::<Vec<_>>(), ["GET /a HTTP/1.1", "HEAD /b HTTP/1.1", "POST /c HTTP/1.1", "GET /d HTTP/1.1"]);
        let methods: Vec<String> = ["GET", "HEAD", "POST", "GET"].iter().map(|s| s.to_string()).collect();
        let resps = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloHTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\nHTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=1\r\nde\r\n0\r\n\r\nHTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let s = parse_h1(resps, true, &methods);
        assert_eq!(s.len(), 4, "100 Continue is skipped");
        assert_eq!(s[0].body, b"hello");
        assert_eq!(s[1].body_len, 0, "HEAD response has no body despite Content-Length");
        assert_eq!(s[2].body, b"abcde");
        assert!(s[3].first_line.contains("404"));
    }

    #[test]
    fn har_is_valid_json_shape() {
        let r = HttpRequest {
            version: 2,
            method: "GET".into(),
            scheme: "https",
            host: "example.com".into(),
            path: "/q?\"x\"".into(),
            status: Some(200),
            req_headers: vec![(":method".into(), "GET".into())],
            resp_headers: vec![("content-type".into(), "text/plain".into())],
            body_bytes: 2,
            body: b"hi".to_vec(),
            start: 1_700_000_000.5,
            first_byte: Some(1_700_000_000.6),
            end: Some(1_700_000_000.7),
            conn_start: Some(1_700_000_000.4),
            conv: (StreamKind::Tcp, 0),
            stream_id: Some(1),
            req_pkt: 0,
            server: ("1.2.3.4".parse().unwrap(), 443),
            process: Some("curl".into()),
            encrypted: true,
        };
        let h = har(&[r]);
        assert!(h.contains("\"url\":\"https://example.com/q?\\\"x\\\"\""));
        assert!(h.contains("\"startedDateTime\":\"2023-11-14T22:13:20.400Z\""));
        assert!(h.contains("\"wait\":100.000"));
        assert!(h.contains("\"text\":\"hi\""));
        assert_eq!(h.matches('{').count(), h.matches('}').count());
    }
}
