//! End-to-end tests against real protocol stacks: the `h2` crate for HTTP/2 (HPACK) and
//! quinn + h3 for QUIC/HTTP/3. Their traffic is recorded, turned into captures, and must decode.

use crate::e2e_tests::{build_capture, run_tls_with};
use crate::engine::Engine;
use crate::model::{proto, Frame, HttpMsg, StreamKind};
use crate::tls::TlsStatus;
use bytes::Bytes;
use rustls::crypto::ring::cipher_suite as cs;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

type Log = Arc<Mutex<Vec<(usize, Vec<u8>)>>>;

/// Wraps the client side of a connection and records bytes: writes are dir 0, reads dir 1.
struct Recorder<T> {
    inner: T,
    log: Log,
}

impl<T: AsyncRead + Unpin> AsyncRead for Recorder<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        let new = buf.filled()[before..].to_vec();
        if !new.is_empty() {
            self.log.lock().unwrap().push((1, new));
        }
        r
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Recorder<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = r {
            self.log.lock().unwrap().push((0, buf[..n].to_vec()));
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

const PATHS: [&str; 3] = ["/index.html", "/api/items?id=7", "/missing"];

/// Runs three HTTP/2 requests over one connection with the `h2` crate and returns the recorded
/// client→server / server→client bytes.
fn record_h2() -> Vec<(usize, Vec<u8>)> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (c, s) = tokio::io::duplex(1 << 20);
        let log: Log = Default::default();
        let server = tokio::spawn(async move {
            let mut conn = h2::server::handshake(s).await.unwrap();
            while let Some(r) = conn.accept().await {
                let (req, mut respond) = r.unwrap();
                let path = req.uri().path_and_query().unwrap().to_string();
                let status = if path == "/missing" { 404 } else { 200 };
                let resp = http::Response::builder()
                    .status(status)
                    .header("content-type", "text/plain")
                    .header("x-served-path", path.clone())
                    .header("cache-control", "no-cache")
                    .body(())
                    .unwrap();
                let mut tx = respond.send_response(resp, false).unwrap();
                tx.send_data(Bytes::from(format!("body of {path}")), true).unwrap();
            }
        });
        let (mut send, conn) = h2::client::handshake(Recorder { inner: c, log: log.clone() }).await.unwrap();
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        for path in PATHS {
            let req = http::Request::builder()
                .uri(format!("https://example.test{path}"))
                .header("user-agent", "netsift-test/1.0")
                .header("accept", "*/*")
                .body(())
                .unwrap();
            send = send.ready().await.unwrap();
            let (resp, _) = send.send_request(req, true).unwrap();
            let mut body = resp.await.unwrap().into_body();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.unwrap();
                body.flow_control().release_capacity(chunk.len()).unwrap();
            }
        }
        drop(send);
        let _ = tokio::time::timeout(std::time::Duration::from_millis(200), driver).await;
        server.abort();
        log.lock().unwrap().clone()
    })
}

fn msgs(eng: &Engine, kind: StreamKind, id: usize) -> Vec<HttpMsg> {
    eng.streams.get(kind, id).http_msgs().to_vec()
}

fn check_h2_msgs(m: &[HttpMsg]) {
    let reqs: Vec<&HttpMsg> = m.iter().filter(|m| m.kind == "HEADERS" && m.header(":method").is_some()).collect();
    let resps: Vec<&HttpMsg> = m.iter().filter(|m| m.kind == "HEADERS" && m.header(":status").is_some()).collect();
    assert_eq!(reqs.len(), 3, "{m:#?}");
    assert_eq!(resps.len(), 3);
    for (r, path) in reqs.iter().zip(PATHS) {
        assert_eq!(r.header(":path"), Some(path));
        assert_eq!(r.header(":authority"), Some("example.test"));
        assert_eq!(r.header("user-agent"), Some("netsift-test/1.0"));
        assert!(r.note.is_empty(), "{}", r.note);
    }
    for (r, path) in resps.iter().zip(PATHS) {
        assert_eq!(r.header("x-served-path"), Some(path));
        assert_eq!(r.header(":status"), Some(if path == "/missing" { "404" } else { "200" }));
    }
    let bodies: Vec<String> = m.iter().filter(|m| m.kind == "DATA").map(|m| String::from_utf8_lossy(&m.data).to_string()).collect();
    assert!(bodies.contains(&"body of /api/items?id=7".to_string()), "{bodies:?}");
}

#[test]
fn http2_cleartext_hpack() {
    let rec = record_h2();
    let mut eng = Engine::default();
    for f in build_capture(&rec, false) {
        eng.ingest(f);
    }
    check_h2_msgs(&msgs(&eng, StreamKind::Tcp, 0));
    assert!(eng.packets.iter().any(|p| p.protocol == "HTTP2" && p.info.contains("GET example.test/api/items?id=7")));
    assert!(eng.experts.iter().any(|e| e.message.contains("404")));
}

#[test]
fn http2_over_tls13_hpack() {
    let rec = record_h2();
    let concat = |d: usize| rec.iter().filter(|r| r.0 == d).flat_map(|r| r.1.clone()).collect::<Vec<u8>>();
    let (segs, keys) = run_tls_with(cs::TLS13_AES_256_GCM_SHA384, &rustls::version::TLS13, b"h2", &concat(0), &concat(1));
    let mut eng = Engine::default();
    eng.keylog.parse(&keys);
    for f in build_capture(&segs, false) {
        eng.ingest(f);
    }
    assert_eq!(eng.streams.tcp[0].tls.as_ref().unwrap().alpn.as_deref(), Some("h2"));
    check_h2_msgs(&msgs(&eng, StreamKind::Tcp, 0));
    let bm = Default::default();
    let ctx = crate::filter::EvalCtx { bookmarks: &bm, processes: &eng.processes, missing: &bm };
    let count = |f: &str| {
        let e = crate::filter::parse(f).unwrap().unwrap();
        eng.packets.iter().enumerate().filter(|(i, p)| e.matches(*i, p, &ctx)).count()
    };
    assert!(count("http2 && http.host == \"example.test\"") >= 1);
    assert!(count("http.response.code == 404") >= 1);
    if let Some(dir) = std::env::var_os("NETSIFT_DEMO_DIR") {
        let dir = std::path::PathBuf::from(dir);
        crate::capture::save_pcap(&dir.join("netsift-h2.pcap"), build_capture(&segs, false).iter(), 1).unwrap();
        std::fs::write(dir.join("netsift-h2-keys.log"), &keys).unwrap();
    }
}

// ---------------------------------------------------------------------------------------------
// QUIC + HTTP/3

/// Forwards UDP between a client and the real server, recording each datagram.
async fn relay(server: SocketAddr, log: Log) -> SocketAddr {
    let front = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let back = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    back.connect(server).await.unwrap();
    let addr = front.local_addr().unwrap();
    tokio::spawn(async move {
        let mut client: Option<SocketAddr> = None;
        let (mut a, mut b) = (vec![0u8; 65536], vec![0u8; 65536]);
        loop {
            tokio::select! {
                r = front.recv_from(&mut a) => {
                    let (n, from) = r.unwrap();
                    client = Some(from);
                    log.lock().unwrap().push((0, a[..n].to_vec()));
                    back.send(&a[..n]).await.unwrap();
                }
                r = back.recv(&mut b) => {
                    let n = r.unwrap();
                    log.lock().unwrap().push((1, b[..n].to_vec()));
                    if let Some(c) = client { front.send_to(&b[..n], c).await.unwrap(); }
                }
            }
        }
    });
    addr
}

#[derive(Debug, Default)]
struct Keys(Mutex<String>);
impl rustls::KeyLog for Keys {
    fn log(&self, label: &str, cr: &[u8], secret: &[u8]) {
        let h = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        self.0.lock().unwrap().push_str(&format!("{label} {} {}\n", h(cr), h(secret)));
    }
}

fn record_h3(suite: rustls::SupportedCipherSuite) -> (Vec<(usize, Vec<u8>)>, String) {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async move {
        let ck = rcgen::generate_simple_self_signed(vec!["example.test".to_string()]).unwrap();
        let cert = rustls::pki_types::CertificateDer::from(ck.cert.der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(ck.signing_key.serialize_der().into());
        let mut provider = rustls::crypto::ring::default_provider();
        // QUIC requires TLS_AES_128_GCM_SHA256 for Initial packets; prefer the suite under test.
        provider.cipher_suites.retain(|s| s.suite() == suite.suite() || s.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256);
        provider.cipher_suites.sort_by_key(|s| s.suite() != suite.suite());
        let provider = Arc::new(provider);

        let mut scfg = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        scfg.alpn_protocols = vec![b"h3".to_vec()];
        scfg.ignore_client_order = true;
        let scfg = quinn::ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(scfg).unwrap()));
        let server = quinn::Endpoint::server(scfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            while let Some(inc) = server.accept().await {
                tokio::spawn(async move {
                    let conn = inc.await.unwrap();
                    let mut h3c: h3::server::Connection<_, Bytes> = h3::server::Connection::new(h3_quinn::Connection::new(conn)).await.unwrap();
                    while let Ok(Some(resolver)) = h3c.accept().await {
                        let (req, mut stream) = resolver.resolve_request().await.unwrap();
                        let path = req.uri().path_and_query().unwrap().to_string();
                        let status = if path == "/missing" { 404 } else { 200 };
                        let resp = http::Response::builder()
                            .status(status)
                            .header("content-type", "text/plain")
                            .header("x-served-path", path.clone())
                            .body(())
                            .unwrap();
                        stream.send_response(resp).await.unwrap();
                        stream.send_data(Bytes::from(format!("body of {path}"))).await.unwrap();
                        stream.finish().await.unwrap();
                    }
                });
            }
        });

        let log: Log = Default::default();
        let relay_addr = relay(server_addr, log.clone()).await;
        let keys = Arc::new(Keys::default());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let mut ccfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        ccfg.alpn_protocols = vec![b"h3".to_vec()];
        ccfg.key_log = keys.clone();
        let ccfg = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(ccfg).unwrap()));
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(ccfg);
        let conn = client.connect(relay_addr, "example.test").unwrap().await.unwrap();
        let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn.clone())).await.unwrap();
        let drive = tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
        for path in PATHS {
            let req = http::Request::builder()
                .uri(format!("https://example.test{path}"))
                .header("user-agent", "netsift-test/1.0")
                .body(())
                .unwrap();
            let mut stream = send.send_request(req).await.unwrap();
            stream.finish().await.unwrap();
            let _ = stream.recv_response().await.unwrap();
            while stream.recv_data().await.unwrap().is_some() {}
            // Rotate 1-RTT keys mid-connection (RFC 9001 §6) so key updates are exercised.
            conn.force_key_update();
        }
        conn.close(0u32.into(), b"done");
        client.wait_idle().await;
        drive.abort();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let rec = log.lock().unwrap().clone();
        let k = keys.0.lock().unwrap().clone();
        (rec, k)
    })
}

fn udp_capture(rec: &[(usize, Vec<u8>)]) -> Vec<Frame> {
    let mut ts = 1_750_000_000.0;
    rec.iter()
        .map(|(dir, payload)| {
            ts += 0.0005;
            let (src, dst, sp, dp) = if *dir == 0 { ([10, 0, 0, 1], [10, 0, 0, 2], 50000u16, 443u16) } else { ([10, 0, 0, 2], [10, 0, 0, 1], 443, 50000) };
            let mut u = sp.to_be_bytes().to_vec();
            u.extend_from_slice(&dp.to_be_bytes());
            u.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
            u.extend_from_slice(&[0, 0]);
            u.extend_from_slice(payload);
            let mut d = vec![0x02, 0, 0, 0, 0, dst[3], 0x02, 0, 0, 0, 0, src[3], 0x08, 0x00];
            let total = (20 + u.len()) as u16;
            d.extend_from_slice(&[0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0x40, 0, 64, 17, 0, 0]);
            d.extend_from_slice(&src);
            d.extend_from_slice(&dst);
            d.extend_from_slice(&u);
            Frame { ts, orig_len: d.len() as u32, linktype: 1, data: d, comment: None }
        })
        .collect()
}

fn check_h3(suite: rustls::SupportedCipherSuite, keys_later: bool) {
    let (rec, keys) = record_h3(suite);
    let mut eng = Engine::default();
    if !keys_later {
        eng.keylog.parse(&keys);
    }
    for f in udp_capture(&rec) {
        eng.ingest(f);
    }
    {
        let q = eng.streams.udp[0].quic.as_ref().expect("QUIC detected");
        // Initial packets decrypt without any keys: the SNI is always visible.
        assert_eq!(q.sni.as_deref(), Some("example.test"));
        assert!(eng.packets[0].info.contains("Client Hello SNI=example.test"), "{}", eng.packets[0].info);
    }
    if keys_later {
        assert_eq!(eng.streams.udp[0].quic.as_ref().unwrap().status, TlsStatus::WaitingForKeys);
        let mut k = crate::tls::KeyLog::default();
        k.parse(&keys);
        eng.set_keylog(k);
    }
    let q = eng.streams.udp[0].quic.as_ref().unwrap();
    assert_eq!(q.status, TlsStatus::Decrypting);
    assert_eq!(q.alpn.as_deref(), Some("h3"));
    assert_eq!(q.suite, Some(u16::from(suite.suite())));
    let m = msgs(&eng, StreamKind::Udp, 0);
    let reqs: Vec<&HttpMsg> = m.iter().filter(|m| m.kind == "HEADERS" && m.header(":method").is_some()).collect();
    let resps: Vec<&HttpMsg> = m.iter().filter(|m| m.kind == "HEADERS" && m.header(":status").is_some()).collect();
    assert_eq!(reqs.len(), 3, "{m:#?}");
    assert_eq!(resps.len(), 3, "{m:#?}");
    for (r, path) in reqs.iter().zip(PATHS) {
        assert_eq!(r.header(":path"), Some(path));
        assert_eq!(r.header("user-agent"), Some("netsift-test/1.0"));
    }
    for (r, path) in resps.iter().zip(PATHS) {
        assert_eq!(r.header("x-served-path"), Some(path));
    }
    assert!(m.iter().any(|m| m.kind == "DATA" && m.data == b"body of /missing"));
    assert!(m.iter().any(|m| m.kind == "SETTINGS"));
    assert!(eng.packets.iter().any(|p| p.meta.protos & proto::HTTP3 != 0 && p.info.contains("GET example.test/api/items?id=7")));
    assert!(eng.packets.iter().all(|p| !p.info.contains("decryption failed")), "a packet failed to decrypt");
    assert!(eng.packets.iter().all(|p| !p.info.contains("frame type") && !p.info.contains("truncated")), "unparsed QUIC frames");
    assert!(eng.experts.iter().any(|e| e.message.contains("404")));
    assert!(eng.packets.iter().any(|p| p.info.contains("KP1")), "no packet after the key update was decrypted");
    if let Some(dir) = std::env::var_os("NETSIFT_DEMO_DIR").filter(|_| suite.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256) {
        let dir = std::path::PathBuf::from(dir);
        crate::capture::save_pcap(&dir.join("netsift-h3.pcap"), udp_capture(&rec).iter(), 1).unwrap();
        std::fs::write(dir.join("netsift-h3-keys.log"), &keys).unwrap();
    }
}

#[test]
fn quic_h3_aes128() {
    check_h3(cs::TLS13_AES_128_GCM_SHA256, false);
}

#[test]
fn quic_h3_aes256_keys_loaded_later() {
    check_h3(cs::TLS13_AES_256_GCM_SHA384, true);
}

#[test]
fn quic_h3_chacha20() {
    check_h3(cs::TLS13_CHACHA20_POLY1305_SHA256, false);
}


/// Random and mutated inputs must never panic the parsers (they see untrusted traffic).
#[test]
fn parsers_survive_garbage() {
    let mut seed = 0x9e3779b97f4a7c15u64;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let (rec, keys) = record_h3(cs::TLS13_AES_128_GCM_SHA256);
    let h2 = record_h2();
    let kl = {
        let mut k = crate::tls::KeyLog::default();
        k.parse(&keys);
        k
    };
    for round in 0..3000 {
        let len = (rnd() % 1500) as usize;
        let mut junk: Vec<u8> = (0..len).map(|_| rnd() as u8).collect();
        let _ = crate::hpack::HpackDecoder::default().decode(&junk);
        let _ = crate::hpack::QpackDecoder::default().decode(&junk);
        crate::hpack::QpackDecoder::default().encoder_stream(&junk);
        let _ = crate::huffman::decode(&junk);
        let _ = crate::quic::parse_frames(&junk);
        // Mutate real traffic so parsing gets deep before hitting corruption.
        let (dir, base) = &rec[round % rec.len()];
        let mut m = base.clone();
        for _ in 0..1 + rnd() % 4 {
            if !m.is_empty() {
                let i = (rnd() as usize) % m.len();
                m[i] = rnd() as u8;
            }
        }
        if rnd() % 4 == 0 {
            m.truncate((rnd() as usize) % (m.len() + 1));
        }
        let mut q = crate::quic::QuicConn::default();
        let mut out = Vec::new();
        for (d, dg) in rec.iter().take(3) {
            q.datagram(*d, 0, dg, &kl, &mut out);
        }
        q.datagram(*dir, 1, &m, &kl, &mut out);
        q.datagram(0, 2, &junk, &kl, &mut out);
        let mut conn = crate::h2::H2Conn::default();
        let (d0, d1): (Vec<u8>, Vec<u8>) = (
            h2.iter().filter(|r| r.0 == 0).flat_map(|r| r.1.clone()).collect(),
            h2.iter().filter(|r| r.0 == 1).flat_map(|r| r.1.clone()).collect(),
        );
        let mut d0 = d0;
        if !d0.is_empty() {
            let i = (rnd() as usize) % d0.len();
            d0[i] = rnd() as u8;
        }
        junk.extend_from_slice(&d1);
        let _ = conn.update([&d0, &junk], [&[(0, 0)], &[(0, 0)]]);
    }
}

#[test]
#[ignore = "inspects a local capture; set NETSIFT_REAL_PCAP and NETSIFT_REAL_KEYS"]
fn real_capture_qpack_usage() {
    let (Ok(p), Ok(k)) = (std::env::var("NETSIFT_REAL_PCAP"), std::env::var("NETSIFT_REAL_KEYS")) else { return };
    let eng = crate::cli::load(std::path::Path::new(&p), Some(std::path::Path::new(&k))).unwrap();
    let mut with_ua = 0;
    let mut total = 0;
    for c in &eng.streams.udp {
        if let Some(q) = &c.quic {
            for m in q.h3.msgs.iter().filter(|m| m.kind == "HEADERS") {
                total += 1;
                with_ua += m.header("user-agent").is_some_and(|u| u.contains("Firefox")) as usize;
                assert!(m.note.is_empty(), "{}", m.note);
            }
        }
    }
    let ech: Vec<_> = eng.streams.udp.iter().filter_map(|c| c.quic.as_ref()).filter(|q| q.ech).map(|q| (q.ech_resolved, q.decrypted_packets)).collect();
    eprintln!("ECH sessions (resolved, packets): {ech:?}");
    // Firefox sends (GREASE) ECH almost everywhere; only Cloudflare actually accepts it here.
    let real_ech = eng.streams.udp.iter().filter_map(|c| c.quic.as_ref()).find(|q| q.sni.as_deref() == Some("cloudflare-ech.com")).unwrap();
    assert!(real_ech.ech_resolved && real_ech.decrypted_packets > 0);
    eprintln!("HTTP/3 header blocks: {total}, requests with a Firefox user-agent: {with_ua}; dynamic entries inserted: {:?}",
        eng.streams.udp.iter().filter_map(|c| c.quic.as_ref()).map(|q| q.h3.dynamic_inserts()).collect::<Vec<_>>());
}
