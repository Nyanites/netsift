//! End-to-end decryption tests: a real rustls client and server talk in memory, the TLS bytes are
//! wrapped in synthetic Ethernet/IPv4/TCP frames, and the engine must recover the plaintext.

use crate::engine::Engine;
use crate::model::{proto, Frame};
use crate::tls::{KeyLog, TlsStatus};
use rustls::crypto::{ring, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, SupportedCipherSuite};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
struct CollectKeys(Mutex<String>);

impl rustls::KeyLog for CollectKeys {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let h = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let mut s = self.0.lock().unwrap();
        s.push_str(&format!("{label} {} {}\n", h(client_random), h(secret)));
    }
}

const REQUEST: &[u8] = b"GET /secret HTTP/1.1\r\nHost: example.test\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world";

/// Runs a full TLS exchange; returns the wire segments as (direction, bytes) and the key log.
fn run_tls(suite: SupportedCipherSuite, version: &'static rustls::SupportedProtocolVersion) -> (Vec<(usize, Vec<u8>)>, String) {
    run_tls_with(suite, version, b"http/1.1", REQUEST, RESPONSE)
}

/// Runs a TLS exchange where the client sends `request` and the server answers with `response`
/// once the whole request has arrived.
pub(crate) fn run_tls_with(
    suite: SupportedCipherSuite,
    version: &'static rustls::SupportedProtocolVersion,
    alpn: &[u8],
    request: &[u8],
    response: &[u8],
) -> (Vec<(usize, Vec<u8>)>, String) {
    let ck = rcgen::generate_simple_self_signed(vec!["example.test".to_string()]).unwrap();
    let cert = CertificateDer::from(ck.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let provider = Arc::new(CryptoProvider { cipher_suites: vec![suite], ..ring::default_provider() });
    let keys = Arc::new(CollectKeys::default());

    let mut scfg = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    scfg.alpn_protocols = vec![alpn.to_vec()];
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut ccfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    ccfg.alpn_protocols = vec![alpn.to_vec()];
    ccfg.key_log = keys.clone();

    let mut client = ClientConnection::new(Arc::new(ccfg), "example.test".try_into().unwrap()).unwrap();
    let mut server = ServerConnection::new(Arc::new(scfg)).unwrap();
    client.writer().write_all(request).unwrap();

    let mut segs = Vec::new();
    let mut got_req = Vec::new();
    let mut got_resp = Vec::new();
    let mut responded = false;
    for _ in 0..32 {
        let mut moved = false;
        let mut buf = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            moved = true;
            server.read_tls(&mut &buf[..]).unwrap();
            server.process_new_packets().unwrap();
            segs.push((0, buf));
        }
        let mut tmp = [0u8; 4096];
        while let Ok(n) = server.reader().read(&mut tmp) {
            if n == 0 {
                break;
            }
            got_req.extend_from_slice(&tmp[..n]);
        }
        if got_req == request && !responded {
            server.writer().write_all(response).unwrap();
            responded = true;
        }
        let mut buf = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            moved = true;
            client.read_tls(&mut &buf[..]).unwrap();
            client.process_new_packets().unwrap();
            segs.push((1, buf));
        }
        while let Ok(n) = client.reader().read(&mut tmp) {
            if n == 0 {
                break;
            }
            got_resp.extend_from_slice(&tmp[..n]);
        }
        if !moved {
            break;
        }
    }
    assert_eq!(got_resp, response, "the in-memory TLS exchange itself failed");
    let k = keys.0.lock().unwrap().clone();
    (segs, k)
}

fn tcp_frame(from_client: bool, seq: u32, ack: u32, flags: u8, payload: &[u8], ts: f64) -> Frame {
    let (src, dst, sp, dp) = if from_client {
        ([10, 0, 0, 1], [10, 0, 0, 2], 50000u16, 443u16)
    } else {
        ([10, 0, 0, 2], [10, 0, 0, 1], 443, 50000)
    };
    let mut d = Vec::new();
    d.extend_from_slice(&[0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00]);
    let total = (20 + 20 + payload.len()) as u16;
    d.extend_from_slice(&[0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0x40, 0, 64, 6, 0, 0]);
    d.extend_from_slice(&src);
    d.extend_from_slice(&dst);
    d.extend_from_slice(&sp.to_be_bytes());
    d.extend_from_slice(&dp.to_be_bytes());
    d.extend_from_slice(&seq.to_be_bytes());
    d.extend_from_slice(&ack.to_be_bytes());
    d.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    d.extend_from_slice(payload);
    Frame { ts, orig_len: d.len() as u32, linktype: 1, data: d, comment: None }
}

/// Builds a TCP capture of the exchange. Segments are cut at 300 bytes so TLS records span
/// packets; `shuffle` swaps a pair of segments and duplicates one to exercise reassembly.
pub(crate) fn build_capture(segs: &[(usize, Vec<u8>)], shuffle: bool) -> Vec<Frame> {
    let mut frames = Vec::new();
    let (mut cseq, mut sseq) = (1000u32, 9000u32);
    let mut ts = 1_700_000_000.0;
    let mut t = || {
        ts += 0.001;
        ts
    };
    frames.push(tcp_frame(true, cseq, 0, 0x02, &[], t()));
    frames.push(tcp_frame(false, sseq, cseq + 1, 0x12, &[], t()));
    cseq += 1;
    sseq += 1;
    frames.push(tcp_frame(true, cseq, sseq, 0x10, &[], t()));
    let mut data_frames = Vec::new();
    for (dir, bytes) in segs {
        for chunk in bytes.chunks(300) {
            let f = if *dir == 0 {
                let f = tcp_frame(true, cseq, sseq, 0x18, chunk, 0.0);
                cseq += chunk.len() as u32;
                f
            } else {
                let f = tcp_frame(false, sseq, cseq, 0x18, chunk, 0.0);
                sseq += chunk.len() as u32;
                f
            };
            data_frames.push(f);
        }
    }
    assert!(!shuffle || data_frames.len() > 4, "capture too small to shuffle");
    if shuffle {
        data_frames.swap(2, 3);
        let dup = data_frames[1].clone();
        data_frames.insert(4, dup);
    }
    for mut f in data_frames {
        f.ts = t();
        frames.push(f);
    }
    frames
}

fn check(suite: SupportedCipherSuite, version: &'static rustls::SupportedProtocolVersion, shuffle: bool, keys_first: bool) {
    let (segs, keylog) = run_tls(suite, version);
    let mut eng = Engine::default();
    let mut k = KeyLog::default();
    k.parse(&keylog);
    let mut pending = Some(k);
    if keys_first {
        eng.keylog = pending.take().unwrap();
    }
    for f in build_capture(&segs, shuffle) {
        eng.ingest(f);
    }
    if !keys_first {
        // Keys arriving after the traffic (e.g. key log loaded later) must also work.
        assert_eq!(eng.streams.tcp[0].tls.as_ref().unwrap().status, TlsStatus::WaitingForKeys);
        eng.set_keylog(pending.take().unwrap());
    }
    let conv = &eng.streams.tcp[0];
    let tls = conv.tls.as_ref().expect("TLS session detected");
    assert_eq!(tls.status, TlsStatus::Decrypting, "suite {:?}", suite.suite());
    assert_eq!(tls.sni.as_deref(), Some("example.test"));
    assert_eq!(tls.alpn.as_deref(), Some("http/1.1"));
    let client = tls.client_dir.unwrap();
    assert_eq!(tls.dirs[client].plain, REQUEST);
    assert_eq!(tls.dirs[1 - client].plain, RESPONSE);
    let http: Vec<_> = eng.packets.iter().filter(|p| p.meta.protos & proto::HTTP != 0).collect();
    assert_eq!(http.len(), 2, "request and response rows are marked HTTP");
    assert!(http.iter().any(|p| p.meta.http_status == Some(200)));
    assert!(http.iter().any(|p| p.meta.http_host.as_deref() == Some("example.test")));
    if shuffle {
        assert!(eng.packets.iter().any(|p| p.retransmission), "duplicate flagged as retransmission");
    }
}

use rustls::crypto::ring::cipher_suite as cs;

#[test]
fn tls13_aes128() {
    check(cs::TLS13_AES_128_GCM_SHA256, &rustls::version::TLS13, false, true);
}

#[test]
fn tls13_aes256_out_of_order() {
    check(cs::TLS13_AES_256_GCM_SHA384, &rustls::version::TLS13, true, true);
}

#[test]
fn tls13_chacha_keys_later() {
    check(cs::TLS13_CHACHA20_POLY1305_SHA256, &rustls::version::TLS13, false, false);
}

#[test]
fn tls12_aes128() {
    check(cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, &rustls::version::TLS12, false, true);
}

#[test]
fn tls12_aes256_out_of_order() {
    check(cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, &rustls::version::TLS12, true, true);
}

#[test]
fn tls12_chacha_keys_later() {
    check(cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, &rustls::version::TLS12, false, false);
}

#[test]
fn filters_on_decrypted_traffic() {
    let (segs, keylog) = run_tls(cs::TLS13_AES_128_GCM_SHA256, &rustls::version::TLS13);
    let mut eng = Engine::default();
    eng.keylog.parse(&keylog);
    for f in build_capture(&segs, false) {
        eng.ingest(f);
    }
    let bm = Default::default();
    let ctx = crate::filter::EvalCtx { bookmarks: &bm, processes: &eng.processes, missing: &bm };
    let count = |f: &str| {
        let e = crate::filter::parse(f).unwrap().unwrap();
        eng.packets.iter().enumerate().filter(|(i, p)| e.matches(*i, p, &ctx)).count()
    };
    assert_eq!(count("http.host == \"example.test\""), 1);
    assert_eq!(count("http.response.code == 200"), 1);
    assert_eq!(count("tls.sni contains \"example\""), 1);
    assert!(count("decrypted") >= 2);
    assert_eq!(count("tcp.stream == 0"), eng.packets.len());
    assert_eq!(count("tcp.flags.syn && !tcp.flags.ack"), 1);
    assert_eq!(count("ip.src == 10.0.0.0/24 && !tcp"), 0);
}


#[test]
fn pcap_roundtrip_through_libpcap() {
    let (segs, keylog) = run_tls(cs::TLS13_AES_128_GCM_SHA256, &rustls::version::TLS13);
    let frames = build_capture(&segs, false);
    let dir = std::env::var_os("NETSIFT_DEMO_DIR").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir);
    let path = dir.join(format!("netsift-demo-{}.pcap", std::process::id()));
    crate::capture::save_pcap(&path, frames.iter(), 1).unwrap();
    std::fs::write(dir.join("netsift-demo-keys.log"), &keylog).unwrap();

    let src = crate::capture::open_file(&path, eframe::egui::Context::default());
    let mut eng = Engine::default();
    eng.keylog.parse(&keylog);
    loop {
        match src.rx.recv().unwrap() {
            crate::capture::Msg::Frames(v) => v.into_iter().for_each(|f| eng.ingest(f)),
            crate::capture::Msg::Done => break,
            crate::capture::Msg::Error(e) => panic!("{e}"),
            _ => {}
        }
    }
    assert_eq!(eng.packets.len(), frames.len());
    assert_eq!(eng.packets[3].frame.data, frames[3].data);
    assert_eq!(eng.streams.tcp[0].tls.as_ref().unwrap().status, TlsStatus::Decrypting);
    if std::env::var_os("NETSIFT_DEMO_DIR").is_none() {
        let _ = std::fs::remove_file(&path);
    }
}

fn eth_ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8]) -> Vec<u8> {
    let mut d = vec![0x02, 0, 0, 0, 0, dst[3], 0x02, 0, 0, 0, 0, src[3], 0x08, 0x00];
    let total = (20 + l4.len()) as u16;
    d.extend_from_slice(&[0x45, 0, (total >> 8) as u8, total as u8, 0, 1, 0x40, 0, 64, proto, 0, 0]);
    d.extend_from_slice(&src);
    d.extend_from_slice(&dst);
    d.extend_from_slice(l4);
    d
}

fn udp(sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    let mut u = Vec::new();
    u.extend_from_slice(&sp.to_be_bytes());
    u.extend_from_slice(&dp.to_be_bytes());
    u.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(payload);
    u
}

fn tcp_seg(sp: u16, dp: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&sp.to_be_bytes());
    t.extend_from_slice(&dp.to_be_bytes());
    t.extend_from_slice(&seq.to_be_bytes());
    t.extend_from_slice(&ack.to_be_bytes());
    t.extend_from_slice(&[0x50, flags, 0xfa, 0xf0, 0, 0, 0, 0]);
    t.extend_from_slice(payload);
    t
}

fn dns_msg(id: u16, name: &str, qtype: u16, response: Option<(u8, Option<[u8; 4]>)>) -> Vec<u8> {
    let mut m = id.to_be_bytes().to_vec();
    let (flags, an) = match response {
        None => (0x0100u16, 0u16),
        Some((rcode, a)) => (0x8180 | rcode as u16, a.is_some() as u16),
    };
    m.extend_from_slice(&flags.to_be_bytes());
    m.extend_from_slice(&[0, 1]);
    m.extend_from_slice(&an.to_be_bytes());
    m.extend_from_slice(&[0, 0, 0, 0]);
    for label in name.split('.') {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&[0, 1]);
    if let Some((_, Some(ip))) = response {
        m.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4]);
        m.extend_from_slice(&ip);
    }
    m
}

/// A capture with a bit of everything. Written to $NETSIFT_DEMO_DIR when set.
#[test]
fn rich_capture() {
    let me = [192, 168, 1, 20];
    let gw = [192, 168, 1, 1];
    let web = [93, 184, 216, 34];
    let mut ts = 1_760_000_000.0;
    let mut frames: Vec<Frame> = Vec::new();
    let mut push = |data: Vec<u8>| {
        ts += 0.0137;
        frames.push(Frame { ts, orig_len: data.len() as u32, linktype: 1, data, comment: None });
    };
    // ARP
    let mut arp = vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 20, 0x08, 0x06];
    arp.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1, 0x02, 0, 0, 0, 0, 20]);
    arp.extend_from_slice(&me);
    arp.extend_from_slice(&[0; 6]);
    arp.extend_from_slice(&gw);
    push(arp);
    // DNS: one success, one NXDOMAIN
    push(eth_ipv4(me, gw, 17, &udp(53001, 53, &dns_msg(0x1a2b, "example.com", 1, None))));
    push(eth_ipv4(gw, me, 17, &udp(53, 53001, &dns_msg(0x1a2b, "example.com", 1, Some((0, Some(web)))))));
    push(eth_ipv4(me, gw, 17, &udp(53002, 53, &dns_msg(0x3c4d, "nope.invalid", 1, None))));
    push(eth_ipv4(gw, me, 17, &udp(53, 53002, &dns_msg(0x3c4d, "nope.invalid", 1, Some((3, None))))));
    // ICMP echo
    let mut ping = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1];
    ping.extend_from_slice(b"abcdefghijklmnop");
    push(eth_ipv4(me, web, 1, &ping));
    ping[0] = 0;
    push(eth_ipv4(web, me, 1, &ping));
    // Plain HTTP with a 404
    let (c, s) = (40000u32, 70000u32);
    push(eth_ipv4(me, web, 6, &tcp_seg(51000, 80, c, 0, 0x02, &[])));
    push(eth_ipv4(web, me, 6, &tcp_seg(80, 51000, s, c + 1, 0x12, &[])));
    push(eth_ipv4(me, web, 6, &tcp_seg(51000, 80, c + 1, s + 1, 0x10, &[])));
    let req = b"GET /missing HTTP/1.1\r\nHost: example.com\r\nUser-Agent: netsift-test\r\n\r\n";
    push(eth_ipv4(me, web, 6, &tcp_seg(51000, 80, c + 1, s + 1, 0x18, req)));
    let resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found";
    push(eth_ipv4(web, me, 6, &tcp_seg(80, 51000, s + 1, c + 1 + req.len() as u32, 0x18, resp)));
    push(eth_ipv4(me, web, 6, &tcp_seg(51000, 80, c + 1 + req.len() as u32, s + 1 + resp.len() as u32, 0x14, &[])));
    // Decryptable TLS 1.2 and an undecryptable TLS 1.3 session on other ports
    let (segs12, keys12) = run_tls(cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, &rustls::version::TLS12);
    let (segs13, _keys13) = run_tls(cs::TLS13_AES_128_GCM_SHA256, &rustls::version::TLS13);
    for (segs, port) in [(&segs12, 52000u16), (&segs13, 52001u16)] {
        for f in build_capture(segs, false) {
            // Re-address the synthetic TLS frames onto this capture's hosts.
            let mut d = f.data;
            let (src, dst) = if d[29] == 1 { (me, web) } else { (web, me) };
            d[26..30].copy_from_slice(&src);
            d[30..34].copy_from_slice(&dst);
            if d[34..36] == 50000u16.to_be_bytes() {
                d[34..36].copy_from_slice(&port.to_be_bytes());
            } else {
                d[36..38].copy_from_slice(&port.to_be_bytes());
            }
            push(d);
        }
    }
    let mut eng = Engine::default();
    eng.keylog.parse(&keys12);
    for f in frames.iter().cloned() {
        eng.ingest(f);
    }
    assert_eq!(eng.packets[0].info, "Who has 192.168.1.1? Tell 192.168.1.20");
    assert!(eng.packets[2].info.contains("A 93.184.216.34"), "{}", eng.packets[2].info);
    assert!(eng.experts.iter().any(|e| e.message.contains("No such name")));
    assert!(eng.experts.iter().any(|e| e.message.contains("404")));
    assert!(eng.experts.iter().any(|e| e.category == "Reset"));
    assert!(eng.packets[5].info.starts_with("Echo (ping) request"));
    let tls: Vec<_> = eng.streams.tcp.iter().filter_map(|c| c.tls.as_ref()).map(|t| t.status.clone()).collect();
    assert_eq!(tls, vec![TlsStatus::Decrypting, TlsStatus::WaitingForKeys]);
    if let Some(dir) = std::env::var_os("NETSIFT_DEMO_DIR") {
        let dir = std::path::PathBuf::from(dir);
        crate::capture::save_pcap(&dir.join("netsift-rich.pcap"), frames.iter(), 1).unwrap();
        std::fs::write(dir.join("netsift-rich-keys.log"), keys12).unwrap();
    }
}

#[test]
#[ignore = "benchmark; run with --release -- --ignored"]
fn ingest_throughput() {
    let (segs, keylog) = run_tls(cs::TLS13_AES_128_GCM_SHA256, &rustls::version::TLS13);
    let base = build_capture(&segs, false);
    let mut eng = Engine::default();
    eng.keylog.parse(&keylog);
    let mut frames = Vec::new();
    for conn in 0..30_000u32 {
        for f in &base {
            let mut f = f.clone();
            // Give every copy its own client port so each is a separate decryptable session.
            let port = (10_000 + conn % 50_000) as u16;
            let off = if f.data[37] == 0xbb && f.data[36] == 0x01 { 34 } else { 36 };
            f.data[off..off + 2].copy_from_slice(&port.to_be_bytes());
            frames.push(f);
        }
    }
    let n = frames.len();
    let t = std::time::Instant::now();
    for f in frames {
        eng.ingest(f);
    }
    let secs = t.elapsed().as_secs_f64();
    let (s, d, _) = eng.tls_summary();
    eprintln!("{n} packets in {secs:.2}s = {:.0} pkt/s; TLS {d}/{s} decrypted", n as f64 / secs);
}

#[test]
fn compare_finds_missing_packets_and_offset() {
    let (segs, _) = run_tls(cs::TLS13_AES_128_GCM_SHA256, &rustls::version::TLS13);
    let frames = build_capture(&segs, false);
    let mut a = Engine::default();
    let mut b = Engine::default();
    // A sees an extra copy of a retransmitted ACK much later; B lost packets 3 and 5.
    let mut fa = frames.clone();
    let mut dup = frames[2].clone();
    dup.ts += 5.0;
    fa.push(dup);
    for f in fa {
        a.ingest(f);
    }
    for (i, mut f) in frames.into_iter().enumerate() {
        if i == 3 || i == 5 {
            continue;
        }
        f.ts += 0.25;
        b.ingest(f);
    }
    let r = crate::compare::compare(&a, &b);
    assert_eq!(r.only_a, vec![3, 5, a.packets.len() - 1]);
    assert!(r.only_b.is_empty());
    assert!(r.deltas.iter().all(|d| (d - 0.25).abs() < 1e-6), "{:?}", r.deltas);
}

/// Builds a large benchmark capture from a real one: N copies, each with a different local IP
/// (so conversations stay distinct) and shifted in time.
/// NETSIFT_BIG_IN=browse.pcap NETSIFT_BIG_OUT=big.pcap NETSIFT_BIG_COPIES=100 cargo test --release make_big -- --ignored
#[test]
#[ignore = "benchmark data generator"]
fn make_big_capture() {
    let (Ok(input), Ok(out)) = (std::env::var("NETSIFT_BIG_IN"), std::env::var("NETSIFT_BIG_OUT")) else { return };
    let copies: u32 = std::env::var("NETSIFT_BIG_COPIES").ok().and_then(|s| s.parse().ok()).unwrap_or(100);
    let local: [u8; 4] = std::env::var("NETSIFT_BIG_LOCAL").ok().and_then(|s| s.parse::<std::net::Ipv4Addr>().ok()).map(|a| a.octets()).unwrap_or([192, 168, 50, 157]);
    let mut frames = Vec::new();
    crate::capture::for_each_frame(std::path::Path::new(&input), |f| frames.push(f)).unwrap();
    let span = frames.last().unwrap().ts - frames[0].ts + 1.0;
    let all = (0..copies).flat_map(|k| {
        frames.iter().map(move |f| {
            let mut f = f.clone();
            f.ts += k as f64 * span;
            let d = &mut f.data;
            if std::env::var_os("NETSIFT_BIG_ANON").is_some() && f.linktype == 1 && d.len() >= 34 {
                // Replace MAC addresses with locally administered placeholders:
                // 02:00:00:00:00:01 for this host, 02:00:00:00:00:fe for the gateway.
                let outgoing = d[26..30] == local;
                let (me, gw) = ([0x02, 0, 0, 0, 0, 0x01], [0x02, 0, 0, 0, 0, 0xfe]);
                let (dst, src) = if outgoing { (gw, me) } else { (me, gw) };
                d[0..6].copy_from_slice(&dst);
                d[6..12].copy_from_slice(&src);
            }
            if f.linktype == 1 && d.len() >= 34 && d[12..14] == [8, 0] {
                let new = [10, (k >> 8) as u8, k as u8, local[3]];
                for off in [26, 30] {
                    if d[off..off + 4] == local {
                        d[off..off + 4].copy_from_slice(&new);
                    }
                }
            }
            f
        })
    });
    let all: Vec<Frame> = all.collect();
    crate::capture::save_pcap(std::path::Path::new(&out), all.iter(), 1).unwrap();
    eprintln!("wrote {} packets", all.len());
}
