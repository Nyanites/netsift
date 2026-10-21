//! Live-capture tests. They need permission to open /dev/bpf* (root, or the access_bpf group
//! that Wireshark's ChmodBPF sets up), so they are ignored by default:
//! `cargo test -- --ignored live_`

use crate::capture::{self, Msg};
use crate::engine::Engine;
use std::io::{Read, Write};
use std::time::Duration;

fn loopback() -> &'static str {
    if cfg!(target_os = "macos") { "lo0" } else { "lo" }
}

#[test]
#[ignore = "needs packet capture permission"]
fn live_capture_attributes_processes() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut src = capture::start_live(loopback(), &format!("tcp port {port}"), false, true, eframe::egui::Context::default()).unwrap();
    std::thread::sleep(Duration::from_millis(400));

    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).unwrap();
        s.write_all(b"world").unwrap();
    });
    let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.write_all(b"hello").unwrap();
    let mut buf = [0u8; 5];
    c.read_exact(&mut buf).unwrap();
    server.join().unwrap();
    std::thread::sleep(Duration::from_millis(300));
    drop(c);
    std::thread::sleep(Duration::from_millis(300));
    src.stop();

    let mut eng = Engine::default();
    let mut linktypes = std::collections::HashSet::new();
    while let Ok(m) = src.rx.try_recv() {
        match m {
            Msg::Frames(v) => v.into_iter().for_each(|f| {
                linktypes.insert(f.linktype);
                eng.ingest(f)
            }),
            Msg::Sockets(s) => eng.apply_sockets(s),
            Msg::Error(e) => panic!("{e}"),
            _ => {}
        }
    }
    assert!(eng.packets.len() >= 6, "captured {} packets", eng.packets.len());
    let conv = eng.streams.tcp.iter().find(|c| c.a.1 == port || c.b.1 == port).expect("conversation captured");
    let me = std::process::id();
    let p = &eng.processes[conv.process.expect("conversation attributed") as usize];
    assert_eq!(p.pid, me, "attributed to {p:?}");
    // Every packet of the conversation carries the process, including ones before the snapshot.
    assert!(conv.packets.iter().all(|&i| eng.packets[i].meta.process.is_some()));
    eprintln!("linktypes {linktypes:?}; process {p:?}; {} packets", eng.packets.len());
    if cfg!(target_os = "macos") {
        // Apple per-packet metadata: direction always; process names only when running as root.
        let comments: Vec<_> = eng.packets.iter().filter_map(|p| p.frame.comment.clone()).collect();
        eprintln!("sample metadata: {:?}", comments.iter().take(3).collect::<Vec<_>>());
        assert_eq!(comments.len(), eng.packets.len(), "every packet carries metadata");
        assert!(eng.packets.iter().all(|p| p.meta.pktap.as_ref().is_some_and(|t| t.dir.is_some())));
    }
}


/// A separate, short-lived process (curl) on the real network interface must be attributed via
/// the socket-table watcher.
#[test]
#[ignore = "needs packet capture permission and network access"]
fn live_attributes_short_lived_curl() {
    let dev = crate::capture::list_devices().unwrap().into_iter().find(|d| d.up && !d.loopback && !d.addrs.is_empty()).expect("an active interface");
    let mut src = capture::start_live(&dev.name, "tcp port 443 and host example.com", false, true, eframe::egui::Context::default()).unwrap();
    std::thread::sleep(Duration::from_millis(400));
    let child = std::process::Command::new("curl").args(["-s", "-o", "/dev/null", "https://example.com/"]).spawn().unwrap();
    let curl_pid = child.id();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    std::thread::sleep(Duration::from_millis(500));
    src.stop();
    let mut eng = Engine::default();
    while let Ok(m) = src.rx.try_recv() {
        match m {
            Msg::Frames(v) => v.into_iter().for_each(|f| eng.ingest(f)),
            Msg::Sockets(s) => eng.apply_sockets(s),
            _ => {}
        }
    }
    let convs: Vec<_> = eng.streams.tcp.iter().collect();
    assert!(!convs.is_empty(), "no traffic captured");
    for c in &convs {
        let p = c.process.map(|i| &eng.processes[i as usize]);
        eprintln!("{} → {:?} ({} packets)", c.label(), p.map(|p| (&p.name, p.pid, p.source)), c.packets.len());
        let p = p.expect("curl connection attributed");
        assert_eq!((p.pid, p.name.as_str()), (curl_pid, "curl"));
        assert!(c.packets.iter().all(|&i| eng.packets[i].meta.process.is_some()));
    }
    let bm = Default::default();
    let ctx = crate::filter::EvalCtx { bookmarks: &bm, processes: &eng.processes, missing: &bm };
    let count = |f: &str| {
        let e = crate::filter::parse(f).unwrap().unwrap();
        eng.packets.iter().enumerate().filter(|(i, p)| e.matches(*i, p, &ctx)).count()
    };
    let total: usize = convs.iter().map(|c| c.packets.len()).sum();
    assert_eq!(count("process == \"curl\""), total);
    assert_eq!(count(&format!("pid == {curl_pid}")), total);
    assert_eq!(count("app contains \"cur\""), total);
    assert_eq!(count("!process"), eng.packets.len() - total);
}
