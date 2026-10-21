//! Headless mode: `netsift query|sessions|har|diff …` for scripting and benchmarking.

use crate::engine::Engine;
use crate::filter::{self, EvalCtx};
use crate::tls::KeyLog;
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;
use std::time::Instant;

pub const USAGE: &str = "\
Usage:
  netsift [capture.pcap] [--keylog keys.log]          open the GUI
  netsift query <file> [-k keys.log] [-f filter] [-c] [-w out.pcap]
                                                         print (or save) matching packets; -c: count only
  netsift sessions <file> [-k keys.log]                 list TLS/QUIC sessions and decryption status
  netsift http <file> [-k keys.log]                     list HTTP requests with timings
  netsift har <file> -o out.har [-k keys.log]           export HTTP (incl. decrypted) as HAR
  netsift diff <a.pcap> <b.pcap> [-f filter]            compare two captures";

/// Loads a capture synchronously, printing timing to stderr.
pub fn load(path: &Path, keylog: Option<&Path>) -> Result<Engine, String> {
    let mut eng = Engine::default();
    if let Some(k) = keylog {
        eng.keylog = KeyLog::load(k).map_err(|e| format!("{}: {e}", k.display()))?;
    }
    let t = Instant::now();
    crate::capture::for_each_frame(path, |f| eng.ingest(f))?;
    let secs = t.elapsed().as_secs_f64();
    eprintln!(
        "loaded {} packets ({:.1} MB) in {secs:.2}s — {:.0} packets/s",
        eng.packets.len(),
        eng.total_bytes as f64 / 1e6,
        eng.packets.len() as f64 / secs.max(1e-9)
    );
    Ok(eng)
}

struct Args {
    pos: Vec<String>,
    keylog: Option<String>,
    filter: Option<String>,
    out: Option<String>,
    write: Option<String>,
    count: bool,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut a = Args { pos: Vec::new(), keylog: None, filter: None, out: None, write: None, count: false };
    let mut it = args.iter();
    while let Some(x) = it.next() {
        match x.as_str() {
            "-k" | "--keylog" => a.keylog = Some(it.next().ok_or("-k needs a file")?.clone()),
            "-f" | "--filter" | "-Y" => a.filter = Some(it.next().ok_or("-f needs a filter")?.clone()),
            "-o" | "--out" => a.out = Some(it.next().ok_or("-o needs a file")?.clone()),
            "-c" | "--count" => a.count = true,
            "-w" | "--write" => a.write = Some(it.next().ok_or("-w needs a file")?.clone()),
            _ => a.pos.push(x.clone()),
        }
    }
    Ok(a)
}

/// Runs a CLI command if `args` (without the program name) starts with one. Returns the exit
/// code, or None to launch the GUI.
pub fn run(args: &[String]) -> Option<i32> {
    let cmd = args.first()?.as_str();
    if !matches!(cmd, "query" | "sessions" | "http" | "har" | "diff") {
        return None;
    }
    let result = parse(&args[1..]).and_then(|a| match cmd {
        "query" => query(&a),
        "sessions" => sessions(&a),
        "http" => http(&a),
        "har" => har(&a),
        _ => diff(&a),
    });
    Some(match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            2
        }
    })
}

fn file_arg(a: &Args, i: usize) -> Result<&Path, String> {
    a.pos.get(i).map(Path::new).ok_or_else(|| "missing capture file".to_string())
}

fn query(a: &Args) -> Result<(), String> {
    let eng = load(file_arg(a, 0)?, a.keylog.as_deref().map(Path::new))?;
    let expr = match &a.filter {
        Some(f) => filter::parse(f)?,
        None => None,
    };
    let bm = HashSet::new();
    let ctx = EvalCtx { bookmarks: &bm, processes: &eng.processes, missing: &bm };
    let t = Instant::now();
    let matches: Vec<usize> = match &expr {
        Some(e) => crate::filter::matching(e, &eng.packets, &ctx),
        None => (0..eng.packets.len()).collect(),
    };
    let ms = t.elapsed().as_secs_f64() * 1000.0;
    if let Some(w) = &a.write {
        let lt = eng.packets.first().map(|p| p.frame.linktype).unwrap_or(1);
        let n = crate::capture::save_pcap(Path::new(w), matches.iter().map(|&i| &eng.packets[i].frame), lt).map_err(|e| e.to_string())?;
        eprintln!("wrote {n} packets to {w}");
    } else if !a.count {
        let out = std::io::stdout();
        let mut w = std::io::BufWriter::new(out.lock());
        let t0 = eng.first_ts();
        for &i in &matches {
            let p = &eng.packets[i];
            let _ = writeln!(w, "{:>7} {:>10.6} {} → {} {} {} {}", i + 1, p.frame.ts - t0, p.src, p.dst, p.protocol, p.frame.orig_len, p.info);
        }
    }
    eprintln!("filter matched {} of {} packets in {ms:.1} ms", matches.len(), eng.packets.len());
    if a.count {
        println!("{}", matches.len());
    }
    Ok(())
}

fn sessions(a: &Args) -> Result<(), String> {
    let eng = load(file_arg(a, 0)?, a.keylog.as_deref().map(Path::new))?;
    for c in &eng.streams.tcp {
        if let Some(t) = &c.tls {
            println!(
                "TLS  tcp.stream {:<4} {:<44} {:<30} {:<8} {:<6} {}",
                c.id,
                c.label(),
                t.sni.clone().unwrap_or_default(),
                t.version.map(crate::dissect::tls_version_name).unwrap_or("?"),
                t.alpn.clone().unwrap_or_default(),
                t.status.label() + if t.ech_resolved { " (ECH)" } else { "" }
            );
        }
    }
    for c in &eng.streams.udp {
        if let Some(q) = &c.quic {
            println!(
                "QUIC udp.stream {:<4} {:<44} {:<30} {:<8} {:<6} {} ({} packets decrypted)",
                c.id,
                c.label(),
                q.sni.clone().unwrap_or_default(),
                "QUIC",
                q.alpn.clone().unwrap_or_default(),
                q.status.label() + if q.ech_resolved { " (ECH)" } else { "" },
                q.decrypted_packets
            );
        }
    }
    let (s, d, m) = eng.tls_summary();
    eprintln!("{d}/{s} encrypted sessions decrypted ({m} missing keys)");
    Ok(())
}

fn http(a: &Args) -> Result<(), String> {
    let eng = load(file_arg(a, 0)?, a.keylog.as_deref().map(Path::new))?;
    let t0 = eng.first_ts();
    let reqs = crate::timeline::requests(&eng);
    for r in &reqs {
        println!(
            "{:>8.3}s {:>7} {:<6} {:<4} {:<60} {:>4} {:>9} B  wait {:>7.1} ms  total {:>7.1} ms  {}.stream == {}",
            r.start - t0,
            format!("HTTP/{}", r.version),
            r.method,
            r.status.map(|s| s.to_string()).unwrap_or_else(|| "—".into()),
            format!("{}{}", r.host, r.path).chars().take(60).collect::<String>(),
            r.process.clone().unwrap_or_default().chars().take(4).collect::<String>(),
            r.body_bytes,
            r.ttfb().unwrap_or(0.0) * 1000.0,
            r.total().unwrap_or(0.0) * 1000.0,
            if r.conv.0 == crate::model::StreamKind::Tcp { "tcp" } else { "udp" },
            r.conv.1
        );
    }
    eprintln!("{} HTTP requests", reqs.len());
    Ok(())
}

fn har(a: &Args) -> Result<(), String> {
    let eng = load(file_arg(a, 0)?, a.keylog.as_deref().map(Path::new))?;
    let out = a.out.as_ref().ok_or("-o out.har is required")?;
    let reqs = crate::timeline::requests(&eng);
    std::fs::write(out, crate::timeline::har(&reqs)).map_err(|e| e.to_string())?;
    eprintln!("wrote {} requests to {out}", reqs.len());
    Ok(())
}

fn diff(a: &Args) -> Result<(), String> {
    let left = load(file_arg(a, 0)?, None)?;
    let right = load(file_arg(a, 1)?, None)?;
    let t = Instant::now();
    let d = crate::compare::compare(&left, &right);
    eprintln!("compared in {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
    println!("{}", d.summary());
    for (label, list, eng) in [("only in A", &d.only_a, &left), ("only in B", &d.only_b, &right)] {
        println!("\n{label}: {}", list.len());
        for &i in list.iter().take(50) {
            let p = &eng.packets[i];
            println!("  #{:<7} {} → {} {} {}", i + 1, p.src, p.dst, p.protocol, p.info);
        }
        if list.len() > 50 {
            println!("  … {} more", list.len() - 50);
        }
    }
    Ok(())
}
