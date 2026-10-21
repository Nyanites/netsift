//! Packet sources: live capture via libpcap and pcap/pcapng file loading, both on background
//! threads that stream frames to the UI over a channel.

use crate::model::Frame;
use eframe::egui;
use crossbeam_channel::{unbounded, Receiver, Sender};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub enum Msg {
    Frames(Vec<Frame>),
    Progress(f32),
    Stats { received: u32, dropped: u32 },
    /// New sockets seen by the process watcher (live capture only).
    Sockets(crate::procs::Snapshot),
    Error(String),
    Done,
}

pub struct Source {
    pub rx: Receiver<Msg>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    pub live: bool,
}

impl Source {
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

#[derive(Clone)]
pub struct DeviceInfo {
    pub name: String,
    pub desc: String,
    pub addrs: Vec<String>,
    pub up: bool,
    pub loopback: bool,
}

impl DeviceInfo {
    pub fn label(&self) -> String {
        let mut s = self.name.clone();
        if let Some(a) = self.addrs.first() {
            s.push_str(&format!("  ({a})"));
        } else if !self.desc.is_empty() {
            s.push_str(&format!("  ({})", self.desc));
        }
        s
    }
}

pub fn list_devices() -> Result<Vec<DeviceInfo>, String> {
    let devs = pcap::Device::list().map_err(|e| e.to_string())?;
    let mut v: Vec<DeviceInfo> = devs
        .into_iter()
        .map(|d| DeviceInfo {
            desc: d.desc.clone().unwrap_or_default(),
            addrs: d.addresses.iter().map(|a| a.addr.to_string()).filter(|a| !a.starts_with("fe80")).collect(),
            up: d.flags.is_up() && d.flags.is_running(),
            loopback: d.flags.is_loopback(),
            name: d.name,
        })
        .collect();
    // Interfaces with addresses first, then running ones; "any"/loopback last.
    v.sort_by_key(|d| (d.addrs.is_empty(), !d.up, d.loopback));
    Ok(v)
}

fn ts_of(h: &pcap::PacketHeader) -> f64 {
    h.ts.tv_sec as f64 + h.ts.tv_usec as f64 / 1e6
}

pub fn open_file(path: &Path, ctx: egui::Context) -> Source {
    let (tx, rx) = unbounded();
    let stop = Arc::new(AtomicBool::new(false));
    let st = stop.clone();
    let path: PathBuf = path.to_path_buf();
    let handle = std::thread::spawn(move || read_file(&path, &tx, &st, &ctx));
    Source { rx, stop, handle: Some(handle), live: false }
}

fn read_file(path: &Path, tx: &Sender<Msg>, stop: &AtomicBool, ctx: &egui::Context) {
    let total = std::fs::metadata(path).map(|m| m.len()).unwrap_or(1).max(1) as f64;
    let mut cap = match pcap::Capture::from_file(path) {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(Msg::Error(format!("Cannot open {}: {e}", path.display())));
            ctx.request_repaint();
            return;
        }
    };
    let lt = cap.get_datalink().0;
    let mut batch = Vec::with_capacity(4096);
    let mut read = 24.0;
    let mut last = Instant::now();
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match cap.next_packet() {
            Ok(p) => {
                read += p.header.caplen as f64 + 16.0;
                batch.push(Frame { ts: ts_of(p.header), orig_len: p.header.len, linktype: lt, data: p.data.to_vec(), comment: None });
                if batch.len() >= 4096 {
                    let _ = tx.send(Msg::Frames(std::mem::take(&mut batch)));
                    if last.elapsed() > Duration::from_millis(50) {
                        let _ = tx.send(Msg::Progress((read / total).min(1.0) as f32));
                        ctx.request_repaint();
                        last = Instant::now();
                    }
                }
            }
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => {
                let _ = tx.send(Msg::Frames(std::mem::take(&mut batch)));
                let _ = tx.send(Msg::Error(format!("Read error (file may be truncated): {e}")));
                break;
            }
        }
    }
    let _ = tx.send(Msg::Frames(batch));
    let _ = tx.send(Msg::Done);
    ctx.request_repaint();
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    /// Apple libpcap: have the kernel attach PKTAP metadata (interface, direction, process).
    fn pcap_set_want_pktap(p: *mut std::ffi::c_void, want: i32) -> i32;
    /// Apple libpcap: expose that metadata as text in `pcap_pkthdr::comment`.
    fn pcap_apple_set_exthdr(p: *mut std::ffi::c_void, v: i32) -> i32;
}

/// Reads Apple's `char comment[256]`, which follows the standard `pcap_pkthdr` fields.
#[cfg(target_os = "macos")]
fn apple_comment(h: &pcap::PacketHeader) -> Option<String> {
    // SAFETY: on macOS libpcap's `struct pcap_pkthdr` is { timeval, caplen, len, comment[256] }
    // and `h` points at libpcap's own copy of it.
    let c = unsafe { std::slice::from_raw_parts((h as *const pcap::PacketHeader as *const u8).add(std::mem::size_of::<pcap::PacketHeader>()), 256) };
    let end = c.iter().position(|&b| b == 0)?;
    (end > 0).then(|| String::from_utf8_lossy(&c[..end]).into_owned())
}

#[cfg(not(target_os = "macos"))]
fn apple_comment(_: &pcap::PacketHeader) -> Option<String> {
    None
}

/// Starts a live capture. With `procs`, packets are attributed to local processes: on macOS via
/// PKTAP headers (per packet, needs root for process names) and, everywhere, via a socket-table
/// watcher thread.
/// Reads every frame of a capture file synchronously (headless mode).
pub fn for_each_frame(path: &Path, mut f: impl FnMut(Frame)) -> Result<(), String> {
    let mut cap = pcap::Capture::from_file(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let lt = cap.get_datalink().0;
    loop {
        match cap.next_packet() {
            Ok(p) => f(Frame { ts: ts_of(p.header), orig_len: p.header.len, linktype: lt, data: p.data.to_vec(), comment: None }),
            Err(pcap::Error::NoMorePackets) => return Ok(()),
            Err(e) => return Err(format!("read error (file may be truncated): {e}")),
        }
    }
}

pub fn start_live(device: &str, bpf: &str, promisc: bool, procs: bool, ctx: egui::Context) -> Result<Source, String> {
    let inactive = pcap::Capture::from_device(device)
        .map_err(|e| e.to_string())?
        .promisc(promisc)
        .snaplen(262_144)
        .timeout(100)
        .immediate_mode(true);
    #[cfg(target_os = "macos")]
    if procs {
        // SAFETY: the handle is a valid, not yet activated pcap_t.
        unsafe { pcap_set_want_pktap(inactive.as_ptr() as *mut std::ffi::c_void, 1) };
    }
    let cap = inactive.open().map_err(|e| permission_hint(e.to_string()))?;
    #[allow(unused_mut)]
    let mut apple_meta = false;
    #[cfg(target_os = "macos")]
    if procs {
        // SAFETY: the handle is a valid, activated pcap_t.
        apple_meta = unsafe { pcap_apple_set_exthdr(cap.as_ptr() as *mut std::ffi::c_void, 1) } == 0;
    }
    let mut cap = cap;
    if !bpf.trim().is_empty() {
        cap.filter(bpf, true).map_err(|e| format!("Capture filter error: {e}"))?;
    }
    let (tx, rx) = unbounded();
    let stop = Arc::new(AtomicBool::new(false));
    if procs {
        spawn_proc_watcher(tx.clone(), stop.clone());
    }
    let st = stop.clone();
    let handle = std::thread::spawn(move || {
        let lt = cap.get_datalink().0;
        let mut batch = Vec::new();
        let mut last_flush = Instant::now();
        let mut last_stats = Instant::now();
        while !st.load(Ordering::Relaxed) {
            match cap.next_packet() {
                Ok(p) => batch.push(Frame {
                    ts: ts_of(p.header),
                    orig_len: p.header.len,
                    linktype: lt,
                    data: p.data.to_vec(),
                    comment: if apple_meta { apple_comment(p.header) } else { None },
                }),
                Err(pcap::Error::TimeoutExpired) => {}
                Err(e) => {
                    let _ = tx.send(Msg::Error(format!("Capture stopped: {e}")));
                    break;
                }
            }
            if !batch.is_empty() && (batch.len() >= 512 || last_flush.elapsed() > Duration::from_millis(40)) {
                let _ = tx.send(Msg::Frames(std::mem::take(&mut batch)));
                ctx.request_repaint();
                last_flush = Instant::now();
            }
            if last_stats.elapsed() > Duration::from_secs(1) {
                if let Ok(s) = cap.stats() {
                    let _ = tx.send(Msg::Stats { received: s.received, dropped: s.dropped + s.if_dropped });
                }
                last_stats = Instant::now();
            }
        }
        let _ = tx.send(Msg::Frames(batch));
        let _ = tx.send(Msg::Done);
        ctx.request_repaint();
    });
    Ok(Source { rx, stop, handle: Some(handle), live: true })
}

/// Polls the socket table and forwards sockets not seen before.
fn spawn_proc_watcher(tx: Sender<Msg>, stop: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        let mut seen = std::collections::HashSet::new();
        let mut known_procs = std::collections::HashMap::new();
        while !stop.load(Ordering::Relaxed) {
            let Ok(snap) = crate::procs::snapshot() else { return };
            let socks: Vec<_> = snap.socks.into_iter().filter(|s| seen.insert(s.clone())).collect();
            let procs: Vec<_> = snap
                .procs
                .into_iter()
                .filter(|p| known_procs.insert(p.pid, (p.name.clone(), p.path.clone())) != Some((p.name.clone(), p.path.clone())))
                .collect();
            if (!socks.is_empty() || !procs.is_empty()) && tx.send(Msg::Sockets(crate::procs::Snapshot { socks, procs })).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
}

fn permission_hint(e: String) -> String {
    if e.contains("ermission") || e.contains("bpf") {
        format!(
            "{e}\n\nLive capture needs access to the packet capture devices. Either run with sudo, \
             install Wireshark's ChmodBPF helper, or run: sudo chmod o+r /dev/bpf*"
        )
    } else {
        e
    }
}

/// Writes frames as a classic microsecond pcap file.
pub fn save_pcap<'a>(path: &Path, frames: impl Iterator<Item = &'a Frame>, linktype: i32) -> std::io::Result<usize> {
    let mut w = std::io::BufWriter::new(std::fs::File::create(path)?);
    w.write_all(&0xa1b2c3d4u32.to_le_bytes())?;
    w.write_all(&2u16.to_le_bytes())?;
    w.write_all(&4u16.to_le_bytes())?;
    w.write_all(&0i32.to_le_bytes())?;
    w.write_all(&0u32.to_le_bytes())?;
    w.write_all(&262_144u32.to_le_bytes())?;
    // Live macOS PKTAP captures report DLT_USER2 (149); files use LINKTYPE_PKTAP (258).
    let linktype = if linktype == 149 { 258 } else { linktype };
    w.write_all(&(linktype as u32).to_le_bytes())?;
    let mut n = 0;
    for f in frames {
        let secs = f.ts.floor();
        let usec = ((f.ts - secs) * 1e6).round().min(999_999.0);
        w.write_all(&(secs as u32).to_le_bytes())?;
        w.write_all(&(usec as u32).to_le_bytes())?;
        w.write_all(&(f.data.len() as u32).to_le_bytes())?;
        w.write_all(&f.orig_len.to_le_bytes())?;
        w.write_all(&f.data)?;
        n += 1;
    }
    w.flush()?;
    Ok(n)
}
