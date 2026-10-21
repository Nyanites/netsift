//! The NetSift user interface.
//!
//! Layout follows an analysis workflow, top to bottom and left to right:
//! acquire (toolbar) → narrow down (filter bar) → navigate (left workspace panel) →
//! inspect (packet list, details tree, bytes) → dig in (streams, conversations, insights,
//! decryption).

use crate::capture::{self, DeviceInfo, Msg, Source};
use crate::dissect::{dissect, dissect_plaintext, fmt_abs_time, printable};
use crate::engine::Engine;
use crate::timeline::HttpRequest;
use crate::filter::{self, EvalCtx, Expr};
use crate::model::{proto, tcpflag, Field, HttpMsg, PacketRow, Severity, StreamKind};
use crate::streams::{fmt_ip, Conversation};
use crate::tls::{KeyLog, TlsStatus};
use eframe::egui::{
    self, Align, Align2, Color32, CornerRadius, FontId, Key, KeyboardShortcut, Layout, Modifiers, RichText, Sense,
    Vec2,
};
use egui_extras::{Column, TableBuilder};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(PartialEq, Clone, Copy)]
enum View {
    Packets,
    Conversations,
    Apps,
    Timeline,
    Compare,
    Endpoints,
    Protocols,
    Insights,
    Decryption,
    Stream,
}

#[derive(PartialEq, Clone, Copy)]
enum TimeFmt {
    Relative,
    Delta,
    Absolute,
    Epoch,
}

#[derive(PartialEq, Clone, Copy)]
enum ConvSort {
    Id,
    Packets,
    Bytes,
    Duration,
    Start,
}

#[derive(PartialEq, Clone, Copy, Debug)]
enum FollowMode {
    Raw,
    Decrypted,
    Messages,
}

/// The most useful way to show a conversation: decoded HTTP messages, else decrypted bytes.
fn best_mode(c: &Conversation) -> FollowMode {
    if !c.http_msgs().is_empty() {
        FollowMode::Messages
    } else if c.tls.as_ref().is_some_and(|t| t.decrypted_records > 0) {
        FollowMode::Decrypted
    } else {
        FollowMode::Raw
    }
}

struct Follow {
    kind: StreamKind,
    id: usize,
    mode: FollowMode,
    hex: bool,
    show: [bool; 2],
    cache: Vec<(usize, usize, Vec<u8>)>,
    cache_key: (usize, FollowMode, usize),
}

struct DetailCache {
    pkt: usize,
    tree: Vec<Field>,
    /// Number of top-level nodes that belong to the frame; the rest are decrypted sections.
    frame_nodes: usize,
}

enum Action {
    Select(usize),
    Goto(usize),
    SelectField(Vec<usize>),
    SetFilter(String),
    CombineFilter(&'static str, String),
    Follow(StreamKind, usize, FollowMode),
    ToggleBookmark(usize),
    Copy(String),
}

/// (packet count, endpoints, protocol hierarchy rows).
type StatsCache = (usize, Vec<crate::engine::Endpoint>, Vec<(&'static str, &'static str, u64, u64)>);

pub struct App {
    engine: Engine,
    source: Option<Source>,
    source_label: String,
    loading: Option<f32>,
    load_started: Option<Instant>,
    cap_stats: Option<(u32, u32)>,

    devices: Vec<DeviceInfo>,
    device_idx: usize,
    capture_filter: String,
    promisc: bool,
    /// Attribute live traffic to local processes.
    capture_procs: bool,

    filter_text: String,
    filter: Option<Expr>,
    filter_error: Option<String>,
    filter_applied: String,
    visible: Vec<usize>,
    filtered_upto: usize,

    selected: Option<usize>,
    selected_field: Option<Vec<usize>>,
    bytes_tab: usize,
    detail: Option<DetailCache>,
    scroll_to_row: Option<usize>,

    view: View,
    time_fmt: TimeFmt,
    autoscroll: bool,
    dark: bool,
    bookmarks: HashSet<usize>,
    follow: Option<Follow>,
    conv_udp: bool,
    conv_sort: (ConvSort, bool),
    conv_search: String,
    selected_conv: Option<(StreamKind, usize)>,

    error: Option<String>,
    toast: Option<(String, Instant)>,
    show_filter_help: bool,
    show_about: bool,
    keylog_checked: Instant,
    focus_filter: bool,
    actions: Vec<Action>,
    /// Clipboard writes need a Context; the text waits here until the end of the frame.
    copy_queue: Option<String>,
    /// Endpoint and protocol statistics, recomputed only when the packet count changes.
    stats_cache: Option<StatsCache>,
    timeline_cache: Option<((usize, usize, usize), Vec<HttpRequest>)>,
    timeline_search: String,
    timeline_versions: [bool; 3],
    /// Zoomed time range (absolute timestamps); requests outside it are hidden.
    timeline_zoom: Option<(f64, f64)>,
    timeline_drag: Option<f32>,
    compare: Option<CompareState>,
    compare_rx: Option<crossbeam_channel::Receiver<CompareLoad>>,
    compare_missing: HashSet<usize>,
    browser_child: Option<std::process::Child>,
}

/// A second capture loaded in the background for comparison: (file name, engine).
type CompareLoad = Result<(String, Box<Engine>), String>;

struct CompareState {
    name: String,
    other: Box<Engine>,
    result: crate::compare::CompareResult,
}

#[derive(Clone, Copy)]
enum Browser {
    Firefox,
    Chrome,
}

impl Browser {
    fn name(self) -> &'static str {
        match self {
            Browser::Firefox => "Firefox",
            Browser::Chrome => "Chrome",
        }
    }

    fn binary(self) -> PathBuf {
        let mac = match self {
            Browser::Firefox => "/Applications/Firefox.app/Contents/MacOS/firefox",
            Browser::Chrome => "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        };
        if cfg!(target_os = "macos") {
            return PathBuf::from(mac);
        }
        let names: &[&str] = match self {
            Browser::Firefox => &["firefox"],
            Browser::Chrome => &["google-chrome", "chromium", "chromium-browser"],
        };
        std::env::var_os("PATH")
            .and_then(|path| std::env::split_paths(&path).flat_map(|d| names.iter().map(move |n| d.join(n))).find(|p| p.exists()))
            .unwrap_or_else(|| PathBuf::from(names[0]))
    }

    fn installed() -> Vec<Browser> {
        [Browser::Firefox, Browser::Chrome].into_iter().filter(|b| b.binary().exists()).collect()
    }
}

fn fmt_dur(s: f64) -> String {
    if s >= 1.0 {
        format!("{s:.2} s")
    } else {
        format!("{:.1} ms", s * 1000.0)
    }
}

fn ui_ok_color() -> Color32 {
    Color32::from_rgb(120, 200, 140)
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, file: Option<PathBuf>, keylog: Option<PathBuf>) -> Self {
        let mut style = (*cc.egui_ctx.global_style()).clone();
        style.spacing.item_spacing = egui::vec2(6.0, 4.0);
        cc.egui_ctx.set_global_style(style);
        cc.egui_ctx.set_theme(egui::Theme::Dark);

        let (devices, dev_err) = match capture::list_devices() {
            Ok(d) => (d, None),
            Err(e) => (Vec::new(), Some(e)),
        };
        let mut app = App {
            engine: Engine::default(),
            source: None,
            source_label: String::new(),
            loading: None,
            load_started: None,
            cap_stats: None,
            devices,
            device_idx: 0,
            capture_filter: String::new(),
            promisc: true,
            capture_procs: true,
            filter_text: String::new(),
            filter: None,
            filter_error: None,
            filter_applied: String::new(),
            visible: Vec::new(),
            filtered_upto: 0,
            selected: None,
            selected_field: None,
            bytes_tab: 0,
            detail: None,
            scroll_to_row: None,
            view: View::Packets,
            time_fmt: TimeFmt::Relative,
            autoscroll: true,
            dark: true,
            bookmarks: HashSet::new(),
            follow: None,
            conv_udp: false,
            conv_sort: (ConvSort::Bytes, true),
            conv_search: String::new(),
            selected_conv: None,
            error: dev_err.map(|e| format!("Could not list capture interfaces: {e}")),
            toast: None,
            show_filter_help: false,
            show_about: false,
            keylog_checked: Instant::now(),
            focus_filter: false,
            actions: Vec::new(),
            copy_queue: None,
            stats_cache: None,
            timeline_cache: None,
            timeline_search: String::new(),
            timeline_versions: [true; 3],
            timeline_zoom: None,
            timeline_drag: None,
            compare: None,
            compare_rx: None,
            compare_missing: HashSet::new(),
            browser_child: None,
        };
        let keylog = keylog.or_else(|| std::env::var_os("SSLKEYLOGFILE").map(PathBuf::from));
        if let Some(k) = keylog {
            app.load_keylog(&k);
        }
        if let Some(f) = file {
            app.open_file(&f, &cc.egui_ctx);
        }
        app
    }

    // ---- Sources ------------------------------------------------------------------------

    fn reset_capture(&mut self) {
        if let Some(mut s) = self.source.take() {
            s.stop();
        }
        self.engine.clear();
        self.visible.clear();
        self.filtered_upto = 0;
        self.selected = None;
        self.selected_field = None;
        self.detail = None;
        self.follow = None;
        self.bookmarks.clear();
        self.cap_stats = None;
        self.selected_conv = None;
        self.compare = None;
        self.compare_missing.clear();
        self.timeline_cache = None;
        if self.view == View::Stream {
            self.view = View::Packets;
        }
    }

    fn open_file(&mut self, path: &Path, ctx: &egui::Context) {
        self.reset_capture();
        self.source = Some(capture::open_file(path, ctx.clone()));
        self.source_label = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        self.loading = Some(0.0);
        self.load_started = Some(Instant::now());
    }

    fn pick_and_open(&mut self, ctx: &egui::Context) {
        if let Some(p) = rfd::FileDialog::new()
            .add_filter("Capture files", &["pcap", "pcapng", "cap", "dmp", "pcap.gz"])
            .add_filter("All files", &["*"])
            .pick_file()
        {
            self.open_file(&p, ctx);
        }
    }

    fn start_capture(&mut self, ctx: &egui::Context) {
        let Some(dev) = self.devices.get(self.device_idx).cloned() else {
            self.error = Some("No capture interface selected.".into());
            return;
        };
        self.reset_capture();
        match capture::start_live(&dev.name, &self.capture_filter, self.promisc, self.capture_procs, ctx.clone()) {
            Ok(s) => {
                self.source = Some(s);
                self.source_label = format!("Live: {}", dev.name);
                self.load_started = Some(Instant::now());
                self.view = View::Packets;
            }
            Err(e) => self.error = Some(e),
        }
    }

    fn stop_capture(&mut self) {
        if let Some(s) = &self.source
            && s.live {
                if let Some(mut s) = self.source.take() {
                    s.stop();
                    self.drain_after_stop(&s);
                }
                self.toast(format!("Capture stopped — {} packets", self.engine.packets.len()));
            }
    }

    fn drain_after_stop(&mut self, s: &Source) {
        while let Ok(m) = s.rx.try_recv() {
            if let Msg::Frames(v) = m {
                for f in v {
                    self.engine.ingest(f);
                }
            }
        }
    }

    fn capturing(&self) -> bool {
        self.source.as_ref().map(|s| s.live).unwrap_or(false)
    }

    fn save(&mut self, displayed_only: bool) {
        if self.engine.packets.is_empty() {
            return;
        }
        let Some(path) = rfd::FileDialog::new().add_filter("pcap", &["pcap"]).set_file_name("capture.pcap").save_file() else {
            return;
        };
        let lt = self.engine.packets[0].frame.linktype;
        let res = if displayed_only {
            capture::save_pcap(&path, self.visible.iter().map(|&i| &self.engine.packets[i].frame), lt)
        } else {
            capture::save_pcap(&path, self.engine.packets.iter().map(|p| &p.frame), lt)
        };
        match res {
            Ok(n) => self.toast(format!("Saved {n} packets to {}", path.display())),
            Err(e) => self.error = Some(format!("Save failed: {e}")),
        }
    }

    fn load_keylog(&mut self, path: &Path) {
        match KeyLog::load(path) {
            Ok(k) => {
                let n = k.len();
                self.engine.set_keylog(k);
                self.after_decrypt_change();
                let (s, d, _) = self.engine.tls_summary();
                self.toast(format!("Loaded {n} TLS secrets — {d}/{s} sessions decrypted"));
            }
            Err(e) => self.error = Some(format!("Cannot read key log {}: {e}", path.display())),
        }
    }

    fn after_decrypt_change(&mut self) {
        self.detail = None;
        if let Some(f) = &mut self.follow {
            f.cache_key = (usize::MAX, FollowMode::Raw, 0);
        }
        self.refilter();
    }

    fn toast(&mut self, s: String) {
        self.toast = Some((s, Instant::now()));
    }

    /// Pulls frames from the active source within a frame-time budget.
    fn pump(&mut self, ctx: &egui::Context) {
        let deadline = Instant::now() + Duration::from_millis(14);
        let mut done = false;
        let mut more = false;
        if let Some(src) = &self.source {
            loop {
                if Instant::now() > deadline {
                    more = true;
                    break;
                }
                match src.rx.try_recv() {
                    Ok(Msg::Frames(v)) => {
                        for f in v {
                            self.engine.ingest(f);
                        }
                    }
                    Ok(Msg::Progress(p)) => self.loading = Some(p),
                    Ok(Msg::Stats { received, dropped }) => self.cap_stats = Some((received, dropped)),
                    Ok(Msg::Sockets(snap)) => self.engine.apply_sockets(snap),
                    Ok(Msg::Error(e)) => self.error = Some(e),
                    Ok(Msg::Done) | Err(crossbeam_channel::TryRecvError::Disconnected) => {
                        done = true;
                        break;
                    }
                    Err(crossbeam_channel::TryRecvError::Empty) => break,
                }
            }
        }
        if done {
            let was_file = self.source.as_ref().map(|s| !s.live).unwrap_or(false);
            self.source = None;
            self.loading = None;
            if was_file {
                let secs = self.load_started.map(|t| t.elapsed().as_secs_f32()).unwrap_or(0.0);
                self.toast(format!("Loaded {} packets in {secs:.2}s", self.engine.packets.len()));
            }
        }
        if more {
            ctx.request_repaint();
        }
        if self.keylog_checked.elapsed() > Duration::from_secs(1) {
            self.keylog_checked = Instant::now();
            if self.engine.keylog.reload_if_changed() {
                self.engine.redecrypt();
                self.after_decrypt_change();
            }
        }
        self.update_filter();
        if self.capturing() {
            ctx.request_repaint_after(Duration::from_millis(250));
        }
    }

    // ---- Filtering ----------------------------------------------------------------------

    fn apply_filter_text(&mut self) {
        match filter::parse(&self.filter_text) {
            Ok(e) => {
                self.filter = e;
                self.filter_error = None;
                self.filter_applied = self.filter_text.clone();
                self.refilter();
            }
            Err(e) => self.filter_error = Some(e),
        }
    }

    fn set_filter(&mut self, s: String) {
        self.filter_text = s;
        self.apply_filter_text();
        self.view = View::Packets;
    }

    fn refilter(&mut self) {
        // Full re-filter runs on all cores; new packets are then filtered incrementally.
        let n = self.engine.packets.len();
        self.visible = match &self.filter {
            Some(e) => {
                let ctx = EvalCtx { bookmarks: &self.bookmarks, processes: &self.engine.processes, missing: &self.compare_missing };
                filter::matching(e, &self.engine.packets, &ctx)
            }
            None => (0..n).collect(),
        };
        self.filtered_upto = n;
        self.engine.changed.clear();
        if let Some(sel) = self.selected
            && let Ok(i) = self.visible.binary_search(&sel) {
                self.scroll_to_row = Some(i);
            }
    }

    fn matches(&self, i: usize) -> bool {
        match &self.filter {
            None => true,
            Some(e) => e.matches(i, &self.engine.packets[i], &EvalCtx { bookmarks: &self.bookmarks, processes: &self.engine.processes, missing: &self.compare_missing }),
        }
    }

    fn update_filter(&mut self) {
        let n = self.engine.packets.len();
        for i in self.filtered_upto..n {
            if self.matches(i) {
                self.visible.push(i);
            }
        }
        self.filtered_upto = n;
        // Packets whose info changed after the fact (e.g. decrypted later) are re-evaluated.
        let changed = std::mem::take(&mut self.engine.changed);
        for i in changed {
            if self.detail.as_ref().map(|d| d.pkt) == Some(i) {
                self.detail = None;
            }
            if self.filter.is_none() {
                continue;
            }
            let m = self.matches(i);
            match self.visible.binary_search(&i) {
                Ok(pos) if !m => {
                    self.visible.remove(pos);
                }
                Err(pos) if m => self.visible.insert(pos, i),
                _ => {}
            }
        }
    }

    // ---- Actions ------------------------------------------------------------------------

    fn run_actions(&mut self) {
        for a in std::mem::take(&mut self.actions) {
            match a {
                Action::Select(i) => {
                    if self.selected != Some(i) {
                        self.selected = Some(i);
                        self.selected_field = None;
                        self.bytes_tab = 0;
                    }
                }
                Action::Goto(i) => {
                    self.view = View::Packets;
                    if self.visible.binary_search(&i).is_err() {
                        self.filter_text.clear();
                        self.apply_filter_text();
                        self.toast("Filter cleared to show the selected packet".into());
                    }
                    self.selected = Some(i);
                    self.selected_field = None;
                    self.bytes_tab = 0;
                    self.scroll_to_row = self.visible.binary_search(&i).ok();
                }
                Action::SelectField(path) => {
                    if let Some(d) = &self.detail {
                        self.bytes_tab = if path[0] >= d.frame_nodes { path[0] - d.frame_nodes + 1 } else { 0 };
                    }
                    self.selected_field = Some(path);
                }
                Action::SetFilter(f) => self.set_filter(f),
                Action::CombineFilter(op, f) => {
                    let cur = self.filter_applied.trim().to_string();
                    let next = if cur.is_empty() {
                        if op == "&& !" { format!("!({f})") } else { f }
                    } else {
                        format!("({cur}) {op} ({f})").replace("&& ! (", "&& !(")
                    };
                    self.set_filter(next);
                }
                Action::Follow(kind, id, mode) => {
                    self.follow = Some(Follow {
                        kind,
                        id,
                        mode,
                        hex: false,
                        show: [true, true],
                        cache: Vec::new(),
                        cache_key: (usize::MAX, FollowMode::Raw, 0),
                    });
                    self.view = View::Stream;
                }
                Action::ToggleBookmark(i) => {
                    if !self.bookmarks.remove(&i) {
                        self.bookmarks.insert(i);
                    }
                    if matches!(self.filter_applied.as_str(), s if s.contains("bookmark") || s.contains("marked")) {
                        self.refilter();
                    }
                }
                Action::Copy(s) => {
                    self.toast("Copied to clipboard".into());
                    self.copy_queue = Some(s);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Colours

fn tint(r: u8, g: u8, b: u8, a: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(r, g, b, a)
}

fn row_tint(p: &PacketRow) -> Color32 {
    let pr = p.meta.protos;
    let flags = p.meta.tcp.map(|t| t.flags).unwrap_or(0);
    if p.severity == Some(Severity::Error) || flags & tcpflag::RST != 0 {
        return tint(230, 60, 60, 70);
    }
    if p.retransmission {
        return tint(240, 140, 40, 55);
    }
    if pr & proto::DECRYPTED != 0 {
        return tint(240, 200, 50, 60);
    }
    if pr & (proto::HTTP | proto::HTTP2) != 0 {
        return tint(120, 210, 90, 55);
    }
    if pr & proto::TLS != 0 {
        return tint(160, 120, 240, 50);
    }
    if pr & (proto::DNS | proto::MDNS | proto::LLMNR) != 0 {
        return tint(80, 160, 245, 55);
    }
    if pr & proto::QUIC != 0 {
        return tint(50, 200, 180, 45);
    }
    if pr & proto::ARP != 0 {
        return tint(245, 205, 120, 50);
    }
    if pr & (proto::ICMP | proto::ICMPV6) != 0 {
        return tint(235, 130, 235, 50);
    }
    if pr & proto::SSH != 0 {
        return tint(200, 160, 100, 45);
    }
    if flags & (tcpflag::SYN | tcpflag::FIN) != 0 {
        return tint(160, 160, 160, 50);
    }
    if pr & proto::TCP != 0 {
        return tint(170, 160, 230, 22);
    }
    if pr & proto::UDP != 0 {
        return tint(110, 190, 240, 22);
    }
    Color32::TRANSPARENT
}

fn sev_color(s: Severity) -> Color32 {
    match s {
        Severity::Error => Color32::from_rgb(235, 80, 80),
        Severity::Warn => Color32::from_rgb(240, 170, 40),
        Severity::Note => Color32::from_rgb(100, 170, 240),
    }
}

const CLIENT_COLOR: Color32 = Color32::from_rgb(240, 110, 110);
const SERVER_COLOR: Color32 = Color32::from_rgb(110, 160, 245);

fn fmt_bytes(b: u64) -> String {
    let b = b as f64;
    if b >= 1e9 {
        format!("{:.2} GB", b / 1e9)
    } else if b >= 1e6 {
        format!("{:.2} MB", b / 1e6)
    } else if b >= 1e3 {
        format!("{:.1} kB", b / 1e3)
    } else {
        format!("{b} B")
    }
}

fn fmt_count(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::group(ui.style())
        .corner_radius(CornerRadius::same(6))
        .inner_margin(egui::Margin::same(10))
        .show(ui, add);
}

// ---------------------------------------------------------------------------------------------
// Main loop

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.pump(&ctx);
        self.poll_compare();
        self.shortcuts(&ctx);
        let dropped: Vec<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().map(|f| f.path().to_path_buf()).collect());
        for p in dropped {
            let is_keylog = p.extension().map(|e| e == "log" || e == "txt" || e == "keys").unwrap_or(false);
            if is_keylog {
                self.load_keylog(&p);
            } else {
                self.open_file(&p, &ctx);
            }
        }

        egui::Panel::top("menu").show(ui, |ui| self.menu_bar(ui));
        egui::Panel::top("toolbar").show(ui, |ui| self.toolbar(ui));
        egui::Panel::top("filterbar").show(ui, |ui| self.filter_bar(ui));
        egui::Panel::bottom("status").show(ui, |ui| self.status_bar(ui));
        egui::Panel::left("nav").resizable(true).default_size(220.0).min_size(180.0).show(ui, |ui| self.nav(ui));
        egui::CentralPanel::default().show(ui, |ui| {
            if self.engine.packets.is_empty() && self.source.is_none() {
                self.welcome(ui);
                return;
            }
            match self.view {
                View::Packets => self.packets_view(ui),
                View::Conversations => self.conversations_view(ui),
                View::Apps => self.apps_view(ui),
                View::Timeline => self.timeline_view(ui),
                View::Compare => self.compare_view(ui),
                View::Endpoints => self.endpoints_view(ui),
                View::Protocols => self.protocols_view(ui),
                View::Insights => self.insights_view(ui),
                View::Decryption => self.decryption_view(ui),
                View::Stream => self.stream_view(ui),
            }
        });
        self.windows(&ctx);
        self.run_actions();
        if let Some(s) = self.copy_queue.take() {
            ctx.copy_text(s);
        }
    }
}

impl App {
    fn shortcuts(&mut self, ctx: &egui::Context) {
        let sc = |m, k| KeyboardShortcut::new(m, k);
        if ctx.input_mut(|i| i.consume_shortcut(&sc(Modifiers::COMMAND, Key::O))) {
            self.pick_and_open(ctx);
        }
        if ctx.input_mut(|i| i.consume_shortcut(&sc(Modifiers::COMMAND, Key::S))) {
            self.save(false);
        }
        if ctx.input_mut(|i| i.consume_shortcut(&sc(Modifiers::COMMAND, Key::E))) {
            if self.capturing() { self.stop_capture() } else { self.start_capture(ctx) }
        }
        if ctx.input_mut(|i| i.consume_shortcut(&sc(Modifiers::COMMAND, Key::F))) {
            self.focus_filter = true;
        }
        if ctx.input_mut(|i| i.consume_shortcut(&sc(Modifiers::COMMAND, Key::M)))
            && let Some(s) = self.selected {
                self.actions.push(Action::ToggleBookmark(s));
            }
        // Arrow-key navigation through the packet list when no text field has focus.
        if self.view == View::Packets && !ctx.egui_wants_keyboard_input() && !self.visible.is_empty() {
            let (down, up, home, end) = ctx.input(|i| {
                (i.key_pressed(Key::ArrowDown), i.key_pressed(Key::ArrowUp), i.key_pressed(Key::Home), i.key_pressed(Key::End))
            });
            let cur = self.selected.and_then(|s| self.visible.binary_search(&s).ok());
            let next = if down {
                Some(cur.map(|c| (c + 1).min(self.visible.len() - 1)).unwrap_or(0))
            } else if up {
                Some(cur.map(|c| c.saturating_sub(1)).unwrap_or(0))
            } else if home {
                Some(0)
            } else if end {
                Some(self.visible.len() - 1)
            } else {
                None
            };
            if let Some(n) = next {
                self.actions.push(Action::Select(self.visible[n]));
                self.scroll_to_row = Some(n);
                self.autoscroll = false;
            }
        }
    }

    fn menu_bar(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui.button("Open…            ⌘O").clicked() {
                    self.pick_and_open(&ctx);
                }
                ui.add_enabled_ui(!self.engine.packets.is_empty(), |ui| {
                    if ui.button("Save all as pcap…  ⌘S").clicked() {
                        self.save(false);
                    }
                    if ui.button("Save displayed as pcap…").clicked() {
                        self.save(true);
                    }
                });
                ui.add_enabled_ui(!self.engine.packets.is_empty(), |ui| {
                    if ui.button("Export HTTP as HAR…").clicked() {
                        self.export_har();
                    }
                    if ui.button("Compare with another capture…").clicked() {
                        self.start_compare(&ctx);
                    }
                });
                ui.separator();
                if ui.button("Load TLS key log…").clicked()
                    && let Some(p) = rfd::FileDialog::new().pick_file() {
                        self.load_keylog(&p);
                    }
                ui.separator();
                if ui.button("Close capture").clicked() {
                    self.reset_capture();
                    self.source_label.clear();
                }
                if ui.button("Quit").clicked() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            ui.menu_button("Capture", |ui| {
                if self.capturing() {
                    if ui.button("Stop          ⌘E").clicked() {
                        self.stop_capture();
                    }
                } else if ui.button("Start         ⌘E").clicked() {
                    self.start_capture(&ctx);
                }
                if ui.button("Refresh interfaces").clicked() {
                    match capture::list_devices() {
                        Ok(d) => self.devices = d,
                        Err(e) => self.error = Some(e),
                    }
                }
                ui.checkbox(&mut self.promisc, "Promiscuous mode");
            });
            ui.menu_button("View", |ui| {
                ui.label("Time display");
                ui.radio_value(&mut self.time_fmt, TimeFmt::Relative, "Seconds since start");
                ui.radio_value(&mut self.time_fmt, TimeFmt::Delta, "Seconds since previous packet");
                ui.radio_value(&mut self.time_fmt, TimeFmt::Absolute, "Time of day (UTC)");
                ui.radio_value(&mut self.time_fmt, TimeFmt::Epoch, "Unix epoch");
                ui.separator();
                ui.checkbox(&mut self.autoscroll, "Auto-scroll during live capture");
                if ui.button("📷 Save screenshot…").clicked()
                    && let Some(p) = rfd::FileDialog::new().add_filter("PNG", &["png"]).set_file_name("netsift.png").save_file()
                {
                    save_screenshot(&ctx, p, None);
                }
                if ui.checkbox(&mut self.dark, "Dark theme").changed() {
                    ctx.set_theme(if self.dark { egui::Theme::Dark } else { egui::Theme::Light });
                }
            });
            ui.menu_button("Help", |ui| {
                if ui.button("Display filter reference").clicked() {
                    self.show_filter_help = true;
                }
                if ui.button("About NetSift").clicked() {
                    self.show_about = true;
                }
            });
        });
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.add_space(2.0);
        ui.horizontal(|ui| {
            if ui.button("📂 Open").on_hover_text("Open a pcap / pcapng file (⌘O). You can also drop files on the window.").clicked() {
                self.pick_and_open(&ctx);
            }
            if ui.add_enabled(!self.engine.packets.is_empty(), egui::Button::new("💾 Save")).on_hover_text("Save all packets as pcap (⌘S)").clicked() {
                self.save(false);
            }
            ui.separator();
            ui.label("Interface");
            let capturing = self.capturing();
            ui.add_enabled_ui(!capturing, |ui| {
                let current = self.devices.get(self.device_idx).map(|d| d.label()).unwrap_or_else(|| "(none)".into());
                egui::ComboBox::from_id_salt("iface").width(230.0).selected_text(current).show_ui(ui, |ui| {
                    for (i, d) in self.devices.iter().enumerate() {
                        let mut label = d.label();
                        if !d.up {
                            label.push_str("  [down]");
                        }
                        ui.selectable_value(&mut self.device_idx, i, label);
                    }
                });
                ui.add(
                    egui::TextEdit::singleline(&mut self.capture_filter)
                        .hint_text("capture filter (BPF), e.g. port 443")
                        .desired_width(200.0),
                )
                .on_hover_text("Berkeley Packet Filter applied by the kernel while capturing");
                ui.checkbox(&mut self.capture_procs, "🧩 Apps").on_hover_text(
                    "Attribute live traffic to the local processes that sent or received it.\n\
                     Works without root for your own apps; run as root to also see system processes.",
                );
            });
            if capturing {
                let b = egui::Button::new(RichText::new("■ Stop").color(Color32::WHITE)).fill(Color32::from_rgb(190, 50, 50));
                if ui.add(b).on_hover_text("Stop capture (⌘E)").clicked() {
                    self.stop_capture();
                }
                let t = ui.input(|i| i.time);
                let a = ((t * 3.0).sin() * 0.5 + 0.5) as f32;
                ui.label(RichText::new("●").color(Color32::from_rgba_unmultiplied(235, 60, 60, (100.0 + a * 155.0) as u8)));
                ui.ctx().request_repaint_after(Duration::from_millis(60));
            } else {
                let b = egui::Button::new(RichText::new("▶ Capture").color(Color32::WHITE)).fill(Color32::from_rgb(40, 140, 80));
                if ui.add_enabled(!self.devices.is_empty(), b).on_hover_text("Start live capture (⌘E)").clicked() {
                    self.start_capture(&ctx);
                }
            }
            ui.separator();
            let keys = self.engine.keylog.len();
            let label = if keys > 0 { format!("🔑 Key log ({keys})") } else { "🔑 Key log…".to_string() };
            ui.menu_button(label, |ui| {
                ui.label(RichText::new("Decrypt HTTPS, HTTP/2 and HTTP/3").weak());
                for b in Browser::installed() {
                    if ui.button(format!("🌐 Launch {} with decryption", b.name())).on_hover_text(
                        "Starts the browser with its own profile and SSLKEYLOGFILE pointed at NetSift, loads that key log, and starts capturing.",
                    ).clicked() {
                        self.launch_browser(b, &ctx);
                        ui.close();
                    }
                }
                if ui.button("📄 Load key log file…").on_hover_text("An SSLKEYLOGFILE from any browser or tool. Re-read automatically when it changes.").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        self.load_keylog(&p);
                    }
                    ui.close();
                }
            });
            if let Some(p) = self.loading {
                ui.separator();
                ui.add(egui::ProgressBar::new(p).desired_width(160.0).show_percentage().text(format!("Loading {:.0}%", p * 100.0)));
            }
        });
        ui.add_space(2.0);
    }

    fn filter_bar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(2.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Filter").strong());
            let dirty = self.filter_text != self.filter_applied;
            let bg = if self.filter_error.is_some() {
                tint(230, 60, 60, 60)
            } else if !self.filter_applied.is_empty() && !dirty {
                tint(60, 200, 90, 45)
            } else {
                ui.visuals().extreme_bg_color
            };
            let width = (ui.available_width() - 520.0).max(220.0);
            let te = egui::TextEdit::singleline(&mut self.filter_text)
                .hint_text("Display filter — e.g.  tls.sni contains \"example\"  ·  ip.addr == 10.0.0.0/8 && !dns  ·  http.response.code >= 400")
                .background_color(bg)
                .font(egui::TextStyle::Monospace)
                .desired_width(width);
            let r = ui.add(te);
            if self.focus_filter {
                r.request_focus();
                self.focus_filter = false;
            }
            if r.changed() {
                // Live validation while typing.
                self.filter_error = filter::parse(&self.filter_text).err();
            }
            if r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                self.apply_filter_text();
            }
            if let Some(e) = &self.filter_error {
                r.on_hover_text(RichText::new(e).color(Color32::from_rgb(240, 100, 100)));
            }
            if ui.add_enabled(dirty || self.filter_error.is_some(), egui::Button::new("Apply")).clicked() {
                self.apply_filter_text();
            }
            if ui.add_enabled(!self.filter_text.is_empty(), egui::Button::new("✖")).on_hover_text("Clear filter").clicked() {
                self.filter_text.clear();
                self.apply_filter_text();
            }
            ui.menu_button("+ Field", |ui| {
                ui.label(RichText::new("Insert field").weak());
                for s in filter::SUGGESTIONS {
                    if ui.button(*s).clicked() {
                        if !self.filter_text.trim().is_empty() {
                            self.filter_text.push_str(" && ");
                        }
                        self.filter_text.push_str(s);
                        self.focus_filter = true;
                        ui.close();
                    }
                }
            });
            ui.separator();
            for (label, f, tip) in [
                ("TCP", "tcp", "TCP traffic"),
                ("UDP", "udp", "UDP traffic"),
                ("DNS", "dns", "DNS, mDNS and LLMNR"),
                ("HTTP", "http || http2 || http3", "HTTP/1.x, HTTP/2 and HTTP/3 (plain or decrypted)"),
                ("QUIC", "quic", "QUIC / HTTP/3 traffic"),
                ("TLS", "tls", "TLS records"),
                ("🔓", "decrypted", "Packets with decrypted TLS payload"),
                ("⚠", "expert", "Packets with problems (retransmissions, resets, errors…)"),
                ("★", "bookmarked", "Bookmarked packets (⌘M)"),
            ] {
                let on = self.filter_applied == f;
                if ui.selectable_label(on, label).on_hover_text(tip).clicked() {
                    self.set_filter(if on { String::new() } else { f.to_string() });
                }
            }
        });
        if let Some(e) = &self.filter_error {
            ui.label(RichText::new(format!("⚠ {e}")).color(Color32::from_rgb(240, 110, 110)).small());
        }
        ui.add_space(2.0);
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let n = self.engine.packets.len();
            if self.capturing() {
                ui.label(RichText::new(format!("● {}", self.source_label)).color(Color32::from_rgb(235, 80, 80)));
                if let Some((r, d)) = self.cap_stats {
                    ui.label(format!("kernel: {} received, {} dropped", fmt_count(r as usize), fmt_count(d as usize)));
                }
            } else if !self.source_label.is_empty() {
                ui.label(&self.source_label);
            } else {
                ui.label(RichText::new("Ready").weak());
            }
            ui.separator();
            ui.label(format!("Packets: {}", fmt_count(n)));
            if self.filter.is_some() {
                let pct = if n > 0 { self.visible.len() as f64 * 100.0 / n as f64 } else { 0.0 };
                ui.label(format!("Displayed: {} ({pct:.1}%)", fmt_count(self.visible.len())));
            }
            if let Some(s) = self.selected {
                ui.label(format!("Selected: #{}", s + 1));
            }
            ui.separator();
            let (s, d, _) = self.engine.tls_summary();
            if s > 0 {
                ui.label(format!("Encrypted sessions decrypted: {d}/{s}"));
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if let Some((msg, t)) = &self.toast
                    && t.elapsed() < Duration::from_secs(6) {
                        ui.label(RichText::new(msg).color(Color32::from_rgb(120, 200, 140)));
                        ui.ctx().request_repaint_after(Duration::from_millis(500));
                    }
            });
        });
    }

    fn nav(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.label(RichText::new("NETSIFT").strong().size(16.0).color(Color32::from_rgb(110, 170, 250)));
        ui.label(RichText::new("packet analysis workspace").weak().small());
        ui.add_space(8.0);
        let n = self.engine.packets.len();
        let experts = self.engine.experts.iter().filter(|e| e.severity >= Severity::Warn).count();
        let (tls_s, tls_d, _) = self.engine.tls_summary();
        let items: Vec<(View, String, String)> = vec![
            (View::Packets, "📦  Packets".into(), fmt_count(n)),
            (View::Conversations, "🔀  Conversations".into(), fmt_count(self.engine.streams.tcp.len() + self.engine.streams.udp.len())),
            (View::Apps, "🧩  Apps".into(), {
                let mut apps: Vec<&str> = self.engine.processes.iter().map(|p| p.app.as_str()).collect();
                apps.sort_unstable();
                apps.dedup();
                if apps.is_empty() { String::new() } else { fmt_count(apps.len()) }
            }),
            (View::Endpoints, "🖥  Endpoints".into(), String::new()),
            (View::Protocols, "📊  Protocols".into(), String::new()),
            (View::Timeline, "⏱  Timeline".into(), self.timeline_cache.as_ref().map(|c| c.1.len()).filter(|&n| n > 0).map(fmt_count).unwrap_or_default()),
            (View::Compare, "⚖  Compare".into(), self.compare.as_ref().map(|c| format!("−{}", fmt_count(c.result.only_a.len()))).unwrap_or_default()),
            (View::Insights, "⚠  Insights".into(), if experts > 0 { fmt_count(experts) } else { String::new() }),
            (View::Decryption, "🔓  Decryption".into(), if tls_s > 0 { format!("{tls_d}/{tls_s}") } else { String::new() }),
        ];
        ui.label(RichText::new("ANALYZE").small().weak());
        for (v, label, badge) in items {
            self.nav_item(ui, v, &label, &badge);
        }
        if let Some(f) = &self.follow {
            let label = format!("📜  {} stream {}", if f.kind == StreamKind::Tcp { "TCP" } else { "UDP" }, f.id);
            self.nav_item(ui, View::Stream, &label, "");
        }
        ui.add_space(10.0);
        ui.separator();
        ui.label(RichText::new("CAPTURE").small().weak());
        egui::Grid::new("summary").num_columns(2).spacing([8.0, 2.0]).show(ui, |ui| {
            let dur = self.engine.duration();
            ui.label(RichText::new("Source").weak());
            ui.label(if self.source_label.is_empty() { "—" } else { &self.source_label });
            ui.end_row();
            ui.label(RichText::new("Packets").weak());
            ui.label(fmt_count(n));
            ui.end_row();
            ui.label(RichText::new("Bytes").weak());
            ui.label(fmt_bytes(self.engine.total_bytes));
            ui.end_row();
            ui.label(RichText::new("Duration").weak());
            ui.label(format!("{dur:.2}s"));
            ui.end_row();
            if dur > 0.0 {
                ui.label(RichText::new("Rate").weak());
                ui.label(format!("{:.0} pkt/s · {}/s", n as f64 / dur, fmt_bytes((self.engine.total_bytes as f64 / dur) as u64)));
                ui.end_row();
            }
        });
        if !self.bookmarks.is_empty() {
            ui.add_space(10.0);
            ui.separator();
            ui.label(RichText::new("BOOKMARKS").small().weak());
            let mut b: Vec<usize> = self.bookmarks.iter().copied().collect();
            b.sort();
            egui::ScrollArea::vertical().id_salt("bm").max_height(200.0).show(ui, |ui| {
                for i in b {
                    let p = &self.engine.packets[i];
                    let r = ui.selectable_label(self.selected == Some(i), format!("★ #{}  {}", i + 1, p.protocol));
                    if r.on_hover_text(&p.info).clicked() {
                        self.actions.push(Action::Goto(i));
                    }
                }
            });
        }
    }

    fn nav_item(&mut self, ui: &mut egui::Ui, v: View, label: &str, badge: &str) {
        let sel = self.view == v;
        let r = ui.add_sized([ui.available_width(), 26.0], egui::Button::selectable(sel, "").frame_when_inactive(false));
        let rect = r.rect;
        let color = if sel { ui.visuals().strong_text_color() } else { ui.visuals().text_color() };
        ui.painter().text(rect.left_center() + Vec2::new(8.0, 0.0), Align2::LEFT_CENTER, label, FontId::proportional(14.0), color);
        if !badge.is_empty() {
            ui.painter().text(rect.right_center() - Vec2::new(8.0, 0.0), Align2::RIGHT_CENTER, badge, FontId::proportional(12.0), ui.visuals().weak_text_color());
        }
        if r.clicked() {
            self.view = v;
        }
    }

    fn welcome(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.vertical_centered(|ui| {
            ui.add_space(ui.available_height() * 0.12);
            ui.label(RichText::new("NetSift").size(34.0).strong());
            ui.label(RichText::new("Capture, inspect and decrypt network traffic").size(15.0).weak());
            ui.add_space(24.0);
        });
        ui.columns(2, |cols| {
            card(&mut cols[0], |ui| {
                ui.set_min_height(170.0);
                ui.label(RichText::new("📂  Analyze a capture file").size(17.0).strong());
                ui.add_space(4.0);
                ui.label("pcap and pcapng files from Wireshark, tcpdump, tshark and others.");
                ui.label(RichText::new("Tip: drag & drop a capture or a key log onto this window.").weak());
                ui.add_space(10.0);
                if ui.add(egui::Button::new(RichText::new("Open file…").size(15.0)).min_size([140.0, 32.0].into())).clicked() {
                    self.pick_and_open(&ctx);
                }
            });
            card(&mut cols[1], |ui| {
                ui.set_min_height(170.0);
                ui.label(RichText::new("📡  Capture live traffic").size(17.0).strong());
                ui.add_space(4.0);
                if self.devices.is_empty() {
                    ui.label("No interfaces available. Check capture permissions (see Help).");
                } else {
                    egui::ComboBox::from_id_salt("iface_welcome")
                        .width(280.0)
                        .selected_text(self.devices.get(self.device_idx).map(|d| d.label()).unwrap_or_default())
                        .show_ui(ui, |ui| {
                            for (i, d) in self.devices.iter().enumerate() {
                                ui.selectable_value(&mut self.device_idx, i, d.label());
                            }
                        });
                    ui.add(egui::TextEdit::singleline(&mut self.capture_filter).hint_text("optional capture filter, e.g. tcp port 443").desired_width(280.0));
                    ui.add_space(6.0);
                    if ui.add(egui::Button::new(RichText::new("▶ Start capture").size(15.0)).min_size([140.0, 32.0].into())).clicked() {
                        self.start_capture(&ctx);
                    }
                }
            });
        });
        ui.add_space(14.0);
        card(ui, |ui| {
            ui.label(RichText::new("🔓  Decrypt HTTPS").size(15.0).strong());
            ui.label("One click: 🔑 → “Launch Firefox/Chrome with decryption” starts the browser with key logging, loads the keys and starts capturing. HTTPS, HTTP/2 and HTTP/3 decrypt live as you browse.");
            ui.label(RichText::new("Or point any tool at a key log yourself and load it from the 🔑 menu:").weak());
            ui.monospace("export SSLKEYLOGFILE=~/tls-keys.log");
            if self.engine.keylog.len() > 0 {
                ui.label(RichText::new(format!("✔ {} secrets loaded", self.engine.keylog.len())).color(Color32::from_rgb(120, 200, 140)));
            }
        });
    }

    // ---- Packets view -------------------------------------------------------------------

    fn packets_view(&mut self, ui: &mut egui::Ui) {
        let h = ui.available_height();
        egui::Panel::bottom("details")
            .resizable(true)
            .default_size(h * 0.45)
            .min_size(120.0)
            .show(ui, |ui| {
                egui::Panel::right("bytes").resizable(true).default_size(560.0).min_size(300.0).show(ui, |ui| self.bytes_pane(ui));
                egui::CentralPanel::default().show(ui, |ui| self.details_pane(ui));
            });
        egui::CentralPanel::default().show(ui, |ui| self.packet_list(ui));
    }

    fn stats(&mut self) -> &StatsCache {
        let n = self.engine.packets.len();
        if self.stats_cache.as_ref().map(|c| c.0) != Some(n) {
            self.stats_cache = Some((n, self.engine.endpoints(), self.engine.protocol_hierarchy()));
        }
        self.stats_cache.as_ref().unwrap()
    }

    fn time_text(&self, i: usize) -> String {
        let p = &self.engine.packets[i];
        match self.time_fmt {
            TimeFmt::Relative => format!("{:.6}", p.frame.ts - self.engine.first_ts()),
            TimeFmt::Delta => {
                let prev = if i > 0 { self.engine.packets[i - 1].frame.ts } else { p.frame.ts };
                format!("{:.6}", p.frame.ts - prev)
            }
            TimeFmt::Absolute => fmt_abs_time(p.frame.ts).split(' ').nth(1).unwrap_or("").to_string(),
            TimeFmt::Epoch => format!("{:.6}", p.frame.ts),
        }
    }

    fn packet_list(&mut self, ui: &mut egui::Ui) {
        if self.visible.is_empty() {
            ui.centered_and_justified(|ui| {
                if self.engine.packets.is_empty() {
                    ui.label(RichText::new("Waiting for packets…").weak().size(16.0));
                } else {
                    ui.label(RichText::new("No packets match the display filter").weak().size(16.0));
                }
            });
            return;
        }
        let row_h = 19.0;
        // The Process column appears once any traffic has been attributed to a process.
        let show_proc = !self.engine.processes.is_empty();
        let mut table = TableBuilder::new(ui)
            .id_salt(("packets", show_proc))
            .striped(false)
            .resizable(true)
            .sense(Sense::click())
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::initial(64.0).at_least(40.0))
            .column(Column::initial(96.0).at_least(60.0));
        if show_proc {
            table = table.column(Column::initial(130.0).at_least(50.0).clip(true));
        }
        table = table
            .column(Column::initial(160.0).at_least(60.0))
            .column(Column::initial(160.0).at_least(60.0))
            .column(Column::initial(70.0).at_least(40.0))
            .column(Column::initial(56.0).at_least(40.0))
            .column(Column::remainder().at_least(200.0).clip(true))
            .min_scrolled_height(0.0)
            .max_scroll_height(f32::INFINITY);
        if self.autoscroll && self.capturing() {
            table = table.stick_to_bottom(true);
        }
        if let Some(r) = self.scroll_to_row.take() {
            table = table.scroll_to_row(r, None);
        }
        let mut actions = Vec::new();
        table
            .header(22.0, |mut h| {
                let mut titles = vec!["No.", "Time"];
                if show_proc {
                    titles.push("Process");
                }
                titles.extend(["Source", "Destination", "Protocol", "Length", "Info"]);
                for t in titles {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(row_h, self.visible.len(), |mut row| {
                    let pi = self.visible[row.index()];
                    let p = &self.engine.packets[pi];
                    let selected = self.selected == Some(pi);
                    row.set_selected(selected);
                    let bg = if selected { Color32::TRANSPARENT } else { row_tint(p) };
                    let fg = if p.severity == Some(Severity::Error) && !selected { Some(Color32::from_rgb(255, 170, 170)) } else { None };
                    let mark = if self.bookmarks.contains(&pi) { "★ " } else { "" };
                    let lock = if p.meta.protos & proto::DECRYPTED != 0 { "🔓 " } else { "" };
                    let mut cells = vec![format!("{mark}{}", pi + 1), self.time_text(pi)];
                    if show_proc {
                        cells.push(p.meta.process.map(|i| self.engine.processes[i as usize].name.clone()).unwrap_or_default());
                    }
                    cells.extend([
                        p.src.clone(),
                        p.dst.clone(),
                        p.protocol.clone(),
                        p.frame.orig_len.to_string(),
                        format!("{lock}{}", p.info),
                    ]);
                    for c in cells {
                        row.col(|ui| {
                            if bg != Color32::TRANSPARENT {
                                ui.painter().rect_filled(ui.max_rect().expand2(Vec2::new(4.0, 1.0)), 0.0, bg);
                            }
                            let mut t = RichText::new(c);
                            if let Some(fg) = fg {
                                t = t.color(fg);
                            }
                            ui.add(egui::Label::new(t).truncate().selectable(false));
                        });
                    }
                    let r = row.response();
                    if r.clicked() {
                        actions.push(Action::Select(pi));
                    }
                    if r.double_clicked()
                        && let Some(s) = p.stream {
                            actions.push(Action::Follow(s.kind, s.id, best_mode(self.engine.streams.get(s.kind, s.id))));
                        }
                    r.context_menu(|ui| packet_menu(ui, pi, p, &self.engine, &self.bookmarks, &mut actions));
                });
            });
        if !actions.is_empty() && self.capturing() {
            self.autoscroll = false;
        }
        self.actions.extend(actions);
    }

    fn ensure_detail(&mut self) {
        let Some(pi) = self.selected else { return };
        if self.detail.as_ref().map(|d| d.pkt) == Some(pi) {
            return;
        }
        let p = &self.engine.packets[pi];
        let d = dissect(&p.frame, pi + 1);
        let mut tree = d.tree;
        if let Some(s) = p.stream {
            let c = self.engine.streams.get(s.kind, s.id);
            let kind = if s.kind == StreamKind::Tcp { "tcp" } else { "udp" };
            let mut f = Field::text(format!("[Conversation: {kind}.stream == {} — {}]", s.id, c.label())).filter(format!("{kind}.stream == {}", s.id));
            f.push(Field::text(format!("Packets in conversation: {}", c.packets.len())));
            if let Some(h) = &c.host {
                f.push(Field::text(format!("Host: {h}")));
            }
            if let Some(t) = &c.tls {
                f.push(Field::text(format!("TLS: {} · {} · {}", crate::dissect::tls_version_name(t.version.unwrap_or(0)), t.suite_name(), t.status.label())));
            }
            if let Some(q) = &c.quic {
                let suite = q.suite.map(crate::dissect::cipher_suite_name).unwrap_or_else(|| "?".into());
                f.push(Field::text(format!(
                    "QUIC: version 0x{:08x} · {suite} · ALPN {} · {}",
                    q.version,
                    q.alpn.as_deref().unwrap_or("?"),
                    q.status.label()
                )));
            }
            if p.retransmission {
                f.push(Field::text("[This segment is a retransmission]").filter("tcp.analysis.retransmission"));
            }
            tree.insert(1, f);
        }
        if p.protocol == "TLS" && p.info == "Continuation Data"
            && let Some(last) = tree.last_mut().filter(|f| f.label.starts_with("Data (")) {
                last.label = format!("TLS segment data ({} bytes) — continues a record started in an earlier packet", last.range.map(|r| r.1).unwrap_or(0));
            }
        if let Some(pr) = p.meta.process.map(|i| &self.engine.processes[i as usize]) {
            let mut f = Field::text(format!("[Process: {} (pid {}){}]", pr.name, pr.pid, if pr.app != pr.name { format!(" — {}", pr.app) } else { String::new() }))
                .filter(format!("process == \"{}\"", pr.name));
            f.push(Field::text(format!("PID: {}", pr.pid)).filter(format!("pid == {}", pr.pid)));
            f.push(Field::text(format!("Application: {}", pr.app)).filter(format!("app == \"{}\"", pr.app)));
            if !pr.path.is_empty() {
                f.push(Field::text(format!("Executable: {}", pr.path)));
            }
            f.push(Field::text(format!(
                "Attributed via: {}",
                if pr.source == "PKTAP" { "per-packet kernel metadata (PKTAP)" } else { "socket table (connection owner)" }
            )));
            tree.insert(1, f);
        }
        let is_quic = p.stream.is_some_and(|s| self.engine.streams.get(s.kind, s.id).quic.is_some());
        if is_quic && let Some(last) = tree.last_mut().filter(|f| f.label.starts_with("Data (")) {
            last.label = "QUIC packet (protected; see the decrypted section below)".into();
        }
        if let Some(entries) = self.engine.msg_index.get(&pi) {
            for &(kind, id, i) in entries {
                let m = &self.engine.streams.get(kind, id).http_msgs()[i];
                tree.push(http_msg_field(m));
            }
        }
        let frame_nodes = tree.len();
        if let Some(decs) = self.engine.decrypted.get(&pi) {
            for (k, dec) in decs.iter().enumerate() {
                let dir = if dec.dir == 0 { "initiator → responder" } else { "responder → initiator" };
                if dec.quic {
                    let mut f = Field::new(format!("🔓 Decrypted QUIC packet {} ({dir}): {}", k + 1, dec.note), 0, dec.data.len());
                    f.children = crate::quic::frames_tree(&dec.data);
                    tree.push(f);
                    continue;
                }
                let mut f = Field::new(format!("🔓 Decrypted TLS record {} ({dir}): {}", k + 1, dec.note), 0, dec.data.len());
                let h2_conn = p.stream.is_some_and(|s| self.engine.streams.get(s.kind, s.id).h2.is_some());
                if dec.content_type == 23 && !dec.data.is_empty() && h2_conn {
                    f.push(Field::new(
                        format!("HTTP/2 bytes ({}) — frames are decoded across records in the HTTP/2 sections above", dec.data.len()),
                        0,
                        dec.data.len(),
                    ));
                } else if dec.content_type == 23 && !dec.data.is_empty() {
                    f.children = dissect_plaintext(&dec.data).0;
                } else if !dec.data.is_empty() {
                    f.push(Field::new(printable(&dec.data, 200), 0, dec.data.len()));
                }
                tree.push(f);
            }
        }
        self.detail = Some(DetailCache { pkt: pi, tree, frame_nodes });
    }

    fn details_pane(&mut self, ui: &mut egui::Ui) {
        self.ensure_detail();
        let Some(d) = &self.detail else {
            ui.centered_and_justified(|ui| ui.label(RichText::new("Select a packet to see its details").weak()));
            return;
        };
        let mut actions = Vec::new();
        egui::ScrollArea::both().id_salt("details").auto_shrink([false, false]).show(ui, |ui| {
            let last_frame_layer = d.frame_nodes.saturating_sub(1);
            for (i, f) in d.tree.iter().enumerate() {
                let open = i == last_frame_layer || i >= d.frame_nodes || ((f.label.starts_with("HTTP/2 ") || f.label.starts_with("HTTP/3 ")) && !f.label.contains("SETTINGS"));
                field_ui(ui, f, vec![i], open, &self.selected_field, &mut actions);
            }
        });
        self.actions.extend(actions);
    }

    fn bytes_pane(&mut self, ui: &mut egui::Ui) {
        let Some(pi) = self.selected else {
            ui.centered_and_justified(|ui| ui.label(RichText::new("Packet bytes").weak()));
            return;
        };
        let decs = self.engine.decrypted.get(&pi);
        let ndec = decs.map(|d| d.len()).unwrap_or(0);
        if self.bytes_tab > ndec {
            self.bytes_tab = 0;
        }
        ui.horizontal(|ui| {
            let flen = self.engine.packets[pi].frame.data.len();
            ui.selectable_value(&mut self.bytes_tab, 0, format!("Frame ({flen} B)"));
            if let Some(decs) = decs {
                for (k, d) in decs.iter().enumerate() {
                    ui.selectable_value(&mut self.bytes_tab, k + 1, format!("🔓 Decrypted {} ({} B)", k + 1, d.data.len()));
                }
            }
        });
        ui.separator();
        let data: &[u8] = if self.bytes_tab == 0 { &self.engine.packets[pi].frame.data } else { &decs.unwrap()[self.bytes_tab - 1].data };
        // Highlight the selected field if it belongs to the buffer being shown.
        let hl = (|| {
            let d = self.detail.as_ref()?;
            let path = self.selected_field.as_ref()?;
            let tab = if path[0] >= d.frame_nodes { path[0] - d.frame_nodes + 1 } else { 0 };
            if tab != self.bytes_tab {
                return None;
            }
            field_at(&d.tree, path)?.range
        })();
        if let Some(clicked) = hex_view(ui, data, hl)
            && let Some(d) = &self.detail {
                let (lo, hi) = if self.bytes_tab == 0 { (0, d.frame_nodes) } else { (d.frame_nodes + self.bytes_tab - 1, d.frame_nodes + self.bytes_tab) };
                let mut best: Option<Vec<usize>> = None;
                for i in lo..hi.min(d.tree.len()) {
                    deepest(&d.tree[i], vec![i], clicked, &mut best);
                }
                if let Some(p) = best {
                    self.actions.push(Action::SelectField(p));
                }
            }
    }

    // ---- Stream view --------------------------------------------------------------------

    fn stream_view(&mut self, ui: &mut egui::Ui) {
        let Some(f) = &mut self.follow else {
            ui.label("No stream selected. Double-click a packet or use a conversation's context menu.");
            return;
        };
        let conv = self.engine.streams.get(f.kind, f.id);
        let kind = if f.kind == StreamKind::Tcp { "tcp" } else { "udp" };
        let has_tls = conv.tls.as_ref().map(|t| t.decrypted_records > 0).unwrap_or(false);
        let msgs = conv.http_msgs();
        let msg_label = if msgs.first().map(|m| m.version) == Some(3) { "🔓 HTTP/3 messages" } else { "HTTP/2 messages" };
        let mut actions = Vec::new();
        ui.horizontal(|ui| {
            ui.heading(format!("{} stream {}", kind.to_uppercase(), f.id));
            ui.label(RichText::new(conv.label()).weak());
            if let Some(h) = &conv.host {
                ui.label(RichText::new(format!("· {h}")).weak());
            }
        });
        ui.horizontal(|ui| {
            ui.selectable_value(&mut f.mode, FollowMode::Raw, "Raw bytes");
            if f.kind == StreamKind::Tcp {
                ui.add_enabled_ui(has_tls, |ui| {
                    ui.selectable_value(&mut f.mode, FollowMode::Decrypted, "🔓 Decrypted TLS");
                })
                .response
                .on_disabled_hover_text("No decrypted TLS data in this stream. Load a key log that contains its secrets.");
            }
            if !msgs.is_empty() {
                ui.selectable_value(&mut f.mode, FollowMode::Messages, msg_label);
            }
            ui.separator();
            if f.mode != FollowMode::Messages {
                ui.selectable_value(&mut f.hex, false, "ASCII");
                ui.selectable_value(&mut f.hex, true, "Hex dump");
            }
            ui.separator();
            ui.checkbox(&mut f.show[0], RichText::new(format!("{}:{} →", fmt_ip(conv.a.0), conv.a.1)).color(CLIENT_COLOR));
            ui.checkbox(&mut f.show[1], RichText::new(format!("← {}:{}", fmt_ip(conv.b.0), conv.b.1)).color(SERVER_COLOR));
            ui.separator();
            if ui.button("Filter on stream").clicked() {
                actions.push(Action::SetFilter(format!("{kind}.stream == {}", f.id)));
            }
        });
        if f.mode == FollowMode::Messages {
            ui.separator();
            messages_ui(ui, msgs, f.show, &mut actions);
            self.actions.extend(actions);
            return;
        }
        let key = (conv.packets.len(), f.mode, conv.tls.as_ref().map(|t| t.decrypted_records).unwrap_or(0));
        if f.cache_key != key {
            f.cache = stream_blocks(&self.engine, conv, f.mode == FollowMode::Decrypted);
            f.cache_key = key;
        }
        let total: usize = f.cache.iter().map(|b| b.2.len()).sum();
        let shown: Vec<&(usize, usize, Vec<u8>)> = f.cache.iter().filter(|b| f.show[b.0]).collect();
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{} segments · {}", f.cache.len(), fmt_bytes(total as u64))).weak());
            if ui.button("📋 Copy").clicked() {
                let mut s = String::new();
                for b in &shown {
                    s.push_str(&String::from_utf8_lossy(&b.2));
                }
                actions.push(Action::Copy(s));
            }
            if ui.button("💾 Save…").clicked()
                && let Some(p) = rfd::FileDialog::new().set_file_name(format!("{kind}-stream-{}.bin", f.id)).save_file() {
                    let mut all = Vec::new();
                    for b in &shown {
                        all.extend_from_slice(&b.2);
                    }
                    if let Err(e) = std::fs::write(&p, all) {
                        self.error = Some(e.to_string());
                    }
                }
        });
        ui.separator();
        const LIMIT: usize = 4 * 1024 * 1024;
        egui::ScrollArea::vertical().id_salt("stream").auto_shrink([false, false]).show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            let mut budget = LIMIT;
            for (dir, pkt, data) in shown {
                if budget == 0 {
                    ui.label(RichText::new("… output truncated (use Save to get the full stream)").weak());
                    break;
                }
                let take = data.len().min(budget);
                budget -= take;
                let text = if f.hex { hexdump(&data[..take]) } else { stream_text(&data[..take]) };
                let color = if *dir == 0 { CLIENT_COLOR } else { SERVER_COLOR };
                let bg = if *dir == 0 { tint(240, 110, 110, 18) } else { tint(110, 160, 245, 18) };
                let r = ui.add(egui::Label::new(RichText::new(text).monospace().color(color).background_color(bg)).sense(Sense::click()));
                if r.on_hover_text(format!("Packet #{} — click to jump", pkt + 1)).clicked() {
                    actions.push(Action::Goto(*pkt));
                }
            }
        });
        self.actions.extend(actions);
    }

    // ---- Conversations ------------------------------------------------------------------

    fn conversations_view(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Conversations");
            ui.separator();
            ui.selectable_value(&mut self.conv_udp, false, format!("TCP ({})", self.engine.streams.tcp.len()));
            ui.selectable_value(&mut self.conv_udp, true, format!("UDP ({})", self.engine.streams.udp.len()));
            ui.separator();
            ui.add(egui::TextEdit::singleline(&mut self.conv_search).hint_text("search address, port, host…").desired_width(220.0));
            ui.label(RichText::new("Double-click to follow · right-click for actions").weak());
        });
        ui.separator();
        let list: &Vec<Conversation> = if self.conv_udp { &self.engine.streams.udp } else { &self.engine.streams.tcp };
        let q = self.conv_search.to_lowercase();
        let mut rows: Vec<&Conversation> = list
            .iter()
            .filter(|c| q.is_empty() || c.label().to_lowercase().contains(&q) || c.process.is_some_and(|i| self.engine.processes[i as usize].name.to_lowercase().contains(&q)) || c.host.as_deref().unwrap_or("").to_lowercase().contains(&q) || c.app.to_lowercase().contains(&q))
            .collect();
        let (key, desc) = self.conv_sort;
        rows.sort_by(|a, b| {
            let o = match key {
                ConvSort::Id => a.id.cmp(&b.id),
                ConvSort::Packets => a.packets.len().cmp(&b.packets.len()),
                ConvSort::Bytes => a.total_bytes().cmp(&b.total_bytes()),
                ConvSort::Duration => (a.last_ts - a.first_ts).total_cmp(&(b.last_ts - b.first_ts)),
                ConvSort::Start => a.first_ts.total_cmp(&b.first_ts),
            };
            if desc { o.reverse() } else { o }
        });
        let t0 = self.engine.first_ts();
        let mut actions = Vec::new();
        let mut sort_click = None;
        TableBuilder::new(ui)
            .id_salt(("convs", self.conv_udp))
            .striped(true)
            .resizable(true)
            .sense(Sense::click())
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::initial(56.0))
            .column(Column::initial(170.0).clip(true))
            .column(Column::initial(170.0).clip(true))
            .column(Column::initial(110.0).clip(true))
            .column(Column::initial(64.0))
            .column(Column::initial(72.0))
            .column(Column::initial(68.0))
            .column(Column::initial(68.0))
            .column(Column::initial(60.0))
            .column(Column::initial(64.0))
            .column(Column::initial(170.0).clip(true))
            .column(Column::remainder().at_least(120.0).clip(true))
            .header(22.0, |mut h| {
                for (t, k) in [
                    ("Stream", Some(ConvSort::Id)),
                    ("Initiator", None),
                    ("Responder", None),
                    ("Process", None),
                    ("Packets", Some(ConvSort::Packets)),
                    ("Bytes", Some(ConvSort::Bytes)),
                    ("A → B", None),
                    ("B → A", None),
                    ("Start", Some(ConvSort::Start)),
                    ("Duration", Some(ConvSort::Duration)),
                    ("Host / SNI", None),
                    ("Protocol", None),
                ] {
                    h.col(|ui| {
                        let arrow = if Some(key) == k { if desc { " ⏷" } else { " ⏶" } } else { "" };
                        let r = ui.add(egui::Label::new(RichText::new(format!("{t}{arrow}")).strong()).sense(Sense::click()));
                        if let (Some(k), true) = (k, r.clicked()) {
                            sort_click = Some(k);
                        }
                    });
                }
            })
            .body(|body| {
                body.rows(19.0, rows.len(), |mut row| {
                    let c = rows[row.index()];
                    let sel = self.selected_conv == Some((c.kind, c.id));
                    row.set_selected(sel);
                    let app = match (&c.tls, &c.quic) {
                        (Some(t), _) => format!("TLS · {}", t.status.label()),
                        (_, Some(q)) => format!("QUIC · {}{}", q.status.label(), q.alpn.as_ref().map(|a| format!(" · {a}")).unwrap_or_default()),
                        _ => c.app.to_string(),
                    };
                    let cells = [
                        c.id.to_string(),
                        format!("{}:{}", fmt_ip(c.a.0), c.a.1),
                        format!("{}:{}", fmt_ip(c.b.0), c.b.1),
                        c.process.map(|i| self.engine.processes[i as usize].name.clone()).unwrap_or_default(),
                        fmt_count(c.packets.len()),
                        fmt_bytes(c.total_bytes()),
                        fmt_bytes(c.bytes[0]),
                        fmt_bytes(c.bytes[1]),
                        format!("{:.3}", c.first_ts - t0),
                        format!("{:.3}", c.last_ts - c.first_ts),
                        c.host.clone().unwrap_or_default(),
                        app,
                    ];
                    for t in cells {
                        row.col(|ui| {
                            ui.add(egui::Label::new(t).truncate().selectable(false));
                        });
                    }
                    let r = row.response();
                    if r.clicked() {
                        self.selected_conv = Some((c.kind, c.id));
                    }
                    if r.double_clicked() {
                        actions.push(Action::Follow(c.kind, c.id, best_mode(c)));
                    }
                    r.context_menu(|ui| conv_menu(ui, c, &mut actions));
                });
            });
        if let Some(k) = sort_click {
            self.conv_sort = if self.conv_sort.0 == k { (k, !self.conv_sort.1) } else { (k, true) };
        }
        self.actions.extend(actions);
    }

    // ---- Timeline (HTTP waterfall) ----------------------------------------------------------

    fn timeline_requests(&mut self) -> &Vec<HttpRequest> {
        let key = (self.engine.packets.len(), self.engine.msg_index.len(), self.engine.decrypted.len());
        if self.timeline_cache.as_ref().map(|c| c.0) != Some(key) {
            self.timeline_cache = Some((key, crate::timeline::requests(&self.engine)));
        }
        &self.timeline_cache.as_ref().unwrap().1
    }

    fn export_har(&mut self) {
        let reqs = self.timeline_requests().clone();
        if reqs.is_empty() {
            self.error = Some("No HTTP requests in this capture (load a key log to include HTTPS).".into());
            return;
        }
        let Some(path) = rfd::FileDialog::new().add_filter("HTTP Archive", &["har"]).set_file_name("capture.har").save_file() else { return };
        match std::fs::write(&path, crate::timeline::har(&reqs)) {
            Ok(()) => self.toast(format!("Exported {} requests to {}", reqs.len(), path.display())),
            Err(e) => self.error = Some(format!("HAR export failed: {e}")),
        }
    }

    fn timeline_view(&mut self, ui: &mut egui::Ui) {
        let q = self.timeline_search.to_lowercase();
        let versions = self.timeline_versions;
        let all = self.timeline_requests().clone();
        let zoom = self.timeline_zoom;
        let reqs: Vec<&HttpRequest> = all
            .iter()
            .filter(|r| versions[(r.version.clamp(1, 3) - 1) as usize])
            .filter(|r| zoom.is_none_or(|(a, b)| r.end.unwrap_or(r.start) >= a && r.conn_start.unwrap_or(r.start) <= b))
            .filter(|r| q.is_empty() || r.url().to_lowercase().contains(&q) || r.process.as_deref().unwrap_or("").to_lowercase().contains(&q))
            .collect();
        let mut actions = Vec::new();
        let mut export = false;
        ui.horizontal(|ui| {
            ui.heading("Timeline");
            ui.label(RichText::new(format!("{} HTTP requests", reqs.len())).weak());
            ui.separator();
            ui.add(egui::TextEdit::singleline(&mut self.timeline_search).hint_text("filter URL or process…").desired_width(220.0));
            for (i, v) in ["HTTP/1", "HTTP/2", "HTTP/3"].iter().enumerate() {
                ui.toggle_value(&mut self.timeline_versions[i], *v);
            }
            ui.separator();
            if ui.button("⬇ Export HAR…").on_hover_text("Save these requests as an HTTP Archive for browser devtools and HAR viewers").clicked() {
                export = true;
            }
            if self.timeline_zoom.is_some() && ui.button("⟲ Reset zoom").clicked() {
                self.timeline_zoom = None;
            }
        });
        ui.horizontal(|ui| {
            for (c, l) in [(Color32::from_gray(140), "connection setup (TCP + TLS/QUIC)"), (Color32::from_rgb(240, 160, 50), "waiting for server"), (Color32::from_rgb(80, 150, 240), "download")] {
                let (r, _) = ui.allocate_exact_size(Vec2::new(14.0, 10.0), Sense::hover());
                ui.painter().rect_filled(r, 2.0, c);
                ui.label(RichText::new(l).small());
            }
        });
        ui.separator();
        if reqs.is_empty() {
            ui.label(RichText::new("No HTTP requests found. HTTPS needs a key log (🔑 in the toolbar).").weak());
            if export {
                self.export_har();
            }
            return;
        }
        let (t_min, t_max) = match zoom {
            Some(z) => z,
            None => (
                reqs.iter().map(|r| r.conn_start.unwrap_or(r.start)).fold(f64::INFINITY, f64::min),
                reqs.iter().map(|r| r.end.unwrap_or(r.start)).fold(f64::NEG_INFINITY, f64::max),
            ),
        };
        let t_max = t_max.max(t_min + 0.001);
        let span = t_max - t_min;
        let mut new_zoom = None;
        let mut drag = self.timeline_drag;
        let base_ts = self.engine.first_ts();
        TableBuilder::new(ui)
            .id_salt("timeline")
            .striped(true)
            .resizable(true)
            .sense(Sense::click())
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::initial(56.0))
            .column(Column::initial(50.0))
            .column(Column::initial(300.0).clip(true))
            .column(Column::initial(46.0))
            .column(Column::initial(90.0).clip(true))
            .column(Column::initial(70.0))
            .column(Column::initial(66.0))
            .column(Column::remainder().at_least(260.0))
            .header(22.0, |mut h| {
                for t in ["Status", "Method", "URL", "Ver", "Process", "Size", "Time"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
                h.col(|ui| {
                    let r = ui.max_rect();
                    // Drag across the time axis to zoom into that range.
                    let resp = ui.interact(r, ui.scope_id().with("tl_axis"), Sense::drag()).on_hover_text("Drag to zoom into a time range");
                    if resp.drag_started() {
                        drag = resp.interact_pointer_pos().map(|p| p.x);
                    }
                    if let (Some(x0), Some(p)) = (drag, resp.interact_pointer_pos()) {
                        let sel = egui::Rect::from_x_y_ranges(x0.min(p.x)..=x0.max(p.x), r.y_range());
                        ui.painter().rect_filled(sel, 2.0, ui.visuals().selection.bg_fill.gamma_multiply(0.5));
                        if resp.drag_stopped() {
                            let t = |x: f32| t_min + ((x - r.left()) / r.width()).clamp(0.0, 1.0) as f64 * span;
                            let (a, b) = (t(x0.min(p.x)), t(x0.max(p.x)));
                            if b - a > span * 0.005 {
                                new_zoom = Some((a, b));
                            }
                            drag = None;
                        }
                    }
                    let painter = ui.painter();
                    for i in 0..=4 {
                        let x = r.left() + r.width() * i as f32 / 4.0;
                        let label = format!("{:.2} s", t_min - base_ts + span * i as f64 / 4.0);
                        let align = if i == 4 { Align2::RIGHT_CENTER } else { Align2::LEFT_CENTER };
                        painter.text(egui::pos2(x, r.center().y), align, label, FontId::proportional(11.0), ui.visuals().weak_text_color());
                    }
                });
            })
            .body(|body| {
                body.rows(20.0, reqs.len(), |mut row| {
                    let r = reqs[row.index()];
                    let status_color = match r.status {
                        Some(s) if s >= 500 => Color32::from_rgb(235, 90, 90),
                        Some(s) if s >= 400 => Color32::from_rgb(240, 170, 60),
                        Some(_) => ui_ok_color(),
                        None => Color32::GRAY,
                    };
                    let cells = [
                        RichText::new(r.status.map(|s| s.to_string()).unwrap_or_else(|| "—".into())).color(status_color),
                        RichText::new(&r.method),
                        RichText::new(format!("{}{}", r.host, r.path)),
                        RichText::new(format!("h{}", r.version)),
                        RichText::new(r.process.clone().unwrap_or_default()),
                        RichText::new(fmt_bytes(r.body_bytes as u64)),
                        RichText::new(r.total().map(fmt_dur).unwrap_or_else(|| "—".into())),
                    ];
                    for c in cells {
                        row.col(|ui| {
                            ui.add(egui::Label::new(c).truncate().selectable(false));
                        });
                    }
                    row.col(|ui| {
                        let rect = ui.max_rect().shrink2(Vec2::new(0.0, 4.0));
                        let x = |t: f64| rect.left() + (((t - t_min) / span) as f32).clamp(0.0, 1.0) * rect.width();
                        let painter = ui.painter();
                        let seg = |a: f64, b: f64, c: Color32| {
                            let (x0, x1) = (x(a), x(b).max(x(a) + 1.5));
                            painter.rect_filled(egui::Rect::from_x_y_ranges(x0..=x1, rect.y_range()), 1.5, c);
                        };
                        if let Some(cs) = r.conn_start {
                            seg(cs, r.start, Color32::from_gray(140));
                        }
                        let fb = r.first_byte.unwrap_or(r.start);
                        seg(r.start, fb, Color32::from_rgb(240, 160, 50));
                        if let Some(e) = r.end {
                            seg(fb, e, Color32::from_rgb(80, 150, 240));
                        }
                    });
                    let resp = row.response();
                    let tip = format!(
                        "{} {}\n{}{}waiting {}\ndownload {}\n{} bytes{}",
                        r.method,
                        r.url(),
                        r.conn_start.map(|c| format!("connection setup {}\n", fmt_dur(r.start - c))).unwrap_or_default(),
                        if r.encrypted { "🔓 decrypted\n" } else { "" },
                        r.ttfb().map(fmt_dur).unwrap_or_else(|| "—".into()),
                        match (r.first_byte, r.end) {
                            (Some(f), Some(e)) => fmt_dur(e - f),
                            _ => "—".into(),
                        },
                        r.body_bytes,
                        r.process.as_ref().map(|p| format!("\nprocess {p}")).unwrap_or_default()
                    );
                    let resp = resp.on_hover_text(tip);
                    if resp.clicked() {
                        actions.push(Action::Goto(r.req_pkt));
                    }
                    resp.context_menu(|ui| {
                        if ui.button("Go to request packet").clicked() {
                            actions.push(Action::Goto(r.req_pkt));
                        }
                        if ui.button("Show conversation").clicked() {
                            let kind = if r.conv.0 == StreamKind::Tcp { "tcp" } else { "udp" };
                            actions.push(Action::SetFilter(format!("{kind}.stream == {}", r.conv.1)));
                        }
                        if ui.button("Copy URL").clicked() {
                            actions.push(Action::Copy(r.url()));
                        }
                    });
                });
            });
        self.timeline_drag = drag;
        if new_zoom.is_some() {
            self.timeline_zoom = new_zoom;
        }
        self.actions.extend(actions);
        if export {
            self.export_har();
        }
    }

    // ---- Compare ------------------------------------------------------------------------------

    fn start_compare(&mut self, ctx: &egui::Context) {
        if self.engine.packets.is_empty() {
            self.error = Some("Open or capture traffic first, then compare it with another capture.".into());
            return;
        }
        let Some(path) = rfd::FileDialog::new().add_filter("Capture files", &["pcap", "pcapng", "cap"]).pick_file() else { return };
        let (tx, rx) = crossbeam_channel::bounded(1);
        let c = ctx.clone();
        std::thread::spawn(move || {
            let mut eng = Engine::default();
            let r = crate::capture::for_each_frame(&path, |f| eng.ingest(f));
            let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            let _ = tx.send(r.map(|_| (name, Box::new(eng))));
            c.request_repaint();
        });
        self.compare_rx = Some(rx);
        self.view = View::Compare;
    }

    fn poll_compare(&mut self) {
        let Some(rx) = &self.compare_rx else { return };
        let Ok(msg) = rx.try_recv() else { return };
        self.compare_rx = None;
        match msg {
            Ok((name, other)) => {
                let result = crate::compare::compare(&self.engine, &other);
                self.compare_missing = result.only_a.iter().copied().collect();
                self.compare = Some(CompareState { name, other, result });
                if self.filter_applied.contains("missing") {
                    self.refilter();
                }
            }
            Err(e) => self.error = Some(e),
        }
    }

    fn compare_view(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.horizontal(|ui| {
            ui.heading("Compare captures");
            if ui.button("📂 Compare with…").on_hover_text("Pick a second capture of the same traffic, e.g. taken on the other side of a firewall or proxy").clicked() {
                self.start_compare(&ctx);
            }
        });
        ui.label(
            RichText::new(
                "Matches packets between this capture (A) and another (B) on what survives the path: ports, TCP sequence numbers, flags and payload. TTL, IP ID, checksums, link headers and NAT'd addresses are ignored.",
            )
            .weak(),
        );
        ui.add_space(6.0);
        if self.compare_rx.is_some() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Loading and comparing…");
            });
            return;
        }
        let Some(cs) = &self.compare else {
            card(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(RichText::new("Typical uses").strong());
                ui.label("• Client-side vs server-side capture: which packets never arrived (firewall, MTU, loss)?");
                ui.label("• Before vs after a proxy or load balancer: what was added, dropped or rewritten?");
                ui.label("• How long each packet took between the two capture points.");
            });
            return;
        };
        let r = &cs.result;
        let mut actions = Vec::new();
        ui.horizontal_wrapped(|ui| {
            let stat = |ui: &mut egui::Ui, v: String, l: &str, c: Color32| {
                card(ui, |ui| {
                    ui.set_min_width(120.0);
                    ui.label(RichText::new(v).size(22.0).strong().color(c));
                    ui.label(l);
                });
            };
            stat(ui, fmt_count(r.a_len), "A (this capture)", ui.visuals().text_color());
            stat(ui, fmt_count(r.b_len), &format!("B ({})", cs.name), ui.visuals().text_color());
            stat(ui, fmt_count(r.matched.len()), "in both", ui_ok_color());
            stat(ui, fmt_count(r.only_a.len()), "missing from B", Color32::from_rgb(235, 90, 90));
            stat(ui, fmt_count(r.only_b.len()), "only in B", Color32::from_rgb(240, 170, 60));
            if let (Some(med), Some(p95)) = (r.percentile(0.5), r.percentile(0.95)) {
                stat(ui, format!("{} / {}", fmt_dur(med), fmt_dur(p95)), "B − A median / p95", Color32::from_rgb(110, 170, 250));
            }
        });
        ui.horizontal(|ui| {
            if ui.add_enabled(!r.only_a.is_empty(), egui::Button::new("Show packets missing from B")).clicked() {
                actions.push(Action::SetFilter("compare.missing".into()));
            }
            ui.label(RichText::new("filter: compare.missing").monospace().weak());
        });
        ui.add_space(6.0);
        ui.columns(2, |cols| {
            cols[0].label(RichText::new(format!("Missing from B ({})", r.only_a.len())).strong());
            egui::ScrollArea::vertical().id_salt("cmp_a").max_height(380.0).show(&mut cols[0], |ui| {
                for &i in r.only_a.iter().take(2000) {
                    let p = &self.engine.packets[i];
                    let b = ui.add(egui::Button::selectable(false, format!("#{:<6} {} → {}  {}", i + 1, p.src, p.dst, p.info)).frame_when_inactive(false));
                    if b.clicked() {
                        actions.push(Action::Goto(i));
                    }
                }
            });
            cols[1].label(RichText::new(format!("Only in B ({})", r.only_b.len())).strong());
            egui::ScrollArea::vertical().id_salt("cmp_b").max_height(380.0).show(&mut cols[1], |ui| {
                for &j in r.only_b.iter().take(2000) {
                    let p = &cs.other.packets[j];
                    ui.label(RichText::new(format!("#{:<6} {} → {}  {}", j + 1, p.src, p.dst, p.info)).monospace().size(12.0));
                }
            });
        });
        if !r.lossy_convs.is_empty() {
            ui.add_space(6.0);
            ui.label(RichText::new("Conversations with missing packets").strong());
            for (label, missing, total) in r.lossy_convs.iter().take(10) {
                ui.label(format!("{missing} of {total} packets missing — {label}"));
            }
        }
        self.actions.extend(actions);
    }

    // ---- Decrypt my browser -------------------------------------------------------------------

    fn launch_browser(&mut self, which: Browser, ctx: &egui::Context) {
        let dir = std::env::temp_dir().join(format!("netsift-{}", std::process::id()));
        let keylog = dir.join("tls-keys.log");
        let profile = dir.join(which.name().to_lowercase());
        if let Err(e) = std::fs::create_dir_all(&profile).and_then(|_| std::fs::OpenOptions::new().create(true).append(true).open(&keylog).map(|_| ())) {
            self.error = Some(format!("Cannot prepare key log: {e}"));
            return;
        }
        let mut cmd = std::process::Command::new(which.binary());
        cmd.env("SSLKEYLOGFILE", &keylog);
        match which {
            // A separate profile guarantees a fresh browser process that sees SSLKEYLOGFILE.
            Browser::Firefox => cmd.args(["-no-remote", "-profile"]).arg(&profile),
            Browser::Chrome => cmd.arg(format!("--user-data-dir={}", profile.display())).arg("--no-first-run"),
        };
        match cmd.spawn() {
            Ok(child) => {
                self.browser_child = Some(child);
                self.load_keylog(&keylog);
                if !self.capturing() {
                    self.start_capture(ctx);
                }
                self.toast(format!("{} launched with key logging — browse, and HTTPS decrypts live", which.name()));
            }
            Err(e) => self.error = Some(format!("Could not start {}: {e}", which.name())),
        }
    }

    fn apps_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Apps");
        ui.label(
            RichText::new("Which local programs produced the traffic. Click an app to see its packets; right-click for more.")
                .weak(),
        );
        ui.add_space(4.0);
        let apps = self.engine.apps();
        if self.engine.processes.is_empty() {
            card(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(RichText::new("No process information in this capture").strong());
                ui.label("Process attribution works on live captures: enable 🧩 Apps in the toolbar (on by default) and start capturing.");
                ui.label("Without root you see your own apps (browsers, curl, editors…). Run NetSift as root to also attribute system services, with exact per-packet process info from the kernel (PKTAP).");
            });
            return;
        }
        let total: u64 = apps.iter().map(|a| a.sent + a.received).sum::<u64>().max(1);
        let mut actions = Vec::new();
        TableBuilder::new(ui)
            .id_salt("apps")
            .striped(true)
            .resizable(true)
            .sense(Sense::click())
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::initial(180.0).clip(true))
            .column(Column::initial(220.0).clip(true))
            .column(Column::initial(90.0))
            .column(Column::initial(80.0))
            .column(Column::initial(90.0))
            .column(Column::initial(90.0))
            .column(Column::initial(130.0))
            .column(Column::remainder().at_least(200.0).clip(true))
            .header(22.0, |mut h| {
                for t in ["App", "Processes", "Connections", "Packets", "↑ Sent", "↓ Received", "Share", "Top hosts"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, apps.len(), |mut row| {
                    let a = &apps[row.index()];
                    let unattributed = a.app.is_empty();
                    let name = if unattributed { RichText::new("(unattributed)").weak() } else { RichText::new(&a.app).strong() };
                    let procs = a.procs.iter().map(|(pid, n)| format!("{n} ({pid})")).collect::<Vec<_>>().join(", ");
                    let hosts = a.hosts.iter().take(4).map(|(h, b)| format!("{h} ({})", fmt_bytes(*b))).collect::<Vec<_>>().join(", ");
                    row.col(|ui| {
                        ui.add(egui::Label::new(name).truncate().selectable(false));
                    });
                    for t in [procs, fmt_count(a.conns), fmt_count(a.packets as usize), fmt_bytes(a.sent), fmt_bytes(a.received)] {
                        row.col(|ui| {
                            ui.add(egui::Label::new(t).truncate().selectable(false));
                        });
                    }
                    row.col(|ui| {
                        let share = (a.sent + a.received) as f32 / total as f32;
                        ui.add(egui::ProgressBar::new(share).desired_height(12.0).text(format!("{:.1}%", share * 100.0)));
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(hosts).truncate().selectable(false));
                    });
                    let filter = if unattributed { "!process".to_string() } else { format!("app == \"{}\"", a.app) };
                    let r = row.response();
                    if r.clicked() {
                        actions.push(Action::SetFilter(filter.clone()));
                    }
                    r.context_menu(|ui| {
                        if ui.button(format!("Show packets ({filter})")).clicked() {
                            actions.push(Action::SetFilter(filter.clone()));
                        }
                        if !unattributed {
                            if ui.button(format!("Hide {}", a.app)).clicked() {
                                actions.push(Action::CombineFilter("&& !", filter.clone()));
                            }
                            for (pid, n) in &a.procs {
                                if ui.button(format!("Only {n} (pid {pid})")).clicked() {
                                    actions.push(Action::SetFilter(format!("pid == {pid}")));
                                }
                            }
                        }
                        if !a.hosts.is_empty() && ui.button("Copy host list").clicked() {
                            actions.push(Action::Copy(a.hosts.iter().map(|(h, _)| h.clone()).collect::<Vec<_>>().join("\n")));
                        }
                    });
                });
            });
        self.actions.extend(actions);
    }

    fn endpoints_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Endpoints");
        ui.label(RichText::new("Hosts by traffic volume · right-click to filter").weak());
        ui.separator();
        let eps = self.stats().1.clone();
        let total = self.engine.total_bytes.max(1) as f32;
        let mut actions = Vec::new();
        TableBuilder::new(ui)
            .id_salt("endpoints")
            .striped(true)
            .resizable(true)
            .sense(Sense::click())
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::initial(280.0))
            .columns(Column::initial(90.0), 4)
            .column(Column::remainder().at_least(150.0))
            .header(22.0, |mut h| {
                for t in ["Address", "Tx packets", "Rx packets", "Tx bytes", "Rx bytes", "Share of traffic"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, eps.len(), |mut row| {
                    let e = &eps[row.index()];
                    let addr = e.addr.map(|a| a.to_string()).unwrap_or_default();
                    for t in [addr.clone(), fmt_count(e.tx_pkts as usize), fmt_count(e.rx_pkts as usize), fmt_bytes(e.tx_bytes), fmt_bytes(e.rx_bytes)] {
                        row.col(|ui| {
                            ui.add(egui::Label::new(t).selectable(false));
                        });
                    }
                    row.col(|ui| {
                        let share = (e.tx_bytes + e.rx_bytes) as f32 / total;
                        ui.add(egui::ProgressBar::new(share.min(1.0)).desired_height(12.0).text(format!("{:.1}%", share * 100.0)));
                    });
                    let r = row.response();
                    if r.double_clicked() {
                        actions.push(Action::SetFilter(format!("ip.addr == {addr}")));
                    }
                    r.context_menu(|ui| {
                        if ui.button(format!("Filter: ip.addr == {addr}")).clicked() {
                            actions.push(Action::SetFilter(format!("ip.addr == {addr}")));
                        }
                        if ui.button("Filter: as source").clicked() {
                            actions.push(Action::SetFilter(format!("ip.src == {addr}")));
                        }
                        if ui.button("Filter: as destination").clicked() {
                            actions.push(Action::SetFilter(format!("ip.dst == {addr}")));
                        }
                        if ui.button("Copy address").clicked() {
                            actions.push(Action::Copy(addr.clone()));
                        }
                    });
                });
            });
        self.actions.extend(actions);
    }

    fn protocols_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Protocol hierarchy");
        ui.label(RichText::new("Share of packets containing each protocol · click to filter").weak());
        ui.separator();
        let stats = self.stats().2.clone();
        let n = self.engine.packets.len().max(1) as f32;
        let mut actions = Vec::new();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            egui::Grid::new("protos").num_columns(4).striped(true).spacing([16.0, 6.0]).show(ui, |ui| {
                ui.strong("Protocol");
                ui.strong("Packets");
                ui.strong("Bytes");
                ui.strong("% of packets");
                ui.end_row();
                for (key, name, pk, by) in stats {
                    if ui.link(name).on_hover_text(format!("Filter: {key}")).clicked() {
                        actions.push(Action::SetFilter(key.to_string()));
                    }
                    ui.label(fmt_count(pk as usize));
                    ui.label(fmt_bytes(by));
                    ui.add(egui::ProgressBar::new(pk as f32 / n).desired_width(300.0).text(format!("{:.1}%", pk as f32 * 100.0 / n)));
                    ui.end_row();
                }
            });
        });
        self.actions.extend(actions);
    }

    fn insights_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Insights");
        ui.label(RichText::new("Automatic expert analysis — click an entry to jump to the packet").weak());
        ui.add_space(6.0);
        let ex = &self.engine.experts;
        let count = |s| ex.iter().filter(|e| e.severity == s).count();
        ui.horizontal(|ui| {
            for (s, label) in [(Severity::Error, "Errors"), (Severity::Warn, "Warnings"), (Severity::Note, "Notes")] {
                card(ui, |ui| {
                    ui.set_min_width(130.0);
                    ui.label(RichText::new(fmt_count(count(s))).size(24.0).strong().color(sev_color(s)));
                    ui.label(label);
                });
            }
            let (s, d, m) = self.engine.tls_summary();
            card(ui, |ui| {
                ui.set_min_width(150.0);
                ui.label(RichText::new(format!("{d}/{s}")).size(24.0).strong().color(Color32::from_rgb(240, 200, 60)));
                ui.label(if m > 0 { format!("sessions decrypted ({m} missing keys)") } else { "encrypted sessions decrypted".to_string() });
            });
        });
        ui.add_space(6.0);
        let mut groups: BTreeMap<(std::cmp::Reverse<Severity>, &'static str), Vec<usize>> = BTreeMap::new();
        for (i, e) in ex.iter().enumerate() {
            groups.entry((std::cmp::Reverse(e.severity), e.category)).or_default().push(i);
        }
        if groups.is_empty() {
            ui.label(RichText::new("✔ Nothing suspicious found.").color(Color32::from_rgb(120, 200, 140)));
            return;
        }
        let mut actions = Vec::new();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for ((sev, cat), items) in &groups {
                let title = RichText::new(format!("{cat} — {}", fmt_count(items.len()))).color(sev_color(sev.0)).strong();
                egui::CollapsingHeader::new(title).id_salt(("ex", *cat, sev.0 as u8)).default_open(ex.len() <= 300).show(ui, |ui| {
                    for &i in items.iter().take(1000) {
                        let e = &ex[i];
                        let r = ui.add(egui::Button::selectable(false, format!("#{:<7} {}", e.packet + 1, e.message)).frame_when_inactive(false));
                        if r.clicked() {
                            actions.push(Action::Goto(e.packet));
                        }
                    }
                    if items.len() > 1000 {
                        ui.label(RichText::new(format!("… and {} more (use the ⚠ filter)", items.len() - 1000)).weak());
                    }
                });
            }
        });
        self.actions.extend(actions);
    }

    fn decryption_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Decryption");
        ui.add_space(4.0);
        let mut actions = Vec::new();
        card(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("🔑 TLS key log").strong());
                match &self.engine.keylog.path {
                    Some(p) => ui.monospace(p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()).on_hover_text(p.display().to_string()),
                    None => ui.label(RichText::new("none loaded").weak()),
                };
            });
            ui.label(format!(
                "{} secrets for {} sessions · re-read automatically when the file changes",
                self.engine.keylog.len(),
                self.engine.keylog.sessions()
            ));
            ui.horizontal(|ui| {
                if ui.button("Load key log…").clicked()
                    && let Some(p) = rfd::FileDialog::new().pick_file() {
                        self.load_keylog(&p);
                    }
                if let Some(p) = self.engine.keylog.path.clone()
                    && ui.button("Reload").clicked() {
                        self.load_keylog(&p);
                    }
            });
            egui::CollapsingHeader::new("How to get a key log").show(ui, |ui| {
                ui.label("Browsers (Chrome, Firefox, Edge), curl, and most apps using OpenSSL, BoringSSL, NSS or rustls write session secrets to the file named by SSLKEYLOGFILE:");
                ui.monospace("export SSLKEYLOGFILE=~/tls-keys.log");
                ui.monospace("curl https://example.com          # writes keys");
                ui.monospace("open -na 'Google Chrome' --args --user-data-dir=/tmp/netsift-chrome");
                ui.label("Start that before capturing, point NetSift at the same file, and sessions decrypt live. Supported: TLS 1.3 (AES-GCM, ChaCha20-Poly1305), TLS 1.2 AEAD suites, and QUIC v1/v2 (HTTP/3) including key updates.");
            });
        });
        ui.add_space(8.0);
        struct Row<'a> {
            c: &'a Conversation,
            proto: &'static str,
            server: String,
            sni: String,
            version: String,
            suite: String,
            alpn: String,
            count: String,
            status: TlsStatus,
            ech: bool,
        }
        let mut sessions: Vec<Row> = Vec::new();
        for c in &self.engine.streams.tcp {
            if let Some(t) = &c.tls {
                let server = if t.client_dir == Some(1) { c.a } else { c.b };
                sessions.push(Row {
                    c,
                    proto: "TLS",
                    server: format!("{}:{}", fmt_ip(server.0), server.1),
                    sni: t.sni.clone().unwrap_or_default(),
                    version: t.version.map(crate::dissect::tls_version_name).unwrap_or("?").to_string(),
                    suite: t.suite_name(),
                    alpn: t.alpn.clone().unwrap_or_default(),
                    count: format!("{} records", t.decrypted_records),
                    status: t.status.clone(),
                    ech: t.ech_resolved,
                });
            }
        }
        for c in &self.engine.streams.udp {
            if let Some(q) = &c.quic {
                let server = if q.client_dir == Some(1) { c.a } else { c.b };
                sessions.push(Row {
                    c,
                    proto: "QUIC",
                    server: format!("{}:{}", fmt_ip(server.0), server.1),
                    sni: q.sni.clone().unwrap_or_default(),
                    version: match q.version {
                        crate::quic::V1 => "QUIC v1".into(),
                        crate::quic::V2 => "QUIC v2".into(),
                        v => format!("0x{v:08x}"),
                    },
                    suite: q.suite.map(crate::dissect::cipher_suite_name).unwrap_or_else(|| "?".into()),
                    alpn: q.alpn.clone().unwrap_or_default(),
                    count: format!("{} packets", q.decrypted_packets),
                    status: q.status.clone(),
                    ech: q.ech_resolved,
                });
            }
        }
        sessions.sort_by(|x, y| x.c.first_ts.total_cmp(&y.c.first_ts));
        ui.label(RichText::new(format!("Encrypted sessions ({})", sessions.len())).strong());
        ui.label(
            RichText::new("QUIC Initial packets (and so the SNI) decrypt without keys; the rest of the handshake and the HTTP/3 traffic need the key log.")
                .weak()
                .small(),
        );
        TableBuilder::new(ui)
            .id_salt("tls")
            .striped(true)
            .resizable(true)
            .sense(Sense::click())
            .max_scroll_height(360.0)
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::initial(76.0))
            .column(Column::initial(170.0).clip(true))
            .column(Column::initial(170.0).clip(true))
            .column(Column::initial(70.0))
            .column(Column::initial(240.0).clip(true))
            .column(Column::initial(60.0))
            .column(Column::initial(90.0))
            .column(Column::remainder().at_least(150.0))
            .header(22.0, |mut h| {
                for t in ["Session", "Server", "SNI", "Version", "Cipher suite", "ALPN", "Decrypted", "Status"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(19.0, sessions.len(), |mut row| {
                    let r = &sessions[row.index()];
                    let status_color = match r.status {
                        TlsStatus::Decrypting => Color32::from_rgb(120, 200, 140),
                        TlsStatus::WaitingForKeys | TlsStatus::Handshake => Color32::from_rgb(240, 180, 60),
                        _ => Color32::from_rgb(235, 90, 90),
                    };
                    let cells = [
                        RichText::new(format!("{} {}", r.proto, r.c.id)),
                        RichText::new(&r.server),
                        RichText::new(&r.sni),
                        RichText::new(&r.version),
                        RichText::new(&r.suite),
                        RichText::new(&r.alpn),
                        RichText::new(&r.count),
                        RichText::new(r.status.label() + if r.ech { " · ECH" } else { "" }).color(status_color),
                    ];
                    for txt in cells {
                        row.col(|ui| {
                            ui.add(egui::Label::new(txt).truncate().selectable(false));
                        });
                    }
                    if row.response().clicked() {
                        actions.push(Action::Follow(r.c.kind, r.c.id, best_mode(r.c)));
                    }
                });
            });
        ui.add_space(8.0);
        // Other encrypted traffic we can see but not open.
        let mut other: BTreeMap<&str, usize> = BTreeMap::new();
        for c in self.engine.streams.tcp.iter().chain(self.engine.streams.udp.iter()) {
            if matches!(c.app, "SSH" | "WireGuard") {
                *other.entry(c.app).or_default() += 1;
            }
        }
        let esp = self.engine.packets.iter().filter(|p| p.protocol == "ESP").count();
        if !other.is_empty() || esp > 0 {
            card(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(RichText::new("Other encrypted traffic").strong());
                for (k, n) in &other {
                    let why = match *k {
                        "SSH" => "SSH session keys are never exported by clients; payload stays encrypted.",
                        _ => "WireGuard requires the peers' static and ephemeral private keys.",
                    };
                    ui.horizontal(|ui| {
                        if ui.link(format!("{k}: {n} flows")).clicked() {
                            actions.push(Action::SetFilter(k.to_lowercase().replace("wireguard", "wg")));
                        }
                        ui.label(RichText::new(why).weak());
                    });
                }
                if esp > 0 {
                    ui.label(format!("IPsec ESP: {esp} packets — requires SA keys (not supported)."));
                }
            });
        }
        self.actions.extend(actions);
    }

    fn windows(&mut self, ctx: &egui::Context) {
        if let Some(e) = self.error.clone() {
            let mut open = true;
            egui::Window::new("⚠ Problem").collapsible(false).resizable(false).anchor(Align2::CENTER_CENTER, [0.0, 0.0]).open(&mut open).show(ctx, |ui| {
                ui.set_max_width(480.0);
                ui.label(e);
                ui.add_space(6.0);
                if ui.button("OK").clicked() {
                    self.error = None;
                }
            });
            if !open {
                self.error = None;
            }
        }
        egui::Window::new("Display filter reference").open(&mut self.show_filter_help).default_width(560.0).show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.label(RichText::new("Combine with && || ! (or: and, or, not) and parentheses.").strong());
                ui.add_space(4.0);
                egui::Grid::new("fhelp").striped(true).num_columns(2).show(ui, |ui| {
                    for (a, b) in [
                        ("tcp  udp  dns  http  http2  tls  quic  arp  icmp  ssh  dhcp …", "protocol present"),
                        ("decrypted", "packet carries decrypted TLS or QUIC data"),
                        ("http2   http3", "decoded HTTP/2 (HPACK) or HTTP/3 (QPACK) frames"),
                        ("ip.addr == 10.0.0.0/8", "either address in subnet (also ip.src, ip.dst; IPv6 works)"),
                        ("192.168.1.10", "shorthand for ip.addr == 192.168.1.10"),
                        ("port == 443   tcp.port   udp.dstport …", "ports"),
                        ("tcp.stream == 4   udp.stream == 2", "a single conversation"),
                        ("tcp.flags.syn && !tcp.flags.ack", "TCP flags (syn ack fin reset push urg)"),
                        ("tcp.analysis.retransmission", "retransmitted segments"),
                        ("frame.len > 1000   tcp.len > 0", "lengths"),
                        ("frame contains \"password\"", "raw bytes (case-insensitive), or hex: de:ad:be:ef"),
                        ("dns.qry.name contains \"apple\"", "DNS query name"),
                        ("dns.flags.rcode != 0", "DNS errors"),
                        ("http.host == \"example.com\"", "also http.request.method, http.request.uri"),
                        ("http.response.code >= 400", "HTTP status (HTTP/1.x, HTTP/2 and HTTP/3, decrypted too)"),
                        ("tls.sni contains \"google\"", "server name from the TLS or QUIC Client Hello"),
                        ("info contains \"Retransmission\"", "the Info column"),
                        ("process == \"curl\"   app == \"Google Chrome\"   pid == 123", "traffic of a local process (live capture)"),
                        ("compare.missing", "packets not found in the compared capture"),
                        ("expert   malformed   bookmarked", "analysis flags"),
                    ] {
                        ui.monospace(a);
                        ui.label(b);
                        ui.end_row();
                    }
                });
            });
        });
        egui::Window::new("About NetSift").open(&mut self.show_about).collapsible(false).resizable(false).show(ctx, |ui| {
            ui.label(RichText::new("NetSift").size(20.0).strong());
            ui.label(format!("Version {}", env!("CARGO_PKG_VERSION")));
            ui.label("A fast, workflow-oriented packet analyzer written in Rust.");
            ui.label("Live capture via libpcap · pcap/pcapng · TLS 1.2/1.3 decryption via key logs.");
        });
    }
}

// ---------------------------------------------------------------------------------------------
// Free helpers used inside table/tree closures

fn packet_menu(ui: &mut egui::Ui, pi: usize, p: &PacketRow, eng: &Engine, bookmarks: &HashSet<usize>, actions: &mut Vec<Action>) {
    if let Some(s) = p.stream {
        let kind = if s.kind == StreamKind::Tcp { "tcp" } else { "udp" };
        if ui.button(format!("📜 Follow {} stream", kind.to_uppercase())).clicked() {
            actions.push(Action::Follow(s.kind, s.id, FollowMode::Raw));
        }
        let conv = eng.streams.get(s.kind, s.id);
        if conv.tls.as_ref().is_some_and(|t| t.decrypted_records > 0) && ui.button("🔓 Follow decrypted TLS stream").clicked() {
            actions.push(Action::Follow(s.kind, s.id, FollowMode::Decrypted));
        }
        if !conv.http_msgs().is_empty() && ui.button("🔓 Show HTTP messages").clicked() {
            actions.push(Action::Follow(s.kind, s.id, FollowMode::Messages));
        }
        if ui.button(format!("Filter on this conversation ({kind}.stream == {})", s.id)).clicked() {
            actions.push(Action::SetFilter(format!("{kind}.stream == {}", s.id)));
        }
        ui.separator();
    }
    if let (Some(a), Some(b)) = (p.meta.src_ip, p.meta.dst_ip) {
        ui.menu_button("Filter on address", |ui| {
            for (label, f) in [
                (format!("ip.addr == {a}"), format!("ip.addr == {a}")),
                (format!("ip.addr == {b}"), format!("ip.addr == {b}")),
                (format!("between {a} and {b}"), format!("ip.addr == {a} && ip.addr == {b}")),
            ] {
                if ui.button(label).clicked() {
                    actions.push(Action::SetFilter(f));
                }
            }
        });
    }
    if let Some(pr) = p.meta.process.map(|i| &eng.processes[i as usize]) {
        ui.menu_button(format!("Process: {}", pr.name), |ui| {
            for (label, f) in [
                (format!("Only {}", pr.name), format!("process == \"{}\"", pr.name)),
                (format!("Only app {}", pr.app), format!("app == \"{}\"", pr.app)),
                (format!("Only pid {}", pr.pid), format!("pid == {}", pr.pid)),
            ] {
                if ui.button(label).clicked() {
                    actions.push(Action::SetFilter(f));
                }
            }
            if ui.button(format!("Hide {}", pr.name)).clicked() {
                actions.push(Action::CombineFilter("&& !", format!("process == \"{}\"", pr.name)));
            }
        });
    }
    let proto_kw = proto::TABLE.iter().rev().find(|(_, bit, _)| p.meta.protos & bit != 0 && *bit != proto::DECRYPTED && *bit != proto::DATA).map(|(k, _, _)| *k);
    if let Some(k) = proto_kw {
        if ui.button(format!("Filter on protocol: {k}")).clicked() {
            actions.push(Action::SetFilter(k.to_string()));
        }
        if ui.button(format!("Exclude protocol: {k}")).clicked() {
            actions.push(Action::CombineFilter("&& !", k.to_string()));
        }
    }
    ui.separator();
    let bm = bookmarks.contains(&pi);
    if ui.button(if bm { "☆ Remove bookmark  ⌘M" } else { "★ Bookmark  ⌘M" }).clicked() {
        actions.push(Action::ToggleBookmark(pi));
    }
    if ui.button("Copy summary").clicked() {
        actions.push(Action::Copy(format!("{}\t{}\t{}\t{}\t{}\t{}", pi + 1, p.src, p.dst, p.protocol, p.frame.orig_len, p.info)));
    }
    if ui.button("Copy bytes as hex").clicked() {
        actions.push(Action::Copy(crate::dissect::hex(&p.frame.data)));
    }
}

fn conv_menu(ui: &mut egui::Ui, c: &Conversation, actions: &mut Vec<Action>) {
    let kind = if c.kind == StreamKind::Tcp { "tcp" } else { "udp" };
    if ui.button("📜 Follow stream").clicked() {
        actions.push(Action::Follow(c.kind, c.id, FollowMode::Raw));
    }
    if c.tls.as_ref().is_some_and(|t| t.decrypted_records > 0) && ui.button("🔓 Follow decrypted").clicked() {
        actions.push(Action::Follow(c.kind, c.id, FollowMode::Decrypted));
    }
    if !c.http_msgs().is_empty() && ui.button("🔓 Show HTTP messages").clicked() {
        actions.push(Action::Follow(c.kind, c.id, FollowMode::Messages));
    }
    if ui.button(format!("Show packets ({kind}.stream == {})", c.id)).clicked() {
        actions.push(Action::SetFilter(format!("{kind}.stream == {}", c.id)));
    }
    if ui.button("Exclude this conversation").clicked() {
        actions.push(Action::CombineFilter("&& !", format!("{kind}.stream == {}", c.id)));
    }
    if let Some(h) = &c.host
        && ui.button(format!("Copy host ({h})")).clicked() {
            actions.push(Action::Copy(h.clone()));
        }
}

fn field_ui(ui: &mut egui::Ui, f: &Field, path: Vec<usize>, default_open: bool, sel: &Option<Vec<usize>>, actions: &mut Vec<Action>) {
    let selected = sel.as_ref() == Some(&path);
    let handle = |r: egui::Response, actions: &mut Vec<Action>| {
        if r.clicked() {
            actions.push(Action::SelectField(path.clone()));
        }
        r.context_menu(|ui| {
            if let Some(flt) = &f.filter {
                ui.label(RichText::new(flt).monospace().weak());
                if ui.button("Apply as filter").clicked() {
                    actions.push(Action::SetFilter(flt.clone()));
                }
                if ui.button("…and selected").clicked() {
                    actions.push(Action::CombineFilter("&&", flt.clone()));
                }
                if ui.button("…or selected").clicked() {
                    actions.push(Action::CombineFilter("||", flt.clone()));
                }
                if ui.button("…and not selected").clicked() {
                    actions.push(Action::CombineFilter("&& !", flt.clone()));
                }
                ui.separator();
            }
            if ui.button("Copy line").clicked() {
                actions.push(Action::Copy(f.label.clone()));
            }
            if let Some((_, v)) = f.label.split_once(": ")
                && ui.button("Copy value").clicked() {
                    actions.push(Action::Copy(v.to_string()));
                }
        });
    };
    if f.children.is_empty() {
        let r = ui.add(egui::Button::selectable(selected, &f.label).frame_when_inactive(false));
        handle(r, actions);
        return;
    }
    // Top-level layers are keyed by name so their expansion state carries over between packets;
    // deeper nodes also need their position because siblings often share a name.
    let key: String = f.label.split([',', ':', '(']).next().unwrap_or("").to_string();
    let id = if path.len() == 1 { ui.make_persistent_id(("field", key)) } else { ui.make_persistent_id(("field", &path, key)) };
    egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, default_open)
        .show_header(ui, |ui| {
            let r = ui.add(egui::Button::selectable(selected, &f.label).frame_when_inactive(false));
            handle(r, actions);
        })
        .body(|ui| {
            for (i, c) in f.children.iter().enumerate() {
                let mut p = path.clone();
                p.push(i);
                field_ui(ui, c, p, false, sel, actions);
            }
        });
}

fn field_at<'a>(tree: &'a [Field], path: &[usize]) -> Option<&'a Field> {
    let mut f = tree.get(path[0])?;
    for &i in &path[1..] {
        f = f.children.get(i)?;
    }
    Some(f)
}

fn deepest(f: &Field, path: Vec<usize>, byte: usize, best: &mut Option<Vec<usize>>) {
    if let Some((o, l)) = f.range
        && byte >= o && byte < o + l.max(1) {
            *best = Some(path.clone());
        }
    for (i, c) in f.children.iter().enumerate() {
        let mut p = path.clone();
        p.push(i);
        deepest(c, p, byte, best);
    }
}

/// Hex + ASCII dump with field highlighting. Returns the byte index that was clicked.
fn hex_view(ui: &mut egui::Ui, data: &[u8], hl: Option<(usize, usize)>) -> Option<usize> {
    let font = FontId::monospace(12.5);
    let (cw, row_h) = ui.fonts_mut(|f| (f.glyph_width(&font, '0'), f.row_height(&font) + 1.0));
    let ow = if data.len() > 0xffff { 6 } else { 4 };
    let hex_start = ow + 2;
    let ascii_start = hex_start + 49 + 1;
    let rows = data.len().div_ceil(16);
    let text_color = ui.visuals().text_color();
    let weak = ui.visuals().weak_text_color();
    let hl_bg = ui.visuals().selection.bg_fill;
    let mut clicked = None;
    egui::ScrollArea::both().id_salt("hex").auto_shrink([false, false]).show_rows(ui, row_h, rows, |ui, range| {
        for r in range {
            let (rect, resp) = ui.allocate_exact_size(Vec2::new(cw * (ascii_start + 17) as f32, row_h), Sense::click());
            let painter = ui.painter_at(rect);
            let x0 = rect.left();
            for i in 0..16 {
                let idx = r * 16 + i;
                if idx >= data.len() {
                    break;
                }
                if let Some((o, l)) = hl
                    && idx >= o && idx < o + l {
                        let hx = hex_start + i * 3 + (i >= 8) as usize;
                        let hr = egui::Rect::from_min_size(egui::pos2(x0 + hx as f32 * cw - 1.0, rect.top()), Vec2::new(cw * 2.0 + 2.0, row_h));
                        painter.rect_filled(hr, 2.0, hl_bg);
                        let ar = egui::Rect::from_min_size(egui::pos2(x0 + (ascii_start + i) as f32 * cw, rect.top()), Vec2::new(cw, row_h));
                        painter.rect_filled(ar, 1.0, hl_bg);
                    }
            }
            let mut hexs = String::new();
            let mut asc = String::new();
            for i in 0..16 {
                if i == 8 {
                    hexs.push(' ');
                }
                match data.get(r * 16 + i) {
                    Some(b) => {
                        hexs.push_str(&format!("{b:02x} "));
                        asc.push(if (0x20..0x7f).contains(b) { *b as char } else { '·' });
                    }
                    None => hexs.push_str("   "),
                }
            }
            let off = format!("{:0w$x}", r * 16, w = ow);
            painter.text(rect.left_top(), Align2::LEFT_TOP, off, font.clone(), weak);
            painter.text(egui::pos2(x0 + hex_start as f32 * cw, rect.top()), Align2::LEFT_TOP, hexs, font.clone(), text_color);
            painter.text(egui::pos2(x0 + ascii_start as f32 * cw, rect.top()), Align2::LEFT_TOP, asc, font.clone(), text_color);
            if resp.clicked()
                && let Some(pos) = resp.interact_pointer_pos() {
                    let col = ((pos.x - x0) / cw) as usize;
                    let i = if col >= ascii_start {
                        Some(col - ascii_start)
                    } else if col >= hex_start {
                        let c = col - hex_start;
                        let c = if c >= 25 { c - 1 } else { c };
                        Some(c / 3)
                    } else {
                        None
                    };
                    if let Some(i) = i.filter(|&i| i < 16 && r * 16 + i < data.len()) {
                        clicked = Some(r * 16 + i);
                    }
                }
        }
    });
    clicked
}

fn hexdump(d: &[u8]) -> String {
    let mut s = String::new();
    for (r, chunk) in d.chunks(16).enumerate() {
        s.push_str(&format!("{:08x}  ", r * 16));
        for i in 0..16 {
            match chunk.get(i) {
                Some(b) => s.push_str(&format!("{b:02x} ")),
                None => s.push_str("   "),
            }
            if i == 7 {
                s.push(' ');
            }
        }
        s.push(' ');
        s.extend(chunk.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }));
        s.push('\n');
    }
    s.pop();
    s
}

fn stream_text(d: &[u8]) -> String {
    let mut s = String::with_capacity(d.len());
    for &b in d {
        match b {
            b'\n' | b'\t' => s.push(b as char),
            b'\r' => {}
            0x20..=0x7e => s.push(b as char),
            _ => s.push('.'),
        }
    }
    s
}

/// Builds (direction, packet, bytes) blocks for the follow-stream view, coalescing consecutive
/// segments in the same direction.
fn stream_blocks(eng: &Engine, c: &Conversation, decrypted: bool) -> Vec<(usize, usize, Vec<u8>)> {
    let mut segs: Vec<(usize, usize, &[u8])> = Vec::new();
    if c.kind == StreamKind::Udp {
        for &pi in &c.packets {
            let p = &eng.packets[pi];
            if let (Some((o, l)), Some(s)) = (p.meta.udp_payload, p.stream) {
                segs.push((pi, s.dir, &p.frame.data[o..o + l]));
            }
        }
    } else {
        for dir in 0..2 {
            let (data, chunks): (&[u8], &[(usize, usize)]) = if decrypted {
                match &c.tls {
                    Some(t) => (&t.dirs[dir].plain, &t.dirs[dir].plain_chunks),
                    None => (&[], &[]),
                }
            } else {
                (&c.dirs[dir].data, &c.dirs[dir].chunks)
            };
            for (k, &(off, pkt)) in chunks.iter().enumerate() {
                let end = chunks.get(k + 1).map(|c| c.0).unwrap_or(data.len());
                segs.push((pkt, dir, &data[off..end]));
            }
        }
        segs.sort_by_key(|s| s.0);
    }
    let mut out: Vec<(usize, usize, Vec<u8>)> = Vec::new();
    for (pkt, dir, d) in segs {
        if d.is_empty() {
            continue;
        }
        match out.last_mut() {
            Some(last) if last.0 == dir => last.2.extend_from_slice(d),
            _ => out.push((dir, pkt, d.to_vec())),
        }
    }
    out
}


/// Details-tree node for a decoded HTTP/2 or HTTP/3 message.
fn http_msg_field(m: &HttpMsg) -> Field {
    let mut f = Field::text(format!("HTTP/{} {}", m.version, m.summary())).filter(format!("http{}", m.version));
    for (n, v) in &m.headers {
        let mut h = Field::text(format!("{n}: {v}"));
        h.filter = match n.as_str() {
            ":authority" => Some(format!("http.host == \"{v}\"")),
            ":path" => Some(format!("http.request.uri == \"{v}\"")),
            ":method" => Some(format!("http.request.method == \"{v}\"")),
            ":status" => Some(format!("http.response.code == {v}")),
            _ => None,
        };
        f.push(h);
    }
    if m.kind == "DATA" {
        f.push(Field::text(format!("Data ({} bytes): {}", m.data_len, printable(&m.data, 300))));
    }
    if m.end_stream {
        f.push(Field::text("[END_STREAM]"));
    }
    f
}

/// Renders decoded HTTP/2 / HTTP/3 messages, coloured by direction.
fn messages_ui(ui: &mut egui::Ui, msgs: &[HttpMsg], show: [bool; 2], actions: &mut Vec<Action>) {
    const BODY_SHOWN: usize = 64 * 1024;
    egui::ScrollArea::vertical().id_salt("msgs").auto_shrink([false, false]).show(ui, |ui| {
        for m in msgs.iter().filter(|m| show[m.dir]) {
            let color = if m.dir == 0 { CLIENT_COLOR } else { SERVER_COLOR };
            let bg = if m.dir == 0 { tint(240, 110, 110, 18) } else { tint(110, 160, 245, 18) };
            let arrow = if m.dir == 0 { "→" } else { "←" };
            let mut text = format!("{arrow} {}  (packet #{})", m.summary(), m.pkt + 1);
            for (n, v) in &m.headers {
                text.push_str(&format!("\n    {n}: {v}"));
            }
            if m.kind == "DATA" && !m.data.is_empty() {
                let shown = m.data.len().min(BODY_SHOWN);
                text.push('\n');
                text.push_str(&stream_text(&m.data[..shown]));
                if m.data_len > shown {
                    text.push_str(&format!("\n    … {} more bytes", m.data_len - shown));
                }
            }
            let r = ui.add(egui::Label::new(RichText::new(text).monospace().color(color).background_color(bg)).sense(Sense::click()));
            if r.on_hover_text("Click to jump to the packet").clicked() {
                actions.push(Action::Goto(m.pkt));
            }
            ui.add_space(3.0);
        }
    });
}




/// Captures the window to a PNG. `then` runs after the file is written.
fn save_screenshot(ctx: &egui::Context, path: PathBuf, then: Option<Box<dyn FnOnce() + Send>>) {
    ctx.request_screenshot(move |image| {
        let write = || -> Result<(), String> {
            let f = std::fs::File::create(&path).map_err(|e| e.to_string())?;
            let mut enc = png::Encoder::new(std::io::BufWriter::new(f), image.size[0] as u32, image.size[1] as u32);
            enc.set_color(png::ColorType::Rgba);
            let mut w = enc.write_header().map_err(|e| e.to_string())?;
            w.write_image_data(image.as_raw()).map_err(|e| e.to_string())
        };
        if let Err(e) = write() {
            eprintln!("screenshot failed: {e}");
        }
        if let Some(f) = then {
            f();
        }
    });
    ctx.request_repaint();
}


