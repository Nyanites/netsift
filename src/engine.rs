//! Ingest pipeline: dissect → track conversations → reassemble → decrypt → expert analysis.

use crate::dissect::{dissect, dissect_plaintext, dns_rcode_name, http_tree, is_http_start, is_tls_record_start, tcp_flags_str, tls_alert_name};
use crate::model::{proto, tcpflag, Decrypted, Expert, Frame, HttpMsg, PacketRow, ProcInfo, Severity, StreamKind, StreamRef};
use crate::procs::{app_name, ProcTable, Snapshot};
use crate::quic::QuicOut;
use crate::streams::StreamTable;
use crate::tls::KeyLog;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Default)]
pub struct Engine {
    pub packets: Vec<PacketRow>,
    pub streams: StreamTable,
    pub keylog: KeyLog,
    pub decrypted: HashMap<usize, Vec<Decrypted>>,
    pub experts: Vec<Expert>,
    pub total_bytes: u64,
    /// Per conversation, how many HTTP messages have been indexed.
    applied: HashMap<(u8, usize), usize>,
    /// Already-ingested packets whose summary changed (e.g. decrypted later).
    pub changed: Vec<usize>,
    /// Packet → decoded HTTP/2 / HTTP/3 messages it completed: (conversation kind, id, msg index).
    pub msg_index: HashMap<usize, Vec<(StreamKind, usize, usize)>>,
    /// Packet → summaries of the QUIC packets in its datagram.
    quic_info: HashMap<usize, Vec<String>>,
    /// Local processes traffic was attributed to; `Meta::process` indexes this.
    pub processes: Vec<ProcInfo>,
    procs_by_pid: HashMap<u32, Vec<u32>>,
    proc_table: ProcTable,
    /// Conversations still waiting for a socket-table match: (kind, id, attempts).
    unattributed: Vec<(StreamKind, usize, u32)>,
}

/// Traffic of one application (all its processes), from the local host's point of view.
#[derive(Default, Clone)]
pub struct AppStat {
    pub app: String,
    pub procs: Vec<(u32, String)>,
    pub conns: usize,
    pub packets: u64,
    pub sent: u64,
    pub received: u64,
    /// Remote hosts (SNI/Host/DNS name, else address) by bytes, largest first.
    pub hosts: Vec<(String, u64)>,
}

#[derive(Default, Clone)]
pub struct Endpoint {
    pub addr: Option<IpAddr>,
    pub tx_pkts: u64,
    pub rx_pkts: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

impl Engine {
    /// Resets the capture but keeps the loaded key log.
    pub fn clear(&mut self) {
        let keylog = std::mem::take(&mut self.keylog);
        *self = Engine { keylog, ..Default::default() };
    }

    pub fn first_ts(&self) -> f64 {
        self.packets.first().map(|p| p.frame.ts).unwrap_or(0.0)
    }

    pub fn duration(&self) -> f64 {
        match (self.packets.first(), self.packets.last()) {
            (Some(a), Some(b)) => b.frame.ts - a.frame.ts,
            _ => 0.0,
        }
    }

    fn expert(&mut self, packet: usize, severity: Severity, category: &'static str, message: String) {
        self.experts.push(Expert { packet, severity, category, message });
    }

    pub fn ingest(&mut self, frame: Frame) {
        let idx = self.packets.len();
        let d = dissect(&frame, idx + 1);
        let ts = frame.ts;
        let wire_len = frame.orig_len as u64;
        let mut row = PacketRow {
            frame,
            protocol: d.protocol,
            src: d.src,
            dst: d.dst,
            info: d.info,
            meta: d.meta,
            stream: None,
            retransmission: false,
            severity: None,
        };
        self.total_bytes += wire_len;
        let mut experts: Vec<(Severity, &'static str, String)> = Vec::new();
        let mut tls_conv = None;
        let mut h2c_conv = None;
        let mut quic_conv = None;

        let m = &row.meta;
        if let (Some(sip), Some(dip), Some(sp), Some(dp)) = (m.src_ip, m.dst_ip, m.src_port, m.dst_port) {
            if let Some(t) = m.tcp {
                let new_syn = t.flags & tcpflag::SYN != 0 && t.flags & tcpflag::ACK == 0;
                let (id, dir) = self.streams.lookup(StreamKind::Tcp, (sip, sp), (dip, dp), ts, new_syn);
                let c = self.streams.get_mut(StreamKind::Tcp, id);
                c.packets.push(idx);
                c.pkts[dir] += 1;
                c.bytes[dir] += wire_len;
                c.last_ts = ts;
                c.syn |= t.flags & tcpflag::SYN != 0;
                c.fin |= t.flags & tcpflag::FIN != 0;
                c.rst |= t.flags & tcpflag::RST != 0;
                let payload = &row.frame.data[t.payload_off..t.payload_off + t.payload_len];
                let seg = c.dirs[dir].segment(t.seq, t.flags, payload, idx);
                let rel_ack = c.dirs[1 - dir].rel(t.ack);
                if c.app.is_empty() && !payload.is_empty() && !seg.retransmission {
                    c.app = if is_tls_record_start(payload) {
                        "TLS"
                    } else if is_http_start(payload) {
                        "HTTP"
                    } else if payload.starts_with(b"SSH-") {
                        "SSH"
                    } else if payload.starts_with(&crate::h2::PREFACE[..payload.len().min(crate::h2::PREFACE.len())]) && payload.len() >= 4 {
                        "HTTP2"
                    } else {
                        "Data"
                    };
                }
                if c.host.is_none() {
                    c.host = row.meta.http_host.clone().or_else(|| row.meta.tls_sni.clone());
                }
                if row.protocol == "TCP" {
                    let ack = if t.flags & tcpflag::ACK != 0 { format!(" Ack={rel_ack}") } else { String::new() };
                    row.info = format!(
                        "{sp} → {dp} [{}] Seq={}{ack} Win={} Len={}",
                        tcp_flags_str(t.flags),
                        seg.rel_seq,
                        t.window,
                        t.payload_len
                    );
                    if !payload.is_empty() && !seg.retransmission {
                        match c.app {
                            "TLS" => {
                                row.protocol = "TLS".into();
                                row.meta.protos |= proto::TLS;
                                row.info = "Continuation Data".into();
                            }
                            "HTTP" => {
                                row.protocol = "HTTP".into();
                                row.meta.protos |= proto::HTTP;
                                row.info = format!("Continuation ({} bytes)", t.payload_len);
                            }
                            _ => {}
                        }
                    }
                }
                if seg.retransmission {
                    row.retransmission = true;
                    row.info = format!("[TCP Retransmission] {}", row.info);
                    experts.push((Severity::Warn, "Retransmission", format!("TCP retransmission in stream {id}")));
                } else if seg.out_of_order {
                    experts.push((Severity::Note, "Sequence", format!("Out-of-order segment in stream {id}")));
                }
                if t.flags & tcpflag::RST != 0 {
                    experts.push((Severity::Warn, "Reset", format!("Connection reset (RST) in stream {id}")));
                }
                if t.window == 0 && t.flags & (tcpflag::RST | tcpflag::SYN | tcpflag::FIN) == 0 {
                    experts.push((Severity::Warn, "Zero window", format!("Receiver window is zero in stream {id}")));
                }
                if c.app == "TLS" && !payload.is_empty() {
                    tls_conv = Some(id);
                }
                if c.app == "HTTP2" && !payload.is_empty() {
                    h2c_conv = Some(id);
                }
                row.stream = Some(StreamRef { kind: StreamKind::Tcp, id, dir });
            } else if m.udp_payload.is_some() {
                let (id, dir) = self.streams.lookup(StreamKind::Udp, (sip, sp), (dip, dp), ts, false);
                let c = self.streams.get_mut(StreamKind::Udp, id);
                c.packets.push(idx);
                c.pkts[dir] += 1;
                c.bytes[dir] += wire_len;
                c.last_ts = ts;
                if c.app.is_empty() {
                    c.app = udp_app(row.meta.protos);
                }
                if c.host.is_none() {
                    c.host = row.meta.dns_name.clone();
                }
                if row.meta.protos & proto::QUIC != 0 && c.app != "QUIC" && c.pkts[0] + c.pkts[1] == 1 {
                    c.app = "QUIC";
                }
                if c.app == "QUIC" {
                    quic_conv = Some((id, dir));
                }
                row.stream = Some(StreamRef { kind: StreamKind::Udp, id, dir });
            }
        }

        if let Some(sref) = row.stream {
            self.attribute(&mut row, sref);
        }
        let m = &row.meta;
        if m.malformed {
            experts.push((Severity::Error, "Malformed", "Malformed or truncated packet".into()));
        }
        if m.dns_response && m.dns_rcode.unwrap_or(0) != 0 {
            experts.push((
                Severity::Warn,
                "DNS",
                format!("DNS error {} for {}", dns_rcode_name(m.dns_rcode.unwrap()), m.dns_name.clone().unwrap_or_default()),
            ));
        }
        if let Some(s) = m.http_status {
            http_expert(s, &mut experts);
        }
        if let Some(a) = m.tls_alert {
            let sev = if a == 0 { Severity::Note } else { Severity::Error };
            experts.push((sev, "TLS alert", format!("TLS alert: {}", tls_alert_name(a))));
        }
        if let Some((t, c)) = m.icmp
            && ((m.protos & proto::ICMP != 0 && (t == 3 || t == 11)) || (m.protos & proto::ICMPV6 != 0 && (1..=4).contains(&t))) {
                experts.push((Severity::Warn, "ICMP", format!("{} (code {c})", row.info)));
            }
        row.severity = experts.iter().map(|e| e.0).max();
        self.packets.push(row);
        for (s, cat, msg) in experts {
            self.expert(idx, s, cat, msg);
        }
        if let Some(id) = tls_conv {
            self.run_tls(id);
        }
        if let Some(id) = h2c_conv {
            let c = &mut self.streams.tcp[id];
            let new = c.h2.get_or_insert_with(Default::default).update(
                [&c.dirs[0].data, &c.dirs[1].data],
                [&c.dirs[0].chunks, &c.dirs[1].chunks],
            );
            self.apply_http(StreamKind::Tcp, id, new);
        }
        if let Some((id, dir)) = quic_conv {
            let p = &self.packets[idx];
            let (o, l) = p.meta.udp_payload.unwrap();
            let payload = p.frame.data[o..o + l].to_vec();
            let mut out = Vec::new();
            let q = self.streams.udp[id].quic.get_or_insert_with(Default::default);
            q.datagram(dir, idx, &payload, &self.keylog, &mut out);
            self.apply_quic(id, out);
        }
    }

    fn apply_quic(&mut self, id: usize, out: Vec<QuicOut>) {
        let c = &mut self.streams.udp[id];
        let q = c.quic.as_mut().unwrap();
        if q.sni.is_some() && !q.ech_resolved {
            c.host = q.sni.clone();
        }
        let mut touched = Vec::new();
        for o in out {
            let infos = self.quic_info.entry(o.pkt).or_default();
            // A retried packet replaces its earlier "protected" placeholder.
            if let Some(i) = infos.iter().position(|s| s.starts_with(o.level.name()) && s.contains("[protected")) {
                infos.remove(i);
            }
            infos.push(o.summary.clone());
            let row = &mut self.packets[o.pkt];
            row.protocol = "QUIC".into();
            row.meta.protos |= proto::QUIC;
            if o.summary.contains("Client Hello") {
                row.meta.tls_sni = q.sni.clone();
            }
            if o.summary.contains("CONNECTION_CLOSE") {
                self.experts.push(Expert { packet: o.pkt, severity: Severity::Note, category: "QUIC", message: format!("QUIC connection closed: {}", o.summary) });
            }
            if let Some(payload) = o.payload {
                row.meta.protos |= proto::DECRYPTED;
                self.decrypted.entry(o.pkt).or_default().push(Decrypted { dir: o.dir, content_type: 0, data: payload, note: o.summary, quic: true });
            }
            touched.push(o.pkt);
        }
        touched.dedup();
        for pkt in &touched {
            self.packets[*pkt].info = self.quic_info[pkt].join(" · ");
        }
        self.changed.extend(touched);
        let done = self.msg_count_applied(StreamKind::Udp, id);
        let h3 = &mut self.streams.udp[id].quic.as_mut().unwrap().h3;
        let mut new: Vec<usize> = std::mem::take(&mut h3.updated);
        new.extend(done..h3.msgs.len());
        self.apply_http(StreamKind::Udp, id, new);
    }

    /// Number of messages of a conversation already indexed (they are applied in order).
    fn msg_count_applied(&self, kind: StreamKind, id: usize) -> usize {
        self.applied.get(&(kind as u8, id)).copied().unwrap_or(0)
    }

    /// Indexes new HTTP/2 or HTTP/3 messages and rewrites the affected packet rows.
    fn apply_http(&mut self, kind: StreamKind, id: usize, new: Vec<usize>) {
        if new.is_empty() {
            return;
        }
        let conv = self.streams.get(kind, id);
        let conv_ech = conv.tls.as_ref().is_some_and(|t| t.ech_resolved) || conv.quic.as_ref().is_some_and(|q| q.ech_resolved);
        let mut real_host: Option<String> = None;
        let msgs = conv.http_msgs();
        let mut pkts = Vec::new();
        for i in new {
            let m = &msgs[i];
            let entry = self.msg_index.entry(m.pkt).or_default();
            if !entry.contains(&(kind, id, i)) {
                entry.push((kind, id, i));
            }
            pkts.push(m.pkt);
            let a = self.applied.entry((kind as u8, id)).or_default();
            *a = (*a).max(i + 1);
        }
        pkts.sort_unstable();
        pkts.dedup();
        for pkt in pkts {
            let row = &mut self.packets[pkt];
            let list: Vec<&HttpMsg> = self.msg_index[&pkt].iter().map(|&(_, _, i)| &msgs[i]).collect();
            let v3 = list.iter().any(|m| m.version == 3);
            row.protocol = if v3 { "HTTP3" } else { "HTTP2" }.into();
            row.meta.protos |= if v3 { proto::HTTP3 } else { proto::HTTP2 };
            let interesting: Vec<&&HttpMsg> = list.iter().filter(|m| m.kind != "SETTINGS").collect();
            let shown = if interesting.is_empty() { list.iter().collect() } else { interesting };
            let mut info: Vec<String> = shown.iter().map(|m| m.summary()).collect();
            info.dedup();
            row.info = info.join(", ");
            let mut experts = Vec::new();
            for m in &list {
                if let Some(a) = m.header(":authority") {
                    row.meta.http_host = Some(a.to_string());
                    // With ECH the visible SNI is a decoy; the real host is in the request.
                    if conv_ech {
                        real_host = Some(a.to_string());
                    }
                }
                if let Some(v) = m.header(":method") {
                    row.meta.http_method = Some(v.to_string());
                }
                if let Some(v) = m.header(":path") {
                    row.meta.http_uri = Some(v.to_string());
                }
                if let Some(s) = m.header(":status").and_then(|s| s.parse().ok()) {
                    row.meta.http_status = Some(s);
                    http_expert(s, &mut experts);
                }
                if m.kind == "RST_STREAM" || m.kind == "GOAWAY" {
                    experts.push((Severity::Note, if v3 { "HTTP/3" } else { "HTTP/2" }, format!("{} {}", m.kind, m.note)));
                }
                if m.note.contains("HPACK") || m.note.contains("QPACK") {
                    experts.push((Severity::Warn, "Header compression", m.note.clone()));
                }
            }
            for (s, cat, msg) in experts {
                if !self.experts.iter().any(|e| e.packet == pkt && e.message == msg) {
                    row.severity = row.severity.max(Some(s));
                    self.experts.push(Expert { packet: pkt, severity: s, category: cat, message: msg });
                }
            }
            self.changed.push(pkt);
        }
        if let Some(h) = real_host {
            self.streams.get_mut(kind, id).host = Some(h);
        }
    }

    /// Finds or registers a process. PKTAP names are truncated to 16 characters, so a pid entry
    /// whose name is a prefix-compatible match is reused (and upgraded to the longer name).
    fn intern(&mut self, pid: u32, name: &str, path: &str, source: &'static str) -> u32 {
        let full = if path.is_empty() { name.to_string() } else { path.rsplit('/').next().unwrap_or(name).to_string() };
        if let Some(ids) = self.procs_by_pid.get(&pid) {
            for &i in ids {
                let p = &mut self.processes[i as usize];
                if p.name.starts_with(&full) || full.starts_with(&p.name) || (full.starts_with(name) && p.name.starts_with(name)) {
                    if full.len() > p.name.len() {
                        p.name = full.clone();
                    }
                    if p.path.is_empty() && !path.is_empty() {
                        p.path = path.to_string();
                        p.app = app_name(&p.name, path);
                    }
                    return i;
                }
            }
        }
        let i = self.processes.len() as u32;
        self.processes.push(ProcInfo { pid, name: full.clone(), path: path.to_string(), app: app_name(&full, path), source });
        self.procs_by_pid.entry(pid).or_default().push(i);
        i
    }

    /// Attributes a packet (and its conversation) to a local process.
    fn attribute(&mut self, row: &mut PacketRow, s: StreamRef) {
        let from_pktap = row.meta.pktap.as_ref().and_then(|p| match (p.epid, &p.ecomm) {
            (Some(e), Some(n)) => Some((e, n.clone())),
            _ => Some((p.pid?, p.comm.clone()?)),
        });
        if let Some((pid, name)) = from_pktap {
            let path = self.proc_table.procs.get(&pid).map(|d| d.path.clone()).unwrap_or_default();
            let idx = self.intern(pid, &name, &path, "PKTAP");
            row.meta.process = Some(idx);
            let c = self.streams.get_mut(s.kind, s.id);
            c.process.get_or_insert(idx);
            return;
        }
        let c = self.streams.get(s.kind, s.id);
        if let Some(p) = c.process {
            row.meta.process = Some(p);
            return;
        }
        if c.packets.len() != 1 {
            return; // Already queued when the conversation started.
        }
        let proto = if s.kind == StreamKind::Tcp { 6 } else { 17 };
        if let Some(d) = self.proc_table.lookup(proto, c.a, c.b).cloned() {
            let idx = self.intern(d.pid, &d.name, &d.path, "socket table");
            row.meta.process = Some(idx);
            self.streams.get_mut(s.kind, s.id).process = Some(idx);
        } else {
            self.unattributed.push((s.kind, s.id, 0));
        }
    }

    /// Merges a socket-table snapshot and attributes conversations that were waiting for it,
    /// including their earlier packets.
    pub fn apply_sockets(&mut self, snap: Snapshot) {
        self.proc_table.update(&snap);
        for p in &snap.procs {
            if self.procs_by_pid.contains_key(&p.pid) {
                self.intern(p.pid, &p.name, &p.path, "socket table");
            }
        }
        for (kind, id, tries) in std::mem::take(&mut self.unattributed) {
            let c = self.streams.get(kind, id);
            if c.process.is_some() {
                continue;
            }
            let proto = if kind == StreamKind::Tcp { 6 } else { 17 };
            let Some(d) = self.proc_table.lookup(proto, c.a, c.b).cloned() else {
                if tries < 50 {
                    self.unattributed.push((kind, id, tries + 1));
                }
                continue;
            };
            let idx = self.intern(d.pid, &d.name, &d.path, "socket table");
            let c = self.streams.get_mut(kind, id);
            c.process = Some(idx);
            for &pi in &c.packets {
                let m = &mut self.packets[pi].meta;
                if m.process.is_none() {
                    m.process = Some(idx);
                    self.changed.push(pi);
                }
            }
        }
    }

    fn run_tls(&mut self, id: usize) {
        let mut out = Vec::new();
        let c = &mut self.streams.tcp[id];
        let tls = c.tls.get_or_insert_with(Default::default);
        tls.update(
            [&c.dirs[0].data, &c.dirs[1].data],
            [&c.dirs[0].chunks, &c.dirs[1].chunks],
            &self.keylog,
            &mut out,
        );
        if c.host.is_none() {
            c.host = tls.sni.clone();
        }
        let client = tls.client_dir.unwrap_or(0);
        let is_h2 = tls.alpn.as_deref() == Some("h2") || tls.dirs[client].plain.starts_with(crate::h2::PREFACE);
        let new = if is_h2 {
            c.h2.get_or_insert_with(Default::default).update(
                [&tls.dirs[0].plain, &tls.dirs[1].plain],
                [&tls.dirs[0].plain_chunks, &tls.dirs[1].plain_chunks],
            )
        } else {
            Vec::new()
        };
        self.apply_decrypted(out);
        self.apply_http(StreamKind::Tcp, id, new);
    }

    fn apply_decrypted(&mut self, out: Vec<(usize, Decrypted)>) {
        let mut touched = Vec::new();
        for (pkt, dec) in out {
            self.decrypted.entry(pkt).or_default().push(dec);
            touched.push(pkt);
        }
        touched.dedup();
        self.changed.extend(&touched);
        for pkt in touched {
            let decs = &self.decrypted[&pkt];
            let row = &mut self.packets[pkt];
            // On HTTP/2 connections TLS records don't align with HTTP/2 frames, so records are not
            // parsed individually; the connection-level parser labels the packets that complete
            // frames (apply_http).
            let h2_conn = row.stream.is_some_and(|s| {
                let c = self.streams.get(s.kind, s.id);
                c.h2.is_some() || c.tls.as_ref().is_some_and(|t| t.alpn.as_deref() == Some("h2"))
            });
            row.meta.protos |= proto::DECRYPTED;
            let mut infos = Vec::new();
            let mut experts = Vec::new();
            for dec in decs {
                if dec.content_type == 23 && !dec.data.is_empty() && h2_conn {
                    row.meta.protos |= proto::HTTP2;
                    infos.push(format!("HTTP/2 data ({} bytes)", dec.data.len()));
                } else if dec.content_type == 23 && !dec.data.is_empty() {
                    let (_, info, bits) = dissect_plaintext(&dec.data);
                    row.meta.protos |= bits;
                    if bits & proto::HTTP != 0 {
                        row.protocol = "HTTP".into();
                        if let Some((_, h)) = http_tree(&dec.data, 0, dec.data.len()) {
                            row.meta.http_host = h.host.or(row.meta.http_host.take());
                            row.meta.http_method = h.method;
                            row.meta.http_uri = h.uri;
                            row.meta.http_status = h.status;
                            if let Some(s) = h.status {
                                http_expert(s, &mut experts);
                            }
                        }
                    } else if bits & proto::HTTP2 != 0 {
                        row.protocol = "HTTP2".into();
                    } else if row.protocol != "HTTP" && row.protocol != "HTTP2" {
                        row.protocol = "TLS".into();
                    }
                    infos.push(info);
                } else {
                    infos.push(dec.note.clone());
                }
            }
            infos.dedup();
            row.info = infos.join(" | ");
            for (s, cat, msg) in experts {
                row.severity = row.severity.max(Some(s));
                self.experts.push(Expert { packet: pkt, severity: s, category: cat, message: msg });
            }
        }
    }

    /// Re-attempts decryption of every TLS session (after loading or updating a key log).
    pub fn redecrypt(&mut self) {
        let ids: Vec<usize> = (0..self.streams.tcp.len()).filter(|&i| self.streams.tcp[i].tls.is_some()).collect();
        for id in ids {
            if let Some(t) = self.streams.tcp[id].tls.as_mut() {
                t.reset_if_failed();
            }
            self.run_tls(id);
        }
        let quic: Vec<usize> = (0..self.streams.udp.len()).filter(|&i| self.streams.udp[i].quic.as_ref().is_some_and(|q| q.has_pending())).collect();
        for id in quic {
            let mut out = Vec::new();
            self.streams.udp[id].quic.as_mut().unwrap().retry(&self.keylog, &mut out);
            self.apply_quic(id, out);
        }
    }

    pub fn set_keylog(&mut self, k: KeyLog) {
        self.keylog = k;
        self.redecrypt();
    }

    pub fn tls_summary(&self) -> (usize, usize, usize) {
        let mut sessions = 0;
        let mut decrypted = 0;
        let mut missing = 0;
        let statuses = self.streams.tcp.iter().filter_map(|c| c.tls.as_ref().map(|t| &t.status));
        let quic = self.streams.udp.iter().filter_map(|c| c.quic.as_ref().filter(|q| q.client_random.is_some()).map(|q| &q.status));
        for st in statuses.chain(quic) {
            {
                sessions += 1;
                match st {
                    crate::tls::TlsStatus::Decrypting => decrypted += 1,
                    crate::tls::TlsStatus::WaitingForKeys => missing += 1,
                    _ => {}
                }
            }
        }
        (sessions, decrypted, missing)
    }

    pub fn protocol_hierarchy(&self) -> Vec<(&'static str, &'static str, u64, u64)> {
        let mut counts = vec![(0u64, 0u64); proto::TABLE.len()];
        for p in &self.packets {
            for (i, (_, bit, _)) in proto::TABLE.iter().enumerate() {
                if p.meta.protos & bit != 0 {
                    counts[i].0 += 1;
                    counts[i].1 += p.frame.orig_len as u64;
                }
            }
        }
        proto::TABLE
            .iter()
            .zip(counts)
            .filter(|(_, c)| c.0 > 0)
            .map(|((k, _, n), c)| (*k, *n, c.0, c.1))
            .collect()
    }

    /// Per-application traffic summary. Conversations without a process are grouped under an
    /// empty app name.
    pub fn apps(&self) -> Vec<AppStat> {
        let mut map: HashMap<String, (AppStat, HashMap<String, u64>)> = HashMap::new();
        for c in self.streams.tcp.iter().chain(self.streams.udp.iter()) {
            let p = c.process.map(|i| &self.processes[i as usize]);
            let app = p.map(|p| p.app.clone()).unwrap_or_default();
            let (st, hosts) = map.entry(app.clone()).or_insert_with(|| (AppStat { app, ..Default::default() }, HashMap::new()));
            if let Some(p) = p
                && !st.procs.iter().any(|(pid, n)| *pid == p.pid && *n == p.name)
            {
                st.procs.push((p.pid, p.name.clone()));
            }
            // The initiator is local unless the responder's address is one of ours.
            let local_is_b = self.proc_table.is_local(c.b.0) && !self.proc_table.is_local(c.a.0);
            let (sent, recv) = if local_is_b { (c.bytes[1], c.bytes[0]) } else { (c.bytes[0], c.bytes[1]) };
            st.conns += 1;
            st.packets += c.packets.len() as u64;
            st.sent += sent;
            st.received += recv;
            let remote = if local_is_b { c.a.0 } else { c.b.0 };
            let host = c.host.clone().unwrap_or_else(|| remote.to_string());
            *hosts.entry(host).or_default() += sent + recv;
        }
        let mut v: Vec<AppStat> = map
            .into_values()
            .map(|(mut st, hosts)| {
                st.hosts = hosts.into_iter().collect();
                st.hosts.sort_by_key(|h| std::cmp::Reverse(h.1));
                st.procs.sort();
                st
            })
            .collect();
        v.sort_by(|a, b| (a.app.is_empty(), b.sent + b.received).cmp(&(b.app.is_empty(), a.sent + a.received)));
        v
    }

    pub fn endpoints(&self) -> Vec<Endpoint> {
        let mut map: HashMap<IpAddr, Endpoint> = HashMap::new();
        for p in &self.packets {
            let len = p.frame.orig_len as u64;
            if let Some(s) = p.meta.src_ip {
                let e = map.entry(s).or_default();
                e.addr = Some(s);
                e.tx_pkts += 1;
                e.tx_bytes += len;
            }
            if let Some(d) = p.meta.dst_ip {
                let e = map.entry(d).or_default();
                e.addr = Some(d);
                e.rx_pkts += 1;
                e.rx_bytes += len;
            }
        }
        let mut v: Vec<Endpoint> = map.into_values().collect();
        v.sort_by_key(|e| std::cmp::Reverse(e.tx_bytes + e.rx_bytes));
        v
    }
}

fn http_expert(s: u16, experts: &mut Vec<(Severity, &'static str, String)>) {
    if s >= 500 {
        experts.push((Severity::Error, "HTTP", format!("HTTP server error {s}")));
    } else if s >= 400 {
        experts.push((Severity::Warn, "HTTP", format!("HTTP client error {s}")));
    }
}

fn udp_app(protos: u64) -> &'static str {
    for (bit, name) in [
        (proto::MDNS, "mDNS"),
        (proto::LLMNR, "LLMNR"),
        (proto::DNS, "DNS"),
        (proto::QUIC, "QUIC"),
        (proto::DHCP, "DHCP"),
        (proto::NTP, "NTP"),
        (proto::SSDP, "SSDP"),
        (proto::WIREGUARD, "WireGuard"),
    ] {
        if protos & bit != 0 {
            return name;
        }
    }
    "Data"
}
