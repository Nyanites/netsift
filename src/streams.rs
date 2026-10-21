//! Conversation tracking and TCP reassembly.

use crate::model::{tcpflag, StreamKind};
use crate::h2::H2Conn;
use crate::model::HttpMsg;
use crate::quic::QuicConn;
use crate::tls::TlsSession;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

/// Per-direction reassembled payload cap. Beyond this, data is counted but not kept.
const DIR_CAP: usize = 64 * 1024 * 1024;
const MAX_OOO: usize = 256;

#[derive(Default)]
pub struct DirBuf {
    isn: Option<u32>,
    /// Next expected relative sequence number.
    next_rel: u32,
    pub data: Vec<u8>,
    /// (offset into `data`, packet index) for each appended segment.
    pub chunks: Vec<(usize, usize)>,
    ooo: BTreeMap<u32, (Vec<u8>, usize)>,
    pub gaps: usize,
    pub capped: bool,
}

pub struct SegResult {
    pub rel_seq: u32,
    pub retransmission: bool,
    pub out_of_order: bool,
}

impl DirBuf {
    pub fn rel(&self, seq: u32) -> u32 {
        self.isn.map(|i| seq.wrapping_sub(i)).unwrap_or(0)
    }

    pub fn segment(&mut self, seq: u32, flags: u8, payload: &[u8], pkt: usize) -> SegResult {
        let syn = flags & tcpflag::SYN != 0;
        if self.isn.is_none() {
            self.isn = Some(if syn { seq } else { seq.wrapping_sub(1) });
        }
        let isn = self.isn.unwrap();
        let rel_seq = seq.wrapping_sub(isn);
        let mut r = SegResult { rel_seq, retransmission: false, out_of_order: false };
        if payload.is_empty() {
            if syn && seq != isn {
                // SYN with a new ISN on a reused port: treat as a restart.
                self.isn = Some(seq);
                r.rel_seq = 0;
            }
            return r;
        }
        let rel = seq.wrapping_sub(isn.wrapping_add(1));
        let diff = rel.wrapping_sub(self.next_rel) as i32;
        if diff == 0 {
            self.append(payload, pkt);
            self.drain();
        } else if diff < 0 {
            let end = rel.wrapping_add(payload.len() as u32);
            let over = end.wrapping_sub(self.next_rel) as i32;
            if over > 0 {
                let skip = payload.len() - over as usize;
                self.append(&payload[skip..], pkt);
                self.drain();
            } else {
                r.retransmission = true;
            }
        } else {
            r.out_of_order = true;
            if let std::collections::btree_map::Entry::Vacant(e) = self.ooo.entry(rel) {
                e.insert((payload.to_vec(), pkt));
            } else {
                r.retransmission = true;
            }
            if self.ooo.len() > MAX_OOO {
                // Data was lost in the capture; skip the hole.
                let first = *self.ooo.keys().next().unwrap();
                self.next_rel = first;
                self.gaps += 1;
                self.drain();
            }
        }
        r
    }

    fn append(&mut self, p: &[u8], pkt: usize) {
        if self.data.len() + p.len() <= DIR_CAP {
            self.chunks.push((self.data.len(), pkt));
            self.data.extend_from_slice(p);
        } else {
            self.capped = true;
        }
        self.next_rel = self.next_rel.wrapping_add(p.len() as u32);
    }

    fn drain(&mut self) {
        while let Some((&k, _)) = self.ooo.iter().next() {
            let diff = k.wrapping_sub(self.next_rel) as i32;
            if diff > 0 {
                break;
            }
            let (p, pkt) = self.ooo.remove(&k).unwrap();
            let end = k.wrapping_add(p.len() as u32);
            let over = end.wrapping_sub(self.next_rel) as i32;
            if over > 0 {
                let skip = p.len() - over as usize;
                self.append(&p[skip..], pkt);
            }
        }
    }
}

pub struct Conversation {
    pub kind: StreamKind,
    pub id: usize,
    /// Initiator (first packet's source) and responder.
    pub a: (IpAddr, u16),
    pub b: (IpAddr, u16),
    pub packets: Vec<usize>,
    pub pkts: [u64; 2],
    pub bytes: [u64; 2],
    pub first_ts: f64,
    pub last_ts: f64,
    pub app: &'static str,
    pub dirs: [DirBuf; 2],
    pub tls: Option<TlsSession>,
    pub h2: Option<H2Conn>,
    pub quic: Option<QuicConn>,
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
    pub host: Option<String>,
    /// Local process (index into `Engine::processes`).
    pub process: Option<u32>,
}

impl Conversation {
    fn new(kind: StreamKind, id: usize, a: (IpAddr, u16), b: (IpAddr, u16), ts: f64) -> Self {
        Conversation {
            kind,
            id,
            a,
            b,
            packets: Vec::new(),
            pkts: [0; 2],
            bytes: [0; 2],
            first_ts: ts,
            last_ts: ts,
            app: "",
            dirs: Default::default(),
            tls: None,
            h2: None,
            quic: None,
            syn: false,
            fin: false,
            rst: false,
            host: None,
            process: None,
        }
    }

    /// Decoded HTTP/2 or HTTP/3 messages carried by this conversation.
    pub fn http_msgs(&self) -> &[HttpMsg] {
        if let Some(h) = &self.h2 {
            &h.msgs
        } else if let Some(q) = &self.quic {
            &q.h3.msgs
        } else {
            &[]
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes[0] + self.bytes[1]
    }

    pub fn label(&self) -> String {
        format!("{}:{} ⇄ {}:{}", fmt_ip(self.a.0), self.a.1, fmt_ip(self.b.0), self.b.1)
    }
}

pub fn fmt_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v) => format!("[{v}]"),
        IpAddr::V4(v) => v.to_string(),
    }
}

type Key = (IpAddr, u16, IpAddr, u16);

fn key(s: (IpAddr, u16), d: (IpAddr, u16)) -> Key {
    if s <= d { (s.0, s.1, d.0, d.1) } else { (d.0, d.1, s.0, s.1) }
}

#[derive(Default)]
pub struct StreamTable {
    pub tcp: Vec<Conversation>,
    pub udp: Vec<Conversation>,
    tcp_map: HashMap<Key, usize>,
    udp_map: HashMap<Key, usize>,
}

impl StreamTable {
    /// Finds or creates the conversation for a packet; returns (id, direction).
    pub fn lookup(&mut self, kind: StreamKind, s: (IpAddr, u16), d: (IpAddr, u16), ts: f64, new_syn: bool) -> (usize, usize) {
        let k = key(s, d);
        let (list, map) = match kind {
            StreamKind::Tcp => (&mut self.tcp, &mut self.tcp_map),
            StreamKind::Udp => (&mut self.udp, &mut self.udp_map),
        };
        let existing = map.get(&k).copied();
        let reuse = match existing {
            Some(i) => {
                let c = &list[i];
                // A fresh SYN after the old connection closed starts a new stream.
                !(new_syn && (c.fin || c.rst) && c.pkts[0] + c.pkts[1] > 1)
            }
            None => false,
        };
        let id = if reuse {
            existing.unwrap()
        } else {
            let id = list.len();
            list.push(Conversation::new(kind, id, s, d, ts));
            map.insert(k, id);
            id
        };
        let c = &list[id];
        let dir = if c.a == s { 0 } else { 1 };
        (id, dir)
    }

    pub fn get_mut(&mut self, kind: StreamKind, id: usize) -> &mut Conversation {
        match kind {
            StreamKind::Tcp => &mut self.tcp[id],
            StreamKind::Udp => &mut self.udp[id],
        }
    }

    pub fn get(&self, kind: StreamKind, id: usize) -> &Conversation {
        match kind {
            StreamKind::Tcp => &self.tcp[id],
            StreamKind::Udp => &self.udp[id],
        }
    }
}
