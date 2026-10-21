//! Protocol dissectors. Each layer adds a node to the details tree, records filterable facts in
//! [`Meta`], and sets the protocol/info columns. Layers return `None` when the packet is truncated.

use crate::model::{proto, tcpflag, Field, Frame, Meta, TcpInfo};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct Dissection {
    pub tree: Vec<Field>,
    pub meta: Meta,
    pub protocol: String,
    pub src: String,
    pub dst: String,
    pub info: String,
}

// ---------------------------------------------------------------------------------------------
// Byte helpers

pub fn be16(d: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*d.get(i)?, *d.get(i + 1)?]))
}

pub fn be24(d: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes([0, *d.get(i)?, *d.get(i + 1)?, *d.get(i + 2)?]))
}

pub fn be32(d: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes(d.get(i..i + 4)?.try_into().ok()?))
}

fn ip4(d: &[u8], i: usize) -> Option<Ipv4Addr> {
    let b: [u8; 4] = d.get(i..i + 4)?.try_into().ok()?;
    Some(Ipv4Addr::from(b))
}

fn ip6(d: &[u8], i: usize) -> Option<Ipv6Addr> {
    let b: [u8; 16] = d.get(i..i + 16)?.try_into().ok()?;
    Some(Ipv6Addr::from(b))
}

pub fn mac(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":")
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Printable preview of a byte string, replacing control bytes with '.'.
pub fn printable(b: &[u8], max: usize) -> String {
    let mut s: String = b
        .iter()
        .take(max)
        .map(|&c| if (0x20..0x7f).contains(&c) { c as char } else { '.' })
        .collect();
    if b.len() > max {
        s.push('…');
    }
    s
}

pub fn fmt_abs_time(ts: f64) -> String {
    let secs = ts.floor() as i64;
    let micros = ((ts - secs as f64) * 1e6).round() as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    // Civil-from-days (Howard Hinnant).
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{micros:06} UTC",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

/// Parses the per-packet metadata string Apple's libpcap produces in extended-header mode, e.g.
/// "proc curl:1234, svc BE, re, out".
pub fn apple_metadata(comment: &str) -> (crate::model::Pktap, Field) {
    let mut m = crate::model::Pktap::default();
    let mut f = Field::text(format!("Apple packet metadata: {comment}"));
    for item in comment.split(", ") {
        let label = match item {
            "in" => {
                m.dir = Some(true);
                "Direction: inbound".to_string()
            }
            "out" => {
                m.dir = Some(false);
                "Direction: outbound".to_string()
            }
            "re" => "Retransmitted by the sender's stack".to_string(),
            "wk" => "Packet woke the system".to_string(),
            _ => match item.split_once(' ') {
                Some(("proc", v)) => {
                    if let Some((name, pid)) = v.rsplit_once(':') {
                        m.comm = Some(name.to_string());
                        m.pid = pid.parse().ok();
                    }
                    format!("Process: {v}")
                }
                Some(("svc", v)) => format!("Service class: {v}"),
                _ => item.to_string(),
            },
        };
        let mut leaf = Field::text(label);
        if let (Some(pid), true) = (m.pid, item.starts_with("proc ")) {
            leaf = leaf.filter(format!("pid == {pid}"));
        }
        f.push(leaf);
    }
    (m, f)
}

fn svc_name(svc: u32) -> &'static str {
    match svc {
        0 => "BE (best effort)",
        100 => "BK_SYS (background system)",
        200 => "BK (background)",
        300 => "RD (responsive data)",
        400 => "OAM (operations)",
        500 => "AV (multimedia streaming)",
        600 => "RV (responsive multimedia)",
        700 => "VI (interactive video)",
        800 => "VO (voice)",
        900 => "CTL (network control)",
        _ => "other",
    }
}

pub fn linktype_name(lt: i32) -> &'static str {
    match lt {
        149 | 258 => "Apple PKTAP",
        0 => "BSD loopback",
        1 => "Ethernet",
        12 | 14 | 101 => "Raw IP",
        105 => "IEEE 802.11",
        108 => "OpenBSD loopback",
        113 => "Linux cooked (SLL)",
        127 => "802.11 + radiotap",
        228 => "Raw IPv4",
        229 => "Raw IPv6",
        276 => "Linux cooked v2 (SLL2)",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------------------------
// Entry point

pub fn dissect(frame: &Frame, number: usize) -> Dissection {
    let mut c = Ctx {
        d: &frame.data,
        tree: Vec::new(),
        meta: Meta::default(),
        protocol: "Frame".into(),
        src: String::new(),
        dst: String::new(),
        info: String::new(),
    };
    let mut f = Field::new(
        format!(
            "Frame {number}: {} bytes on wire, {} bytes captured",
            frame.orig_len,
            frame.data.len()
        ),
        0,
        frame.data.len(),
    );
    f.push(Field::text(format!("Arrival time: {}", fmt_abs_time(frame.ts))));
    f.push(Field::text(format!("Epoch time: {:.6}", frame.ts)));
    f.push(Field::new(format!("Frame length: {} bytes", frame.orig_len), 0, frame.data.len()).filter(format!("frame.len == {}", frame.orig_len)));
    f.push(Field::text(format!(
        "Link type: {} ({})",
        linktype_name(frame.linktype),
        frame.linktype
    )));
    c.tree.push(f);

    let ok = c.link(frame.linktype, 0);
    if let Some(comment) = &frame.comment {
        let (meta, field) = apple_metadata(comment);
        c.tree.insert(1, field);
        if c.meta.pktap.is_none() {
            c.meta.pktap = Some(meta);
        }
    }
    if ok.is_none() {
        c.meta.malformed = true;
        c.tree.push(Field::text("[Malformed or truncated packet]"));
        if c.info.is_empty() {
            c.info = "[Malformed packet]".into();
        }
    }
    Dissection { tree: c.tree, meta: c.meta, protocol: c.protocol, src: c.src, dst: c.dst, info: c.info }
}

struct Ctx<'a> {
    d: &'a [u8],
    tree: Vec<Field>,
    meta: Meta,
    protocol: String,
    src: String,
    dst: String,
    info: String,
}

impl<'a> Ctx<'a> {
    fn link(&mut self, lt: i32, o: usize) -> Option<()> {
        match lt {
            1 => self.ethernet(o),
            0 => self.null(o, false),
            108 => self.null(o, true),
            12 | 14 | 101 => self.raw_ip(o),
            228 => self.ipv4(o),
            229 => self.ipv6(o),
            113 => self.sll(o),
            276 => self.sll2(o),
            // Apple PKTAP: 258 in files, DLT_USER2 (149) from live macOS captures.
            149 | 258 if o == 0 => self.pktap(o),
            105 | 127 | 163 | 192 => {
                self.meta.protos |= proto::WLAN;
                self.protocol = "802.11".into();
                self.info = "802.11 frame (radio layer not dissected)".into();
                Some(())
            }
            lt => {
                self.info = format!("Unsupported link type {lt}");
                Some(())
            }
        }
    }

    /// Apple PKTAP header (xnu bsd/net/pktap.h, v1): per-packet interface, direction and the
    /// owning process. Fields are in the capturing host's byte order (little-endian on Macs).
    fn pktap(&mut self, o: usize) -> Option<()> {
        let d = self.d;
        let le32 = |i: usize| -> Option<u32> { Some(u32::from_le_bytes(d.get(o + i..o + i + 4)?.try_into().ok()?)) };
        let cstr = |a: usize, b: usize| -> String {
            let s = d.get(o + a..o + b).unwrap_or(&[]);
            let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
            String::from_utf8_lossy(&s[..end]).into_owned()
        };
        let len = le32(0)? as usize;
        let type_next = le32(4)?;
        let dlt = le32(8)?;
        let flags = le32(36)?;
        if len < 108 || o + len > d.len() || flags & 0x0008_0000 != 0 {
            // Too short, or a v2 header (only used inside the kernel and pcapng conversion).
            return None;
        }
        let ifname = cstr(12, 36);
        let pid = le32(52)? as i32;
        let comm = cstr(56, 73);
        let svc = le32(76)?;
        let epid = le32(84)? as i32;
        let ecomm = cstr(88, 105);
        let dir = if flags & 0x1 != 0 {
            Some(true)
        } else if flags & 0x2 != 0 {
            Some(false)
        } else {
            None
        };
        let dir_name = match dir {
            Some(true) => "in",
            Some(false) => "out",
            None => "?",
        };
        let proc_label = if pid > 0 && !comm.is_empty() { format!("{comm} ({pid})") } else { "unknown (needs root)".into() };
        let mut f = Field::new(format!("Apple PKTAP, Interface: {ifname}, Direction: {dir_name}, Process: {proc_label}"), o, len);
        f.leaf(format!("Header length: {len}"), o, 4);
        f.leaf(format!("Inner link type: {} ({dlt})", linktype_name(dlt as i32)), o + 8, 4);
        f.leaf(format!("Interface: {ifname}"), o + 12, 24);
        let mut fl = Field::new(format!("Flags: 0x{flags:08x}"), o + 36, 4);
        for (bit, name) in [
            (0x1, "Inbound"),
            (0x2, "Outbound"),
            (0x4, "Process delegated"),
            (0x8, "Interface delegated"),
            (0x4000, "New flow"),
            (0x8000, "Retransmission"),
            (0x10000, "Keep-alive"),
            (0x20000, "Socket"),
            (0x100000, "Woke the system"),
        ] {
            if flags & bit != 0 {
                fl.leaf(name, o + 36, 4);
            }
        }
        f.push(fl);
        if pid > 0 {
            f.push(Field::new(format!("Process ID: {pid}"), o + 52, 4).filter(format!("pid == {pid}")));
            f.push(Field::new(format!("Process name: {comm}"), o + 56, 17).filter(format!("process == \"{comm}\"")));
        }
        if epid > 0 && epid != pid {
            f.push(Field::new(format!("Effective process: {ecomm} ({epid})"), o + 84, 21).filter(format!("pid == {epid}")));
        }
        f.leaf(format!("Service class: {}", svc_name(svc)), o + 76, 4);
        self.tree.push(f);
        self.meta.pktap = Some(crate::model::Pktap {
            dir,
            pid: (pid > 0).then_some(pid as u32),
            comm: (!comm.is_empty()).then_some(comm),
            epid: (epid > 0 && epid != pid).then_some(epid as u32),
            ecomm: (!ecomm.is_empty() && epid != pid).then_some(ecomm),
        });
        if type_next != 1 {
            self.info = "PKTAP record without packet data".into();
            return Some(());
        }
        self.link(dlt as i32, o + len)
    }

    fn set(&mut self, bit: u64, name: &str) {
        self.meta.protos |= bit;
        self.protocol = name.into();
    }

    // ---- Link layers --------------------------------------------------------------------

    fn ethernet(&mut self, o: usize) -> Option<()> {
        let d = self.d;
        let dst = d.get(o..o + 6)?;
        let src = d.get(o + 6..o + 12)?;
        let mut et = be16(d, o + 12)?;
        let mut f = Field::new(
            format!("Ethernet II, Src: {}, Dst: {}", mac(src), mac(dst)),
            o,
            14,
        );
        f.leaf(format!("Destination: {}", mac(dst)), o, 6);
        f.leaf(format!("Source: {}", mac(src)), o + 6, 6);
        f.leaf(format!("Type: {} (0x{et:04x})", ethertype_name(et)), o + 12, 2);
        self.tree.push(f);
        self.set(proto::ETH, "Ethernet");
        self.src = mac(src);
        self.dst = mac(dst);
        let mut p = o + 14;
        while et == 0x8100 || et == 0x88a8 {
            let tci = be16(d, p)?;
            let inner = be16(d, p + 2)?;
            let mut v = Field::new(
                format!("802.1Q Virtual LAN, PRI: {}, ID: {}", tci >> 13, tci & 0x0fff),
                p,
                4,
            );
            v.leaf(format!("Priority: {}", tci >> 13), p, 2);
            v.leaf(format!("ID: {}", tci & 0x0fff), p, 2);
            v.leaf(format!("Type: {} (0x{inner:04x})", ethertype_name(inner)), p + 2, 2);
            self.tree.push(v);
            self.meta.protos |= proto::VLAN;
            et = inner;
            p += 4;
        }
        self.ethertype(et, p)
    }

    fn ethertype(&mut self, et: u16, p: usize) -> Option<()> {
        match et {
            0x0800 => self.ipv4(p),
            0x86dd => self.ipv6(p),
            0x0806 => self.arp(p),
            _ => {
                self.protocol = ethertype_name(et).into();
                self.info = format!("Ethertype 0x{et:04x} ({} bytes)", self.d.len().saturating_sub(p));
                Some(())
            }
        }
    }

    fn null(&mut self, o: usize, network_order: bool) -> Option<()> {
        let b: [u8; 4] = self.d.get(o..o + 4)?.try_into().ok()?;
        let le = u32::from_le_bytes(b);
        let be = u32::from_be_bytes(b);
        let fam = if network_order { be } else if le < 256 { le } else { be };
        let mut f = Field::new("Null/Loopback", o, 4);
        f.leaf(format!("Family: {fam}"), o, 4);
        self.tree.push(f);
        self.set(proto::LOOPBACK, "Loopback");
        match fam {
            2 => self.ipv4(o + 4),
            24 | 28 | 30 => self.ipv6(o + 4),
            _ => self.raw_ip(o + 4),
        }
    }

    fn raw_ip(&mut self, o: usize) -> Option<()> {
        match self.d.get(o)? >> 4 {
            4 => self.ipv4(o),
            6 => self.ipv6(o),
            _ => None,
        }
    }

    fn sll(&mut self, o: usize) -> Option<()> {
        let pt = be16(self.d, o)?;
        let et = be16(self.d, o + 14)?;
        let mut f = Field::new("Linux cooked capture v1", o, 16);
        f.leaf(format!("Packet type: {}", sll_pkttype(pt as u8)), o, 2);
        f.leaf(format!("Protocol: 0x{et:04x}"), o + 14, 2);
        self.tree.push(f);
        self.set(proto::SLL, "SLL");
        self.ethertype(et, o + 16)
    }

    fn sll2(&mut self, o: usize) -> Option<()> {
        let et = be16(self.d, o)?;
        let ifindex = be32(self.d, o + 4)?;
        let pt = *self.d.get(o + 10)?;
        let mut f = Field::new("Linux cooked capture v2", o, 20);
        f.leaf(format!("Protocol: 0x{et:04x}"), o, 2);
        f.leaf(format!("Interface index: {ifindex}"), o + 4, 4);
        f.leaf(format!("Packet type: {}", sll_pkttype(pt)), o + 10, 1);
        self.tree.push(f);
        self.set(proto::SLL, "SLL");
        self.ethertype(et, o + 20)
    }

    fn arp(&mut self, o: usize) -> Option<()> {
        let d = self.d;
        let op = be16(d, o + 6)?;
        let sha = d.get(o + 8..o + 14)?;
        let spa = ip4(d, o + 14)?;
        let tha = d.get(o + 18..o + 24)?;
        let tpa = ip4(d, o + 24)?;
        let mut f = Field::new(
            format!("Address Resolution Protocol ({})", if op == 1 { "request" } else { "reply" }),
            o,
            28,
        );
        f.leaf(format!("Hardware type: {}", be16(d, o)?), o, 2);
        f.leaf(format!("Protocol type: 0x{:04x}", be16(d, o + 2)?), o + 2, 2);
        f.leaf(format!("Opcode: {} ({op})", if op == 1 { "request" } else { "reply" }), o + 6, 2);
        f.leaf(format!("Sender MAC address: {}", mac(sha)), o + 8, 6);
        f.push(Field::new(format!("Sender IP address: {spa}"), o + 14, 4).filter(format!("ip.addr == {spa}")));
        f.leaf(format!("Target MAC address: {}", mac(tha)), o + 18, 6);
        f.push(Field::new(format!("Target IP address: {tpa}"), o + 24, 4).filter(format!("ip.addr == {tpa}")));
        self.tree.push(f);
        self.set(proto::ARP, "ARP");
        self.info = if op == 1 {
            format!("Who has {tpa}? Tell {spa}")
        } else {
            format!("{spa} is at {}", mac(sha))
        };
        Some(())
    }

    // ---- Network layer ------------------------------------------------------------------

    fn ipv4(&mut self, o: usize) -> Option<()> {
        let d = self.d;
        let vihl = *d.get(o)?;
        let ihl = ((vihl & 0x0f) as usize) * 4;
        if vihl >> 4 != 4 || ihl < 20 {
            return None;
        }
        let tos = *d.get(o + 1)?;
        let total = be16(d, o + 2)? as usize;
        let id = be16(d, o + 4)?;
        let ff = be16(d, o + 6)?;
        let ttl = *d.get(o + 8)?;
        let p = *d.get(o + 9)?;
        let csum = be16(d, o + 10)?;
        let src = ip4(d, o + 12)?;
        let dst = ip4(d, o + 16)?;
        let end = if total >= ihl { (o + total).min(d.len()) } else { d.len() };

        let mut f = Field::new(format!("Internet Protocol Version 4, Src: {src}, Dst: {dst}"), o, ihl);
        f.leaf(format!("Version: 4, Header length: {ihl} bytes"), o, 1);
        f.leaf(format!("DSCP: {}, ECN: {}", tos >> 2, tos & 3), o + 1, 1);
        f.leaf(format!("Total length: {total}"), o + 2, 2);
        f.leaf(format!("Identification: 0x{id:04x} ({id})"), o + 4, 2);
        let mut fl = Field::new(format!("Flags: 0x{:x}", ff >> 13), o + 6, 2);
        fl.leaf(format!("Don't fragment: {}", ff & 0x4000 != 0), o + 6, 1);
        fl.leaf(format!("More fragments: {}", ff & 0x2000 != 0), o + 6, 1);
        f.push(fl);
        f.leaf(format!("Fragment offset: {}", (ff & 0x1fff) * 8), o + 6, 2);
        f.leaf(format!("Time to live: {ttl}"), o + 8, 1);
        f.leaf(format!("Protocol: {} ({p})", ip_proto_name(p)), o + 9, 1);
        f.leaf(format!("Header checksum: 0x{csum:04x}"), o + 10, 2);
        f.push(Field::new(format!("Source address: {src}"), o + 12, 4).filter(format!("ip.src == {src}")));
        f.push(Field::new(format!("Destination address: {dst}"), o + 16, 4).filter(format!("ip.dst == {dst}")));
        self.tree.push(f);

        self.set(proto::IPV4, "IPv4");
        self.meta.src_ip = Some(IpAddr::V4(src));
        self.meta.dst_ip = Some(IpAddr::V4(dst));
        self.src = src.to_string();
        self.dst = dst.to_string();
        self.info = format!("{} ({} bytes)", ip_proto_name(p), end.saturating_sub(o + ihl));
        if ff & 0x1fff != 0 {
            self.info = format!(
                "Fragmented IP protocol (proto={}, off={}, ID={id:04x})",
                ip_proto_name(p),
                (ff & 0x1fff) * 8
            );
            return Some(());
        }
        self.ip_payload(p, o + ihl, end)
    }

    fn ipv6(&mut self, o: usize) -> Option<()> {
        let d = self.d;
        if d.get(o)? >> 4 != 6 {
            return None;
        }
        let vtf = be32(d, o)?;
        let plen = be16(d, o + 4)? as usize;
        let mut nh = *d.get(o + 6)?;
        let hop = *d.get(o + 7)?;
        let src = ip6(d, o + 8)?;
        let dst = ip6(d, o + 24)?;
        let end = (o + 40 + plen).min(d.len());
        let mut f = Field::new(format!("Internet Protocol Version 6, Src: {src}, Dst: {dst}"), o, 40);
        f.leaf(format!("Traffic class: 0x{:02x}", (vtf >> 20) & 0xff), o, 2);
        f.leaf(format!("Flow label: 0x{:05x}", vtf & 0xfffff), o + 1, 3);
        f.leaf(format!("Payload length: {plen}"), o + 4, 2);
        f.leaf(format!("Next header: {} ({nh})", ip_proto_name(nh)), o + 6, 1);
        f.leaf(format!("Hop limit: {hop}"), o + 7, 1);
        f.push(Field::new(format!("Source address: {src}"), o + 8, 16).filter(format!("ip.src == {src}")));
        f.push(Field::new(format!("Destination address: {dst}"), o + 24, 16).filter(format!("ip.dst == {dst}")));

        let mut p = o + 40;
        let mut fragmented = false;
        while matches!(nh, 0 | 43 | 60 | 44) {
            let next = *d.get(p)?;
            let len = if nh == 44 { 8 } else { (*d.get(p + 1)? as usize + 1) * 8 };
            if nh == 44 {
                let off = be16(d, p + 2)? >> 3;
                fragmented = off != 0;
            }
            f.leaf(format!("Extension header: {} ({len} bytes)", ip_proto_name(nh)), p, len);
            nh = next;
            p += len;
        }
        self.tree.push(f);
        self.set(proto::IPV6, "IPv6");
        self.meta.src_ip = Some(IpAddr::V6(src));
        self.meta.dst_ip = Some(IpAddr::V6(dst));
        self.src = src.to_string();
        self.dst = dst.to_string();
        self.info = format!("{} ({} bytes)", ip_proto_name(nh), end.saturating_sub(p));
        if fragmented {
            self.info = format!("IPv6 fragment ({})", ip_proto_name(nh));
            return Some(());
        }
        self.ip_payload(nh, p, end)
    }

    fn ip_payload(&mut self, p: u8, o: usize, end: usize) -> Option<()> {
        match p {
            1 => self.icmp(o, end),
            6 => self.tcp(o, end),
            17 => self.udp(o, end),
            58 => self.icmpv6(o, end),
            4 => self.ipv4(o),
            41 => self.ipv6(o),
            50 => {
                let spi = be32(self.d, o)?;
                let seq = be32(self.d, o + 4)?;
                let mut f = Field::new("Encapsulating Security Payload", o, end - o);
                f.leaf(format!("SPI: 0x{spi:08x}"), o, 4);
                f.leaf(format!("Sequence: {seq}"), o + 4, 4);
                f.leaf("Encrypted payload (IPsec keys required)", o + 8, end.saturating_sub(o + 8));
                self.tree.push(f);
                self.protocol = "ESP".into();
                self.info = format!("ESP (SPI=0x{spi:08x}) seq={seq} [encrypted]");
                Some(())
            }
            _ => Some(()),
        }
    }

    // ---- ICMP -----------------------------------------------------------------------------

    fn icmp(&mut self, o: usize, end: usize) -> Option<()> {
        let d = self.d;
        let t = *d.get(o)?;
        let code = *d.get(o + 1)?;
        let csum = be16(d, o + 2)?;
        let mut f = Field::new("Internet Control Message Protocol", o, end - o);
        f.leaf(format!("Type: {t} ({})", icmp_type_name(t)), o, 1);
        f.leaf(format!("Code: {code}"), o + 1, 1);
        f.leaf(format!("Checksum: 0x{csum:04x}"), o + 2, 2);
        self.set(proto::ICMP, "ICMP");
        self.meta.icmp = Some((t, code));
        self.info = icmp_type_name(t).to_string();
        if t == 0 || t == 8 {
            let id = be16(d, o + 4)?;
            let seq = be16(d, o + 6)?;
            f.leaf(format!("Identifier: 0x{id:04x}"), o + 4, 2);
            f.leaf(format!("Sequence: {seq}"), o + 6, 2);
            f.leaf(format!("Data ({} bytes)", end.saturating_sub(o + 8)), o + 8, end.saturating_sub(o + 8));
            self.info = format!("{} id=0x{id:04x}, seq={seq}", icmp_type_name(t));
        } else if t == 3 {
            self.info = format!("Destination unreachable ({})", icmp_unreach_name(code));
        }
        self.tree.push(f);
        Some(())
    }

    fn icmpv6(&mut self, o: usize, end: usize) -> Option<()> {
        let d = self.d;
        let t = *d.get(o)?;
        let code = *d.get(o + 1)?;
        let mut f = Field::new("Internet Control Message Protocol v6", o, end - o);
        f.leaf(format!("Type: {t} ({})", icmpv6_type_name(t)), o, 1);
        f.leaf(format!("Code: {code}"), o + 1, 1);
        f.leaf(format!("Checksum: 0x{:04x}", be16(d, o + 2)?), o + 2, 2);
        self.set(proto::ICMPV6, "ICMPv6");
        self.meta.icmp = Some((t, code));
        self.info = icmpv6_type_name(t).to_string();
        match t {
            128 | 129 => {
                let id = be16(d, o + 4)?;
                let seq = be16(d, o + 6)?;
                f.leaf(format!("Identifier: 0x{id:04x}"), o + 4, 2);
                f.leaf(format!("Sequence: {seq}"), o + 6, 2);
                self.info = format!("{} id=0x{id:04x}, seq={seq}", icmpv6_type_name(t));
            }
            135 | 136 => {
                let target = ip6(d, o + 8)?;
                f.leaf(format!("Target address: {target}"), o + 8, 16);
                self.info = format!("{} for {target}", icmpv6_type_name(t));
            }
            _ => {}
        }
        self.tree.push(f);
        Some(())
    }

    // ---- Transport ----------------------------------------------------------------------

    fn tcp(&mut self, o: usize, end: usize) -> Option<()> {
        let d = self.d;
        let sport = be16(d, o)?;
        let dport = be16(d, o + 2)?;
        let seq = be32(d, o + 4)?;
        let ack = be32(d, o + 8)?;
        let off_flags = be16(d, o + 12)?;
        let hl = ((off_flags >> 12) as usize) * 4;
        let flags = (off_flags & 0xff) as u8;
        let win = be16(d, o + 14)?;
        let csum = be16(d, o + 16)?;
        if hl < 20 {
            return None;
        }
        let po = (o + hl).min(end);
        let plen = end.saturating_sub(po);

        let mut f = Field::new(
            format!("Transmission Control Protocol, Src Port: {sport}, Dst Port: {dport}, Len: {plen}"),
            o,
            hl.min(end - o),
        );
        f.push(Field::new(format!("Source port: {sport}"), o, 2).filter(format!("tcp.srcport == {sport}")));
        f.push(Field::new(format!("Destination port: {dport}"), o + 2, 2).filter(format!("tcp.dstport == {dport}")));
        f.leaf(format!("Sequence number (raw): {seq}"), o + 4, 4);
        f.leaf(format!("Acknowledgment number (raw): {ack}"), o + 8, 4);
        f.leaf(format!("Header length: {hl} bytes"), o + 12, 1);
        let mut fl = Field::new(format!("Flags: 0x{flags:03x} ({})", tcp_flags_str(flags)), o + 12, 2);
        for (bit, name, key) in [
            (tcpflag::URG, "Urgent", "urg"),
            (tcpflag::ACK, "Acknowledgment", "ack"),
            (tcpflag::PSH, "Push", "push"),
            (tcpflag::RST, "Reset", "reset"),
            (tcpflag::SYN, "Syn", "syn"),
            (tcpflag::FIN, "Fin", "fin"),
        ] {
            let set = flags & bit != 0;
            fl.push(Field::new(format!("{name}: {}", if set { "Set" } else { "Not set" }), o + 13, 1).filter(format!("tcp.flags.{key} == {}", set as u8)));
        }
        f.push(fl);
        f.leaf(format!("Window: {win}"), o + 14, 2);
        f.leaf(format!("Checksum: 0x{csum:04x}"), o + 16, 2);
        if hl > 20 {
            let mut opts = Field::new(format!("Options ({} bytes)", hl - 20), o + 20, hl - 20);
            let mut p = o + 20;
            let oend = (o + hl).min(end);
            while p < oend {
                let kind = d[p];
                if kind == 0 {
                    opts.leaf("End of option list", p, 1);
                    break;
                }
                if kind == 1 {
                    opts.leaf("No-Operation (NOP)", p, 1);
                    p += 1;
                    continue;
                }
                let Some(&len) = d.get(p + 1) else { break };
                let len = len as usize;
                if len < 2 || p + len > oend {
                    break;
                }
                let label = match kind {
                    2 => format!("Maximum segment size: {}", be16(d, p + 2).unwrap_or(0)),
                    3 => format!("Window scale: {}", d.get(p + 2).copied().unwrap_or(0)),
                    4 => "SACK permitted".into(),
                    5 => format!("SACK ({} blocks)", (len - 2) / 8),
                    8 => format!(
                        "Timestamps: TSval {}, TSecr {}",
                        be32(d, p + 2).unwrap_or(0),
                        be32(d, p + 6).unwrap_or(0)
                    ),
                    30 => "Multipath TCP".into(),
                    34 => "TCP Fast Open cookie".into(),
                    _ => format!("Option kind {kind} ({len} bytes)"),
                };
                opts.leaf(label, p, len);
                p += len;
            }
            f.push(opts);
        }
        if plen > 0 {
            f.leaf(format!("TCP payload ({plen} bytes)"), po, plen);
        }
        self.tree.push(f);
        self.set(proto::TCP, "TCP");
        self.meta.src_port = Some(sport);
        self.meta.dst_port = Some(dport);
        self.meta.tcp = Some(TcpInfo { seq, ack, flags, window: win, payload_off: po, payload_len: plen });
        self.info = format!("{sport} → {dport} [{}] Win={win} Len={plen}", tcp_flags_str(flags));
        if plen > 0 {
            self.tcp_app(sport, dport, po, end);
        }
        Some(())
    }

    fn tcp_app(&mut self, sport: u16, dport: u16, o: usize, end: usize) {
        let p = &self.d[o..end];
        let r = if is_tls_record_start(p) {
            self.tls(o, end)
        } else if is_http_start(p) {
            self.http(o, end)
        } else if p.starts_with(b"SSH-") || sport == 22 || dport == 22 {
            self.ssh(o, end)
        } else if sport == 53 || dport == 53 {
            self.dns(o + 2, end, proto::DNS, "DNS")
        } else {
            self.data(o, end);
            Some(())
        };
        if r.is_none() {
            self.meta.malformed = true;
        }
    }

    fn udp(&mut self, o: usize, end: usize) -> Option<()> {
        let d = self.d;
        let sport = be16(d, o)?;
        let dport = be16(d, o + 2)?;
        let len = be16(d, o + 4)? as usize;
        let csum = be16(d, o + 6)?;
        let pend = if len >= 8 { (o + len).min(end) } else { end };
        let po = o + 8;
        let mut f = Field::new(format!("User Datagram Protocol, Src Port: {sport}, Dst Port: {dport}"), o, 8);
        f.push(Field::new(format!("Source port: {sport}"), o, 2).filter(format!("udp.srcport == {sport}")));
        f.push(Field::new(format!("Destination port: {dport}"), o + 2, 2).filter(format!("udp.dstport == {dport}")));
        f.leaf(format!("Length: {len}"), o + 4, 2);
        f.leaf(format!("Checksum: 0x{csum:04x}"), o + 6, 2);
        self.tree.push(f);
        self.set(proto::UDP, "UDP");
        self.meta.src_port = Some(sport);
        self.meta.dst_port = Some(dport);
        let plen = pend.saturating_sub(po);
        self.meta.udp_payload = Some((po, plen));
        self.info = format!("{sport} → {dport} Len={plen}");
        if plen == 0 {
            return Some(());
        }
        let p = &d[po..pend];
        let has = |port: u16| sport == port || dport == port;
        let r = if has(53) {
            self.dns(po, pend, proto::DNS, "DNS")
        } else if has(5353) {
            self.dns(po, pend, proto::MDNS, "mDNS")
        } else if has(5355) {
            self.dns(po, pend, proto::LLMNR, "LLMNR")
        } else if has(67) || has(68) {
            self.dhcp(po, pend)
        } else if has(123) {
            self.ntp(po, pend)
        } else if has(1900) {
            self.ssdp(po, pend)
        } else if is_quic(p, sport, dport) {
            self.quic(po, pend)
        } else if is_wireguard(p) {
            self.wireguard(po, pend)
        } else {
            self.data(po, pend);
            Some(())
        };
        if r.is_none() {
            self.meta.malformed = true;
        }
        Some(())
    }

    fn data(&mut self, o: usize, end: usize) {
        if end > o {
            self.tree.push(Field::new(format!("Data ({} bytes)", end - o), o, end - o));
            self.meta.protos |= proto::DATA;
        }
    }

    // ---- Application ----------------------------------------------------------------------

    fn dns(&mut self, o: usize, end: usize, bit: u64, name: &str) -> Option<()> {
        let (f, info, qname, rcode, resp) = dns_tree(self.d, o, end, name)?;
        self.tree.push(f);
        self.set(bit, name);
        self.meta.protos |= proto::DNS;
        self.meta.dns_name = qname;
        self.meta.dns_rcode = Some(rcode);
        self.meta.dns_response = resp;
        self.info = info;
        Some(())
    }

    fn http(&mut self, o: usize, end: usize) -> Option<()> {
        let (f, h) = http_tree(self.d, o, end)?;
        self.tree.push(f);
        self.set(proto::HTTP, "HTTP");
        self.info = h.first_line.clone();
        self.meta.http_host = h.host;
        self.meta.http_method = h.method;
        self.meta.http_uri = h.uri;
        self.meta.http_status = h.status;
        Some(())
    }

    fn ssh(&mut self, o: usize, end: usize) -> Option<()> {
        let p = &self.d[o..end];
        let mut f = Field::new("SSH Protocol", o, end - o);
        if p.starts_with(b"SSH-") {
            let line = printable(p.split(|&c| c == b'\r' || c == b'\n').next().unwrap_or(p), 200);
            f.leaf(format!("Protocol: {line}"), o, end - o);
            self.info = format!("Server/Client protocol: {line}");
        } else {
            f.leaf(format!("Encrypted packet ({} bytes)", end - o), o, end - o);
            self.info = format!("Encrypted packet (len={})", end - o);
        }
        self.tree.push(f);
        self.set(proto::SSH, "SSH");
        Some(())
    }

    fn tls(&mut self, o: usize, end: usize) -> Option<()> {
        let d = self.d;
        let mut p = o;
        let mut infos: Vec<String> = Vec::new();
        let mut root = Field::new("Transport Layer Security", o, end - o);
        while p + 5 <= end {
            let ct = d[p];
            let ver = be16(d, p + 1)?;
            let len = be16(d, p + 3)? as usize;
            if !(20..=24).contains(&ct) || d[p + 1] != 3 {
                break;
            }
            let rec_end = p + 5 + len;
            let avail = rec_end.min(end);
            let mut rf = Field::new(
                format!("TLS Record: {} ({}), Length: {len}", tls_content_name(ct), tls_version_name(ver)),
                p,
                avail - p,
            );
            rf.leaf(format!("Content type: {} ({ct})", tls_content_name(ct)), p, 1);
            rf.leaf(format!("Version: {} (0x{ver:04x})", tls_version_name(ver)), p + 1, 2);
            rf.leaf(format!("Length: {len}"), p + 3, 2);
            let body = p + 5;
            match ct {
                22 => {
                    let mut q = body;
                    let mut any = false;
                    while q + 4 <= avail {
                        let mt = d[q];
                        let mlen = be24(d, q + 1)? as usize;
                        if tls_hs_name(mt).is_none() || q + 4 + mlen > rec_end {
                            break;
                        }
                        any = true;
                        let mend = (q + 4 + mlen).min(avail);
                        let mut hf = Field::new(
                            format!("Handshake: {} (len {mlen})", tls_hs_name(mt).unwrap()),
                            q,
                            mend - q,
                        );
                        let hs = tls_handshake_body(d, mt, q + 4, mend, &mut hf);
                        let mut label = tls_hs_name(mt).unwrap().to_string();
                        if let Some(sni) = &hs.sni {
                            label = format!("{label} (SNI={sni})");
                            self.meta.tls_sni = Some(sni.clone());
                        }
                        if hs.hrr {
                            label = "Hello Retry Request".into();
                        }
                        infos.push(label);
                        rf.push(hf);
                        q += 4 + mlen;
                    }
                    if !any {
                        rf.leaf("Encrypted Handshake Message", body, avail.saturating_sub(body));
                        infos.push("Encrypted Handshake Message".into());
                    }
                }
                23 => {
                    rf.leaf("Encrypted Application Data", body, avail.saturating_sub(body));
                    infos.push("Application Data".into());
                }
                21 => {
                    if len == 2 && avail >= body + 2 {
                        let lvl = d[body];
                        let desc = d[body + 1];
                        rf.leaf(format!("Alert level: {}", if lvl == 2 { "Fatal" } else { "Warning" }), body, 1);
                        rf.leaf(format!("Description: {} ({desc})", tls_alert_name(desc)), body + 1, 1);
                        infos.push(format!("Alert ({})", tls_alert_name(desc)));
                        self.meta.tls_alert = Some(desc);
                    } else {
                        rf.leaf("Encrypted Alert", body, avail.saturating_sub(body));
                        infos.push("Encrypted Alert".into());
                    }
                }
                20 => infos.push("Change Cipher Spec".into()),
                _ => infos.push("Heartbeat".into()),
            }
            if rec_end > end {
                rf.label.push_str(" [continues in next segment]");
            }
            root.push(rf);
            p = rec_end;
        }
        self.tree.push(root);
        self.set(proto::TLS, "TLS");
        dedup_consecutive(&mut infos);
        self.info = infos.join(", ");
        Some(())
    }

    fn dhcp(&mut self, o: usize, end: usize) -> Option<()> {
        let d = self.d;
        let op = *d.get(o)?;
        let xid = be32(d, o + 4)?;
        let yiaddr = ip4(d, o + 16)?;
        let chaddr = d.get(o + 28..o + 34)?;
        let mut f = Field::new("Dynamic Host Configuration Protocol", o, end - o);
        f.leaf(format!("Message type: Boot {}", if op == 1 { "Request" } else { "Reply" }), o, 1);
        f.leaf(format!("Transaction ID: 0x{xid:08x}"), o + 4, 4);
        f.leaf(format!("Your (client) IP address: {yiaddr}"), o + 16, 4);
        f.leaf(format!("Client MAC address: {}", mac(chaddr)), o + 28, 6);
        let mut msg = "DHCP".to_string();
        if be32(d, o + 236) == Some(0x63825363) {
            let mut p = o + 240;
            while p < end {
                let code = d[p];
                if code == 255 {
                    break;
                }
                if code == 0 {
                    p += 1;
                    continue;
                }
                let Some(&len) = d.get(p + 1) else { break };
                let len = len as usize;
                let v = d.get(p + 2..(p + 2 + len).min(end)).unwrap_or(&[]);
                let label = match code {
                    53 => {
                        let t = v.first().copied().unwrap_or(0);
                        msg = format!("DHCP {}", dhcp_msg_name(t));
                        format!("Option 53: DHCP Message Type ({})", dhcp_msg_name(t))
                    }
                    12 => format!("Option 12: Host name: {}", printable(v, 64)),
                    50 if len == 4 => format!("Option 50: Requested IP: {}", Ipv4Addr::new(v[0], v[1], v[2], v[3])),
                    54 if len == 4 => format!("Option 54: Server identifier: {}", Ipv4Addr::new(v[0], v[1], v[2], v[3])),
                    1 if len == 4 => format!("Option 1: Subnet mask: {}", Ipv4Addr::new(v[0], v[1], v[2], v[3])),
                    3 if len >= 4 => format!("Option 3: Router: {}", Ipv4Addr::new(v[0], v[1], v[2], v[3])),
                    6 => format!(
                        "Option 6: DNS servers: {}",
                        v.chunks(4).filter(|c| c.len() == 4).map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]).to_string()).collect::<Vec<_>>().join(", ")
                    ),
                    51 if len == 4 => format!("Option 51: Lease time: {}s", u32::from_be_bytes([v[0], v[1], v[2], v[3]])),
                    _ => format!("Option {code} ({len} bytes)"),
                };
                f.leaf(label, p, len + 2);
                p += 2 + len;
            }
        }
        self.tree.push(f);
        self.set(proto::DHCP, "DHCP");
        self.info = format!("{msg} - Transaction ID 0x{xid:08x}");
        Some(())
    }

    fn ntp(&mut self, o: usize, end: usize) -> Option<()> {
        let b = *self.d.get(o)?;
        let stratum = *self.d.get(o + 1)?;
        let mode = match b & 7 {
            1 => "symmetric active",
            2 => "symmetric passive",
            3 => "client",
            4 => "server",
            5 => "broadcast",
            _ => "other",
        };
        let mut f = Field::new("Network Time Protocol", o, end - o);
        f.leaf(format!("Version: {}", (b >> 3) & 7), o, 1);
        f.leaf(format!("Mode: {mode}"), o, 1);
        f.leaf(format!("Stratum: {stratum}"), o + 1, 1);
        self.tree.push(f);
        self.set(proto::NTP, "NTP");
        self.info = format!("NTP Version {}, {mode}", (b >> 3) & 7);
        Some(())
    }

    fn ssdp(&mut self, o: usize, end: usize) -> Option<()> {
        let p = &self.d[o..end];
        let first = p.split(|&c| c == b'\r').next().unwrap_or(p);
        let mut f = Field::new("Simple Service Discovery Protocol", o, end - o);
        let mut q = o;
        for line in p.split(|&c| c == b'\n') {
            let l = line.strip_suffix(b"\r").unwrap_or(line);
            if !l.is_empty() {
                f.leaf(printable(l, 200), q, l.len());
            }
            q += line.len() + 1;
        }
        self.tree.push(f);
        self.set(proto::SSDP, "SSDP");
        self.info = printable(first, 120);
        Some(())
    }

    fn quic(&mut self, o: usize, end: usize) -> Option<()> {
        let d = self.d;
        let b0 = *d.get(o)?;
        let mut f = Field::new("QUIC IETF", o, end - o);
        if b0 & 0x80 != 0 {
            let ver = be32(d, o + 1)?;
            let dlen = *d.get(o + 5)? as usize;
            let dcid = d.get(o + 6..o + 6 + dlen)?;
            let slen = *d.get(o + 6 + dlen)? as usize;
            let scid = d.get(o + 7 + dlen..o + 7 + dlen + slen)?;
            let kind = if ver == 0 {
                "Version Negotiation"
            } else {
                let t = (b0 >> 4) & 3;
                // QUIC v2 rotates the type codes.
                let t = if ver == 0x6b3343cf { (t + 3) % 4 } else { t };
                ["Initial", "0-RTT", "Handshake", "Retry"][t as usize]
            };
            f.leaf(format!("Header form: Long, packet type: {kind}"), o, 1);
            f.leaf(format!("Version: 0x{ver:08x}"), o + 1, 4);
            f.leaf(format!("Destination Connection ID: {}", hex(dcid)), o + 6, dlen);
            f.leaf(format!("Source Connection ID: {}", hex(scid)), o + 7 + dlen, slen);
            f.leaf("Protected payload", o + 7 + dlen + slen, end.saturating_sub(o + 7 + dlen + slen));
            self.info = format!("{kind}, DCID={}, SCID={}", hex(dcid), hex(scid));
        } else {
            f.leaf("Header form: Short (1-RTT)", o, 1);
            f.leaf("Protected payload", o + 1, end - o - 1);
            self.info = format!("Protected Payload (1-RTT), {} bytes", end - o);
        }
        self.tree.push(f);
        self.set(proto::QUIC, "QUIC");
        Some(())
    }

    fn wireguard(&mut self, o: usize, end: usize) -> Option<()> {
        let t = *self.d.get(o)?;
        let name = match t {
            1 => "Handshake Initiation",
            2 => "Handshake Response",
            3 => "Cookie Reply",
            _ => "Transport Data",
        };
        let mut f = Field::new("WireGuard Protocol", o, end - o);
        f.leaf(format!("Type: {name} ({t})"), o, 1);
        if t == 4 {
            f.leaf(format!("Receiver: 0x{:08x}", u32::from_le_bytes(self.d.get(o + 4..o + 8)?.try_into().ok()?)), o + 4, 4);
            f.leaf(format!("Counter: {}", u64::from_le_bytes(self.d.get(o + 8..o + 16)?.try_into().ok()?)), o + 8, 8);
            f.leaf("Encrypted packet", o + 16, end.saturating_sub(o + 16));
        }
        self.tree.push(f);
        self.set(proto::WIREGUARD, "WireGuard");
        self.info = name.into();
        Some(())
    }
}

fn dedup_consecutive(v: &mut Vec<String>) {
    // Collapse "Application Data, Application Data, ..." into one entry.
    v.dedup();
}

// ---------------------------------------------------------------------------------------------
// Heuristics

pub fn is_tls_record_start(p: &[u8]) -> bool {
    p.len() >= 5 && (20..=24).contains(&p[0]) && p[1] == 3 && p[2] <= 4
}

pub fn is_http_start(p: &[u8]) -> bool {
    const M: &[&[u8]] = &[
        b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ", b"HTTP/1.",
    ];
    M.iter().any(|m| p.starts_with(m))
}

fn is_quic(p: &[u8], sport: u16, dport: u16) -> bool {
    if p.len() < 7 {
        return false;
    }
    if p[0] & 0xc0 == 0xc0 {
        let v = u32::from_be_bytes([p[1], p[2], p[3], p[4]]);
        return matches!(v, 0 | 1 | 0x6b3343cf) || v >> 8 == 0xff0000;
    }
    // Short header. The fixed bit (0x40) may be greased (RFC 9287), so don't require it.
    sport == 443 || dport == 443
}

fn is_wireguard(p: &[u8]) -> bool {
    p.len() >= 16
        && (1..=4).contains(&p[0])
        && p[1..4] == [0, 0, 0]
        && match p[0] {
            1 => p.len() == 148,
            2 => p.len() == 92,
            3 => p.len() == 64,
            _ => p.len().is_multiple_of(16) && p.len() >= 32,
        }
}

// ---------------------------------------------------------------------------------------------
// Reusable sub-dissectors (also used for decrypted payloads)

#[derive(Default)]
pub struct HttpInfo {
    pub first_line: String,
    pub method: Option<String>,
    pub uri: Option<String>,
    pub host: Option<String>,
    pub status: Option<u16>,
}

pub fn http_tree(d: &[u8], o: usize, end: usize) -> Option<(Field, HttpInfo)> {
    let p = d.get(o..end)?;
    let hdr_end = find(p, b"\r\n\r\n").map(|i| i + 4).unwrap_or(p.len());
    let mut f = Field::new("Hypertext Transfer Protocol", o, end - o);
    let mut h = HttpInfo::default();
    let mut q = 0;
    let mut first = true;
    while q < hdr_end {
        let line_end = find(&p[q..hdr_end], b"\r\n").map(|i| q + i).unwrap_or(hdr_end);
        let line = &p[q..line_end];
        if line.is_empty() {
            break;
        }
        let text = String::from_utf8_lossy(line).to_string();
        if first {
            h.first_line = text.clone();
            let parts: Vec<&str> = text.splitn(3, ' ').collect();
            if text.starts_with("HTTP/") {
                h.status = parts.get(1).and_then(|s| s.parse().ok());
                let mut sf = Field::new(text.clone(), o + q, line.len());
                if let Some(s) = h.status {
                    sf = sf.filter(format!("http.response.code == {s}"));
                }
                f.push(sf);
            } else {
                h.method = parts.first().map(|s| s.to_string());
                h.uri = parts.get(1).map(|s| s.to_string());
                f.push(Field::new(text.clone(), o + q, line.len()));
            }
            first = false;
        } else {
            let mut hf = Field::new(text.clone(), o + q, line.len());
            if let Some((k, v)) = text.split_once(':')
                && k.eq_ignore_ascii_case("host") {
                    h.host = Some(v.trim().to_string());
                    hf = hf.filter(format!("http.host == \"{}\"", v.trim()));
                }
            f.push(hf);
        }
        q = line_end + 2;
    }
    if hdr_end < p.len() {
        let body = &p[hdr_end..];
        let mut bf = Field::new(format!("Body ({} bytes)", body.len()), o + hdr_end, body.len());
        bf.push(Field::new(printable(body, 160), o + hdr_end, body.len()));
        f.push(bf);
    }
    if h.first_line.is_empty() {
        return None;
    }
    Some((f, h))
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// DNS message tree. Returns (tree, info, first query name, rcode, is_response).
pub fn dns_tree(d: &[u8], o: usize, end: usize, name: &str) -> Option<(Field, String, Option<String>, u8, bool)> {
    let id = be16(d, o)?;
    let flags = be16(d, o + 2)?;
    let qd = be16(d, o + 4)?;
    let an = be16(d, o + 6)?;
    let ns = be16(d, o + 8)?;
    let ar = be16(d, o + 10)?;
    let resp = flags & 0x8000 != 0;
    let rcode = (flags & 0xf) as u8;
    let mut f = Field::new(
        format!("{} ({})", if name == "DNS" { "Domain Name System" } else { name }, if resp { "response" } else { "query" }),
        o,
        end - o,
    );
    f.leaf(format!("Transaction ID: 0x{id:04x}"), o, 2);
    let mut ff = Field::new(format!("Flags: 0x{flags:04x}"), o + 2, 2);
    ff.leaf(format!("Response: {}", resp), o + 2, 1);
    ff.leaf(format!("Opcode: {}", (flags >> 11) & 0xf), o + 2, 1);
    ff.leaf(format!("Recursion desired: {}", flags & 0x100 != 0), o + 2, 1);
    if resp {
        ff.push(Field::new(format!("Reply code: {} ({rcode})", dns_rcode_name(rcode)), o + 3, 1).filter(format!("dns.flags.rcode == {rcode}")));
    }
    f.push(ff);
    f.leaf(format!("Questions: {qd}, Answers: {an}, Authority: {ns}, Additional: {ar}"), o + 4, 8);

    let mut p = o + 12;
    let mut first_q: Option<(String, u16)> = None;
    if qd > 0 {
        let mut qf = Field::text("Queries");
        for _ in 0..qd.min(64) {
            let (qname, np) = dns_name(d, o, p, end)?;
            let qt = be16(d, np)?;
            let qc = be16(d, np + 2)?;
            qf.push(
                Field::new(format!("{qname}: type {}, class {}", dns_type_name(qt), dns_class(qc)), p, np + 4 - p)
                    .filter(format!("dns.qry.name == \"{qname}\"")),
            );
            if first_q.is_none() {
                first_q = Some((qname, qt));
            }
            p = np + 4;
        }
        f.push(qf);
    }
    let mut answers: Vec<String> = Vec::new();
    for (count, title) in [(an, "Answers"), (ns, "Authoritative nameservers"), (ar, "Additional records")] {
        if count == 0 {
            continue;
        }
        let mut sf = Field::text(title);
        for _ in 0..count.min(256) {
            let Some((rname, np)) = dns_name(d, o, p, end) else { break };
            let (Some(rt), Some(rc), Some(ttl), Some(rdlen)) = (be16(d, np), be16(d, np + 2), be32(d, np + 4), be16(d, np + 8)) else { break };
            let rd = np + 10;
            let rdlen = rdlen as usize;
            if rd + rdlen > end {
                break;
            }
            let rdata = dns_rdata(d, o, rt, rd, rdlen, end);
            if rt == 41 {
                sf.leaf(format!("<Root>: type OPT, UDP payload size {rc}"), p, rd + rdlen - p);
            } else {
                sf.leaf(
                    format!("{rname}: type {}, class {}, ttl {ttl}, {rdata}", dns_type_name(rt), dns_class(rc)),
                    p,
                    rd + rdlen - p,
                );
                if title == "Answers" {
                    answers.push(format!("{} {rdata}", dns_type_name(rt)));
                }
            }
            p = rd + rdlen;
        }
        f.push(sf);
    }
    let (qn, qt) = first_q.clone().unwrap_or_default();
    let mut info = if resp {
        format!("Standard query response 0x{id:04x} {} {qn}", dns_type_name(qt))
    } else {
        format!("Standard query 0x{id:04x} {} {qn}", dns_type_name(qt))
    };
    if resp && rcode != 0 {
        info.push_str(&format!(" {}", dns_rcode_name(rcode)));
    }
    if !answers.is_empty() {
        let shown: Vec<_> = answers.iter().take(4).cloned().collect();
        info.push(' ');
        info.push_str(&shown.join(" "));
        if answers.len() > 4 {
            info.push_str(" …");
        }
    }
    Some((f, info, first_q.map(|q| q.0), rcode, resp))
}

fn dns_name(d: &[u8], msg: usize, mut p: usize, end: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut next: Option<usize> = None;
    let mut jumps = 0;
    loop {
        if p >= end {
            return None;
        }
        let len = d[p];
        if len == 0 {
            p += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            let ptr = (be16(d, p)? & 0x3fff) as usize;
            if next.is_none() {
                next = Some(p + 2);
            }
            jumps += 1;
            if jumps > 32 {
                return None;
            }
            p = msg + ptr;
            continue;
        }
        let l = len as usize;
        let lab = d.get(p + 1..p + 1 + l)?;
        labels.push(String::from_utf8_lossy(lab).to_string());
        p += 1 + l;
    }
    let name = if labels.is_empty() { "<Root>".to_string() } else { labels.join(".") };
    Some((name, next.unwrap_or(p)))
}

fn dns_rdata(d: &[u8], msg: usize, t: u16, o: usize, len: usize, end: usize) -> String {
    let r = &d[o..o + len];
    match t {
        1 if len == 4 => Ipv4Addr::new(r[0], r[1], r[2], r[3]).to_string(),
        28 if len == 16 => Ipv6Addr::from(<[u8; 16]>::try_from(r).unwrap()).to_string(),
        2 | 5 | 12 => dns_name(d, msg, o, end).map(|n| n.0).unwrap_or_default(),
        15 => format!(
            "pref {} {}",
            be16(d, o).unwrap_or(0),
            dns_name(d, msg, o + 2, end).map(|n| n.0).unwrap_or_default()
        ),
        16 => {
            let mut out = Vec::new();
            let mut q = 0;
            while q < r.len() {
                let l = r[q] as usize;
                out.push(String::from_utf8_lossy(r.get(q + 1..(q + 1 + l).min(r.len())).unwrap_or(&[])).to_string());
                q += 1 + l;
            }
            format!("\"{}\"", out.join(""))
        }
        33 => format!(
            "{}:{}",
            dns_name(d, msg, o + 6, end).map(|n| n.0).unwrap_or_default(),
            be16(d, o + 4).unwrap_or(0)
        ),
        64 | 65 => format!(
            "priority {} target {}",
            be16(d, o).unwrap_or(0),
            dns_name(d, msg, o + 2, end).map(|n| n.0).unwrap_or_default()
        ),
        6 => format!("SOA {}", dns_name(d, msg, o, end).map(|n| n.0).unwrap_or_default()),
        _ => format!("({len} bytes)"),
    }
}

#[derive(Default, Clone)]
pub struct HandshakeInfo {
    pub random: Option<[u8; 32]>,
    pub suite: Option<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub selected_version: Option<u16>,
    pub hrr: bool,
    /// Client offered Encrypted Client Hello: the real (inner) ClientHello is hidden.
    pub ech: bool,
}

const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11,
    0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Dissects a TLS handshake message body (after the 4-byte header) into `f` and returns the
/// fields needed for decryption.
pub fn tls_handshake_body(d: &[u8], mt: u8, o: usize, end: usize, f: &mut Field) -> HandshakeInfo {
    let mut hs = HandshakeInfo::default();
    if mt != 1 && mt != 2 {
        return hs;
    }
    let client = mt == 1;
    let r = (|| -> Option<()> {
        let ver = be16(d, o)?;
        f.leaf(format!("Version: {} (0x{ver:04x})", tls_version_name(ver)), o, 2);
        let random: [u8; 32] = d.get(o + 2..o + 34)?.try_into().ok()?;
        f.leaf(format!("Random: {}", hex(&random)), o + 2, 32);
        hs.random = Some(random);
        if !client && random == HRR_RANDOM {
            hs.hrr = true;
        }
        let sid_len = *d.get(o + 34)? as usize;
        f.leaf(format!("Session ID length: {sid_len}"), o + 34, 1 + sid_len);
        let mut p = o + 35 + sid_len;
        if client {
            let cs_len = be16(d, p)? as usize;
            let mut cs = Field::new(format!("Cipher Suites ({} suites)", cs_len / 2), p, 2 + cs_len);
            for i in 0..cs_len / 2 {
                let s = be16(d, p + 2 + i * 2)?;
                cs.leaf(format!("Cipher Suite: {} (0x{s:04x})", cipher_suite_name(s)), p + 2 + i * 2, 2);
            }
            f.push(cs);
            p += 2 + cs_len;
            let comp_len = *d.get(p)? as usize;
            p += 1 + comp_len;
        } else {
            let s = be16(d, p)?;
            f.leaf(format!("Cipher Suite: {} (0x{s:04x})", cipher_suite_name(s)), p, 2);
            hs.suite = Some(s);
            p += 3;
        }
        let ext_len = be16(d, p)? as usize;
        let mut ef = Field::new(format!("Extensions ({ext_len} bytes)"), p, 2 + ext_len);
        p += 2;
        let eend = (p + ext_len).min(end);
        while p + 4 <= eend {
            let et = be16(d, p)?;
            let el = be16(d, p + 2)? as usize;
            let v = p + 4;
            let mut x = Field::new(format!("Extension: {} (len={el})", tls_ext_name(et)), p, 4 + el);
            if et == 0xfe0d && client {
                hs.ech = true;
            }
            match et {
                0 if client => {
                    if let (Some(nl), true) = (be16(d, v + 3), el >= 5) {
                        let name = String::from_utf8_lossy(d.get(v + 5..v + 5 + nl as usize)?).to_string();
                        x.push(Field::new(format!("Server Name: {name}"), v + 5, nl as usize).filter(format!("tls.sni == \"{name}\"")));
                        hs.sni = Some(name);
                    }
                }
                16 => {
                    let mut q = v + 2;
                    while q < v + el {
                        let l = *d.get(q)? as usize;
                        let pr = String::from_utf8_lossy(d.get(q + 1..q + 1 + l)?).to_string();
                        x.leaf(format!("ALPN Protocol: {pr}"), q, 1 + l);
                        hs.alpn.push(pr);
                        q += 1 + l;
                    }
                }
                43 => {
                    if client {
                        let l = *d.get(v)? as usize;
                        for i in 0..l / 2 {
                            let sv = be16(d, v + 1 + i * 2)?;
                            x.leaf(format!("Supported Version: {}", tls_version_name(sv)), v + 1 + i * 2, 2);
                        }
                    } else {
                        let sv = be16(d, v)?;
                        x.leaf(format!("Selected Version: {}", tls_version_name(sv)), v, 2);
                        hs.selected_version = Some(sv);
                    }
                }
                51 => {
                    if client {
                        let mut q = v + 2;
                        while q + 4 <= v + el {
                            let g = be16(d, q)?;
                            let kl = be16(d, q + 2)? as usize;
                            x.leaf(format!("Key Share: group {} ({kl} bytes)", tls_group_name(g)), q, 4 + kl);
                            q += 4 + kl;
                        }
                    } else if let Some(g) = be16(d, v) {
                        x.leaf(format!("Key Share: group {}", tls_group_name(g)), v, el);
                    }
                }
                _ => {}
            }
            ef.push(x);
            p += 4 + el;
        }
        f.push(ef);
        Some(())
    })();
    if r.is_none() {
        f.push(Field::text("[Truncated handshake message]"));
    }
    hs
}

/// HTTP/2 frame dissector for decrypted TLS payloads. HPACK header blocks are shown but not
/// decompressed.
pub fn h2_tree(d: &[u8]) -> Option<(Field, String)> {
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let mut p = 0;
    let mut f = Field::new("HyperText Transfer Protocol 2", 0, d.len());
    let mut infos = Vec::new();
    if d.starts_with(PREFACE) {
        f.leaf("Connection preface", 0, PREFACE.len());
        infos.push("Magic".to_string());
        p = PREFACE.len();
    }
    let mut frames = 0;
    while p + 9 <= d.len() {
        let len = be24(d, p)? as usize;
        let t = d[p + 3];
        let flags = d[p + 4];
        let sid = be32(d, p + 5)? & 0x7fff_ffff;
        if t > 9 || len > 16_777_215 {
            break;
        }
        let end = (p + 9 + len).min(d.len());
        let name = ["DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS", "PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION"][t as usize];
        let mut ff = Field::new(format!("Stream: {name}, Stream ID: {sid}, Length {len}"), p, end - p);
        ff.leaf(format!("Length: {len}"), p, 3);
        ff.leaf(format!("Type: {name} ({t})"), p + 3, 1);
        ff.leaf(format!("Flags: 0x{flags:02x}{}", if flags & 1 != 0 && (t == 0 || t == 1) { " (END_STREAM)" } else { "" }), p + 4, 1);
        ff.leaf(format!("Stream identifier: {sid}"), p + 5, 4);
        if end > p + 9 {
            let payload = &d[p + 9..end];
            let label = match t {
                0 => format!("Data: {}", printable(payload, 200)),
                1 | 9 => format!("Header block fragment (HPACK, {} bytes)", payload.len()),
                4 => format!("{} setting(s)", payload.len() / 6),
                8 => format!("Window size increment: {}", be32(payload, 0).unwrap_or(0) & 0x7fff_ffff),
                _ => format!("Payload ({} bytes)", payload.len()),
            };
            ff.leaf(label, p + 9, end - p - 9);
        }
        f.push(ff);
        infos.push(if sid > 0 { format!("{name}[{sid}]") } else { name.to_string() });
        frames += 1;
        p += 9 + len;
    }
    if frames == 0 && p == 0 {
        return None;
    }
    infos.dedup();
    Some((f, infos.join(", ")))
}

/// Dissects decrypted application data (HTTP/1.x, HTTP/2, or raw).
pub fn dissect_plaintext(d: &[u8]) -> (Vec<Field>, String, u64) {
    if is_http_start(d)
        && let Some((f, h)) = http_tree(d, 0, d.len()) {
            return (vec![f], h.first_line, proto::HTTP);
        }
    if let Some((f, info)) = h2_tree(d) {
        return (vec![f], info, proto::HTTP2);
    }
    let mut f = Field::new(format!("Decrypted data ({} bytes)", d.len()), 0, d.len());
    f.push(Field::new(printable(d, 200), 0, d.len()));
    (vec![f], format!("Decrypted data: {}", printable(d, 60)), 0)
}

// ---------------------------------------------------------------------------------------------
// Name tables

pub fn tcp_flags_str(f: u8) -> String {
    let mut v = Vec::new();
    for (bit, n) in [
        (tcpflag::SYN, "SYN"),
        (tcpflag::FIN, "FIN"),
        (tcpflag::RST, "RST"),
        (tcpflag::PSH, "PSH"),
        (tcpflag::ACK, "ACK"),
        (tcpflag::URG, "URG"),
    ] {
        if f & bit != 0 {
            v.push(n);
        }
    }
    v.join(", ")
}

fn ethertype_name(et: u16) -> &'static str {
    match et {
        0x0800 => "IPv4",
        0x86dd => "IPv6",
        0x0806 => "ARP",
        0x8100 => "802.1Q",
        0x88a8 => "802.1ad",
        0x88cc => "LLDP",
        0x888e => "EAPOL",
        0x8863 | 0x8864 => "PPPoE",
        0x8847 => "MPLS",
        _ => "Unknown",
    }
}

pub fn ip_proto_name(p: u8) -> &'static str {
    match p {
        0 => "IPv6 Hop-by-Hop",
        1 => "ICMP",
        2 => "IGMP",
        4 => "IPIP",
        6 => "TCP",
        17 => "UDP",
        41 => "IPv6",
        43 => "IPv6 Routing",
        44 => "IPv6 Fragment",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        60 => "IPv6 Destination Options",
        89 => "OSPF",
        132 => "SCTP",
        _ => "Unknown",
    }
}

fn sll_pkttype(t: u8) -> &'static str {
    match t {
        0 => "Unicast to us",
        1 => "Broadcast",
        2 => "Multicast",
        3 => "Unicast to another host",
        4 => "Sent by us",
        _ => "Unknown",
    }
}

fn icmp_type_name(t: u8) -> &'static str {
    match t {
        0 => "Echo (ping) reply",
        3 => "Destination unreachable",
        5 => "Redirect",
        8 => "Echo (ping) request",
        11 => "Time-to-live exceeded",
        12 => "Parameter problem",
        13 => "Timestamp request",
        14 => "Timestamp reply",
        _ => "ICMP",
    }
}

fn icmp_unreach_name(c: u8) -> &'static str {
    match c {
        0 => "Network unreachable",
        1 => "Host unreachable",
        2 => "Protocol unreachable",
        3 => "Port unreachable",
        4 => "Fragmentation needed",
        13 => "Communication administratively prohibited",
        _ => "Other",
    }
}

fn icmpv6_type_name(t: u8) -> &'static str {
    match t {
        1 => "Destination Unreachable",
        2 => "Packet Too Big",
        3 => "Time Exceeded",
        4 => "Parameter Problem",
        128 => "Echo (ping) request",
        129 => "Echo (ping) reply",
        130 => "Multicast Listener Query",
        131 => "Multicast Listener Report",
        133 => "Router Solicitation",
        134 => "Router Advertisement",
        135 => "Neighbor Solicitation",
        136 => "Neighbor Advertisement",
        143 => "Multicast Listener Report v2",
        _ => "ICMPv6",
    }
}

fn dns_type_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        41 => "OPT".into(),
        47 => "NSEC".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        _ => format!("TYPE{t}"),
    }
}

fn dns_class(c: u16) -> String {
    match c & 0x7fff {
        1 => "IN".into(),
        3 => "CH".into(),
        255 => "ANY".into(),
        x => format!("CLASS{x}"),
    }
}

pub fn dns_rcode_name(r: u8) -> &'static str {
    match r {
        0 => "No error",
        1 => "Format error",
        2 => "Server failure",
        3 => "No such name",
        4 => "Not implemented",
        5 => "Refused",
        _ => "Error",
    }
}

fn dhcp_msg_name(t: u8) -> &'static str {
    match t {
        1 => "Discover",
        2 => "Offer",
        3 => "Request",
        4 => "Decline",
        5 => "ACK",
        6 => "NAK",
        7 => "Release",
        8 => "Inform",
        _ => "Unknown",
    }
}

pub fn tls_content_name(ct: u8) -> &'static str {
    match ct {
        20 => "Change Cipher Spec",
        21 => "Alert",
        22 => "Handshake",
        23 => "Application Data",
        24 => "Heartbeat",
        _ => "Unknown",
    }
}

pub fn tls_version_name(v: u16) -> &'static str {
    match v {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ if v & 0x0f0f == 0x0a0a => "GREASE",
        _ => "Unknown",
    }
}

pub fn tls_hs_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0 => "Hello Request",
        1 => "Client Hello",
        2 => "Server Hello",
        4 => "New Session Ticket",
        5 => "End of Early Data",
        8 => "Encrypted Extensions",
        11 => "Certificate",
        12 => "Server Key Exchange",
        13 => "Certificate Request",
        14 => "Server Hello Done",
        15 => "Certificate Verify",
        16 => "Client Key Exchange",
        20 => "Finished",
        24 => "Key Update",
        _ => return None,
    })
}

pub fn tls_alert_name(d: u8) -> &'static str {
    match d {
        0 => "Close Notify",
        10 => "Unexpected Message",
        20 => "Bad Record MAC",
        40 => "Handshake Failure",
        42 => "Bad Certificate",
        44 => "Certificate Revoked",
        45 => "Certificate Expired",
        46 => "Certificate Unknown",
        47 => "Illegal Parameter",
        48 => "Unknown CA",
        50 => "Decode Error",
        51 => "Decrypt Error",
        70 => "Protocol Version",
        71 => "Insufficient Security",
        80 => "Internal Error",
        90 => "User Canceled",
        109 => "Missing Extension",
        112 => "Unrecognized Name",
        116 => "Certificate Required",
        120 => "No Application Protocol",
        _ => "Unknown",
    }
}

fn tls_ext_name(t: u16) -> String {
    match t {
        0 => "server_name".into(),
        5 => "status_request".into(),
        10 => "supported_groups".into(),
        11 => "ec_point_formats".into(),
        13 => "signature_algorithms".into(),
        16 => "application_layer_protocol_negotiation".into(),
        18 => "signed_certificate_timestamp".into(),
        21 => "padding".into(),
        23 => "extended_master_secret".into(),
        27 => "compress_certificate".into(),
        35 => "session_ticket".into(),
        41 => "pre_shared_key".into(),
        42 => "early_data".into(),
        43 => "supported_versions".into(),
        45 => "psk_key_exchange_modes".into(),
        51 => "key_share".into(),
        57 => "quic_transport_parameters".into(),
        0xfe0d => "encrypted_client_hello".into(),
        0xff01 => "renegotiation_info".into(),
        _ if t & 0x0f0f == 0x0a0a => "GREASE".into(),
        _ => format!("unknown ({t})"),
    }
}

fn tls_group_name(g: u16) -> String {
    match g {
        23 => "secp256r1".into(),
        24 => "secp384r1".into(),
        25 => "secp521r1".into(),
        29 => "x25519".into(),
        30 => "x448".into(),
        0x11ec => "X25519MLKEM768".into(),
        0x6399 => "X25519Kyber768Draft00".into(),
        _ if g & 0x0f0f == 0x0a0a => "GREASE".into(),
        _ => format!("0x{g:04x}"),
    }
}

pub fn cipher_suite_name(s: u16) -> String {
    match s {
        0x1301 => "TLS_AES_128_GCM_SHA256".into(),
        0x1302 => "TLS_AES_256_GCM_SHA384".into(),
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256".into(),
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256".into(),
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384".into(),
        0x009e => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256".into(),
        0x009f => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384".into(),
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into(),
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".into(),
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into(),
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".into(),
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".into(),
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".into(),
        0xccaa => "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256".into(),
        0xc013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA".into(),
        0xc014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA".into(),
        0xc009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA".into(),
        0xc00a => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA".into(),
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA".into(),
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA".into(),
        0x003c => "TLS_RSA_WITH_AES_128_CBC_SHA256".into(),
        0x000a => "TLS_RSA_WITH_3DES_EDE_CBC_SHA".into(),
        0x00ff => "TLS_EMPTY_RENEGOTIATION_INFO_SCSV".into(),
        _ if s & 0x0f0f == 0x0a0a => "GREASE".into(),
        _ => format!("Unknown (0x{s:04x})"),
    }
}
