//! Core data types shared by the capture, dissection, analysis and UI layers.

use std::net::IpAddr;

/// One captured frame exactly as it came off the wire (or out of a file).
#[derive(Clone)]
pub struct Frame {
    /// Seconds since the Unix epoch.
    pub ts: f64,
    pub orig_len: u32,
    pub linktype: i32,
    pub data: Vec<u8>,
    /// Apple per-packet metadata from live capture (e.g. "proc curl:123, svc BE, out").
    pub comment: Option<String>,
}

/// Protocol presence bits. Used for filtering, colouring and the protocol hierarchy.
pub mod proto {
    pub const ETH: u64 = 1 << 0;
    pub const VLAN: u64 = 1 << 1;
    pub const ARP: u64 = 1 << 2;
    pub const IPV4: u64 = 1 << 3;
    pub const IPV6: u64 = 1 << 4;
    pub const ICMP: u64 = 1 << 5;
    pub const ICMPV6: u64 = 1 << 6;
    pub const TCP: u64 = 1 << 7;
    pub const UDP: u64 = 1 << 8;
    pub const DNS: u64 = 1 << 9;
    pub const MDNS: u64 = 1 << 10;
    pub const HTTP: u64 = 1 << 11;
    pub const TLS: u64 = 1 << 12;
    pub const QUIC: u64 = 1 << 13;
    pub const DHCP: u64 = 1 << 14;
    pub const NTP: u64 = 1 << 15;
    pub const SSH: u64 = 1 << 16;
    pub const SSDP: u64 = 1 << 17;
    pub const WIREGUARD: u64 = 1 << 18;
    pub const LLMNR: u64 = 1 << 19;
    pub const DECRYPTED: u64 = 1 << 20;
    pub const HTTP2: u64 = 1 << 21;
    pub const DATA: u64 = 1 << 22;
    pub const LOOPBACK: u64 = 1 << 23;
    pub const SLL: u64 = 1 << 24;
    pub const WLAN: u64 = 1 << 25;
    pub const HTTP3: u64 = 1 << 26;

    /// Filter keyword, bit, display name.
    pub const TABLE: &[(&str, u64, &str)] = &[
        ("eth", ETH, "Ethernet"),
        ("vlan", VLAN, "802.1Q VLAN"),
        ("arp", ARP, "ARP"),
        ("ip", IPV4, "IPv4"),
        ("ipv6", IPV6, "IPv6"),
        ("icmp", ICMP, "ICMP"),
        ("icmpv6", ICMPV6, "ICMPv6"),
        ("tcp", TCP, "TCP"),
        ("udp", UDP, "UDP"),
        ("dns", DNS, "DNS"),
        ("mdns", MDNS, "mDNS"),
        ("llmnr", LLMNR, "LLMNR"),
        ("http", HTTP, "HTTP"),
        ("http2", HTTP2, "HTTP/2"),
        ("http3", HTTP3, "HTTP/3"),
        ("tls", TLS, "TLS"),
        ("quic", QUIC, "QUIC"),
        ("dhcp", DHCP, "DHCP"),
        ("ntp", NTP, "NTP"),
        ("ssh", SSH, "SSH"),
        ("ssdp", SSDP, "SSDP"),
        ("wg", WIREGUARD, "WireGuard"),
        ("data", DATA, "Data"),
        ("loopback", LOOPBACK, "Loopback"),
        ("sll", SLL, "Linux cooked"),
        ("wlan", WLAN, "802.11"),
        ("decrypted", DECRYPTED, "Decrypted"),
    ];

    pub fn by_name(name: &str) -> Option<u64> {
        TABLE.iter().find(|(n, _, _)| *n == name).map(|(_, b, _)| *b)
    }
}

/// A node in the packet details tree. Ranges are byte offsets into the buffer that was dissected
/// (the frame for normal dissection, or the plaintext for decrypted data).
#[derive(Clone, Debug, Default)]
pub struct Field {
    pub label: String,
    pub range: Option<(usize, usize)>,
    /// Suggested display filter for "Apply as filter".
    pub filter: Option<String>,
    pub children: Vec<Field>,
}

impl Field {
    pub fn new(label: impl Into<String>, off: usize, len: usize) -> Self {
        Field { label: label.into(), range: Some((off, len)), ..Default::default() }
    }

    pub fn text(label: impl Into<String>) -> Self {
        Field { label: label.into(), ..Default::default() }
    }

    pub fn filter(mut self, f: impl Into<String>) -> Self {
        self.filter = Some(f.into());
        self
    }

    /// Adds a leaf and returns `self` for chaining.
    pub fn leaf(&mut self, label: impl Into<String>, off: usize, len: usize) -> &mut Self {
        self.children.push(Field::new(label, off, len));
        self
    }

    pub fn push(&mut self, f: Field) -> &mut Field {
        self.children.push(f);
        self.children.last_mut().unwrap()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TcpInfo {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub payload_off: usize,
    pub payload_len: usize,
}

pub mod tcpflag {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
}

/// Compact, filterable facts about a packet, computed once at ingest.
#[derive(Clone, Default)]
pub struct Meta {
    pub protos: u64,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp: Option<TcpInfo>,
    pub udp_payload: Option<(usize, usize)>,
    pub dns_name: Option<String>,
    pub dns_rcode: Option<u8>,
    pub dns_response: bool,
    pub http_host: Option<String>,
    pub http_method: Option<String>,
    pub http_uri: Option<String>,
    pub http_status: Option<u16>,
    pub tls_sni: Option<String>,
    pub tls_alert: Option<u8>,
    pub icmp: Option<(u8, u8)>,
    pub malformed: bool,
    pub pktap: Option<Pktap>,
    /// Index into `Engine::processes`.
    pub process: Option<u32>,
}

/// Per-packet metadata from Apple's PKTAP header.
#[derive(Clone, Debug, Default)]
pub struct Pktap {
    /// Some(true) = inbound, Some(false) = outbound.
    pub dir: Option<bool>,
    pub pid: Option<u32>,
    pub comm: Option<String>,
    pub epid: Option<u32>,
    pub ecomm: Option<String>,
}

/// A local process that traffic was attributed to.
#[derive(Clone, Debug)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
    /// Application (bundle) name used for grouping, e.g. "Google Chrome" for its helpers.
    pub app: String,
    /// How the attribution was made.
    pub source: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StreamKind {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug)]
pub struct StreamRef {
    pub kind: StreamKind,
    pub id: usize,
    /// 0 = from the conversation initiator, 1 = towards it.
    pub dir: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Severity {
    Note,
    Warn,
    Error,
}

#[derive(Clone)]
pub struct Expert {
    pub packet: usize,
    pub severity: Severity,
    pub category: &'static str,
    pub message: String,
}

/// A packet after ingest: the raw frame plus everything shown in the packet list.
pub struct PacketRow {
    pub frame: Frame,
    pub protocol: String,
    pub src: String,
    pub dst: String,
    pub info: String,
    pub meta: Meta,
    pub stream: Option<StreamRef>,
    pub retransmission: bool,
    pub severity: Option<Severity>,
}

/// Plaintext recovered from an encrypted record carried (or completed) by a packet.
#[derive(Clone)]
pub struct Decrypted {
    pub dir: usize,
    pub content_type: u8,
    pub data: Vec<u8>,
    pub note: String,
    /// A decrypted QUIC packet payload (frames) rather than a TLS record.
    pub quic: bool,
}

/// One HTTP/2 or HTTP/3 frame of interest, with headers already decompressed.
#[derive(Clone, Debug)]
pub struct HttpMsg {
    pub version: u8,
    pub dir: usize,
    pub pkt: usize,
    pub stream_id: u64,
    pub kind: &'static str,
    pub headers: Vec<(String, String)>,
    /// Body bytes (DATA frames), capped; `data_len` is the full length.
    pub data: Vec<u8>,
    pub data_len: usize,
    pub end_stream: bool,
    pub note: String,
}

pub const HTTP_BODY_CAP: usize = 256 * 1024;

impl HttpMsg {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    pub fn summary(&self) -> String {
        let mut s = format!("{}[{}]", self.kind, self.stream_id);
        if self.kind == "HEADERS" || self.kind == "PUSH_PROMISE" {
            if let Some(m) = self.header(":method") {
                let path = self.header(":path").unwrap_or("");
                match self.header(":authority") {
                    Some(a) => s.push_str(&format!(": {m} {a}{path}")),
                    None => s.push_str(&format!(": {m} {path}")),
                }
            } else if let Some(st) = self.header(":status") {
                s.push_str(&format!(": {st}"));
                if let Some(ct) = self.header("content-type") {
                    s.push_str(&format!(" {ct}"));
                }
            } else {
                s.push_str(&format!(": {} headers (trailers)", self.headers.len()));
            }
        } else if self.kind == "DATA" {
            s.push_str(&format!(" {} bytes", self.data_len));
        }
        if !self.note.is_empty() {
            s.push_str(&format!(" [{}]", self.note));
        }
        s
    }
}
