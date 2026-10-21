//! Display filter language.
//!
//! ```text
//! tcp && ip.addr == 10.0.0.0/8
//! dns.qry.name contains "google" || http.response.code >= 400
//! !(arp or icmp) and frame.len > 1000
//! tls.sni == "example.com"   decrypted   tcp.stream == 3   frame contains "password"
//! ```

use crate::model::{proto, tcpflag, PacketRow, StreamKind};
use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Proto(u64),
    Present(FieldId),
    Cmp(FieldId, Op, Value),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Op {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
    Contains,
}

#[derive(Debug, Clone)]
pub enum Value {
    Num(u64),
    Net(IpAddr, u8),
    Str(String),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FieldId {
    IpAddr,
    IpSrc,
    IpDst,
    Port,
    SrcPort,
    DstPort,
    TcpPort,
    UdpPort,
    TcpSrcPort,
    TcpDstPort,
    UdpSrcPort,
    UdpDstPort,
    FrameLen,
    FrameNumber,
    Frame,
    TcpStream,
    UdpStream,
    TcpLen,
    TcpWindow,
    TcpFlag(u8),
    Retransmission,
    DnsName,
    DnsRcode,
    HttpHost,
    HttpMethod,
    HttpUri,
    HttpCode,
    TlsSni,
    TlsAlert,
    IcmpType,
    Info,
    Protocol,
    Expert,
    Malformed,
    Bookmarked,
    Process,
    App,
    Pid,
    CompareMissing,
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Ip,
    Num,
    Str,
    Bytes,
    Bool,
}

fn field_by_name(n: &str) -> Option<(FieldId, Kind)> {
    use FieldId::*;
    Some(match n {
        "ip.addr" | "ipv6.addr" | "addr" | "host" => (IpAddr, Kind::Ip),
        "ip.src" | "ipv6.src" | "src" => (IpSrc, Kind::Ip),
        "ip.dst" | "ipv6.dst" | "dst" => (IpDst, Kind::Ip),
        "port" => (Port, Kind::Num),
        "srcport" => (SrcPort, Kind::Num),
        "dstport" => (DstPort, Kind::Num),
        "tcp.port" => (TcpPort, Kind::Num),
        "udp.port" => (UdpPort, Kind::Num),
        "tcp.srcport" => (TcpSrcPort, Kind::Num),
        "tcp.dstport" => (TcpDstPort, Kind::Num),
        "udp.srcport" => (UdpSrcPort, Kind::Num),
        "udp.dstport" => (UdpDstPort, Kind::Num),
        "frame.len" | "len" => (FrameLen, Kind::Num),
        "frame.number" | "frame.no" => (FrameNumber, Kind::Num),
        "frame" => (Frame, Kind::Bytes),
        "tcp.stream" => (TcpStream, Kind::Num),
        "udp.stream" => (UdpStream, Kind::Num),
        "tcp.len" => (TcpLen, Kind::Num),
        "tcp.window_size" | "tcp.window" => (TcpWindow, Kind::Num),
        "tcp.flags.syn" => (TcpFlag(tcpflag::SYN), Kind::Bool),
        "tcp.flags.ack" => (TcpFlag(tcpflag::ACK), Kind::Bool),
        "tcp.flags.fin" => (TcpFlag(tcpflag::FIN), Kind::Bool),
        "tcp.flags.reset" | "tcp.flags.rst" => (TcpFlag(tcpflag::RST), Kind::Bool),
        "tcp.flags.push" | "tcp.flags.psh" => (TcpFlag(tcpflag::PSH), Kind::Bool),
        "tcp.flags.urg" => (TcpFlag(tcpflag::URG), Kind::Bool),
        "tcp.analysis.retransmission" | "retransmission" => (Retransmission, Kind::Bool),
        "dns.qry.name" | "dns.name" => (DnsName, Kind::Str),
        "dns.flags.rcode" | "dns.rcode" => (DnsRcode, Kind::Num),
        "http.host" => (HttpHost, Kind::Str),
        "http.request.method" | "http.method" => (HttpMethod, Kind::Str),
        "http.request.uri" | "http.uri" => (HttpUri, Kind::Str),
        "http.response.code" | "http.status" => (HttpCode, Kind::Num),
        "tls.sni" | "tls.handshake.extensions_server_name" | "sni" => (TlsSni, Kind::Str),
        "tls.alert" | "tls.alert_message.desc" => (TlsAlert, Kind::Num),
        "icmp.type" | "icmpv6.type" => (IcmpType, Kind::Num),
        "info" => (Info, Kind::Str),
        "protocol" | "proto" => (Protocol, Kind::Str),
        "expert" | "_ws.expert" => (Expert, Kind::Bool),
        "malformed" | "_ws.malformed" => (Malformed, Kind::Bool),
        "bookmarked" | "marked" | "frame.marked" => (Bookmarked, Kind::Bool),
        "process" | "proc" | "process.name" => (Process, Kind::Str),
        "app" | "process.app" => (App, Kind::Str),
        "pid" | "process.pid" => (Pid, Kind::Num),
        "compare.missing" | "missing" => (CompareMissing, Kind::Bool),
        _ => return None,
    })
}

/// Field names offered by autocomplete.
pub const SUGGESTIONS: &[&str] = &[
    "ip.addr == ", "ip.src == ", "ip.dst == ", "port == ", "tcp.port == ", "udp.port == ", "tcp.stream == ",
    "udp.stream == ", "process == \"", "app == \"", "pid == ", "frame.len > ", "frame contains \"", "tcp.flags.syn", "tcp.flags.reset", "tcp.analysis.retransmission",
    "dns.qry.name contains \"", "dns.flags.rcode != 0", "http.host contains \"", "http.request.method == \"",
    "http.response.code >= 400", "tls.sni contains \"", "info contains \"", "expert", "decrypted", "bookmarked",
];

// ---------------------------------------------------------------------------------------------
// Lexer

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Str(String),
    LParen,
    RParen,
    And,
    Or,
    Not,
    Op(Op),
}

fn lex(s: &str) -> Result<Vec<Tok>, String> {
    let c: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < c.len() {
        let ch = c[i];
        match ch {
            ' ' | '\t' | '\n' => i += 1,
            '(' => {
                out.push(Tok::LParen);
                i += 1
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1
            }
            '"' => {
                let mut s = String::new();
                i += 1;
                while i < c.len() && c[i] != '"' {
                    if c[i] == '\\' && i + 1 < c.len() {
                        i += 1;
                    }
                    s.push(c[i]);
                    i += 1;
                }
                if i >= c.len() {
                    return Err("Unterminated string".into());
                }
                i += 1;
                out.push(Tok::Str(s));
            }
            '&' if c.get(i + 1) == Some(&'&') => {
                out.push(Tok::And);
                i += 2
            }
            '|' if c.get(i + 1) == Some(&'|') => {
                out.push(Tok::Or);
                i += 2
            }
            '=' if c.get(i + 1) == Some(&'=') => {
                out.push(Tok::Op(Op::Eq));
                i += 2
            }
            '=' => {
                out.push(Tok::Op(Op::Eq));
                i += 1
            }
            '!' if c.get(i + 1) == Some(&'=') => {
                out.push(Tok::Op(Op::Ne));
                i += 2
            }
            '!' => {
                out.push(Tok::Not);
                i += 1
            }
            '>' | '<' => {
                let eq = c.get(i + 1) == Some(&'=');
                out.push(Tok::Op(match (ch, eq) {
                    ('>', true) => Op::Ge,
                    ('>', false) => Op::Gt,
                    ('<', true) => Op::Le,
                    _ => Op::Lt,
                }));
                i += if eq { 2 } else { 1 };
            }
            _ if ch.is_alphanumeric() || "._:/-*[]".contains(ch) => {
                let st = i;
                while i < c.len() && (c[i].is_alphanumeric() || "._:/-*[]".contains(c[i])) {
                    i += 1;
                }
                let w: String = c[st..i].iter().collect();
                out.push(match w.to_ascii_lowercase().as_str() {
                    "and" => Tok::And,
                    "or" => Tok::Or,
                    "not" => Tok::Not,
                    "eq" => Tok::Op(Op::Eq),
                    "ne" => Tok::Op(Op::Ne),
                    "gt" => Tok::Op(Op::Gt),
                    "lt" => Tok::Op(Op::Lt),
                    "ge" => Tok::Op(Op::Ge),
                    "le" => Tok::Op(Op::Le),
                    "contains" => Tok::Op(Op::Contains),
                    _ => Tok::Word(w),
                });
            }
            _ => return Err(format!("Unexpected character '{ch}'")),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Parser

pub fn parse(s: &str) -> Result<Option<Expr>, String> {
    let toks = lex(s)?;
    if toks.is_empty() {
        return Ok(None);
    }
    let mut p = Parser { t: toks, i: 0 };
    let e = p.or()?;
    if p.i < p.t.len() {
        return Err(format!("Unexpected '{}'", tok_str(&p.t[p.i])));
    }
    Ok(Some(e))
}

fn tok_str(t: &Tok) -> String {
    match t {
        Tok::Word(w) => w.clone(),
        Tok::Str(s) => format!("\"{s}\""),
        Tok::LParen => "(".into(),
        Tok::RParen => ")".into(),
        Tok::And => "&&".into(),
        Tok::Or => "||".into(),
        Tok::Not => "!".into(),
        Tok::Op(o) => format!("{o:?}"),
    }
}

struct Parser {
    t: Vec<Tok>,
    i: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.t.get(self.i)
    }

    fn or(&mut self) -> Result<Expr, String> {
        let mut l = self.and()?;
        while self.peek() == Some(&Tok::Or) {
            self.i += 1;
            let r = self.and()?;
            l = Expr::Or(Box::new(l), Box::new(r));
        }
        Ok(l)
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut l = self.not()?;
        while self.peek() == Some(&Tok::And) {
            self.i += 1;
            let r = self.not()?;
            l = Expr::And(Box::new(l), Box::new(r));
        }
        Ok(l)
    }

    fn not(&mut self) -> Result<Expr, String> {
        if self.peek() == Some(&Tok::Not) {
            self.i += 1;
            return Ok(Expr::Not(Box::new(self.not()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, String> {
        match self.t.get(self.i).cloned() {
            Some(Tok::LParen) => {
                self.i += 1;
                let e = self.or()?;
                if self.peek() != Some(&Tok::RParen) {
                    return Err("Missing ')'".into());
                }
                self.i += 1;
                Ok(e)
            }
            Some(Tok::Word(w)) => {
                self.i += 1;
                let lw = w.to_ascii_lowercase();
                if let Some(Tok::Op(op)) = self.peek().cloned() {
                    self.i += 1;
                    let (fid, kind) = field_by_name(&lw).ok_or_else(|| format!("Unknown field '{w}'"))?;
                    let raw = match self.t.get(self.i).cloned() {
                        Some(Tok::Word(v)) => (v, false),
                        Some(Tok::Str(v)) => (v, true),
                        _ => return Err(format!("Expected a value after '{w}'")),
                    };
                    self.i += 1;
                    let val = parse_value(kind, &raw.0, raw.1, op)?;
                    return Ok(Expr::Cmp(fid, op, val));
                }
                if let Some(bit) = proto::by_name(&lw) {
                    return Ok(Expr::Proto(bit));
                }
                if let Some((fid, _)) = field_by_name(&lw) {
                    return Ok(Expr::Present(fid));
                }
                // Convenience: a bare address or subnet means "ip.addr == …".
                if let Ok(v) = parse_value(Kind::Ip, &w, false, Op::Eq) {
                    return Ok(Expr::Cmp(FieldId::IpAddr, Op::Eq, v));
                }
                Err(format!("Unknown protocol or field '{w}'"))
            }
            Some(t) => Err(format!("Unexpected '{}'", tok_str(&t))),
            None => Err("Unexpected end of filter".into()),
        }
    }
}

fn parse_value(kind: Kind, s: &str, quoted: bool, op: Op) -> Result<Value, String> {
    match kind {
        Kind::Ip => {
            let (a, p) = match s.split_once('/') {
                Some((a, p)) => (a, Some(p.parse::<u8>().map_err(|_| format!("Bad prefix length '{p}'"))?)),
                None => (s, None),
            };
            let ip: IpAddr = a.trim_matches(|c| c == '[' || c == ']').parse().map_err(|_| format!("'{s}' is not an IP address"))?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            Ok(Value::Net(ip, p.unwrap_or(max).min(max)))
        }
        Kind::Num | Kind::Bool => {
            let n = if let Some(h) = s.strip_prefix("0x") {
                u64::from_str_radix(h, 16)
            } else if s == "true" {
                Ok(1)
            } else if s == "false" {
                Ok(0)
            } else {
                s.parse()
            };
            n.map(Value::Num).map_err(|_| format!("'{s}' is not a number"))
        }
        Kind::Str => Ok(Value::Str(s.to_string())),
        Kind::Bytes => {
            if op != Op::Contains && op != Op::Eq {
                return Err("Only 'contains' and '==' work on frame bytes".into());
            }
            if !quoted && s.contains(':') {
                let b: Result<Vec<u8>, _> = s.split(':').map(|h| u8::from_str_radix(h, 16)).collect();
                return b.map(Value::Bytes).map_err(|_| format!("Bad byte string '{s}'"));
            }
            Ok(Value::Bytes(s.as_bytes().to_vec()))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Evaluation

pub struct EvalCtx<'a> {
    pub bookmarks: &'a HashSet<usize>,
    pub processes: &'a [crate::model::ProcInfo],
    /// Packets of this capture not found in the capture it was compared with.
    pub missing: &'a HashSet<usize>,
}

impl Expr {
    pub fn matches(&self, idx: usize, row: &PacketRow, ctx: &EvalCtx) -> bool {
        match self {
            Expr::And(a, b) => a.matches(idx, row, ctx) && b.matches(idx, row, ctx),
            Expr::Or(a, b) => a.matches(idx, row, ctx) || b.matches(idx, row, ctx),
            Expr::Not(a) => !a.matches(idx, row, ctx),
            Expr::Proto(bit) => row.meta.protos & bit != 0,
            Expr::Present(f) => present(*f, idx, row, ctx),
            Expr::Cmp(f, Op::Ne, v) => !cmp(*f, Op::Eq, v, idx, row, ctx),
            Expr::Cmp(f, op, v) => cmp(*f, *op, v, idx, row, ctx),
        }
    }
}

/// Evaluates a filter over many packets in parallel; returns matching indices in order.
pub fn matching(e: &Expr, packets: &[PacketRow], ctx: &EvalCtx) -> Vec<usize> {
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let chunk = packets.len().div_ceil(threads).max(4096);
    std::thread::scope(|s| {
        let handles: Vec<_> = packets
            .chunks(chunk)
            .enumerate()
            .map(|(ci, part)| {
                s.spawn(move || {
                    let base = ci * chunk;
                    part.iter().enumerate().filter(|(i, p)| e.matches(base + i, p, ctx)).map(|(i, _)| base + i).collect::<Vec<_>>()
                })
            })
            .collect();
        handles.into_iter().flat_map(|h| h.join().unwrap()).collect()
    })
}

fn present(f: FieldId, idx: usize, row: &PacketRow, ctx: &EvalCtx) -> bool {
    use FieldId::*;
    let m = &row.meta;
    match f {
        TcpFlag(b) => m.tcp.map(|t| t.flags & b != 0).unwrap_or(false),
        Retransmission => row.retransmission,
        Expert => row.severity.is_some(),
        Malformed => m.malformed,
        Bookmarked => ctx.bookmarks.contains(&idx),
        DnsName => m.dns_name.is_some(),
        HttpHost => m.http_host.is_some(),
        HttpMethod => m.http_method.is_some(),
        HttpCode => m.http_status.is_some(),
        TlsSni => m.tls_sni.is_some(),
        TlsAlert => m.tls_alert.is_some(),
        Process | App | Pid => m.process.is_some(),
        CompareMissing => ctx.missing.contains(&idx),
        _ => !nums(f, idx, row, ctx).is_empty() || !ips(f, row).is_empty(),
    }
}

fn ips(f: FieldId, row: &PacketRow) -> Vec<IpAddr> {
    let m = &row.meta;
    match f {
        FieldId::IpAddr => m.src_ip.into_iter().chain(m.dst_ip).collect(),
        FieldId::IpSrc => m.src_ip.into_iter().collect(),
        FieldId::IpDst => m.dst_ip.into_iter().collect(),
        _ => vec![],
    }
}

fn nums(f: FieldId, idx: usize, row: &PacketRow, ctx: &EvalCtx) -> Vec<u64> {
    use FieldId::*;
    let m = &row.meta;
    let is_tcp = m.tcp.is_some();
    let is_udp = m.udp_payload.is_some();
    let sp = m.src_port.map(|p| p as u64);
    let dp = m.dst_port.map(|p| p as u64);
    let both = || sp.into_iter().chain(dp).collect::<Vec<_>>();
    match f {
        Port => both(),
        SrcPort => sp.into_iter().collect(),
        DstPort => dp.into_iter().collect(),
        TcpPort if is_tcp => both(),
        UdpPort if is_udp => both(),
        TcpSrcPort if is_tcp => sp.into_iter().collect(),
        TcpDstPort if is_tcp => dp.into_iter().collect(),
        UdpSrcPort if is_udp => sp.into_iter().collect(),
        UdpDstPort if is_udp => dp.into_iter().collect(),
        FrameLen => vec![row.frame.orig_len as u64],
        FrameNumber => vec![idx as u64 + 1],
        TcpStream => row.stream.filter(|s| s.kind == StreamKind::Tcp).map(|s| s.id as u64).into_iter().collect(),
        UdpStream => row.stream.filter(|s| s.kind == StreamKind::Udp).map(|s| s.id as u64).into_iter().collect(),
        TcpLen => m.tcp.map(|t| t.payload_len as u64).into_iter().collect(),
        TcpWindow => m.tcp.map(|t| t.window as u64).into_iter().collect(),
        TcpFlag(b) => m.tcp.map(|t| (t.flags & b != 0) as u64).into_iter().collect(),
        Retransmission => vec![row.retransmission as u64],
        DnsRcode => m.dns_rcode.map(|r| r as u64).into_iter().collect(),
        HttpCode => m.http_status.map(|r| r as u64).into_iter().collect(),
        TlsAlert => m.tls_alert.map(|r| r as u64).into_iter().collect(),
        IcmpType => m.icmp.map(|r| r.0 as u64).into_iter().collect(),
        Expert => vec![row.severity.is_some() as u64],
        Malformed => vec![m.malformed as u64],
        Pid => m.process.and_then(|i| ctx.processes.get(i as usize)).map(|p| p.pid as u64).into_iter().collect(),
        _ => vec![],
    }
}

fn strs<'a>(f: FieldId, row: &'a PacketRow, ctx: &EvalCtx<'a>) -> Vec<&'a str> {
    use FieldId::*;
    let m = &row.meta;
    fn o(s: &Option<String>) -> Vec<&str> {
        s.as_deref().into_iter().collect()
    }
    match f {
        DnsName => o(&m.dns_name),
        HttpHost => o(&m.http_host),
        HttpMethod => o(&m.http_method),
        HttpUri => o(&m.http_uri),
        TlsSni => o(&m.tls_sni),
        Info => vec![row.info.as_str()],
        Protocol => vec![row.protocol.as_str()],
        // `process` matches the executable name or its application.
        Process => m.process.and_then(|i| ctx.processes.get(i as usize)).map(|p| vec![p.name.as_str(), p.app.as_str()]).unwrap_or_default(),
        App => m.process.and_then(|i| ctx.processes.get(i as usize)).map(|p| vec![p.app.as_str()]).unwrap_or_default(),
        _ => vec![],
    }
}

fn in_net(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix as u32) };
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

fn cmp(f: FieldId, op: Op, v: &Value, idx: usize, row: &PacketRow, ctx: &EvalCtx) -> bool {
    match v {
        Value::Net(net, prefix) => ips(f, row).into_iter().any(|ip| in_net(ip, *net, *prefix)),
        Value::Num(n) => {
            if f == FieldId::Bookmarked {
                return ctx.bookmarks.contains(&idx) == (*n != 0);
            }
            nums(f, idx, row, ctx).into_iter().any(|x| match op {
                Op::Eq | Op::Ne => x == *n,
                Op::Gt => x > *n,
                Op::Lt => x < *n,
                Op::Ge => x >= *n,
                Op::Le => x <= *n,
                Op::Contains => x.to_string().contains(&n.to_string()),
            })
        }
        Value::Str(s) => {
            let s = s.to_ascii_lowercase();
            strs(f, row, ctx).into_iter().any(|x| {
                let x = x.to_ascii_lowercase();
                match op {
                    Op::Contains => x.contains(&s),
                    Op::Eq | Op::Ne => x == s,
                    Op::Gt => x > s,
                    Op::Lt => x < s,
                    Op::Ge => x >= s,
                    Op::Le => x <= s,
                }
            })
        }
        Value::Bytes(b) => {
            let d = &row.frame.data;
            match op {
                Op::Eq | Op::Ne => d == b,
                _ => !b.is_empty() && d.windows(b.len()).any(|w| w.eq_ignore_ascii_case(b)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_filters() {
        for f in [
            "tcp",
            "tcp && ip.addr == 10.0.0.0/8",
            "!(arp or icmp) and frame.len > 1000",
            "dns.qry.name contains \"google\" || http.response.code >= 400",
            "frame contains de:ad:be:ef",
            "192.168.1.1",
            "tcp.flags.syn == 1 && !tcp.flags.ack",
            "ip.addr == fe80::1",
        ] {
            assert!(parse(f).is_ok(), "{f}: {:?}", parse(f));
        }
        assert!(parse("bogus.field == 3").is_err());
        assert!(parse("tcp &&").is_err());
    }
}
