//! QUIC (RFC 9000/9001, v1 and v2) decryption and HTTP/3 (RFC 9114) parsing.
//!
//! Initial packets are decrypted with keys derived from the client's Destination Connection ID,
//! so the ClientHello (SNI, ALPN) is always visible. Handshake, 0-RTT and 1-RTT packets use the
//! TLS 1.3 secrets from the key log, keyed by the ClientHello random. Header protection, packet
//! number recovery, coalesced packets and key updates are handled.

use crate::dissect::{be24, be32, hex, printable, tls_handshake_body, tls_hs_name};
use crate::hpack::QpackDecoder;
use crate::model::{Field, HttpMsg, HTTP_BODY_CAP};
use crate::tls::{
    aead_open, alpn_from_extensions, hkdf_expand_label, hmac, pkt_for, suite_info, xor_nonce, CipherAlg, HashAlg, KeyLog,
    Suite, TlsStatus,
};
use std::collections::{BTreeMap, HashMap};

pub const V1: u32 = 1;
pub const V2: u32 = 0x6b33_43cf;
const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
];

// ---------------------------------------------------------------------------------------------
// Primitives

pub fn varint(b: &[u8], p: &mut usize) -> Option<u64> {
    let first = *b.get(*p)?;
    let len = 1usize << (first >> 6);
    let bytes = b.get(*p..*p + len)?;
    let mut v = (first & 0x3f) as u64;
    for &x in &bytes[1..] {
        v = (v << 8) | x as u64;
    }
    *p += len;
    Some(v)
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Level {
    Initial,
    ZeroRtt,
    Handshake,
    OneRtt,
}

impl Level {
    fn space(self) -> usize {
        match self {
            Level::Initial => 0,
            Level::Handshake => 1,
            _ => 2,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Level::Initial => "Initial",
            Level::ZeroRtt => "0-RTT",
            Level::Handshake => "Handshake",
            Level::OneRtt => "1-RTT",
        }
    }
}

#[derive(Clone)]
struct Keys {
    cipher: CipherAlg,
    key: Vec<u8>,
    iv: Vec<u8>,
    hp: Vec<u8>,
}

fn label(version: u32, l: &str) -> String {
    if version == V2 { format!("quicv2 {l}") } else { format!("quic {l}") }
}

fn keys_from_secret(version: u32, suite: Suite, secret: &[u8]) -> Keys {
    Keys {
        cipher: suite.cipher,
        key: hkdf_expand_label(suite.hash, secret, &label(version, "key"), &[], suite.key_len),
        iv: hkdf_expand_label(suite.hash, secret, &label(version, "iv"), &[], 12),
        hp: hkdf_expand_label(suite.hash, secret, &label(version, "hp"), &[], suite.key_len),
    }
}

/// Client and server Initial keys for a given original Destination Connection ID.
fn initial_keys(version: u32, dcid: &[u8]) -> [Keys; 2] {
    let salt: &[u8] = if version == V2 { &SALT_V2 } else { &SALT_V1 };
    let initial = hmac(HashAlg::Sha256, salt, &[dcid]);
    let suite = suite_info(0x1301).unwrap();
    let c = hkdf_expand_label(HashAlg::Sha256, &initial, "client in", &[], 32);
    let s = hkdf_expand_label(HashAlg::Sha256, &initial, "server in", &[], 32);
    [keys_from_secret(version, suite, &c), keys_from_secret(version, suite, &s)]
}

fn hp_mask(cipher: CipherAlg, hp: &[u8], sample: &[u8]) -> Option<[u8; 5]> {
    let mut mask = [0u8; 5];
    match cipher {
        CipherAlg::Aes128Gcm | CipherAlg::Aes256Gcm => {
            use aes::cipher::{BlockCipherEncrypt, KeyInit};
            let mut block = aes::Block::try_from(sample).ok()?;
            if cipher == CipherAlg::Aes128Gcm {
                aes::Aes128::new_from_slice(hp).ok()?.encrypt_block(&mut block);
            } else {
                aes::Aes256::new_from_slice(hp).ok()?.encrypt_block(&mut block);
            }
            mask.copy_from_slice(&block[..5]);
        }
        CipherAlg::ChaCha20 => {
            use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
            let counter = u32::from_le_bytes(sample[..4].try_into().ok()?);
            let mut c = chacha20::ChaCha20::new_from_slices(hp, &sample[4..16]).ok()?;
            c.seek(counter as u64 * 64);
            c.apply_keystream(&mut mask);
        }
    }
    Some(mask)
}

/// RFC 9000 Appendix A.3.
fn decode_pn(largest: Option<u64>, truncated: u64, bits: u32) -> u64 {
    let expected = largest.map(|l| l + 1).unwrap_or(0);
    let win = 1u64 << bits;
    let hwin = win / 2;
    let mask = win - 1;
    let candidate = (expected & !mask) | truncated;
    if candidate + hwin <= expected && candidate < (1u64 << 62) - win {
        candidate + win
    } else if candidate > expected + hwin && candidate >= win {
        candidate - win
    } else {
        candidate
    }
}

/// A byte stream delivered at arbitrary offsets (QUIC CRYPTO and STREAM frames).
#[derive(Default)]
pub struct OffsetStream {
    pub data: Vec<u8>,
    pub chunks: Vec<(usize, usize)>,
    ooo: BTreeMap<u64, (Vec<u8>, usize)>,
    pub parsed: usize,
    pub fin: bool,
}

impl OffsetStream {
    pub fn add(&mut self, off: u64, d: &[u8], pkt: usize) {
        if self.data.len() >= 64 * 1024 * 1024 {
            return;
        }
        self.ooo.entry(off).or_insert_with(|| (d.to_vec(), pkt));
        while let Some((&o, _)) = self.ooo.iter().next() {
            let have = self.data.len() as u64;
            if o > have {
                break;
            }
            let (d, pkt) = self.ooo.remove(&o).unwrap();
            let end = o + d.len() as u64;
            if end > have {
                self.chunks.push((self.data.len(), pkt));
                self.data.extend_from_slice(&d[(have - o) as usize..]);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Frames

pub enum QFrame {
    Padding(usize),
    Crypto { off: u64, start: usize, len: usize },
    Stream { id: u64, off: u64, fin: bool, start: usize, len: usize },
    Ack { largest: u64 },
    Close { code: u64, app: bool, reason: String },
    NewConnectionId { seq: u64, cid: Vec<u8> },
    Other(String),
}

/// Parses all frames in a decrypted packet payload: (frame, start, end).
pub fn parse_frames(b: &[u8]) -> (Vec<(QFrame, usize, usize)>, Option<String>) {
    let mut out = Vec::new();
    let mut p = 0;
    let mut unknown = None;
    let ok = (|| -> Option<()> {
        while p < b.len() {
            let start = p;
            let ty = varint(b, &mut p)?;
            let f = match ty {
                0x00 => {
                    while p < b.len() && b[p] == 0 {
                        p += 1;
                    }
                    QFrame::Padding(p - start)
                }
                0x01 => QFrame::Other("PING".into()),
                0x02 | 0x03 => {
                    let largest = varint(b, &mut p)?;
                    varint(b, &mut p)?;
                    let n = varint(b, &mut p)?;
                    varint(b, &mut p)?;
                    for _ in 0..n {
                        varint(b, &mut p)?;
                        varint(b, &mut p)?;
                    }
                    if ty == 0x03 {
                        for _ in 0..3 {
                            varint(b, &mut p)?;
                        }
                    }
                    QFrame::Ack { largest }
                }
                0x04 => {
                    let id = varint(b, &mut p)?;
                    let code = varint(b, &mut p)?;
                    varint(b, &mut p)?;
                    QFrame::Other(format!("RESET_STREAM(id={id}, code=0x{code:x})"))
                }
                0x05 => {
                    let id = varint(b, &mut p)?;
                    let code = varint(b, &mut p)?;
                    QFrame::Other(format!("STOP_SENDING(id={id}, code=0x{code:x})"))
                }
                0x06 => {
                    let off = varint(b, &mut p)?;
                    let len = varint(b, &mut p)? as usize;
                    b.get(p..p + len)?;
                    let f = QFrame::Crypto { off, start: p, len };
                    p += len;
                    f
                }
                0x07 => {
                    let len = varint(b, &mut p)? as usize;
                    p += len;
                    QFrame::Other("NEW_TOKEN".into())
                }
                0x08..=0x0f => {
                    let id = varint(b, &mut p)?;
                    let off = if ty & 0x04 != 0 { varint(b, &mut p)? } else { 0 };
                    let len = if ty & 0x02 != 0 { varint(b, &mut p)? as usize } else { b.len() - p };
                    b.get(p..p + len)?;
                    let f = QFrame::Stream { id, off, fin: ty & 0x01 != 0, start: p, len };
                    p += len;
                    f
                }
                0x10 => QFrame::Other(format!("MAX_DATA({})", varint(b, &mut p)?)),
                0x11 => {
                    let id = varint(b, &mut p)?;
                    QFrame::Other(format!("MAX_STREAM_DATA(id={id}, {})", varint(b, &mut p)?))
                }
                0x12 | 0x13 => QFrame::Other(format!("MAX_STREAMS({})", varint(b, &mut p)?)),
                0x14 => QFrame::Other(format!("DATA_BLOCKED({})", varint(b, &mut p)?)),
                0x15 => {
                    let id = varint(b, &mut p)?;
                    varint(b, &mut p)?;
                    QFrame::Other(format!("STREAM_DATA_BLOCKED(id={id})"))
                }
                0x16 | 0x17 => QFrame::Other(format!("STREAMS_BLOCKED({})", varint(b, &mut p)?)),
                0x18 => {
                    let seq = varint(b, &mut p)?;
                    varint(b, &mut p)?;
                    let l = *b.get(p)? as usize;
                    let cid = b.get(p + 1..p + 1 + l)?.to_vec();
                    p += 1 + l + 16;
                    QFrame::NewConnectionId { seq, cid }
                }
                0x19 => QFrame::Other(format!("RETIRE_CONNECTION_ID({})", varint(b, &mut p)?)),
                0x1a | 0x1b => {
                    p += 8;
                    QFrame::Other(if ty == 0x1a { "PATH_CHALLENGE" } else { "PATH_RESPONSE" }.into())
                }
                0x1c | 0x1d => {
                    let code = varint(b, &mut p)?;
                    if ty == 0x1c {
                        varint(b, &mut p)?;
                    }
                    let l = varint(b, &mut p)? as usize;
                    let reason = String::from_utf8_lossy(b.get(p..p + l)?).to_string();
                    p += l;
                    QFrame::Close { code, app: ty == 0x1d, reason }
                }
                0x1e => QFrame::Other("HANDSHAKE_DONE".into()),
                // ACK frequency extension (draft-ietf-quic-ack-frequency).
                0x1f => QFrame::Other("IMMEDIATE_ACK".into()),
                0xaf => {
                    let seq = varint(b, &mut p)?;
                    let threshold = varint(b, &mut p)?;
                    let delay = varint(b, &mut p)?;
                    varint(b, &mut p)?;
                    QFrame::Other(format!("ACK_FREQUENCY(seq={seq}, threshold={threshold}, max_delay={delay}µs)"))
                }
                0x30 | 0x31 => {
                    let len = if ty == 0x31 { varint(b, &mut p)? as usize } else { b.len() - p };
                    p += len;
                    QFrame::Other(format!("DATAGRAM({len} bytes)"))
                }
                _ => {
                    unknown = Some(ty);
                    return None;
                }
            };
            if p > b.len() {
                return None;
            }
            out.push((f, start, p));
        }
        Some(())
    })();
    let err = match (ok, unknown) {
        (Some(()), _) => None,
        (None, Some(t)) => Some(format!("unknown frame type 0x{t:x}")),
        (None, None) => Some("truncated frame".to_string()),
    };
    (out, err)
}

fn frame_name(f: &QFrame) -> String {
    match f {
        QFrame::Padding(n) => format!("PADDING({n})"),
        QFrame::Crypto { off, len, .. } => format!("CRYPTO(off={off}, len={len})"),
        QFrame::Stream { id, off, fin, len, .. } => {
            format!("STREAM(id={id}, off={off}, len={len}{})", if *fin { ", FIN" } else { "" })
        }
        QFrame::Ack { largest } => format!("ACK(largest={largest})"),
        QFrame::NewConnectionId { seq, cid } => format!("NEW_CONNECTION_ID(seq={seq}, {})", hex(cid)),
        QFrame::Close { code, app, reason } => {
            format!("CONNECTION_CLOSE({}0x{code:x}{})", if *app { "app " } else { "" }, if reason.is_empty() { String::new() } else { format!(", \"{reason}\"") })
        }
        QFrame::Other(s) => s.clone(),
    }
}

/// Details-pane tree for a decrypted QUIC packet payload.
pub fn frames_tree(b: &[u8]) -> Vec<Field> {
    let (frames, err) = parse_frames(b);
    let mut out: Vec<Field> = frames
        .iter()
        .map(|(f, s, e)| {
            let mut field = Field::new(frame_name(f), *s, e - s);
            match f {
                QFrame::Crypto { start, len, .. } => {
                    field.push(Field::new(format!("Crypto data ({len} bytes)"), *start, *len));
                }
                QFrame::Stream { start, len, .. } => {
                    field.push(Field::new(format!("Stream data: {}", printable(&b[*start..*start + *len], 120)), *start, *len));
                }
                _ => {}
            }
            field
        })
        .collect();
    if let Some(e) = err {
        out.push(Field::text(format!("[Remaining bytes not parsed: {e}]")));
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Connection state

struct AppKeys {
    secret: Vec<u8>,
    phase: bool,
    current: Keys,
    prev: Option<Keys>,
}

struct Pending {
    dir: usize,
    pkt: usize,
    data: Vec<u8>,
    pn_off: usize,
    level: Level,
}

/// One decrypted (or undecryptable) QUIC packet, reported to the engine.
pub struct QuicOut {
    pub pkt: usize,
    pub dir: usize,
    pub level: Level,
    pub payload: Option<Vec<u8>>,
    pub summary: String,
}

pub struct QuicConn {
    pub version: u32,
    pub client_dir: Option<usize>,
    pub initial_dcid: Option<Vec<u8>>,
    /// Source Connection ID chosen by the sender of each direction.
    pub cids: [Option<Vec<u8>>; 2],
    /// Connection IDs that packets travelling in each direction may carry as their DCID.
    known_dcids: [std::collections::HashSet<Vec<u8>>; 2],
    initial: Option<[Keys; 2]>,
    handshake: [Option<Keys>; 2],
    zero_rtt: Option<Keys>,
    app: [Option<AppKeys>; 2],
    largest: [[Option<u64>; 3]; 2],
    crypto: [[OffsetStream; 3]; 2],
    pub client_random: Option<[u8; 32]>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub suite: Option<u16>,
    pub status: TlsStatus,
    /// Client offered ECH; `ech_resolved` once the inner random was found in the key log.
    pub ech: bool,
    pub ech_resolved: bool,
    key_search_at: usize,
    pub decrypted_packets: usize,
    pub protected_packets: usize,
    pending: Vec<Pending>,
    pub h3: H3Conn,
}

impl Default for QuicConn {
    fn default() -> Self {
        QuicConn {
            version: V1,
            client_dir: None,
            initial_dcid: None,
            cids: [None, None],
            known_dcids: Default::default(),
            initial: None,
            handshake: [None, None],
            zero_rtt: None,
            app: [None, None],
            largest: [[None; 3]; 2],
            crypto: Default::default(),
            client_random: None,
            sni: None,
            alpn: None,
            suite: None,
            status: TlsStatus::Handshake,
            ech: false,
            ech_resolved: false,
            key_search_at: usize::MAX,
            decrypted_packets: 0,
            protected_packets: 0,
            pending: Vec::new(),
            h3: H3Conn::default(),
        }
    }
}

impl QuicConn {
    fn is_client(&self, dir: usize) -> bool {
        self.client_dir.map(|c| c == dir).unwrap_or(dir == 0)
    }

    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Processes one UDP datagram (which may contain several coalesced QUIC packets).
    pub fn datagram(&mut self, dir: usize, pkt: usize, d: &[u8], keylog: &KeyLog, out: &mut Vec<QuicOut>) {
        let mut p = 0;
        while p < d.len() {
            let first = d[p];
            if first & 0x80 == 0 {
                // Short header: the DCID is the one the receiver chose for itself.
                let Some(dcil) = self.cids[1 - dir].as_ref().map(|c| c.len()) else {
                    out.push(QuicOut { pkt, dir, level: Level::OneRtt, payload: None, summary: "1-RTT [connection IDs unknown: handshake not captured]".into() });
                    return;
                };
                // After coalesced long-header packets, bytes whose DCID is not one the peer
                // issued are datagram padding (often random, RFC 9000 §12.2), not a packet.
                let dcid = d.get(p + 1..p + 1 + dcil);
                if p > 0 && !dcid.is_some_and(|c| self.known_dcids[dir].contains(c)) {
                    return;
                }
                self.packet(dir, pkt, &d[p..], 1 + dcil, Level::OneRtt, keylog, out, true);
                return;
            }
            let Some(hdr) = parse_long_header(d, p) else { return };
            if hdr.version == 0 {
                out.push(QuicOut { pkt, dir, level: Level::Initial, payload: None, summary: "Version Negotiation".into() });
                return;
            }
            self.version = hdr.version;
            if hdr.retry {
                self.cids[dir] = Some(hdr.scid.to_vec());
                out.push(QuicOut { pkt, dir, level: Level::Initial, payload: None, summary: format!("Retry, new SCID={}", hex(hdr.scid)) });
                return;
            }
            let from_client = self.client_dir.is_none_or(|c| c == dir);
            if hdr.level == Level::Initial && from_client && self.largest[1 - dir][0].is_none() {
                // The client's Initial picks the DCID that seeds Initial keys (again after Retry,
                // until the server's first Initial has been read).
                if self.initial_dcid.as_deref() != Some(hdr.dcid) {
                    self.client_dir = Some(dir);
                    self.initial_dcid = Some(hdr.dcid.to_vec());
                    let k = initial_keys(hdr.version, hdr.dcid);
                    self.initial = Some(if dir == 0 { k } else { let [c, s] = k; [s, c] });
                }
            }
            self.cids[dir] = Some(hdr.scid.to_vec());
            self.known_dcids[1 - dir].insert(hdr.scid.to_vec());
            let end = (hdr.pn_off + hdr.len).min(d.len());
            self.packet(dir, pkt, &d[p..end], hdr.pn_off - p, hdr.level, keylog, out, true);
            p = end;
        }
    }

    /// Retries packets whose keys were missing (after the key log changed).
    pub fn retry(&mut self, keylog: &KeyLog, out: &mut Vec<QuicOut>) {
        let pending = std::mem::take(&mut self.pending);
        for pd in pending {
            self.packet(pd.dir, pd.pkt, &pd.data, pd.pn_off, pd.level, keylog, out, false);
        }
    }

    fn suite(&self) -> Option<Suite> {
        self.suite.and_then(suite_info)
    }

    fn keys_for(&mut self, dir: usize, level: Level, keylog: &KeyLog) -> Option<Keys> {
        match level {
            Level::Initial => self.initial.as_ref().map(|k| k[dir].clone()),
            Level::Handshake => {
                if self.handshake[dir].is_none() {
                    let (cr, suite) = (self.client_random?, self.suite()?);
                    let lbl = if self.is_client(dir) { "CLIENT_HANDSHAKE_TRAFFIC_SECRET" } else { "SERVER_HANDSHAKE_TRAFFIC_SECRET" };
                    self.handshake[dir] = Some(keys_from_secret(self.version, suite, keylog.get(lbl, &cr)?));
                }
                self.handshake[dir].clone()
            }
            Level::ZeroRtt => {
                if self.zero_rtt.is_none() {
                    let cr = self.client_random?;
                    // 0-RTT uses the cipher suite of the resumed session; assume the offered default.
                    let suite = self.suite().or_else(|| suite_info(0x1301))?;
                    self.zero_rtt = Some(keys_from_secret(self.version, suite, keylog.get("CLIENT_EARLY_TRAFFIC_SECRET", &cr)?));
                }
                self.zero_rtt.clone()
            }
            Level::OneRtt => {
                if self.app[dir].is_none() {
                    let (cr, suite) = (self.client_random?, self.suite()?);
                    let lbl = if self.is_client(dir) { "CLIENT_TRAFFIC_SECRET_0" } else { "SERVER_TRAFFIC_SECRET_0" };
                    let secret = keylog.get(lbl, &cr)?.to_vec();
                    let current = keys_from_secret(self.version, suite, &secret);
                    self.app[dir] = Some(AppKeys { secret, phase: false, current, prev: None });
                }
                self.app[dir].as_ref().map(|a| a.current.clone())
            }
        }
    }

    /// Removes header protection and decrypts one QUIC packet `pk` (header + payload).
    #[allow(clippy::too_many_arguments)]
    fn packet(&mut self, dir: usize, pkt: usize, pk: &[u8], pn_off: usize, level: Level, keylog: &KeyLog, out: &mut Vec<QuicOut>, fresh: bool) {
        let long = pk[0] & 0x80 != 0;
        if level == Level::Handshake && self.ech && !self.ech_resolved && self.key_search_at != keylog.len() {
            self.key_search_at = keylog.len();
            self.find_inner_random(dir, pk, pn_off, keylog);
        }
        let Some(keys) = self.keys_for(dir, level, keylog) else {
            self.protected_packets += fresh as usize;
            if level != Level::Initial && self.status != TlsStatus::Decrypting {
                self.status = TlsStatus::WaitingForKeys;
            }
            let why = if level == Level::Initial { "Initial keys unknown (client Initial not captured)" } else { "keys not in key log" };
            out.push(QuicOut { pkt, dir, level, payload: None, summary: format!("{} [protected: {why}]", level.name()) });
            if level != Level::Initial {
                self.pending.push(Pending { dir, pkt, data: pk.to_vec(), pn_off, level });
            }
            return;
        };
        let Some(sample) = pk.get(pn_off + 4..pn_off + 20) else {
            out.push(QuicOut { pkt, dir, level, payload: None, summary: format!("{} [truncated]", level.name()) });
            return;
        };
        let Some(mask) = hp_mask(keys.cipher, &keys.hp, sample) else { return };
        let first = pk[0] ^ (mask[0] & if long { 0x0f } else { 0x1f });
        let pn_len = (first & 3) as usize + 1;
        let mut hdr = pk[..pn_off + pn_len].to_vec();
        hdr[0] = first;
        let mut truncated = 0u64;
        for i in 0..pn_len {
            hdr[pn_off + i] ^= mask[1 + i];
            truncated = (truncated << 8) | hdr[pn_off + i] as u64;
        }
        let space = level.space();
        let pn = decode_pn(self.largest[dir][space], truncated, pn_len as u32 * 8);
        let ct = &pk[pn_off + pn_len..];
        let open = |k: &Keys| aead_open(k.cipher, &k.key, &xor_nonce(&k.iv, pn), &hdr, ct);

        let mut payload = open(&keys);
        if payload.is_none() && level == Level::OneRtt {
            payload = self.try_key_update(dir, first & 0x04 != 0, &open);
        }
        let Some(payload) = payload else {
            out.push(QuicOut { pkt, dir, level, payload: None, summary: format!("{} PKN={pn} [decryption failed]", level.name()) });
            if level != Level::Initial && self.decrypted_packets == 0 {
                self.status = TlsStatus::Failed("QUIC packet authentication failed (wrong keys?)".into());
            }
            return;
        };
        self.largest[dir][space] = Some(self.largest[dir][space].map_or(pn, |l| l.max(pn)));
        if level != Level::Initial {
            self.decrypted_packets += 1;
            self.status = TlsStatus::Decrypting;
        }
        let summary = self.frames(dir, pkt, level, &payload);
        let kp = if level == Level::OneRtt { format!(" KP{}", (first >> 2) & 1) } else { String::new() };
        out.push(QuicOut { pkt, dir, level, payload: Some(payload), summary: format!("{} PKN={pn}{kp}: {summary}", level.name()) });
    }

    /// ECH: keys are logged under the inner ClientHello's random, which is encrypted on the wire.
    /// Try each logged handshake secret on this Handshake packet; the AEAD tag only verifies
    /// with the right one.
    fn find_inner_random(&mut self, dir: usize, pk: &[u8], pn_off: usize, keylog: &KeyLog) {
        let Some(suite) = self.suite() else { return };
        let label = if self.is_client(dir) { "CLIENT_HANDSHAKE_TRAFFIC_SECRET" } else { "SERVER_HANDSHAKE_TRAFFIC_SECRET" };
        if self.client_random.is_some_and(|cr| keylog.get(label, &cr).is_some()) {
            return; // ECH not accepted: keys are under the outer random.
        }
        for cand in keylog.randoms(label) {
            let keys = keys_from_secret(self.version, suite, keylog.get(label, &cand).unwrap());
            if open_packet(&keys, pk, pn_off, self.largest[dir][1]).is_some() {
                self.client_random = Some(cand);
                self.ech_resolved = true;
                self.handshake = [None, None];
                self.app = [None, None];
                return;
            }
        }
    }

    /// Handles a 1-RTT key phase change (RFC 9001 §6): tries the next generation, then the
    /// previous one (for reordered packets).
    fn try_key_update(&mut self, dir: usize, phase: bool, open: &dyn Fn(&Keys) -> Option<Vec<u8>>) -> Option<Vec<u8>> {
        let version = self.version;
        let suite = self.suite()?;
        let app = self.app[dir].as_mut()?;
        if phase != app.phase {
            let next_secret = hkdf_expand_label(suite.hash, &app.secret, &label(version, "ku"), &[], suite.hash.len());
            let mut next = keys_from_secret(version, suite, &next_secret);
            next.hp = app.current.hp.clone();
            if let Some(pt) = open(&next) {
                app.prev = Some(std::mem::replace(&mut app.current, next));
                app.secret = next_secret;
                app.phase = phase;
                return Some(pt);
            }
        }
        app.prev.as_ref().and_then(open)
    }

    fn frames(&mut self, dir: usize, pkt: usize, level: Level, payload: &[u8]) -> String {
        let (frames, err) = parse_frames(payload);
        let mut names: Vec<String> = Vec::new();
        for (f, _, _) in &frames {
            match f {
                QFrame::Crypto { off, start, len } => {
                    let space = level.space();
                    self.crypto[dir][space].add(*off, &payload[*start..*start + *len], pkt);
                    let msgs = self.crypto_messages(dir, space);
                    names.push(if msgs.is_empty() { "CRYPTO".into() } else { format!("CRYPTO({})", msgs.join(", ")) });
                }
                QFrame::Stream { id, off, fin, start, len } => {
                    names.push(format!("STREAM({id})"));
                    let is_h3 = self.alpn.as_deref().map(|a| a.starts_with("h3")).unwrap_or(true);
                    if is_h3 {
                        self.h3.stream_data(dir, pkt, *id, *off, *fin, &payload[*start..*start + *len]);
                    }
                }
                QFrame::NewConnectionId { cid, .. } => {
                    // The peer will use this CID when sending to the frame's sender.
                    self.known_dcids[1 - dir].insert(cid.clone());
                    names.push("NEW_CONNECTION_ID".into());
                }
                QFrame::Padding(_) => {}
                other => names.push(frame_name(other).split('(').next().unwrap().to_string()),
            }
        }
        if frames.iter().any(|f| matches!(f.0, QFrame::Padding(_))) {
            names.push("PADDING".into());
        }
        names.dedup();
        if let Some(e) = err {
            names.push(format!("[{e}]"));
        }
        names.join(", ")
    }

    /// Parses complete TLS handshake messages from a CRYPTO stream; returns their names.
    fn crypto_messages(&mut self, dir: usize, space: usize) -> Vec<String> {
        let mut names = Vec::new();
        loop {
            let cs = &mut self.crypto[dir][space];
            let b = &cs.data[cs.parsed..];
            if b.len() < 4 {
                break;
            }
            let mt = b[0];
            let ml = be24(b, 1).unwrap() as usize;
            if b.len() < 4 + ml {
                break;
            }
            let msg = b[..4 + ml].to_vec();
            cs.parsed += 4 + ml;
            let mut scratch = Field::default();
            let hs = tls_handshake_body(&msg, mt, 4, msg.len(), &mut scratch);
            let mut name = tls_hs_name(mt).unwrap_or("Unknown").to_string();
            match mt {
                1 => {
                    self.client_dir = Some(dir);
                    self.client_random = self.client_random.or(hs.random);
                    self.ech |= hs.ech;
                    if let Some(s) = &hs.sni {
                        name = format!("{name} SNI={s}");
                        self.sni = Some(s.clone());
                    }
                }
                2 => self.suite = hs.suite,
                8 => {
                    if let Some(a) = alpn_from_extensions(&msg[4..]) {
                        name = format!("{name} ALPN={a}");
                        self.alpn = Some(a);
                    }
                }
                _ => {}
            }
            names.push(name);
        }
        names
    }
}

/// Removes header protection and opens one packet with the given keys (no state changes).
fn open_packet(k: &Keys, pk: &[u8], pn_off: usize, largest: Option<u64>) -> Option<(u64, Vec<u8>)> {
    let long = pk[0] & 0x80 != 0;
    let mask = hp_mask(k.cipher, &k.hp, pk.get(pn_off + 4..pn_off + 20)?)?;
    let first = pk[0] ^ (mask[0] & if long { 0x0f } else { 0x1f });
    let pn_len = (first & 3) as usize + 1;
    let mut hdr = pk.get(..pn_off + pn_len)?.to_vec();
    hdr[0] = first;
    let mut truncated = 0u64;
    for i in 0..pn_len {
        hdr[pn_off + i] ^= mask[1 + i];
        truncated = (truncated << 8) | hdr[pn_off + i] as u64;
    }
    let pn = decode_pn(largest, truncated, pn_len as u32 * 8);
    aead_open(k.cipher, &k.key, &xor_nonce(&k.iv, pn), &hdr, &pk[pn_off + pn_len..]).map(|p| (pn, p))
}

struct LongHeader<'a> {
    version: u32,
    dcid: &'a [u8],
    scid: &'a [u8],
    level: Level,
    retry: bool,
    pn_off: usize,
    len: usize,
}

fn parse_long_header(d: &[u8], p: usize) -> Option<LongHeader<'_>> {
    let first = d[p];
    let version = be32(d, p + 1)?;
    let dl = *d.get(p + 5)? as usize;
    let dcid = d.get(p + 6..p + 6 + dl)?;
    let mut q = p + 6 + dl;
    let sl = *d.get(q)? as usize;
    let scid = d.get(q + 1..q + 1 + sl)?;
    q += 1 + sl;
    if version == 0 {
        return Some(LongHeader { version, dcid, scid, level: Level::Initial, retry: false, pn_off: q, len: 0 });
    }
    let t = (first >> 4) & 3;
    let t = if version == V2 { (t + 3) % 4 } else { t };
    let (level, retry) = match t {
        0 => (Level::Initial, false),
        1 => (Level::ZeroRtt, false),
        2 => (Level::Handshake, false),
        _ => (Level::Initial, true),
    };
    if retry {
        return Some(LongHeader { version, dcid, scid, level, retry, pn_off: q, len: 0 });
    }
    if level == Level::Initial {
        let tl = varint(d, &mut q)? as usize;
        q += tl;
    }
    let len = varint(d, &mut q)? as usize;
    Some(LongHeader { version, dcid, scid, level, retry, pn_off: q, len })
}

// ---------------------------------------------------------------------------------------------
// HTTP/3

#[derive(Default)]
struct H3Stream {
    s: OffsetStream,
    uni_type: Option<u64>,
}

#[derive(Default)]
pub struct H3Conn {
    streams: HashMap<(usize, u64), H3Stream>,
    qpack: [QpackDecoder; 2],
    /// Header blocks waiting for encoder-stream inserts: (dir, stream, pkt, block, msg index).
    blocked: Vec<(usize, u64, usize, Vec<u8>, usize)>,
    pub msgs: Vec<HttpMsg>,
    /// Earlier messages whose headers were filled in after their encoder-stream inserts arrived.
    pub updated: Vec<usize>,
}

fn h3_frame_name(t: u64) -> &'static str {
    match t {
        0x0 => "DATA",
        0x1 => "HEADERS",
        0x3 => "CANCEL_PUSH",
        0x4 => "SETTINGS",
        0x5 => "PUSH_PROMISE",
        0x7 => "GOAWAY",
        0xd => "MAX_PUSH_ID",
        _ => "UNKNOWN",
    }
}

impl H3Conn {
    /// QPACK dynamic-table entries inserted per direction (to see if the peer used it).
    #[cfg(test)]
    pub fn dynamic_inserts(&self) -> [u64; 2] {
        [self.qpack[0].inserted(), self.qpack[1].inserted()]
    }

    fn stream_data(&mut self, dir: usize, pkt: usize, id: u64, off: u64, fin: bool, data: &[u8]) {
        let st = self.streams.entry((dir, id)).or_default();
        st.s.add(off, data, pkt);
        st.s.fin |= fin;
        self.process(dir, id);
    }

    fn process(&mut self, dir: usize, id: u64) {
        let unidirectional = id & 0x2 != 0;
        loop {
            let Some(st) = self.streams.get_mut(&(dir, id)) else { return };
            let b = &st.s.data;
            let mut p = st.s.parsed;
            if unidirectional && st.uni_type.is_none() {
                let Some(t) = varint(b, &mut p) else { return };
                st.uni_type = Some(t);
                st.s.parsed = p;
                continue;
            }
            if unidirectional && st.uni_type == Some(0x02) {
                // QPACK encoder stream: raw instructions.
                let new = b[p..].to_vec();
                st.s.parsed = b.len();
                if !new.is_empty() {
                    self.qpack[dir].encoder_stream(&new);
                    self.retry_blocked(dir);
                }
                return;
            }
            if unidirectional && st.uni_type != Some(0x00) {
                st.s.parsed = b.len(); // decoder stream, push, or reserved
                return;
            }
            let Some(ty) = varint(b, &mut p) else { return };
            let Some(len) = varint(b, &mut p) else { return };
            let len = len as usize;
            if b.len() < p + len {
                // DATA frames can be large; report what has arrived only once complete.
                return;
            }
            let payload = b[p..p + len].to_vec();
            st.s.parsed = p + len;
            let pkt = pkt_for(&st.s.chunks, p + len.max(1) - 1);
            let end_stream = st.s.fin && st.s.parsed == st.s.data.len();
            self.frame(dir, id, pkt, ty, payload, end_stream);
        }
    }

    fn frame(&mut self, dir: usize, id: u64, pkt: usize, ty: u64, payload: Vec<u8>, end_stream: bool) {
        let mut msg = HttpMsg {
            version: 3,
            dir,
            pkt,
            stream_id: id,
            kind: h3_frame_name(ty),
            headers: Vec::new(),
            data: Vec::new(),
            data_len: 0,
            end_stream,
            note: String::new(),
        };
        match ty {
            0x0 => {
                msg.data = payload[..payload.len().min(HTTP_BODY_CAP)].to_vec();
                msg.data_len = payload.len();
            }
            0x1 => match self.qpack[dir].decode(&payload) {
                Ok(h) => msg.headers = h,
                Err(e) if e.contains("needs") => {
                    msg.note = "waiting for QPACK encoder stream".into();
                    self.blocked.push((dir, id, pkt, payload, self.msgs.len()));
                }
                Err(e) => msg.note = e,
            },
            0x4 => {
                let mut p = 0;
                while p < payload.len() {
                    let (Some(k), Some(v)) = (varint(&payload, &mut p), varint(&payload, &mut p)) else { break };
                    if k == 0x01 {
                        // The peer's decoder limit bounds the encoder in the other direction.
                        self.qpack[1 - dir].max_capacity = Some(v);
                    }
                    msg.headers.push((h3_setting_name(k), v.to_string()));
                }
            }
            0x7 => msg.note = format!("id {}", varint(&payload, &mut 0).unwrap_or(0)),
            _ => return,
        }
        self.msgs.push(msg);
    }

    fn retry_blocked(&mut self, dir: usize) {
        let blocked = std::mem::take(&mut self.blocked);
        for (d, id, pkt, block, idx) in blocked {
            if d != dir {
                self.blocked.push((d, id, pkt, block, idx));
                continue;
            }
            match self.qpack[dir].decode(&block) {
                Ok(h) => {
                    self.msgs[idx].headers = h;
                    self.msgs[idx].note.clear();
                    self.msgs[idx].pkt = self.msgs[idx].pkt.max(pkt);
                    self.updated.push(idx);
                }
                Err(e) if e.contains("needs") => self.blocked.push((d, id, pkt, block, idx)),
                Err(e) => self.msgs[idx].note = e,
            }
        }
    }
}

fn h3_setting_name(k: u64) -> String {
    match k {
        0x01 => "QPACK_MAX_TABLE_CAPACITY".into(),
        0x06 => "MAX_FIELD_SECTION_SIZE".into(),
        0x07 => "QPACK_BLOCKED_STREAMS".into(),
        0x08 => "ENABLE_CONNECT_PROTOCOL".into(),
        0x33 => "H3_DATAGRAM".into(),
        _ => format!("0x{k:x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 9001 Appendix A.1 / A.2 (QUIC v1 Initial keys).
    #[test]
    fn rfc9001_initial_keys() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let [c, s] = initial_keys(V1, &dcid);
        assert_eq!(hex(&c.key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(hex(&c.iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(hex(&c.hp), "9f50449e04a0e810283a1e9933adedd2");
        assert_eq!(hex(&s.key), "cf3a5331653c364c88f0f379b6067e37");
        assert_eq!(hex(&s.iv), "0ac1493ca1905853b0bba03e");
        assert_eq!(hex(&s.hp), "c206b8d9b9f0f37644430b490eeaa314");
        // A.2 header protection sample → mask.
        let sample = [0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8, 0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b];
        assert_eq!(hex(&hp_mask(c.cipher, &c.hp, &sample).unwrap()), "437b9aec36");
    }

    // RFC 9001 Appendix A.5: ChaCha20 header protection.
    #[test]
    fn rfc9001_chacha_hp() {
        let hp = (0..32).map(|i| u8::from_str_radix(&"25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"[i * 2..i * 2 + 2], 16).unwrap()).collect::<Vec<_>>();
        let sample = [0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80, 0x57, 0x5d, 0x79, 0x99, 0xc2, 0x5a, 0x5b, 0xfb];
        assert_eq!(hex(&hp_mask(CipherAlg::ChaCha20, &hp, &sample).unwrap()), "aefefe7d03");
    }

    #[test]
    fn packet_number_decoding() {
        // RFC 9000 A.3 example.
        assert_eq!(decode_pn(Some(0xa82f30ea), 0x9b32, 16), 0xa82f9b32);
        assert_eq!(decode_pn(None, 0, 8), 0);
    }
}
