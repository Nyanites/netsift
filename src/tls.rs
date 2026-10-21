//! TLS session tracking and decryption using NSS key log files (SSLKEYLOGFILE).
//!
//! Supports TLS 1.2 AEAD suites (AES-GCM, ChaCha20-Poly1305) via `CLIENT_RANDOM` master secrets,
//! and TLS 1.3 (all three standard suites) via handshake/application traffic secrets, including
//! KeyUpdate.

use crate::dissect::{be16, be24, tls_alert_name, tls_handshake_body, tls_hs_name, cipher_suite_name};
use crate::model::{Decrypted, Field};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

// ---------------------------------------------------------------------------------------------
// Key log

#[derive(Default)]
pub struct KeyLog {
    entries: HashMap<(String, [u8; 32]), Vec<u8>>,
    pub path: Option<PathBuf>,
    mtime: Option<SystemTime>,
}

impl KeyLog {
    pub fn load(path: &Path) -> std::io::Result<KeyLog> {
        let text = std::fs::read_to_string(path)?;
        let mut k = KeyLog { path: Some(path.to_path_buf()), ..Default::default() };
        k.mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
        k.parse(&text);
        Ok(k)
    }

    pub fn parse(&mut self, text: &str) {
        for line in text.lines() {
            let mut it = line.split_whitespace();
            let (Some(label), Some(cr), Some(secret)) = (it.next(), it.next(), it.next()) else { continue };
            if label.starts_with('#') {
                continue;
            }
            let (Some(cr), Some(secret)) = (unhex(cr), unhex(secret)) else { continue };
            let Ok(cr) = <[u8; 32]>::try_from(cr.as_slice()) else { continue };
            self.entries.insert((label.to_string(), cr), secret);
        }
    }

    /// Re-reads the file if it changed on disk. Returns true when new keys were loaded.
    pub fn reload_if_changed(&mut self) -> bool {
        let Some(path) = self.path.clone() else { return false };
        let m = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        if m.is_some() && m != self.mtime
            && let Ok(text) = std::fs::read_to_string(&path) {
                let before = self.entries.len();
                self.parse(&text);
                self.mtime = m;
                return self.entries.len() != before;
            }
        false
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn sessions(&self) -> usize {
        let mut s: Vec<&[u8; 32]> = self.entries.keys().map(|(_, cr)| cr).collect();
        s.sort();
        s.dedup();
        s.len()
    }

    pub(crate) fn get(&self, label: &str, cr: &[u8; 32]) -> Option<&[u8]> {
        self.entries.get(&(label.to_string(), *cr)).map(|v| v.as_slice())
    }

    /// Client randoms that have a secret with this label (candidates for ECH sessions, whose
    /// keys are logged under the hidden inner ClientHello's random).
    pub(crate) fn randoms(&self, label: &str) -> Vec<[u8; 32]> {
        self.entries.keys().filter(|(l, _)| l == label).map(|(_, cr)| *cr).collect()
    }
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

// ---------------------------------------------------------------------------------------------
// Crypto primitives

#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum HashAlg {
    Sha256,
    Sha384,
}

impl HashAlg {
    pub(crate) fn len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum CipherAlg {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Suite {
    pub cipher: CipherAlg,
    pub hash: HashAlg,
    pub key_len: usize,
}

pub(crate) fn suite_info(s: u16) -> Option<Suite> {
    use CipherAlg::*;
    use HashAlg::*;
    let (cipher, hash) = match s {
        0x1301 | 0x009c | 0x009e | 0xc02b | 0xc02f => (Aes128Gcm, Sha256),
        0x1302 | 0x009d | 0x009f | 0xc02c | 0xc030 => (Aes256Gcm, Sha384),
        0x1303 | 0xcca8 | 0xcca9 | 0xccaa => (ChaCha20, Sha256),
        _ => return None,
    };
    let key_len = if cipher == Aes128Gcm { 16 } else { 32 };
    Some(Suite { cipher, hash, key_len })
}

pub(crate) fn hmac(hash: HashAlg, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    match hash {
        HashAlg::Sha256 => {
            let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("hmac accepts any key length");
            for p in parts {
                m.update(p);
            }
            m.finalize().into_bytes().to_vec()
        }
        HashAlg::Sha384 => {
            let mut m = <Hmac<Sha384> as KeyInit>::new_from_slice(key).expect("hmac accepts any key length");
            for p in parts {
                m.update(p);
            }
            m.finalize().into_bytes().to_vec()
        }
    }
}

/// TLS 1.2 PRF (RFC 5246 §5).
fn prf(hash: HashAlg, secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut full_seed = label.to_vec();
    full_seed.extend_from_slice(seed);
    let mut out = Vec::with_capacity(len);
    let mut a = hmac(hash, secret, &[&full_seed]);
    while out.len() < len {
        out.extend(hmac(hash, secret, &[&a, &full_seed]));
        a = hmac(hash, secret, &[&a]);
    }
    out.truncate(len);
    out
}

/// HKDF-Expand (RFC 5869) with the PRK used directly as the HMAC key.
fn hkdf_expand(hash: HashAlg, prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut i = 1u8;
    while out.len() < len {
        t = hmac(hash, prk, &[&t, info, &[i]]);
        out.extend_from_slice(&t);
        i += 1;
    }
    out.truncate(len);
    out
}

/// HKDF-Expand-Label (RFC 8446 §7.1).
pub(crate) fn hkdf_expand_label(hash: HashAlg, secret: &[u8], label: &str, ctx: &[u8], len: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::new();
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(ctx.len() as u8);
    info.extend_from_slice(ctx);
    hkdf_expand(hash, secret, &info, len)
}

pub(crate) fn aead_open(cipher: CipherAlg, key: &[u8], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    let payload = Payload { msg: ct, aad };
    let n = (*nonce).into();
    match cipher {
        CipherAlg::Aes128Gcm => Aes128Gcm::new_from_slice(key).ok()?.decrypt(&n, payload).ok(),
        CipherAlg::Aes256Gcm => Aes256Gcm::new_from_slice(key).ok()?.decrypt(&n, payload).ok(),
        CipherAlg::ChaCha20 => ChaCha20Poly1305::new_from_slice(key).ok()?.decrypt(&n, payload).ok(),
    }
}

pub(crate) fn xor_nonce(iv: &[u8], seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n.copy_from_slice(&iv[..12]);
    for (i, b) in seq.to_be_bytes().iter().enumerate() {
        n[4 + i] ^= b;
    }
    n
}

// ---------------------------------------------------------------------------------------------
// Session state

#[derive(Clone, Copy, PartialEq, Debug)]
enum Epoch {
    Handshake,
    App(u32),
}

#[derive(Clone, Debug)]
pub struct Record {
    pub ctype: u8,
    pub version: u16,
    /// Offset of the record payload in the reassembled direction buffer.
    pub start: usize,
    pub len: usize,
    pub pkt: usize,
    pub encrypted: bool,
}

#[derive(Default)]
pub struct DirState {
    parsed: usize,
    pub records: Vec<Record>,
    hs_buf: Vec<u8>,
    ccs: bool,
    cursor: usize,
    epoch: Option<Epoch>,
    seq: u64,
    keys: Option<(Epoch, Vec<u8>, Vec<u8>)>,
    desync: bool,
    /// Decrypted application data, with (offset, packet) chunk boundaries.
    pub plain: Vec<u8>,
    pub plain_chunks: Vec<(usize, usize)>,
}

#[derive(Clone, PartialEq, Debug)]
pub enum TlsStatus {
    Handshake,
    WaitingForKeys,
    Decrypting,
    Unsupported(String),
    Failed(String),
}

impl TlsStatus {
    pub fn label(&self) -> String {
        match self {
            TlsStatus::Handshake => "Handshake not seen".into(),
            TlsStatus::WaitingForKeys => "No keys in key log".into(),
            TlsStatus::Decrypting => "Decrypted".into(),
            TlsStatus::Unsupported(s) => format!("Unsupported: {s}"),
            TlsStatus::Failed(s) => format!("Failed: {s}"),
        }
    }
}

pub struct TlsSession {
    pub client_dir: Option<usize>,
    pub client_random: Option<[u8; 32]>,
    pub server_random: Option<[u8; 32]>,
    pub suite: Option<u16>,
    pub version: Option<u16>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub dirs: [DirState; 2],
    pub status: TlsStatus,
    pub decrypted_records: usize,
    pub failed_records: usize,
    tls12_block: Option<Vec<u8>>,
    /// ClientHello offered ECH; `ech_resolved` once the inner random was found in the key log.
    pub ech: bool,
    pub ech_resolved: bool,
    key_search_at: usize,
}

impl Default for TlsSession {
    fn default() -> Self {
        TlsSession {
            client_dir: None,
            client_random: None,
            server_random: None,
            suite: None,
            version: None,
            sni: None,
            alpn: None,
            dirs: Default::default(),
            status: TlsStatus::Handshake,
            decrypted_records: 0,
            failed_records: 0,
            tls12_block: None,
            ech: false,
            ech_resolved: false,
            key_search_at: usize::MAX,
        }
    }
}

pub(crate) fn pkt_for(chunks: &[(usize, usize)], off: usize) -> usize {
    match chunks.binary_search_by(|c| c.0.cmp(&off)) {
        Ok(i) => chunks[i].1,
        Err(0) => chunks.first().map(|c| c.1).unwrap_or(0),
        Err(i) => chunks[i - 1].1,
    }
}

impl TlsSession {
    pub fn is_tls13(&self) -> bool {
        self.version == Some(0x0304)
    }

    pub fn suite_name(&self) -> String {
        self.suite.map(cipher_suite_name).unwrap_or_else(|| "?".into())
    }

    /// Feeds newly reassembled bytes for both directions and decrypts whatever can be decrypted.
    pub fn update(
        &mut self,
        bufs: [&[u8]; 2],
        chunks: [&[(usize, usize)]; 2],
        keylog: &KeyLog,
        out: &mut Vec<(usize, Decrypted)>,
    ) {
        for (dir, (buf, ch)) in bufs.iter().zip(chunks).enumerate() {
            self.parse_records(dir, buf, ch);
        }
        for (dir, buf) in bufs.iter().enumerate() {
            self.decrypt_pending(dir, buf, keylog, out);
        }
    }

    /// If nothing decrypted yet, forget derived keys so a new key log gets a fresh attempt.
    pub fn reset_if_failed(&mut self) {
        if self.decrypted_records == 0 {
            for d in &mut self.dirs {
                d.cursor = 0;
                d.epoch = None;
                d.seq = 0;
                d.keys = None;
            }
            self.tls12_block = None;
            self.failed_records = 0;
            if matches!(self.status, TlsStatus::Failed(_)) {
                self.status = TlsStatus::WaitingForKeys;
            }
        }
    }

    fn parse_records(&mut self, dir: usize, buf: &[u8], chunks: &[(usize, usize)]) {
        loop {
            let st = &mut self.dirs[dir];
            if st.desync {
                return;
            }
            let p = st.parsed;
            if p + 5 > buf.len() {
                return;
            }
            let ct = buf[p];
            let ver = be16(buf, p + 1).unwrap();
            let len = be16(buf, p + 3).unwrap() as usize;
            if !(20..=24).contains(&ct) || buf[p + 1] != 3 || len > 18432 {
                st.desync = true;
                return;
            }
            if p + 5 + len > buf.len() {
                return;
            }
            let tls13 = self.version == Some(0x0304);
            let st = &mut self.dirs[dir];
            let encrypted = ct == 23 || (st.ccs && !tls13 && ct != 20);
            let rec = Record { ctype: ct, version: ver, start: p + 5, len, pkt: pkt_for(chunks, p + 5 + len - 1), encrypted };
            st.parsed = p + 5 + len;
            if ct == 20 {
                st.ccs = true;
            }
            if ct == 22 && !encrypted {
                st.hs_buf.extend_from_slice(&buf[p + 5..p + 5 + len]);
                self.parse_plain_handshake(dir);
            }
            self.dirs[dir].records.push(rec);
        }
    }

    fn parse_plain_handshake(&mut self, dir: usize) {
        loop {
            let hb = &self.dirs[dir].hs_buf;
            if hb.len() < 4 {
                return;
            }
            let mt = hb[0];
            let mlen = be24(hb, 1).unwrap() as usize;
            if hb.len() < 4 + mlen {
                return;
            }
            let msg: Vec<u8> = hb[..4 + mlen].to_vec();
            self.dirs[dir].hs_buf.drain(..4 + mlen);
            let mut scratch = Field::default();
            let hs = tls_handshake_body(&msg, mt, 4, msg.len(), &mut scratch);
            match mt {
                1 => {
                    self.client_dir = Some(dir);
                    if self.client_random.is_none() {
                        self.client_random = hs.random;
                    }
                    if hs.sni.is_some() {
                        self.sni = hs.sni;
                    }
                    self.ech |= hs.ech;
                }
                2 if !hs.hrr => {
                    self.server_random = hs.random;
                    self.suite = hs.suite;
                    self.version = Some(hs.selected_version.unwrap_or_else(|| be16(&msg, 4).unwrap_or(0)));
                    self.alpn = hs.alpn.first().cloned();
                }
                _ => {}
            }
        }
    }

    fn is_client(&self, dir: usize) -> bool {
        self.client_dir.map(|c| c == dir).unwrap_or(dir == 0)
    }

    /// Derives (key, iv) for a direction/epoch, or None if the key log lacks the secret.
    fn derive(&mut self, dir: usize, epoch: Epoch, suite: Suite, keylog: &KeyLog) -> Option<(Vec<u8>, Vec<u8>)> {
        let cr = self.client_random?;
        let client = self.is_client(dir);
        if self.is_tls13() {
            let label = match (epoch, client) {
                (Epoch::Handshake, true) => "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                (Epoch::Handshake, false) => "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                (Epoch::App(_), true) => "CLIENT_TRAFFIC_SECRET_0",
                (Epoch::App(_), false) => "SERVER_TRAFFIC_SECRET_0",
            };
            let mut secret = keylog.get(label, &cr)?.to_vec();
            if let Epoch::App(n) = epoch {
                for _ in 0..n {
                    secret = hkdf_expand_label(suite.hash, &secret, "traffic upd", &[], suite.hash.len());
                }
            }
            let key = hkdf_expand_label(suite.hash, &secret, "key", &[], suite.key_len);
            let iv = hkdf_expand_label(suite.hash, &secret, "iv", &[], 12);
            Some((key, iv))
        } else {
            let iv_len = if suite.cipher == CipherAlg::ChaCha20 { 12 } else { 4 };
            if self.tls12_block.is_none() {
                let master = keylog.get("CLIENT_RANDOM", &cr)?;
                let sr = self.server_random?;
                let mut seed = sr.to_vec();
                seed.extend_from_slice(&cr);
                self.tls12_block = Some(prf(suite.hash, master, b"key expansion", &seed, 2 * suite.key_len + 2 * iv_len));
            }
            let kb = self.tls12_block.as_ref()?;
            let k = suite.key_len;
            let (key, iv) = if client {
                (&kb[0..k], &kb[2 * k..2 * k + iv_len])
            } else {
                (&kb[k..2 * k], &kb[2 * k + iv_len..2 * k + 2 * iv_len])
            };
            Some((key.to_vec(), iv.to_vec()))
        }
    }

    fn try_decrypt(&self, suite: Suite, key: &[u8], iv: &[u8], seq: u64, buf: &[u8], rec: &Record) -> Option<(u8, Vec<u8>)> {
        let payload = &buf[rec.start..rec.start + rec.len];
        if self.is_tls13() {
            let aad = &buf[rec.start - 5..rec.start];
            let mut pt = aead_open(suite.cipher, key, &xor_nonce(iv, seq), aad, payload)?;
            while pt.last() == Some(&0) {
                pt.pop();
            }
            let ct = pt.pop()?;
            Some((ct, pt))
        } else {
            let (nonce, ct) = if suite.cipher == CipherAlg::ChaCha20 {
                (xor_nonce(iv, seq), payload)
            } else {
                if payload.len() < 8 {
                    return None;
                }
                let mut n = [0u8; 12];
                n[..4].copy_from_slice(iv);
                n[4..].copy_from_slice(&payload[..8]);
                (n, &payload[8..])
            };
            let plen = ct.len().checked_sub(16)?;
            let mut aad = seq.to_be_bytes().to_vec();
            aad.push(rec.ctype);
            aad.extend_from_slice(&rec.version.to_be_bytes());
            aad.extend_from_slice(&(plen as u16).to_be_bytes());
            let pt = aead_open(suite.cipher, key, &nonce, &aad, ct)?;
            Some((rec.ctype, pt))
        }
    }

    /// ECH: the key log is keyed by the inner ClientHello random, which is encrypted on the wire.
    /// Find it by trying each logged handshake secret on the first encrypted record; the AEAD
    /// tag makes a wrong match impossible.
    fn find_inner_random(&mut self, dir: usize, suite: Suite, seq: u64, buf: &[u8], rec: &Record, keylog: &KeyLog) {
        let label = if self.is_client(dir) { "CLIENT_HANDSHAKE_TRAFFIC_SECRET" } else { "SERVER_HANDSHAKE_TRAFFIC_SECRET" };
        let outer = self.client_random;
        if outer.is_some_and(|cr| keylog.get(label, &cr).is_some()) {
            return; // ECH was not accepted; keys are under the outer random.
        }
        for cand in keylog.randoms(label) {
            self.client_random = Some(cand);
            if let Some((k, iv)) = self.derive(dir, Epoch::Handshake, suite, keylog)
                && self.try_decrypt(suite, &k, &iv, seq, buf, rec).is_some()
            {
                self.ech_resolved = true;
                for d in &mut self.dirs {
                    d.keys = None;
                }
                return;
            }
        }
        self.client_random = outer;
    }

    fn keys_for(&mut self, dir: usize, epoch: Epoch, suite: Suite, keylog: &KeyLog) -> Option<(Vec<u8>, Vec<u8>)> {
        if let Some((e, k, iv)) = &self.dirs[dir].keys
            && *e == epoch {
                return Some((k.clone(), iv.clone()));
            }
        let (k, iv) = self.derive(dir, epoch, suite, keylog)?;
        self.dirs[dir].keys = Some((epoch, k.clone(), iv.clone()));
        Some((k, iv))
    }

    fn decrypt_pending(&mut self, dir: usize, buf: &[u8], keylog: &KeyLog, out: &mut Vec<(usize, Decrypted)>) {
        while self.dirs[dir].cursor < self.dirs[dir].records.len() {
            let rec = self.dirs[dir].records[self.dirs[dir].cursor].clone();
            if !rec.encrypted {
                self.dirs[dir].cursor += 1;
                continue;
            }
            let Some(suite_id) = self.suite else {
                self.status = TlsStatus::Handshake;
                return;
            };
            let Some(suite) = suite_info(suite_id) else {
                self.status = TlsStatus::Unsupported(cipher_suite_name(suite_id));
                return;
            };
            if self.client_random.is_none() {
                self.status = TlsStatus::Handshake;
                return;
            }
            let tls13 = self.is_tls13();
            let epoch = self.dirs[dir].epoch.unwrap_or(if tls13 { Epoch::Handshake } else { Epoch::App(0) });
            let seq = self.dirs[dir].seq;

            if tls13 && self.ech && !self.ech_resolved && epoch == Epoch::Handshake && self.key_search_at != keylog.len() {
                self.key_search_at = keylog.len();
                self.find_inner_random(dir, suite, seq, buf, &rec, keylog);
            }
            let mut result = None;
            let mut used_epoch = epoch;
            let mut used_seq = seq;
            if let Some((k, iv)) = self.keys_for(dir, epoch, suite, keylog) {
                result = self.try_decrypt(suite, &k, &iv, seq, buf, &rec);
            }
            // TLS 1.3: if we missed the Finished message, the record may already be under
            // application keys.
            if result.is_none() && tls13 {
                let next = match epoch {
                    Epoch::Handshake => Epoch::App(0),
                    Epoch::App(n) => Epoch::App(n + 1),
                };
                if let Some((k, iv)) = self.derive(dir, next, suite, keylog)
                    && let Some(r) = self.try_decrypt(suite, &k, &iv, 0, buf, &rec) {
                        self.dirs[dir].keys = Some((next, k, iv));
                        used_epoch = next;
                        used_seq = 0;
                        result = Some(r);
                    }
            }

            let Some((ctype, pt)) = result else {
                if self.dirs[dir].keys.is_none() {
                    if !matches!(self.status, TlsStatus::Decrypting) {
                        self.status = TlsStatus::WaitingForKeys;
                    }
                    return;
                }
                self.failed_records += 1;
                if self.decrypted_records == 0 {
                    self.status = TlsStatus::Failed("authentication failed (wrong or stale key?)".into());
                    return;
                }
                // Skip the record but keep the sequence number advancing.
                self.dirs[dir].seq += 1;
                self.dirs[dir].cursor += 1;
                out.push((rec.pkt, Decrypted { dir, content_type: rec.ctype, data: Vec::new(), note: "Decryption failed for this record".into(), quic: false }));
                continue;
            };

            self.status = TlsStatus::Decrypting;
            self.decrypted_records += 1;
            let st = &mut self.dirs[dir];
            st.epoch = Some(used_epoch);
            st.seq = used_seq + 1;
            st.cursor += 1;

            let mut found_alpn = None;
            let note = match ctype {
                22 => {
                    let mut names = Vec::new();
                    let mut q = 0;
                    while q + 4 <= pt.len() {
                        let mt = pt[q];
                        let ml = be24(&pt, q + 1).unwrap() as usize;
                        names.push(tls_hs_name(mt).unwrap_or("Unknown").to_string());
                        if mt == 8 {
                            found_alpn = pt.get(q + 4..(q + 4 + ml).min(pt.len())).and_then(alpn_from_extensions);
                        }
                        if tls13 && mt == 20 {
                            st.epoch = Some(Epoch::App(0));
                            st.seq = 0;
                        }
                        if tls13 && mt == 24
                            && let Some(Epoch::App(n)) = st.epoch {
                                st.epoch = Some(Epoch::App(n + 1));
                                st.seq = 0;
                            }
                        q += 4 + ml;
                    }
                    format!("Decrypted handshake: {}", names.join(", "))
                }
                21 => {
                    let desc = pt.get(1).copied().unwrap_or(0);
                    format!("Decrypted alert: {}", tls_alert_name(desc))
                }
                23 => {
                    st.plain_chunks.push((st.plain.len(), rec.pkt));
                    st.plain.extend_from_slice(&pt);
                    format!("Decrypted application data ({} bytes)", pt.len())
                }
                _ => format!("Decrypted record type {ctype}"),
            };
            if found_alpn.is_some() {
                self.alpn = found_alpn;
            }
            out.push((rec.pkt, Decrypted { dir, content_type: ctype, data: pt, note, quic: false }));
        }
    }
}

/// Extracts the selected ALPN protocol from a TLS 1.3 EncryptedExtensions body.
pub(crate) fn alpn_from_extensions(b: &[u8]) -> Option<String> {
    let total = be16(b, 0)? as usize;
    let mut p = 2;
    while p + 4 <= (2 + total).min(b.len()) {
        let et = be16(b, p)?;
        let el = be16(b, p + 2)? as usize;
        if et == 16 {
            let l = *b.get(p + 6)? as usize;
            return Some(String::from_utf8_lossy(b.get(p + 7..p + 7 + l)?).to_string());
        }
        p += 4 + el;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8448 "Simple 1-RTT Handshake" server handshake traffic secret → key/iv.
    #[test]
    fn tls13_key_schedule() {
        let secret = unhex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38").unwrap();
        let key = hkdf_expand_label(HashAlg::Sha256, &secret, "key", &[], 16);
        let iv = hkdf_expand_label(HashAlg::Sha256, &secret, "iv", &[], 12);
        assert_eq!(crate::dissect::hex(&key), "3fce516009c21727d0f2e4e86ee403bc");
        assert_eq!(crate::dissect::hex(&iv), "5d313eb2671276ee13000b30");
    }

    // TLS 1.2 PRF test vector (SHA-256) from the IETF TLS WG mailing list.
    #[test]
    fn tls12_prf_sha256() {
        let secret = unhex("9bbe436ba940f017b17652849a71db35").unwrap();
        let seed = unhex("a0ba9f936cda311827a6f796ffd5198c").unwrap();
        let out = prf(HashAlg::Sha256, &secret, b"test label", &seed, 100);
        assert_eq!(
            crate::dissect::hex(&out),
            "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66"
        );
    }
}
