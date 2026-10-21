//! HTTP/2 connection parsing over a reassembled byte stream (decrypted TLS or cleartext h2c),
//! with per-direction HPACK state so header blocks decode in order.

use crate::dissect::{be24, be32};
use crate::hpack::HpackDecoder;
use crate::model::{HttpMsg, HTTP_BODY_CAP};
use crate::tls::pkt_for;

pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY: u8 = 0x20;

#[derive(Default)]
struct Dir {
    parsed: usize,
    hpack: HpackDecoder,
    /// Header block being continued: (stream, kind, block, END_STREAM seen).
    cont: Option<(u32, &'static str, Vec<u8>, bool)>,
    /// Set once the byte stream stops looking like HTTP/2 (e.g. capture gap).
    dead: bool,
    hpack_broken: bool,
}

#[derive(Default)]
pub struct H2Conn {
    dirs: [Dir; 2],
    pub msgs: Vec<HttpMsg>,
}

impl H2Conn {
    /// Parses newly available frames. Returns indices of messages added to `msgs`.
    pub fn update(&mut self, bufs: [&[u8]; 2], chunks: [&[(usize, usize)]; 2]) -> Vec<usize> {
        let first_new = self.msgs.len();
        for (dir, (buf, ch)) in bufs.iter().zip(chunks).enumerate() {
            self.parse_dir(dir, buf, ch);
        }
        (first_new..self.msgs.len()).collect()
    }

    fn parse_dir(&mut self, dir: usize, buf: &[u8], chunks: &[(usize, usize)]) {
        loop {
            let st = &mut self.dirs[dir];
            if st.dead {
                return;
            }
            let p = st.parsed;
            if p == 0 && buf.len() >= PREFACE.len() && buf.starts_with(PREFACE) {
                st.parsed = PREFACE.len();
                continue;
            }
            if p == 0 && buf.len() < PREFACE.len() && PREFACE.starts_with(buf) {
                return; // Could still be the preface; wait.
            }
            if p + 9 > buf.len() {
                return;
            }
            let len = be24(buf, p).unwrap() as usize;
            let ty = buf[p + 3];
            let flags = buf[p + 4];
            let sid = be32(buf, p + 5).unwrap() & 0x7fff_ffff;
            if len > 16_777_215 || (ty > 9 && len > 1 << 20) {
                st.dead = true;
                return;
            }
            if p + 9 + len > buf.len() {
                return;
            }
            st.parsed = p + 9 + len;
            let pkt = pkt_for(chunks, p + 9 + len - 1);
            let payload = &buf[p + 9..p + 9 + len];
            self.frame(dir, pkt, ty, flags, sid, payload);
        }
    }

    fn strip_padding(flags: u8, payload: &[u8]) -> Option<&[u8]> {
        if flags & PADDED == 0 {
            return Some(payload);
        }
        let pad = *payload.first()? as usize;
        payload.get(1..payload.len().checked_sub(pad)?)
    }

    fn msg(&mut self, dir: usize, pkt: usize, sid: u32, kind: &'static str) -> &mut HttpMsg {
        self.msgs.push(HttpMsg {
            version: 2,
            dir,
            pkt,
            stream_id: sid as u64,
            kind,
            headers: Vec::new(),
            data: Vec::new(),
            data_len: 0,
            end_stream: false,
            note: String::new(),
        });
        self.msgs.last_mut().unwrap()
    }

    fn frame(&mut self, dir: usize, pkt: usize, ty: u8, flags: u8, sid: u32, payload: &[u8]) {
        match ty {
            0 => {
                let Some(d) = Self::strip_padding(flags, payload) else { return };
                let m = self.msg(dir, pkt, sid, "DATA");
                m.data = d[..d.len().min(HTTP_BODY_CAP)].to_vec();
                m.data_len = d.len();
                m.end_stream = flags & END_STREAM != 0;
            }
            1 | 5 => {
                let Some(mut d) = Self::strip_padding(flags, payload) else { return };
                if ty == 1 && flags & PRIORITY != 0 {
                    d = d.get(5..).unwrap_or(&[]);
                }
                let kind = if ty == 1 { "HEADERS" } else { "PUSH_PROMISE" };
                if ty == 5 {
                    d = d.get(4..).unwrap_or(&[]);
                }
                let es = flags & END_STREAM != 0;
                if flags & END_HEADERS != 0 {
                    self.headers(dir, pkt, sid, kind, d.to_vec(), es);
                } else {
                    self.dirs[dir].cont = Some((sid, kind, d.to_vec(), es));
                }
            }
            9 => {
                if let Some((s, kind, mut block, es)) = self.dirs[dir].cont.take() {
                    block.extend_from_slice(payload);
                    if flags & END_HEADERS != 0 {
                        self.headers(dir, pkt, s, kind, block, es);
                    } else {
                        self.dirs[dir].cont = Some((s, kind, block, es));
                    }
                }
            }
            3 => {
                let code = be32(payload, 0).unwrap_or(0);
                self.msg(dir, pkt, sid, "RST_STREAM").note = format!("error {}", h2_error(code));
            }
            7 => {
                let last = be32(payload, 0).unwrap_or(0) & 0x7fff_ffff;
                let code = be32(payload, 4).unwrap_or(0);
                self.msg(dir, pkt, 0, "GOAWAY").note = format!("last stream {last}, {}", h2_error(code));
            }
            _ => {}
        }
    }

    fn headers(&mut self, dir: usize, pkt: usize, sid: u32, kind: &'static str, block: Vec<u8>, es: bool) {
        let st = &mut self.dirs[dir];
        let result = if st.hpack_broken { Err("HPACK state lost earlier in this direction".to_string()) } else { st.hpack.decode(&block) };
        let m = self.msg(dir, pkt, sid, kind);
        m.end_stream = es;
        match result {
            Ok(h) => m.headers = h,
            Err(e) => {
                m.note = e;
                self.dirs[dir].hpack_broken = true;
            }
        }
    }
}

fn h2_error(code: u32) -> String {
    let name = match code {
        0 => "NO_ERROR",
        1 => "PROTOCOL_ERROR",
        2 => "INTERNAL_ERROR",
        3 => "FLOW_CONTROL_ERROR",
        5 => "STREAM_CLOSED",
        7 => "REFUSED_STREAM",
        8 => "CANCEL",
        9 => "COMPRESSION_ERROR",
        11 => "ENHANCE_YOUR_CALM",
        13 => "HTTP_1_1_REQUIRED",
        _ => return format!("0x{code:x}"),
    };
    name.to_string()
}
