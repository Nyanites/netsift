//! Header compression: HPACK (RFC 7541, HTTP/2) and QPACK (RFC 9204, HTTP/3).

use crate::huffman;
use std::collections::VecDeque;

pub type HeaderList = Vec<(String, String)>;

// ---------------------------------------------------------------------------------------------
// Primitives shared by HPACK and QPACK

/// Prefixed integer (RFC 7541 §5.1). `prefix` is the number of low bits of the first byte used.
pub fn int(b: &[u8], pos: &mut usize, prefix: u32) -> Option<u64> {
    let max = (1u64 << prefix) - 1;
    let mut v = (*b.get(*pos)? as u64) & max;
    *pos += 1;
    if v < max {
        return Some(v);
    }
    let mut shift = 0;
    loop {
        let byte = *b.get(*pos)?;
        *pos += 1;
        v = v.checked_add(((byte & 0x7f) as u64).checked_shl(shift)?)?;
        if byte & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
        if shift > 62 {
            return None;
        }
    }
}

/// String literal whose length uses a `prefix`-bit integer and whose Huffman flag is the bit just
/// above the prefix.
pub fn string(b: &[u8], pos: &mut usize, prefix: u32) -> Option<String> {
    let huff = *b.get(*pos)? & (1 << prefix) != 0;
    let len = int(b, pos, prefix)? as usize;
    let raw = b.get(*pos..pos.checked_add(len)?)?;
    *pos += len;
    let bytes = if huff { huffman::decode(raw)? } else { raw.to_vec() };
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn entry_size(e: &(String, String)) -> usize {
    e.0.len() + e.1.len() + 32
}

// ---------------------------------------------------------------------------------------------
// HPACK

const HPACK_STATIC: [(&str, &str); 61] = [
    (":authority", ""), (":method", "GET"), (":method", "POST"), (":path", "/"), (":path", "/index.html"),
    (":scheme", "http"), (":scheme", "https"), (":status", "200"), (":status", "204"), (":status", "206"),
    (":status", "304"), (":status", "400"), (":status", "404"), (":status", "500"), ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"), ("accept-language", ""), ("accept-ranges", ""), ("accept", ""),
    ("access-control-allow-origin", ""), ("age", ""), ("allow", ""), ("authorization", ""), ("cache-control", ""),
    ("content-disposition", ""), ("content-encoding", ""), ("content-language", ""), ("content-length", ""),
    ("content-location", ""), ("content-range", ""), ("content-type", ""), ("cookie", ""), ("date", ""),
    ("etag", ""), ("expect", ""), ("expires", ""), ("from", ""), ("host", ""), ("if-match", ""),
    ("if-modified-since", ""), ("if-none-match", ""), ("if-range", ""), ("if-unmodified-since", ""),
    ("last-modified", ""), ("link", ""), ("location", ""), ("max-forwards", ""), ("proxy-authenticate", ""),
    ("proxy-authorization", ""), ("range", ""), ("referer", ""), ("refresh", ""), ("retry-after", ""),
    ("server", ""), ("set-cookie", ""), ("strict-transport-security", ""), ("transfer-encoding", ""),
    ("user-agent", ""), ("vary", ""), ("via", ""), ("www-authenticate", ""),
];

/// HPACK decoder for one direction of one connection.
pub struct HpackDecoder {
    table: VecDeque<(String, String)>,
    size: usize,
    max_size: usize,
}

impl Default for HpackDecoder {
    fn default() -> Self {
        HpackDecoder { table: VecDeque::new(), size: 0, max_size: 4096 }
    }
}

impl HpackDecoder {
    fn get(&self, idx: u64) -> Option<(String, String)> {
        let idx = idx as usize;
        if idx == 0 {
            return None;
        }
        if idx <= HPACK_STATIC.len() {
            let (n, v) = HPACK_STATIC[idx - 1];
            return Some((n.to_string(), v.to_string()));
        }
        self.table.get(idx - HPACK_STATIC.len() - 1).cloned()
    }

    fn evict(&mut self) {
        while self.size > self.max_size {
            match self.table.pop_back() {
                Some(e) => self.size -= entry_size(&e),
                None => break,
            }
        }
    }

    fn insert(&mut self, e: (String, String)) {
        self.size += entry_size(&e);
        self.table.push_front(e);
        self.evict();
    }

    #[cfg(test)]
    pub fn dynamic_len(&self) -> usize {
        self.table.len()
    }

    /// Decodes a complete header block. On error, the decoder state is no longer trustworthy
    /// for this connection.
    pub fn decode(&mut self, b: &[u8]) -> Result<HeaderList, String> {
        let mut out = Vec::new();
        let mut p = 0;
        let err = |what: &str| format!("HPACK: malformed {what}");
        while p < b.len() {
            let c = b[p];
            if c & 0x80 != 0 {
                let i = int(b, &mut p, 7).ok_or_else(|| err("index"))?;
                out.push(self.get(i).ok_or_else(|| format!("HPACK: unknown index {i}"))?);
            } else if c & 0xe0 == 0x20 {
                let s = int(b, &mut p, 5).ok_or_else(|| err("size update"))?;
                self.max_size = s as usize;
                self.evict();
            } else {
                let (prefix, index) = if c & 0xc0 == 0x40 { (6, true) } else { (4, false) };
                let ni = int(b, &mut p, prefix).ok_or_else(|| err("literal"))?;
                let name = if ni == 0 {
                    string(b, &mut p, 7).ok_or_else(|| err("name"))?
                } else {
                    self.get(ni).ok_or_else(|| format!("HPACK: unknown name index {ni}"))?.0
                };
                let value = string(b, &mut p, 7).ok_or_else(|| err("value"))?;
                if index {
                    self.insert((name.clone(), value.clone()));
                }
                out.push((name, value));
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------------------------
// QPACK

const QPACK_STATIC: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    ("strict-transport-security", "max-age=31536000; includesubdomains"),
    ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

/// QPACK decoder for one direction: fed by that direction's encoder stream, used for header
/// blocks sent in the same direction.
#[derive(Default)]
pub struct QpackDecoder {
    /// Absolute index i is `entries[i - dropped]`.
    entries: VecDeque<(String, String)>,
    dropped: u64,
    size: usize,
    capacity: usize,
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY advertised by the peer, when known.
    pub max_capacity: Option<u64>,
    /// Bytes of the encoder stream not yet consumed (an instruction may span STREAM frames).
    pending: Vec<u8>,
    pub error: Option<String>,
}

impl QpackDecoder {
    pub fn inserted(&self) -> u64 {
        self.dropped + self.entries.len() as u64
    }

    fn abs(&self, i: u64) -> Option<(String, String)> {
        self.entries.get(i.checked_sub(self.dropped)? as usize).cloned()
    }

    fn insert(&mut self, e: (String, String)) {
        self.size += entry_size(&e);
        self.entries.push_back(e);
        self.evict();
    }

    fn evict(&mut self) {
        while self.size > self.capacity {
            match self.entries.pop_front() {
                Some(e) => {
                    self.size -= entry_size(&e);
                    self.dropped += 1;
                }
                None => break,
            }
        }
    }

    /// Feeds encoder-stream bytes (RFC 9204 §4.3).
    pub fn encoder_stream(&mut self, data: &[u8]) {
        self.pending.extend_from_slice(data);
        let b = std::mem::take(&mut self.pending);
        let mut p = 0;
        while p < b.len() {
            let start = p;
            let c = b[p];
            let done = if c & 0x80 != 0 {
                let is_static = c & 0x40 != 0;
                (|| {
                    let i = int(&b, &mut p, 6)?;
                    let v = string(&b, &mut p, 7)?;
                    Some((is_static, i, v))
                })()
                .map(|(is_static, i, v)| {
                    let name = if is_static {
                        QPACK_STATIC.get(i as usize).map(|e| e.0.to_string())
                    } else {
                        self.inserted().checked_sub(1 + i).and_then(|a| self.abs(a)).map(|e| e.0)
                    };
                    match name {
                        Some(n) => self.insert((n, v)),
                        None => self.error = Some(format!("QPACK: bad name reference {i}")),
                    }
                })
            } else if c & 0x40 != 0 {
                (|| {
                    let n = string(&b, &mut p, 5)?;
                    let v = string(&b, &mut p, 7)?;
                    Some((n, v))
                })()
                .map(|e| self.insert(e))
            } else if c & 0x20 != 0 {
                int(&b, &mut p, 5).map(|cap| {
                    self.capacity = cap as usize;
                    self.evict();
                })
            } else {
                int(&b, &mut p, 5).map(|i| match self.inserted().checked_sub(1 + i).and_then(|a| self.abs(a)) {
                    Some(e) => self.insert(e),
                    None => self.error = Some(format!("QPACK: bad duplicate {i}")),
                })
            };
            if done.is_none() {
                // Incomplete instruction; wait for more data.
                self.pending = b[start..].to_vec();
                return;
            }
        }
    }

    fn required_insert_count(&self, enc: u64) -> Option<u64> {
        if enc == 0 {
            return Some(0);
        }
        let Some(max_cap) = self.max_capacity.filter(|&m| m > 0) else {
            // Without the peer's SETTINGS, assume the block references everything inserted so far.
            return Some(self.inserted());
        };
        let max_entries = max_cap / 32;
        let full = 2 * max_entries;
        if enc > full {
            return None;
        }
        let total = self.inserted();
        let max_value = total + max_entries;
        let max_wrapped = (max_value / full) * full;
        let mut ric = max_wrapped + enc - 1;
        if ric > max_value {
            if ric <= full {
                return None;
            }
            ric -= full;
        }
        if ric == 0 { None } else { Some(ric) }
    }

    /// Decodes a field section (the payload of an HTTP/3 HEADERS frame).
    pub fn decode(&self, b: &[u8]) -> Result<HeaderList, String> {
        let err = |w: &str| format!("QPACK: malformed {w}");
        let mut p = 0;
        let enc = int(b, &mut p, 8).ok_or_else(|| err("prefix"))?;
        let ric = self.required_insert_count(enc).ok_or_else(|| err("required insert count"))?;
        if ric > self.inserted() {
            return Err(format!("QPACK: needs {ric} dynamic entries, only {} seen (encoder stream missing?)", self.inserted()));
        }
        let sign = *b.get(p).ok_or_else(|| err("base"))? & 0x80 != 0;
        let delta = int(b, &mut p, 7).ok_or_else(|| err("base"))?;
        let base = if sign { ric.checked_sub(delta + 1).ok_or_else(|| err("base"))? } else { ric + delta };
        let dynamic = |a: Option<u64>| a.and_then(|a| self.abs(a)).ok_or_else(|| err("dynamic reference"));
        let stat = |i: u64| QPACK_STATIC.get(i as usize).map(|(n, v)| (n.to_string(), v.to_string())).ok_or_else(|| err("static index"));
        let mut out = Vec::new();
        while p < b.len() {
            let c = b[p];
            if c & 0x80 != 0 {
                let i = int(b, &mut p, 6).ok_or_else(|| err("indexed"))?;
                out.push(if c & 0x40 != 0 { stat(i)? } else { dynamic(base.checked_sub(1 + i))? });
            } else if c & 0xf0 == 0x10 {
                let i = int(b, &mut p, 4).ok_or_else(|| err("post-base"))?;
                out.push(dynamic(Some(base + i))?);
            } else if c & 0xc0 == 0x40 {
                let i = int(b, &mut p, 4).ok_or_else(|| err("name ref"))?;
                let name = if c & 0x10 != 0 { stat(i)?.0 } else { dynamic(base.checked_sub(1 + i))?.0 };
                let v = string(b, &mut p, 7).ok_or_else(|| err("value"))?;
                out.push((name, v));
            } else if c & 0xe0 == 0x20 {
                let n = string(b, &mut p, 3).ok_or_else(|| err("name"))?;
                let v = string(b, &mut p, 7).ok_or_else(|| err("value"))?;
                out.push((n, v));
            } else {
                let i = int(b, &mut p, 3).ok_or_else(|| err("post-base name"))?;
                let name = dynamic(Some(base + i))?.0;
                let v = string(b, &mut p, 7).ok_or_else(|| err("value"))?;
                out.push((name, v));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // RFC 7541 C.4: three requests with Huffman coding sharing one dynamic table.
    #[test]
    fn rfc7541_c4() {
        let mut d = HpackDecoder::default();
        let r1 = d.decode(&h("828684418cf1e3c2e5f23a6ba0ab90f4ff")).unwrap();
        assert_eq!(r1[3], (":authority".into(), "www.example.com".into()));
        let r2 = d.decode(&h("828684be5886a8eb10649cbf")).unwrap();
        assert_eq!(r2[3], (":authority".into(), "www.example.com".into()));
        assert_eq!(r2[4], ("cache-control".into(), "no-cache".into()));
        let r3 = d.decode(&h("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf")).unwrap();
        assert_eq!(r3[2], (":path".into(), "/index.html".into()));
        assert_eq!(r3[4], ("custom-key".into(), "custom-value".into()));
        assert_eq!(d.dynamic_len(), 3);
    }

    #[test]
    fn qpack_static_and_dynamic() {
        let mut d = QpackDecoder::default();
        // Static only: :method GET (17), :path "/index.html" literal w/ static name ref (1).
        let blk = [0x00, 0x00, 0xd1, 0x51, 0x0b, b'/', b'i', b'n', b'd', b'e', b'x', b'.', b'h', b't', b'm', b'l'];
        let r = d.decode(&blk).unwrap();
        assert_eq!(r, vec![(":method".into(), "GET".into()), (":path".into(), "/index.html".into())]);
        // Encoder stream: set capacity 220, insert ":authority" (static 0) = "www.example.com".
        d.max_capacity = Some(220);
        let mut enc = vec![0x3f, 0xbd, 0x01, 0xc0, 0x0f];
        enc.extend_from_slice(b"www.example.com");
        d.encoder_stream(&enc[..4]);
        d.encoder_stream(&enc[4..]);
        assert_eq!(d.inserted(), 1);
        // RIC=1 encoded as 2, base delta 0, indexed dynamic relative 0.
        let r = d.decode(&[0x02, 0x00, 0x80]).unwrap();
        assert_eq!(r, vec![(":authority".into(), "www.example.com".into())]);
    }
}
