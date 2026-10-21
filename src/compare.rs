//! Capture comparison: which packets of capture A also appear in capture B (e.g. client-side vs
//! server-side captures), which went missing, which are new, and how long they took.

use crate::engine::Engine;
use crate::model::PacketRow;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

pub struct CompareResult {
    pub a_len: usize,
    pub b_len: usize,
    /// (index in A, index in B)
    pub matched: Vec<(usize, usize)>,
    pub only_a: Vec<usize>,
    pub only_b: Vec<usize>,
    /// Sorted B-minus-A timestamp differences of matched packets, in seconds.
    pub deltas: Vec<f64>,
    /// Conversations with the most packets missing from B: (label, missing, total).
    pub lossy_convs: Vec<(String, usize, usize)>,
}

impl CompareResult {
    pub fn percentile(&self, p: f64) -> Option<f64> {
        if self.deltas.is_empty() {
            return None;
        }
        let i = ((self.deltas.len() - 1) as f64 * p).round() as usize;
        Some(self.deltas[i])
    }

    pub fn summary(&self) -> String {
        let mut s = format!(
            "A: {} packets, B: {} packets\nmatched: {}  only in A (missing from B): {}  only in B (new in B): {}",
            self.a_len,
            self.b_len,
            self.matched.len(),
            self.only_a.len(),
            self.only_b.len()
        );
        if let (Some(min), Some(med), Some(p95), Some(max)) = (self.percentile(0.0), self.percentile(0.5), self.percentile(0.95), self.percentile(1.0)) {
            s.push_str(&format!(
                "\ntime B−A: min {:.3} ms, median {:.3} ms, p95 {:.3} ms, max {:.3} ms",
                min * 1e3,
                med * 1e3,
                p95 * 1e3,
                max * 1e3
            ));
        }
        for (label, missing, total) in self.lossy_convs.iter().take(5) {
            s.push_str(&format!("\n  {missing}/{total} packets missing in {label}"));
        }
        s
    }
}

/// A packet identity that survives routers, NAT and different capture setups: transport header
/// fields that endpoints set (ports, sequence numbers, flags) plus the payload. IP ID, TTL,
/// checksums, link-layer headers and addresses are ignored.
pub fn packet_key(p: &PacketRow) -> u64 {
    let mut h = DefaultHasher::new();
    let m = &p.meta;
    if let Some(t) = m.tcp {
        (6u8, m.src_port, m.dst_port, t.seq, t.ack, t.flags).hash(&mut h);
        p.frame.data.get(t.payload_off..t.payload_off + t.payload_len).hash(&mut h);
    } else if let Some((o, l)) = m.udp_payload {
        (17u8, m.src_port, m.dst_port).hash(&mut h);
        p.frame.data.get(o..o + l).hash(&mut h);
    } else {
        (0u8, &p.protocol, &p.info, m.src_ip, m.dst_ip).hash(&mut h);
    }
    h.finish()
}

pub fn compare(a: &Engine, b: &Engine) -> CompareResult {
    let mut index: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, p) in a.packets.iter().enumerate() {
        index.entry(packet_key(p)).or_default().push(i);
    }
    let b_keys: Vec<u64> = b.packets.iter().map(packet_key).collect();
    // Clock offset between the capture points, from packets that are unique in both captures.
    let mut b_count: HashMap<u64, u32> = HashMap::new();
    for k in &b_keys {
        *b_count.entry(*k).or_default() += 1;
    }
    let mut offsets: Vec<f64> = b_keys
        .iter()
        .enumerate()
        .filter(|(_, k)| b_count[k] == 1 && index.get(k).is_some_and(|v| v.len() == 1))
        .map(|(j, k)| b.packets[j].frame.ts - a.packets[index[k][0]].frame.ts)
        .collect();
    offsets.sort_by(|x, y| x.total_cmp(y));
    let offset = offsets.get(offsets.len() / 2).copied().unwrap_or(0.0);

    // Identical packets (retransmissions, keep-alives, repeated DNS queries) are paired with the
    // closest-in-time unused copy rather than first-come first-served.
    let mut used = vec![false; a.packets.len()];
    let mut matched = Vec::new();
    let mut only_b = Vec::new();
    for (j, k) in b_keys.iter().enumerate() {
        let tb = b.packets[j].frame.ts - offset;
        let best = index.get(k).and_then(|cands| {
            cands.iter().copied().filter(|&i| !used[i]).min_by(|&x, &y| {
                (a.packets[x].frame.ts - tb).abs().total_cmp(&(a.packets[y].frame.ts - tb).abs())
            })
        });
        match best {
            Some(i) => {
                used[i] = true;
                matched.push((i, j));
            }
            None => only_b.push(j),
        }
    }
    let only_a: Vec<usize> = (0..a.packets.len()).filter(|&i| !used[i]).collect();
    matched.sort_unstable();
    let mut deltas: Vec<f64> = matched.iter().map(|&(i, j)| b.packets[j].frame.ts - a.packets[i].frame.ts).collect();
    deltas.sort_by(|x, y| x.total_cmp(y));

    let mut per_conv: HashMap<(u8, usize), usize> = HashMap::new();
    for &i in &only_a {
        if let Some(s) = a.packets[i].stream {
            *per_conv.entry((s.kind as u8, s.id)).or_default() += 1;
        }
    }
    let mut lossy_convs: Vec<(String, usize, usize)> = per_conv
        .into_iter()
        .map(|((k, id), n)| {
            let c = if k == 0 { &a.streams.tcp[id] } else { &a.streams.udp[id] };
            let proto = if k == 0 { "tcp" } else { "udp" };
            (format!("{proto}.stream {id} {}", c.label()), n, c.packets.len())
        })
        .collect();
    lossy_convs.sort_by_key(|c| std::cmp::Reverse(c.1));
    CompareResult { a_len: a.packets.len(), b_len: b.packets.len(), matched, only_a, only_b, deltas, lossy_convs }
}
