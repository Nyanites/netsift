//! Process attribution: which local process owns a connection.
//!
//! Two sources feed this:
//! * PKTAP headers (macOS) carry the pid and command name per packet; see `dissect::pktap`.
//! * Socket-table snapshots (`snapshot`) taken during live capture map 4-tuples to processes,
//!   which works without root (for the user's own processes).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SockEntry {
    pub proto: u8,
    pub local: (IpAddr, u16),
    pub remote: Option<(IpAddr, u16)>,
    pub pid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcDesc {
    pub pid: u32,
    pub name: String,
    pub path: String,
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub socks: Vec<SockEntry>,
    pub procs: Vec<ProcDesc>,
}

/// User-facing application name: the outermost `.app` bundle in the executable path (so helper
/// processes group under their app), otherwise the process name.
pub fn app_name(name: &str, path: &str) -> String {
    path.split('/')
        .find_map(|c| c.strip_suffix(".app"))
        .map(|s| s.to_string())
        .unwrap_or_else(|| name.to_string())
}

// ---------------------------------------------------------------------------------------------
// Platform snapshots

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    #[repr(C)]
    struct NsSock {
        pid: i32,
        proto: i32,
        v6: i32,
        laddr: [u8; 16],
        raddr: [u8; 16],
        lport: u16,
        rport: u16,
    }

    #[repr(C)]
    struct NsProc {
        pid: i32,
        name: [u8; 64],
        path: [u8; 1024],
    }

    unsafe extern "C" {
        fn ns_list_sockets(socks: *mut NsSock, max_socks: i32, procs: *mut NsProc, max_procs: i32, n_procs: *mut i32) -> i32;
    }

    fn cstr(b: &[u8]) -> String {
        let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        String::from_utf8_lossy(&b[..end]).into_owned()
    }

    fn addr(b: &[u8; 16], v6: bool) -> IpAddr {
        if v6 {
            IpAddr::V6(Ipv6Addr::from(*b))
        } else {
            IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
        }
    }

    pub fn snapshot() -> Result<Snapshot, String> {
        const MAX_SOCKS: usize = 65536;
        const MAX_PROCS: usize = 8192;
        let mut socks: Vec<NsSock> = Vec::with_capacity(MAX_SOCKS);
        let mut procs: Vec<NsProc> = Vec::with_capacity(MAX_PROCS);
        let mut np = 0i32;
        // SAFETY: the C side writes at most the given counts into the buffers.
        let n = unsafe { ns_list_sockets(socks.as_mut_ptr(), MAX_SOCKS as i32, procs.as_mut_ptr(), MAX_PROCS as i32, &mut np) };
        if n < 0 {
            return Err("cannot list processes".into());
        }
        unsafe {
            socks.set_len(n as usize);
            procs.set_len(np as usize);
        }
        let socks = socks
            .iter()
            .filter(|s| s.proto == 6 || s.proto == 17)
            .map(|s| {
                let v6 = s.v6 != 0;
                let remote = (s.rport != 0).then(|| (addr(&s.raddr, v6), s.rport));
                SockEntry { proto: s.proto as u8, local: (addr(&s.laddr, v6), s.lport), remote, pid: s.pid as u32 }
            })
            .collect();
        let procs = procs.iter().map(|p| ProcDesc { pid: p.pid as u32, name: cstr(&p.name), path: cstr(&p.path) }).collect();
        Ok(Snapshot { socks, procs })
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    pub fn snapshot() -> Result<Snapshot, String> {
        let mut by_inode: HashMap<u64, (u8, Ep, Option<Ep>)> = HashMap::new();
        for (file, proto) in [("tcp", 6u8), ("tcp6", 6), ("udp", 17), ("udp6", 17)] {
            if let Ok(text) = std::fs::read_to_string(format!("/proc/net/{file}")) {
                for (inode, local, remote) in parse_proc_net(&text) {
                    by_inode.insert(inode, (proto, local, remote));
                }
            }
        }
        let mut socks = Vec::new();
        let mut procs = Vec::new();
        for entry in std::fs::read_dir("/proc").map_err(|e| e.to_string())?.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else { continue };
            let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else { continue };
            let mut owned = false;
            for fd in fds.flatten() {
                let Ok(target) = std::fs::read_link(fd.path()) else { continue };
                let t = target.to_string_lossy();
                let Some(inode) = t.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')).and_then(|s| s.parse::<u64>().ok()) else {
                    continue;
                };
                if let Some(&(proto, local, remote)) = by_inode.get(&inode) {
                    socks.push(SockEntry { proto, local, remote, pid });
                    owned = true;
                }
            }
            if owned {
                let name = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default().trim().to_string();
                let path = std::fs::read_link(entry.path().join("exe")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
                procs.push(ProcDesc { pid, name, path });
            }
        }
        Ok(Snapshot { socks, procs })
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    use super::*;

    pub fn snapshot() -> Result<Snapshot, String> {
        Err("process attribution is not supported on this OS yet".into())
    }
}

pub use platform::snapshot;

/// Parses /proc/net/{tcp,udp}[6]: returns (inode, local, remote) per socket.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_proc_net(text: &str) -> Vec<(u64, Ep, Option<Ep>)> {
    fn endpoint(s: &str) -> Option<(IpAddr, u16)> {
        let (a, p) = s.split_once(':')?;
        let port = u16::from_str_radix(p, 16).ok()?;
        // Addresses are printed as native-endian 32-bit words (little-endian on x86/arm).
        let words: Vec<u32> = (0..a.len() / 8).map(|i| u32::from_str_radix(&a[i * 8..i * 8 + 8], 16)).collect::<Result<_, _>>().ok()?;
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let ip = match bytes.len() {
            4 => IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
            16 => {
                let v6 = Ipv6Addr::from(<[u8; 16]>::try_from(bytes.as_slice()).ok()?);
                v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6))
            }
            _ => return None,
        };
        Some((ip, port))
    }
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let local = endpoint(f.get(1)?)?;
            let remote = endpoint(f.get(2)?)?;
            let inode = f.get(9)?.parse().ok()?;
            Some((inode, local, (remote.1 != 0).then_some(remote)))
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Matching connections to processes

type Ep = (IpAddr, u16);

#[derive(Default)]
pub struct ProcTable {
    exact: HashMap<(u8, Ep, Ep), u32>,
    bound: HashMap<(u8, Ep), u32>,
    wildcard: HashMap<(u8, u16), u32>,
    local_ips: HashSet<IpAddr>,
    pub procs: HashMap<u32, ProcDesc>,
}

impl ProcTable {
    /// Merges a snapshot. Older entries are kept so short-lived connections stay attributable.
    pub fn update(&mut self, snap: &Snapshot) {
        for p in &snap.procs {
            self.procs.insert(p.pid, p.clone());
        }
        for s in &snap.socks {
            if !s.local.0.is_unspecified() {
                self.local_ips.insert(s.local.0);
            }
            match s.remote {
                Some(r) => {
                    self.exact.insert((s.proto, s.local, r), s.pid);
                }
                None if s.local.0.is_unspecified() => {
                    self.wildcard.insert((s.proto, s.local.1), s.pid);
                }
                None => {
                    self.bound.insert((s.proto, s.local), s.pid);
                }
            }
        }
    }

    /// Whether an address belongs to this host (as seen in the socket table).
    pub fn is_local(&self, ip: IpAddr) -> bool {
        ip.is_loopback() || self.local_ips.contains(&ip)
    }

    /// Finds the local process for a conversation between endpoints `a` and `b`.
    pub fn lookup(&self, proto: u8, a: Ep, b: Ep) -> Option<&ProcDesc> {
        let pid = self
            .exact
            .get(&(proto, a, b))
            .or_else(|| self.exact.get(&(proto, b, a)))
            .or_else(|| {
                [a, b].iter().filter(|e| self.local_ips.contains(&e.0) || e.0.is_loopback()).find_map(|e| {
                    self.bound.get(&(proto, *e)).or_else(|| self.wildcard.get(&(proto, e.1)))
                })
            })?;
        self.procs.get(pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_names() {
        assert_eq!(
            app_name(
                "Google Chrome He",
                "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/1/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper"
            ),
            "Google Chrome"
        );
        assert_eq!(app_name("curl", "/usr/bin/curl"), "curl");
    }

    #[test]
    fn proc_net_parsing() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
           0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n\
           1: 1401A8C0:D431 22D8B85D:01BB 01 00000000:00000000 02:000A7B6E 00000000  1000        0 67890 2 0000000000000000 20 4 30 10 -1\n";
        let v = parse_proc_net(tcp);
        assert_eq!(v[0], (12345, ("127.0.0.1".parse().unwrap(), 8080), None));
        assert_eq!(v[1], (67890, ("192.168.1.20".parse().unwrap(), 54321), Some(("93.184.216.34".parse().unwrap(), 443))));
        let tcp6 = "header\n 0: 0000000000000000FFFF00000100007F:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 555\n";
        assert_eq!(parse_proc_net(tcp6)[0], (555, ("127.0.0.1".parse().unwrap(), 8080), None));
    }

    /// The native snapshot must see a connection this process just made.
    #[test]
    fn snapshot_sees_own_sockets() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let server = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(server).unwrap();
        let (_accepted, _) = listener.accept().unwrap();
        let local = client.local_addr().unwrap();
        let t0 = std::time::Instant::now();
        let snap = snapshot().unwrap();
        let took = t0.elapsed();
        let me = std::process::id();
        assert!(snap.procs.iter().any(|p| p.pid == me && !p.name.is_empty()));
        let mut table = ProcTable::default();
        table.update(&snap);
        let found = table.lookup(6, (local.ip(), local.port()), (server.ip(), server.port())).expect("connection attributed");
        assert_eq!(found.pid, me);
        // The listener (no remote) is attributed by its bound address.
        let other = table.lookup(6, ("127.0.0.1".parse().unwrap(), 1), (server.ip(), server.port())).unwrap();
        assert_eq!(other.pid, me);
        eprintln!("snapshot: {} sockets, {} processes in {took:?}", snap.socks.len(), snap.procs.len());
    }
}
