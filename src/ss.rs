//! Lecture de la commande `ss` : tous les sockets TCP/UDP, leur processus et leurs compteurs.

use crate::packet::Proto;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const SS_ARGS: &[&str] = &["-H", "-a", "-t", "-u", "-n", "-i", "-p", "-e", "-O"];

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SockInfo {
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
    pub rtt_ms: Option<f32>,
    pub cwnd: Option<u32>,
    pub retrans: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SockEntry {
    pub proto: Proto,
    pub state: String,
    pub recv_q: u64,
    pub send_q: u64,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub scope_if: Option<String>,
    pub procs: Vec<(String, u32, u32)>,
    pub uid: Option<u32>,
    pub inode: Option<u64>,
    pub service: Option<String>,
    pub info: SockInfo,
}

impl SockEntry {
    pub fn is_listener(&self) -> bool {
        self.state == "LISTEN" || (self.proto == Proto::Udp && self.remote.port() == 0)
    }
}

/// `1.2.3.4:80`, `[::1]:53`, `127.0.0.53%lo:53`, `*:22`, `0.0.0.0:*`, `[fe80::1]%wlo1:68`
pub fn parse_addr(s: &str) -> Option<(SocketAddr, Option<String>)> {
    let (host, port) = s.rsplit_once(':')?;
    let port: u16 = if port == "*" { 0 } else { port.parse().ok()? };
    let (host, scope) = match host.split_once('%') {
        Some((h, sc)) => (h, Some(sc.to_string())),
        None => (host, None),
    };
    let ip: IpAddr = if host == "*" {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else if let Some(h) = host.strip_prefix('[') {
        let h = h.strip_suffix(']').unwrap_or(h);
        let (h, _) = h.split_once('%').unwrap_or((h, ""));
        let v6: Ipv6Addr = h.parse().ok()?;
        match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        }
    } else {
        host.parse().ok()?
    };
    // Le signe % a pu être placé après le crochet fermant.
    let scope = scope.map(|s| s.trim_end_matches(']').to_string()).filter(|s| !s.is_empty());
    Some((SocketAddr::new(ip, port), scope))
}

fn parse_users(line: &str) -> Vec<(String, u32, u32)> {
    let Some(start) = line.find("users:((") else { return vec![] };
    let rest = &line[start + 8..];
    let end = rest.find("))").unwrap_or(rest.len());
    let body = &rest[..end];
    let mut out = vec![];
    for part in body.split("),(") {
        let Some(q1) = part.find('"') else { continue };
        let Some(q2) = part.rfind('"') else { continue };
        if q2 <= q1 {
            continue;
        }
        let name = part[q1 + 1..q2].to_string();
        let mut pid = 0;
        let mut fd = 0;
        for kv in part[q2 + 1..].split(',') {
            if let Some(v) = kv.strip_prefix("pid=") {
                pid = v.parse().unwrap_or(0);
            } else if let Some(v) = kv.strip_prefix("fd=") {
                fd = v.parse().unwrap_or(0);
            }
        }
        out.push((name, pid, fd));
    }
    out
}

/// Nom lisible depuis le groupe de contrôle : `system.slice/sshd.service` → `sshd`.
fn service_from_cgroup(cg: &str) -> Option<String> {
    let last = cg.rsplit('/').next()?;
    if let Some(n) = last.strip_suffix(".service") {
        return Some(n.split('@').next().unwrap_or(n).to_string());
    }
    if last.starts_with("docker-") {
        return Some("conteneur Docker".into());
    }
    None
}

pub fn parse_line(line: &str) -> Option<SockEntry> {
    let mut it = line.split_whitespace();
    let proto = match it.next()? {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        _ => return None,
    };
    let state = it.next()?.to_string();
    let recv_q = it.next()?.parse().ok()?;
    let send_q = it.next()?.parse().ok()?;
    let (local, scope_if) = parse_addr(it.next()?)?;
    let (remote, _) = parse_addr(it.next()?)?;
    let mut e = SockEntry {
        proto,
        state,
        recv_q,
        send_q,
        local,
        remote,
        scope_if,
        procs: parse_users(line),
        uid: None,
        inode: None,
        service: None,
        info: SockInfo::default(),
    };
    for tok in line.split_whitespace() {
        let Some((k, v)) = tok.split_once(':') else { continue };
        match k {
            "uid" => e.uid = v.parse().ok(),
            "ino" => e.inode = v.parse().ok(),
            "cgroup" => e.service = service_from_cgroup(v),
            "bytes_sent" => e.info.bytes_sent = v.parse().ok(),
            "bytes_received" => e.info.bytes_received = v.parse().ok(),
            "cwnd" => e.info.cwnd = v.parse().ok(),
            "rtt" => e.info.rtt_ms = v.split('/').next().and_then(|x| x.parse().ok()),
            "retrans" => e.info.retrans = v.rsplit('/').next().and_then(|x| x.parse().ok()),
            _ => {}
        }
    }
    Some(e)
}

pub fn parse_output(text: &str) -> Vec<SockEntry> {
    text.lines().filter_map(parse_line).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = r#"tcp 0      0           192.168.43.242:49258      160.79.104.10:443   users:(("claude",pid=1571624,fd=14))           timer:(keepalive,9.850sec,0) uid:1000 ino:41872827 sk:1179 cgroup:/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-dev.warp.Warp-12552.scope <-> ts sack cubic wscale:13,10 rto:376 rtt:165.663/8.4 ato:94 mss:1348 pmtu:1500 cwnd:10 bytes_sent:187346 bytes_acked:187347 bytes_received:31496 segs_out:475 retrans:0/2 send 650960bps"#;
    const SYS: &str = "udp UNCONN     0      0                                   127.0.0.54:53               0.0.0.0:*                                                   uid:101 ino:6729 sk:11c cgroup:/system.slice/systemd-resolved.service <->";

    #[test]
    fn line_without_state_column_is_ignored() {
        assert!(parse_output(TCP).is_empty());
    }

    #[test]
    fn full_tcp_line_with_state() {
        let line = TCP.replacen("tcp 0", "tcp ESTAB 0", 1);
        let e = parse_line(&line).unwrap();
        assert_eq!(e.state, "ESTAB");
        assert_eq!(e.remote.to_string(), "160.79.104.10:443");
        assert_eq!(e.procs, vec![("claude".to_string(), 1571624, 14)]);
        assert_eq!(e.uid, Some(1000));
        assert_eq!(e.inode, Some(41872827));
        assert_eq!(e.info.bytes_sent, Some(187346));
        assert_eq!(e.info.bytes_received, Some(31496));
        assert_eq!(e.info.cwnd, Some(10));
        assert_eq!(e.info.retrans, Some(2));
        assert!((e.info.rtt_ms.unwrap() - 165.663).abs() < 0.01);
    }

    #[test]
    fn system_socket_hidden_process_uses_service_name() {
        let e = parse_line(SYS).unwrap();
        assert!(e.procs.is_empty());
        assert_eq!(e.service.as_deref(), Some("systemd-resolved"));
        assert!(e.is_listener());
    }

    #[test]
    fn address_forms() {
        assert_eq!(parse_addr("127.0.0.53%lo:53").unwrap().1.as_deref(), Some("lo"));
        assert_eq!(parse_addr("[::1]:631").unwrap().0.to_string(), "[::1]:631");
        assert_eq!(parse_addr("[::]:22").unwrap().0.port(), 22);
        assert_eq!(parse_addr("*:22").unwrap().0.port(), 22);
        assert_eq!(parse_addr("0.0.0.0:*").unwrap().0.port(), 0);
        let (a, sc) = parse_addr("[fe80::1]%wlo1:546").unwrap();
        assert_eq!(a.port(), 546);
        assert_eq!(sc.as_deref(), Some("wlo1"));
        assert_eq!(parse_addr("[::ffff:10.0.0.1]:80").unwrap().0.to_string(), "10.0.0.1:80");
    }

    #[test]
    fn process_names_with_spaces_and_several_owners() {
        let u = parse_users(r#"users:(("Web Content",pid=12,fd=3),("nginx",pid=13,fd=4))"#);
        assert_eq!(u, vec![("Web Content".into(), 12, 3), ("nginx".into(), 13, 4)]);
    }
}
