//! Pour les tests : de faux programmes qui notent leurs arguments sans rien appliquer, et des
//! paquets à rejouer. Le mode test de l'assistant (`--mock`) refuse de tourner en administrateur.

use crate::packet::{build, TCP_ACK, TCP_PSH, TCP_SYN};
use crate::proto::RawFrame;
use std::os::unix::fs::PermissionsExt;

const IPTABLES: &str = "Chain INPUT (policy DROP 12 packets, 3456 bytes)
num      pkts      bytes target     prot opt in     out     source               destination
1        1840   204800 ACCEPT     all  --  lo     *       0.0.0.0/0            0.0.0.0/0
2        9231  8123456 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
3          14      840 ACCEPT     tcp  --  wlo1   *       192.168.43.0/24      0.0.0.0/0            tcp dpt:22
4          37     2220 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:3306

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
num      pkts      bytes target     prot opt in     out     source               destination
1        5120  3120000 DOCKER-USER  all  --  *      *       0.0.0.0/0            0.0.0.0/0

Chain OUTPUT (policy ACCEPT 120 packets, 9600 bytes)
num      pkts      bytes target     prot opt in     out     source               destination

Chain DOCKER-USER (1 references)
num      pkts      bytes target     prot opt in     out     source               destination
1        5120  3120000 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0
";

fn script(dir: &std::path::Path, name: &str, body: &str) {
    let p = dir.join(name);
    let text = format!("#!/bin/sh\necho \"{name} $*\" >> \"{}/calls.log\"\n{body}\n", dir.display());
    std::fs::write(&p, text).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Écrit les faux programmes et les paquets à rejouer dans `dir`.
pub fn write_mock(dir: &std::path::Path, me: [u8; 4], ifindex: u32) {
    let dir = dir.to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("iptables.txt"), IPTABLES).unwrap();

    script(&dir, "iptables", &format!("case \"$*\" in *'-t filter -L'*) cat \"{}/iptables.txt\";; *-L*) echo 'Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)';; esac", dir.display()));
    script(&dir, "ip6tables", "case \"$*\" in *-L*) echo 'Chain INPUT (policy ACCEPT 0 packets, 0 bytes)';; esac");
    script(&dir, "ufw", "case \"$*\" in
*verbose*) printf 'Status: active\\nLogging: on (low)\\nDefault: deny (incoming), allow (outgoing), disabled (routed)\\n';;
*numbered*) printf 'Status: active\\n\\n     To                         Action      From\\n     --                         ------      ----\\n[ 1] 22/tcp                     ALLOW IN    192.168.43.0/24\\n[ 2] 3306/tcp                   DENY IN     Anywhere\\n[ 3] 8080/tcp on wlo1           ALLOW IN    Anywhere\\n';;
esac");
    script(&dir, "nft", "printf 'table inet filter {\\n\\tchain input {\\n\\t\\ttype filter hook input priority 0; policy drop;\\n\\t\\tct state established,related accept\\n\\t}\\n}\\n'");
    // `ss` reste le vrai : lecture seule, utile pour voir les vraies connexions.
    script(&dir, "ss", "case \"$*\" in *-K*) ;; *) exec /usr/bin/ss \"$@\";; esac");
    for n in ["ip", "systemctl", "kill", "nmcli", "apt-get", "resolvectl", "journalctl"] {
        script(&dir, n, "");
    }
    script(&dir, "sshd", "case \"$*\" in *-T*) printf 'port 22\\npermitrootlogin no\\npasswordauthentication no\\npubkeyauthentication yes\\nx11forwarding no\\nmaxauthtries 4\\n';; esac");

    let (dns_srv, web, http) = ([192, 168, 43, 1], [93, 184, 216, 34], [104, 18, 26, 120]);
    let mut frames: Vec<(Vec<u8>, u8)> = vec![];
    let mut add = |d: Vec<u8>, t: u8| frames.push((d, t));
    add(build::ipv4_udp(me, dns_srv, 53000, 53, &build::dns(1, "www.exemple.fr", None)), 4);
    add(build::ipv4_udp(dns_srv, me, 53, 53000, &build::dns(1, "www.exemple.fr", Some(web))), 0);
    add(build::ipv4_tcp(me, web, 40001, 443, 1000, 0, TCP_SYN, &[]), 4);
    add(build::ipv4_tcp(web, me, 443, 40001, 5000, 1001, TCP_SYN | TCP_ACK, &[]), 0);
    add(build::ipv4_tcp(me, web, 40001, 443, 1001, 5001, TCP_ACK, &[]), 4);
    let hello = build::tls_client_hello("www.exemple.fr", [9; 32]);
    add(build::ipv4_tcp(me, web, 40001, 443, 1001, 5001, TCP_PSH | TCP_ACK, &hello), 4);
    for i in 0..60u32 {
        let mut rec = vec![23, 3, 3, 4, 0];
        rec.extend((0..1024u32).map(|j| (j.wrapping_mul(2654435761).wrapping_add(i) >> 11) as u8));
        add(build::ipv4_tcp(web, me, 443, 40001, 5001 + i * 1029, 1500, TCP_ACK, &rec), 0);
        add(build::ipv4_tcp(me, web, 40001, 443, 1500, 5001 + (i + 1) * 1029, TCP_ACK, &[]), 4);
    }
    let req = b"GET /index.html HTTP/1.1\r\nHost: perdu.exemple\r\nUser-Agent: curl\r\nAccept: */*\r\n\r\n";
    add(build::ipv4_tcp(me, http, 40002, 80, 2000, 7000, TCP_PSH | TCP_ACK, req), 4);
    let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 18\r\n\r\n<h1>Bonjour !</h1>";
    add(build::ipv4_tcp(http, me, 80, 40002, 7000, 2000 + req.len() as u32, TCP_PSH | TCP_ACK, resp), 0);
    add(build::ipv4_udp(me, [142, 250, 201, 14], 41000, 443, &[0xc3, 0, 0, 0, 1, 8, 1, 2, 3, 4]), 4);
    add(build::ipv4_tcp(me, [140, 82, 121, 3], 40003, 22, 1, 1, TCP_PSH | TCP_ACK, b"SSH-2.0-OpenSSH_9.6\r\n"), 4);

    let mut out = vec![];
    for (data, pkttype) in frames {
        let mut enc = vec![];
        RawFrame { ts_us: 0, ifindex, pkttype, proto: 0x0800, orig_len: data.len() as u32, data }.encode(&mut enc);
        out.extend_from_slice(&(enc.len() as u32).to_le_bytes());
        out.extend_from_slice(&enc);
    }
    std::fs::write(dir.join("frames.bin"), out).unwrap();
}
