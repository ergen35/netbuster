//! Lecture des paquets : IP, TCP/UDP/ICMP, ARP, et reconnaissance DNS, TLS, HTTP, SSH, QUIC…

use crate::proto::RawFrame;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Icmp6,
    Igmp,
    Arp,
    Other,
}

impl Proto {
    pub fn label(self) -> &'static str {
        match self {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
            Proto::Icmp => "ICMP",
            Proto::Icmp6 => "ICMPv6",
            Proto::Igmp => "IGMP",
            Proto::Arp => "ARP",
            Proto::Other => "Autre",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    In,
    Out,
    /// Vu par la carte mais destiné à une autre machine, ou passant sur la boucle locale.
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Crypto {
    Yes,
    Probable,
    No,
    #[default]
    Unknown,
}

impl Crypto {
    pub fn label(self) -> &'static str {
        match self {
            Crypto::Yes => "Chiffré",
            Crypto::Probable => "Probablement chiffré",
            Crypto::No => "En clair",
            Crypto::Unknown => "Indéterminé",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub ts_us: u64,
    pub ifindex: u32,
    pub dir: Dir,
    pub orig_len: u32,
    pub l3_proto: u16,
    pub data: Arc<[u8]>,
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
    pub sport: u16,
    pub dport: u16,
    pub proto: Proto,
    pub tcp_flags: u8,
    pub seq: u32,
    pub ack: u32,
    pub payload_off: usize,
    pub app: &'static str,
    pub info: String,
    pub crypto: Crypto,
    pub sni: Option<String>,
    pub http_host: Option<String>,
    pub dns: Option<DnsMessage>,
}

impl Packet {
    pub fn payload(&self) -> &[u8] {
        self.data.get(self.payload_off..).unwrap_or(&[])
    }
}

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

pub fn tcp_flags_label(f: u8) -> String {
    let mut parts = vec![];
    for (bit, name) in [(TCP_SYN, "SYN"), (TCP_FIN, "FIN"), (TCP_RST, "RST"), (TCP_PSH, "PSH"), (TCP_ACK, "ACK")] {
        if f & bit != 0 {
            parts.push(name);
        }
    }
    parts.join(",")
}

fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}
fn be32(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes([*b.get(i)?, *b.get(i + 1)?, *b.get(i + 2)?, *b.get(i + 3)?]))
}

pub fn parse(frame: RawFrame) -> Packet {
    let dir = match frame.pkttype {
        0 | 1 | 2 => Dir::In,
        4 => Dir::Out,
        _ => Dir::Other,
    };
    let data: Arc<[u8]> = frame.data.into();
    let mut p = Packet {
        ts_us: frame.ts_us,
        ifindex: frame.ifindex,
        dir,
        orig_len: frame.orig_len,
        l3_proto: frame.proto,
        data: data.clone(),
        src: None,
        dst: None,
        sport: 0,
        dport: 0,
        proto: Proto::Other,
        tcp_flags: 0,
        seq: 0,
        ack: 0,
        payload_off: data.len(),
        app: "",
        info: String::new(),
        crypto: Crypto::Unknown,
        sni: None,
        http_host: None,
        dns: None,
    };
    let d = &data[..];
    match frame.proto {
        0x0800 => parse_ipv4(d, &mut p),
        0x86DD => parse_ipv6(d, &mut p),
        0x0806 => parse_arp(d, &mut p),
        other => {
            p.app = "Autre";
            p.info = format!("Type de trame 0x{other:04x}");
        }
    }
    if p.app.is_empty() {
        p.app = p.proto.label();
    }
    p
}

fn parse_ipv4(d: &[u8], p: &mut Packet) {
    if d.len() < 20 || d[0] >> 4 != 4 {
        p.info = "En-tête IPv4 incomplet".into();
        return;
    }
    let ihl = (d[0] & 0x0f) as usize * 4;
    p.src = Some(IpAddr::V4(Ipv4Addr::new(d[12], d[13], d[14], d[15])));
    p.dst = Some(IpAddr::V4(Ipv4Addr::new(d[16], d[17], d[18], d[19])));
    let total = be16(d, 2).unwrap_or(0) as usize;
    let frag_off = be16(d, 6).unwrap_or(0) & 0x1fff;
    // Les interfaces qui regroupent les segments peuvent annoncer une longueur totale nulle.
    let end = if total >= ihl && total <= d.len() { total } else { d.len() };
    if frag_off != 0 {
        p.info = format!("Fragment IP (décalage {})", frag_off as u32 * 8);
        return;
    }
    parse_l4(d[9], d, ihl, end, p);
}

fn parse_ipv6(d: &[u8], p: &mut Packet) {
    if d.len() < 40 || d[0] >> 4 != 6 {
        p.info = "En-tête IPv6 incomplet".into();
        return;
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(&d[8..24]);
    p.src = Some(IpAddr::V6(Ipv6Addr::from(a)));
    a.copy_from_slice(&d[24..40]);
    p.dst = Some(IpAddr::V6(Ipv6Addr::from(a)));
    let mut next = d[6];
    let mut off = 40;
    // En-têtes d'extension : saut par saut, routage, destination.
    while matches!(next, 0 | 43 | 60) {
        let Some(&n) = d.get(off) else { return };
        let Some(&l) = d.get(off + 1) else { return };
        next = n;
        off += (l as usize + 1) * 8;
    }
    if next == 44 {
        p.info = "Fragment IPv6".into();
        return;
    }
    let plen = be16(d, 4).unwrap_or(0) as usize;
    let end = if plen > 0 && 40 + plen <= d.len() { 40 + plen } else { d.len() };
    parse_l4(next, d, off, end, p);
}

fn parse_arp(d: &[u8], p: &mut Packet) {
    p.proto = Proto::Arp;
    p.app = "ARP";
    p.crypto = Crypto::No;
    if d.len() < 28 || d[4] != 6 || d[5] != 4 {
        p.info = "ARP".into();
        return;
    }
    let sender = Ipv4Addr::new(d[14], d[15], d[16], d[17]);
    let target = Ipv4Addr::new(d[24], d[25], d[26], d[27]);
    p.src = Some(IpAddr::V4(sender));
    p.dst = Some(IpAddr::V4(target));
    p.info = match be16(d, 6) {
        Some(1) => format!("Qui a {target} ? Demande de {sender}"),
        Some(2) => format!("{sender} est à {}", mac_str(&d[8..14])),
        _ => "ARP".into(),
    };
}

pub fn mac_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":")
}

fn parse_l4(proto: u8, d: &[u8], off: usize, end: usize, p: &mut Packet) {
    let Some(seg) = d.get(off..end) else {
        p.info = "Paquet tronqué".into();
        return;
    };
    match proto {
        6 => parse_tcp(seg, off, p),
        17 => parse_udp(seg, off, p),
        1 => {
            p.proto = Proto::Icmp;
            p.crypto = Crypto::No;
            p.payload_off = off + 8;
            p.info = icmp_info(seg.first().copied().unwrap_or(255), seg.get(1).copied().unwrap_or(0));
        }
        58 => {
            p.proto = Proto::Icmp6;
            p.crypto = Crypto::No;
            p.payload_off = off + 8;
            p.info = icmp6_info(seg.first().copied().unwrap_or(255));
        }
        2 => {
            p.proto = Proto::Igmp;
            p.crypto = Crypto::No;
            p.info = "Abonnement multidiffusion".into();
        }
        50 => {
            p.app = "IPsec";
            p.crypto = Crypto::Yes;
            p.info = "ESP : tunnel VPN IPsec".into();
        }
        47 => {
            p.app = "GRE";
            p.info = "Tunnel GRE".into();
        }
        n => p.info = format!("Protocole IP {n}"),
    }
}

fn icmp_info(t: u8, c: u8) -> String {
    match t {
        0 => "Réponse au ping".into(),
        8 => "Ping".into(),
        3 => match c {
            0 => "Réseau injoignable".into(),
            1 => "Machine injoignable".into(),
            3 => "Port injoignable".into(),
            4 => "Paquet trop grand".into(),
            13 => "Filtré par un pare-feu".into(),
            _ => format!("Destination injoignable (code {c})"),
        },
        11 => "Durée de vie dépassée (étape de traceroute)".into(),
        5 => "Redirection".into(),
        _ => format!("ICMP type {t}"),
    }
}

fn icmp6_info(t: u8) -> String {
    match t {
        1 => "Destination injoignable".into(),
        2 => "Paquet trop grand".into(),
        3 => "Durée de vie dépassée (étape de traceroute)".into(),
        128 => "Ping".into(),
        129 => "Réponse au ping".into(),
        133 => "Recherche de routeur".into(),
        134 => "Annonce de routeur".into(),
        135 => "Recherche de voisin".into(),
        136 => "Annonce de voisin".into(),
        _ => format!("ICMPv6 type {t}"),
    }
}

fn parse_tcp(seg: &[u8], off: usize, p: &mut Packet) {
    p.proto = Proto::Tcp;
    if seg.len() < 20 {
        p.info = "En-tête TCP incomplet".into();
        return;
    }
    p.sport = be16(seg, 0).unwrap_or(0);
    p.dport = be16(seg, 2).unwrap_or(0);
    p.seq = be32(seg, 4).unwrap_or(0);
    p.ack = be32(seg, 8).unwrap_or(0);
    let hl = (seg[12] >> 4) as usize * 4;
    p.tcp_flags = seg[13];
    let flags = tcp_flags_label(p.tcp_flags);
    let payload = seg.get(hl..).unwrap_or(&[]);
    p.payload_off = off + hl;
    let wire_payload = (p.orig_len as usize).saturating_sub(off + hl);

    if payload.is_empty() {
        p.info = if p.tcp_flags & TCP_SYN != 0 && p.tcp_flags & TCP_ACK == 0 {
            "Ouverture de connexion (SYN)".into()
        } else if p.tcp_flags & TCP_RST != 0 {
            "Connexion coupée (RST)".into()
        } else if p.tcp_flags & TCP_FIN != 0 {
            "Fermeture de connexion (FIN)".into()
        } else {
            format!("[{flags}] sans données")
        };
        let known = known_port(p.sport.min(p.dport)).or_else(|| known_port(p.sport)).or_else(|| known_port(p.dport));
        if let Some((app, crypto)) = known {
            p.app = app;
            p.crypto = crypto;
        }
        return;
    }

    if let Some(tls) = parse_tls(payload) {
        p.app = "TLS";
        p.crypto = if tls.handshake_clear { Crypto::No } else { Crypto::Yes };
        p.info = tls.info;
        p.sni = tls.sni;
        // La poignée de main est visible, mais la connexion reste chiffrée : on la présente ainsi.
        p.crypto = if p.crypto == Crypto::No { Crypto::Yes } else { p.crypto };
        return;
    }
    if payload.starts_with(b"SSH-") {
        p.app = "SSH";
        p.crypto = Crypto::No;
        let line = String::from_utf8_lossy(payload);
        p.info = format!("Version annoncée : {}", line.lines().next().unwrap_or(""));
        return;
    }
    if let Some((info, host)) = parse_http(payload) {
        p.app = "HTTP";
        p.crypto = Crypto::No;
        p.info = info;
        p.http_host = host;
        return;
    }
    if p.sport == 53 || p.dport == 53 {
        if let Some(m) = payload.get(2..).and_then(parse_dns) {
            p.app = "DNS";
            p.crypto = Crypto::No;
            p.info = m.summary();
            p.dns = Some(m);
            return;
        }
    }
    if let Some((app, crypto)) = known_port(p.sport).or_else(|| known_port(p.dport)) {
        p.app = app;
        p.crypto = if crypto == Crypto::Unknown { guess_crypto(payload) } else { crypto };
        p.info = match p.crypto {
            Crypto::Yes => format!("{} octets chiffrés", fmt_int(wire_payload)),
            _ => format!("{} octets", fmt_int(wire_payload)),
        };
        return;
    }
    p.crypto = guess_crypto(payload);
    p.info = format!("[{flags}] {} octets", fmt_int(wire_payload));
}

fn fmt_int(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push('\u{a0}');
        }
        out.push(c);
    }
    out
}

fn parse_udp(seg: &[u8], off: usize, p: &mut Packet) {
    p.proto = Proto::Udp;
    if seg.len() < 8 {
        p.info = "En-tête UDP incomplet".into();
        return;
    }
    p.sport = be16(seg, 0).unwrap_or(0);
    p.dport = be16(seg, 2).unwrap_or(0);
    p.payload_off = off + 8;
    let payload = &seg[8..];
    let (sp, dp) = (p.sport, p.dport);
    let any = |x: u16| sp == x || dp == x;

    if any(53) || any(5353) || any(5355) {
        if let Some(m) = parse_dns(payload) {
            p.app = if any(53) { "DNS" } else { "mDNS" };
            p.crypto = Crypto::No;
            p.info = m.summary();
            p.dns = Some(m);
            return;
        }
    }
    if any(443) || any(80) || any(8443) {
        if let Some(&b0) = payload.first() {
            p.app = "QUIC";
            p.crypto = Crypto::Yes;
            p.info = if b0 & 0x80 != 0 {
                match (b0 & 0x30) >> 4 {
                    0 => "Début de connexion QUIC (HTTP/3)".to_string(),
                    2 => "Poignée de main QUIC".to_string(),
                    _ => "QUIC : en-tête long".to_string(),
                }
            } else {
                format!("{} octets chiffrés (HTTP/3)", fmt_int(payload.len()))
            };
            return;
        }
    }
    let label = if any(67) || any(68) {
        Some(("DHCP", Crypto::No, "Attribution d'adresse IP"))
    } else if any(123) {
        Some(("NTP", Crypto::No, "Mise à l'heure"))
    } else if any(1900) {
        Some(("SSDP", Crypto::No, "Découverte d'appareils"))
    } else if any(51820) {
        Some(("WireGuard", Crypto::Yes, "Tunnel VPN"))
    } else if any(1194) {
        Some(("OpenVPN", Crypto::Yes, "Tunnel VPN"))
    } else if any(137) || any(138) {
        Some(("NetBIOS", Crypto::No, "Partage Windows"))
    } else if any(853) {
        Some(("DNS chiffré", Crypto::Yes, "DNS sur DTLS"))
    } else {
        None
    };
    if let Some((app, crypto, info)) = label {
        p.app = app;
        p.crypto = crypto;
        p.info = format!("{info}, {} octets", fmt_int(payload.len()));
        return;
    }
    p.crypto = guess_crypto(payload);
    p.info = format!("{} octets", fmt_int(payload.len()));
}

fn known_port(port: u16) -> Option<(&'static str, Crypto)> {
    Some(match port {
        22 => ("SSH", Crypto::Yes),
        443 | 8443 | 993 | 995 | 465 | 636 | 853 | 5223 | 6697 => ("TLS", Crypto::Yes),
        80 | 8080 => ("HTTP", Crypto::Unknown),
        21 => ("FTP", Crypto::No),
        23 => ("Telnet", Crypto::No),
        25 | 587 => ("SMTP", Crypto::Unknown),
        110 => ("POP3", Crypto::Unknown),
        143 => ("IMAP", Crypto::Unknown),
        445 => ("SMB", Crypto::Unknown),
        3306 => ("MySQL", Crypto::Unknown),
        5432 => ("PostgreSQL", Crypto::Unknown),
        6379 => ("Redis", Crypto::Unknown),
        3389 => ("RDP", Crypto::Unknown),
        _ => return None,
    })
}

/// Sans protocole reconnu : devine à partir du hasard apparent des octets.
pub fn guess_crypto(payload: &[u8]) -> Crypto {
    let sample = &payload[..payload.len().min(1024)];
    if sample.len() < 32 {
        return Crypto::Unknown;
    }
    let printable = sample.iter().filter(|b| matches!(**b, 0x20..=0x7e | b'\n' | b'\r' | b'\t')).count();
    if printable as f32 / sample.len() as f32 > 0.9 {
        return Crypto::No;
    }
    let mut counts = [0u32; 256];
    for &b in sample {
        counts[b as usize] += 1;
    }
    let len = sample.len() as f32;
    let entropy: f32 = counts.iter().filter(|c| **c > 0).map(|&c| -(c as f32 / len) * (c as f32 / len).log2()).sum();
    // Le maximum atteignable dépend de la taille de l'échantillon.
    if entropy > 0.92 * len.log2().min(8.0) {
        Crypto::Probable
    } else {
        Crypto::Unknown
    }
}

fn parse_http(payload: &[u8]) -> Option<(String, Option<String>)> {
    const METHODS: &[&str] = &["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "];
    let head = &payload[..payload.len().min(4096)];
    let text = String::from_utf8_lossy(head);
    let first = text.lines().next()?;
    if METHODS.iter().any(|m| first.starts_with(m)) && first.contains("HTTP/") {
        let host = text
            .lines()
            .find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("host")).map(|(_, v)| v.trim().to_string()));
        return Some((first.to_string(), host));
    }
    if first.starts_with("HTTP/1.") || first.starts_with("HTTP/2") {
        return Some((format!("Réponse : {first}"), None));
    }
    None
}

// ---------- TLS ----------

pub struct TlsSummary {
    pub info: String,
    pub sni: Option<String>,
    pub handshake_clear: bool,
}

pub fn parse_tls(p: &[u8]) -> Option<TlsSummary> {
    if p.len() < 5 || !(20..=23).contains(&p[0]) || p[1] != 3 || p[2] > 4 {
        return None;
    }
    let content = p[0];
    let rec_len = be16(p, 3)? as usize;
    if rec_len == 0 || rec_len > 18432 {
        return None;
    }
    Some(match content {
        22 => match p.get(5) {
            Some(1) => {
                let h = parse_client_hello(&p[5..]).unwrap_or_default();
                let mut info = String::from("Début de connexion chiffrée");
                if let Some(s) = &h.sni {
                    info = format!("Connexion chiffrée vers {s}");
                }
                if !h.alpn.is_empty() {
                    info.push_str(&format!(" ({})", h.alpn.join(", ")));
                }
                TlsSummary { info, sni: h.sni, handshake_clear: true }
            }
            Some(2) => {
                let info = match parse_server_hello(&p[5..]) {
                    Some(h) => format!("Le serveur choisit {} avec {}", h.version_label(), cipher_name(h.cipher)),
                    None => "Réponse du serveur".into(),
                };
                TlsSummary { info, sni: None, handshake_clear: true }
            }
            Some(11) => TlsSummary { info: "Certificat du serveur".into(), sni: None, handshake_clear: true },
            _ => TlsSummary { info: "Négociation chiffrée".into(), sni: None, handshake_clear: false },
        },
        23 => TlsSummary { info: format!("{} octets de données chiffrées", fmt_int(rec_len)), sni: None, handshake_clear: false },
        21 => TlsSummary { info: "Alerte TLS".into(), sni: None, handshake_clear: false },
        _ => TlsSummary { info: "Passage au chiffrement".into(), sni: None, handshake_clear: true },
    })
}

#[derive(Default, Debug, Clone)]
pub struct ClientHello {
    pub random: [u8; 32],
    pub sni: Option<String>,
    pub alpn: Vec<String>,
}

/// `h` commence au type de message de la poignée de main (1).
pub fn parse_client_hello(h: &[u8]) -> Option<ClientHello> {
    if *h.first()? != 1 {
        return None;
    }
    let mut out = ClientHello::default();
    out.random.copy_from_slice(h.get(6..38)?);
    let mut i = 38;
    i += 1 + *h.get(i)? as usize; // identifiant de session
    i += 2 + be16(h, i)? as usize; // suites de chiffrement
    i += 1 + *h.get(i)? as usize; // compression
    let ext_len = be16(h, i)? as usize;
    i += 2;
    let end = (i + ext_len).min(h.len());
    while i + 4 <= end {
        let t = be16(h, i)?;
        let l = be16(h, i + 2)? as usize;
        let body = h.get(i + 4..(i + 4 + l).min(h.len()))?;
        match t {
            0 => {
                // server_name : [liste u16][type u8][longueur u16][nom]
                if let (Some(n), true) = (be16(body, 3), body.len() > 5) {
                    if let Some(name) = body.get(5..5 + n as usize) {
                        out.sni = Some(String::from_utf8_lossy(name).into_owned());
                    }
                }
            }
            16 => {
                let mut j = 2;
                while j < body.len() {
                    let n = body[j] as usize;
                    if let Some(s) = body.get(j + 1..j + 1 + n) {
                        out.alpn.push(String::from_utf8_lossy(s).into_owned());
                    }
                    j += 1 + n;
                }
            }
            _ => {}
        }
        i += 4 + l;
    }
    Some(out)
}

#[derive(Default, Debug, Clone)]
pub struct ServerHello {
    pub random: [u8; 32],
    pub cipher: u16,
    pub tls13: bool,
    pub legacy_version: u16,
}

impl ServerHello {
    pub fn version_label(&self) -> &'static str {
        if self.tls13 {
            "TLS 1.3"
        } else {
            match self.legacy_version {
                0x0303 => "TLS 1.2",
                0x0302 => "TLS 1.1",
                0x0301 => "TLS 1.0",
                _ => "TLS",
            }
        }
    }
}

pub fn parse_server_hello(h: &[u8]) -> Option<ServerHello> {
    if *h.first()? != 2 {
        return None;
    }
    let mut out = ServerHello { legacy_version: be16(h, 4)?, ..Default::default() };
    out.random.copy_from_slice(h.get(6..38)?);
    let mut i = 38;
    i += 1 + *h.get(i)? as usize;
    out.cipher = be16(h, i)?;
    i += 3;
    if let Some(ext_len) = be16(h, i) {
        i += 2;
        let end = (i + ext_len as usize).min(h.len());
        while i + 4 <= end {
            let t = be16(h, i)?;
            let l = be16(h, i + 2)? as usize;
            if t == 0x2b && be16(h, i + 4) == Some(0x0304) {
                out.tls13 = true;
            }
            i += 4 + l;
        }
    }
    Some(out)
}

pub fn cipher_name(c: u16) -> &'static str {
    match c {
        0x1301 => "AES-128-GCM",
        0x1302 => "AES-256-GCM",
        0x1303 => "ChaCha20-Poly1305",
        0xc02f | 0xc02b | 0x009c => "AES-128-GCM",
        0xc030 | 0xc02c | 0x009d => "AES-256-GCM",
        0xcca8 | 0xcca9 => "ChaCha20-Poly1305",
        _ => "un autre chiffrement",
    }
}

// ---------- DNS ----------

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DnsMessage {
    pub id: u16,
    pub response: bool,
    pub rcode: u8,
    pub questions: Vec<(String, u16)>,
    pub answers: Vec<(String, u16, String)>,
}

pub fn dns_type_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        65 => "HTTPS".into(),
        _ => format!("type {t}"),
    }
}

impl DnsMessage {
    pub fn summary(&self) -> String {
        let q = self.questions.first();
        let qname = q.map(|x| x.0.as_str()).unwrap_or("?");
        if !self.response {
            let t = q.map(|x| dns_type_name(x.1)).unwrap_or_default();
            return format!("Question {t} : {qname}");
        }
        if self.rcode == 3 {
            return format!("{qname} : ce nom n'existe pas");
        }
        if self.rcode != 0 {
            return format!("{qname} : erreur DNS {}", self.rcode);
        }
        let ips: Vec<&str> = self.answers.iter().filter(|a| a.1 == 1 || a.1 == 28).map(|a| a.2.as_str()).take(3).collect();
        if ips.is_empty() {
            format!("Réponse pour {qname}")
        } else {
            format!("{qname} : {}", ips.join(", "))
        }
    }
}

fn dns_name(msg: &[u8], mut i: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(i)? as usize;
        if len == 0 {
            end.get_or_insert(i + 1);
            break;
        }
        if len & 0xc0 == 0xc0 {
            let lo = *msg.get(i + 1)? as usize;
            end.get_or_insert(i + 2);
            i = ((len & 0x3f) << 8) | lo;
            jumps += 1;
            if jumps > 32 {
                return None;
            }
            continue;
        }
        if len > 63 {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(msg.get(i + 1..i + 1 + len)?));
        i += 1 + len;
    }
    Some((name, end?))
}

pub fn parse_dns(m: &[u8]) -> Option<DnsMessage> {
    if m.len() < 12 {
        return None;
    }
    let flags = be16(m, 2)?;
    let (qd, an) = (be16(m, 4)? as usize, be16(m, 6)? as usize);
    if qd > 32 || an > 256 {
        return None;
    }
    let mut out = DnsMessage { id: be16(m, 0)?, response: flags & 0x8000 != 0, rcode: (flags & 0xf) as u8, ..Default::default() };
    let mut i = 12;
    for _ in 0..qd {
        let (name, next) = dns_name(m, i)?;
        out.questions.push((name, be16(m, next)?));
        i = next + 4;
    }
    for _ in 0..an {
        let (name, next) = dns_name(m, i)?;
        let t = be16(m, next)?;
        let rdlen = be16(m, next + 8)? as usize;
        let start = next + 10;
        let rd = m.get(start..start + rdlen)?;
        let value = match t {
            1 if rdlen == 4 => Ipv4Addr::new(rd[0], rd[1], rd[2], rd[3]).to_string(),
            28 if rdlen == 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(rd);
                Ipv6Addr::from(a).to_string()
            }
            5 | 12 | 2 => dns_name(m, start).map(|x| x.0).unwrap_or_default(),
            16 => {
                let mut s = String::new();
                let mut j = 0;
                while j < rd.len() {
                    let l = rd[j] as usize;
                    s.push_str(&String::from_utf8_lossy(rd.get(j + 1..j + 1 + l).unwrap_or(&[])));
                    j += 1 + l;
                }
                s
            }
            _ => String::new(),
        };
        out.answers.push((name, t, value));
        i = start + rdlen;
    }
    Some(out)
}

/// Détail d'un paquet, calculé seulement quand on l'ouvre.
pub fn describe(p: &Packet) -> Vec<(String, Vec<(String, String)>)> {
    let mut out: Vec<(String, Vec<(String, String)>)> = vec![];
    let d = &p.data[..];
    if p.l3_proto == 0x0800 && d.len() >= 20 {
        out.push((
            "IPv4".into(),
            vec![
                ("Source".into(), p.src.map(|a| a.to_string()).unwrap_or_default()),
                ("Destination".into(), p.dst.map(|a| a.to_string()).unwrap_or_default()),
                ("Durée de vie (TTL)".into(), d[8].to_string()),
                ("Identifiant".into(), format!("0x{:04x}", be16(d, 4).unwrap_or(0))),
                ("Ne pas fragmenter".into(), if d[6] & 0x40 != 0 { "Oui".into() } else { "Non".into() }),
            ],
        ));
    } else if p.l3_proto == 0x86DD && d.len() >= 40 {
        out.push((
            "IPv6".into(),
            vec![
                ("Source".into(), p.src.map(|a| a.to_string()).unwrap_or_default()),
                ("Destination".into(), p.dst.map(|a| a.to_string()).unwrap_or_default()),
                ("Limite de sauts".into(), d[7].to_string()),
            ],
        ));
    }
    match p.proto {
        Proto::Tcp => out.push((
            "TCP".into(),
            vec![
                ("Port source".into(), p.sport.to_string()),
                ("Port destination".into(), p.dport.to_string()),
                ("Drapeaux".into(), tcp_flags_label(p.tcp_flags)),
                ("Numéro de séquence".into(), p.seq.to_string()),
                ("Accusé".into(), p.ack.to_string()),
                ("Données transportées".into(), format!("{} octets", (p.orig_len as usize).saturating_sub(p.payload_off))),
            ],
        )),
        Proto::Udp => out.push((
            "UDP".into(),
            vec![
                ("Port source".into(), p.sport.to_string()),
                ("Port destination".into(), p.dport.to_string()),
                ("Données transportées".into(), format!("{} octets", (p.orig_len as usize).saturating_sub(p.payload_off))),
            ],
        )),
        _ => {}
    }
    let payload = p.payload();
    if p.app == "TLS" && payload.len() > 5 {
        let mut fields = vec![];
        if let Some(sni) = &p.sni {
            fields.push(("Site demandé (SNI)".to_string(), sni.clone()));
        }
        if payload[0] == 22 {
            if let Some(h) = parse_client_hello(&payload[5..]) {
                if !h.alpn.is_empty() {
                    fields.push(("Protocoles proposés".to_string(), h.alpn.join(", ")));
                }
            }
            if let Some(h) = parse_server_hello(&payload[5..]) {
                fields.push(("Version choisie".to_string(), h.version_label().to_string()));
                fields.push(("Chiffrement".to_string(), cipher_name(h.cipher).to_string()));
            }
        }
        fields.push(("Résumé".to_string(), p.info.clone()));
        out.push(("TLS".into(), fields));
    }
    if let Some(m) = &p.dns {
        let mut fields = vec![];
        for (n, t) in &m.questions {
            fields.push((format!("Question {}", dns_type_name(*t)), n.clone()));
        }
        for (n, t, v) in &m.answers {
            fields.push((format!("{} {}", dns_type_name(*t), n), v.clone()));
        }
        out.push((p.app.to_string(), fields));
    }
    out
}

/// Vue hexadécimale classique : décalage, 16 octets, texte lisible.
pub fn hex_dump(data: &[u8], limit: usize) -> String {
    let mut out = String::new();
    for (i, chunk) in data[..data.len().min(limit)].chunks(16).enumerate() {
        out.push_str(&format!("{:04x}  ", i * 16));
        for j in 0..16 {
            match chunk.get(j) {
                Some(b) => out.push_str(&format!("{b:02x} ")),
                None => out.push_str("   "),
            }
            if j == 7 {
                out.push(' ');
            }
        }
        out.push(' ');
        for b in chunk {
            out.push(if (0x20..0x7f).contains(b) { *b as char } else { '.' });
        }
        out.push('\n');
    }
    if data.len() > limit {
        out.push_str(&format!("… {} octets de plus\n", data.len() - limit));
    }
    out
}

// ---------- Construction de paquets, pour les tests ----------

pub mod build {
    pub fn ipv4_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let total = 40 + payload.len();
        let mut p = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 1, 0x40, 0, 64, 6, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&ack.to_be_bytes());
        p.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        p.extend_from_slice(payload);
        p
    }

    pub fn ipv4_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let total = 28 + payload.len();
        let mut p = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 1, 0x40, 0, 64, 17, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(payload);
        p
    }

    /// Question ou réponse DNS minimale.
    pub fn dns(id: u16, name: &str, answer: Option<[u8; 4]>) -> Vec<u8> {
        let mut m = id.to_be_bytes().to_vec();
        m.extend_from_slice(if answer.is_some() { &[0x81, 0x80] } else { &[0x01, 0x00] });
        m.extend_from_slice(&[0, 1, 0, answer.is_some() as u8, 0, 0, 0, 0]);
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0, 1, 0, 1]);
        if let Some(ip) = answer {
            m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            m.extend_from_slice(&ip);
        }
        m
    }

    /// Début de connexion TLS avec nom de site et protocoles.
    pub fn tls_client_hello(sni: &str, random: [u8; 32]) -> Vec<u8> {
        let mut ext = vec![];
        let n = sni.len() as u16;
        ext.extend_from_slice(&[0, 0]);
        ext.extend_from_slice(&(n + 5).to_be_bytes());
        ext.extend_from_slice(&(n + 3).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&n.to_be_bytes());
        ext.extend_from_slice(sni.as_bytes());
        ext.extend_from_slice(&[0, 16, 0, 5, 0, 3, 2, b'h', b'2']);
        let mut body = vec![3, 3];
        body.extend_from_slice(&random);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        hs.extend_from_slice(&body);
        let mut rec = vec![22, 3, 1, (hs.len() >> 8) as u8, hs.len() as u8];
        rec.extend_from_slice(&hs);
        rec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(data: Vec<u8>, proto: u16, pkttype: u8) -> RawFrame {
        RawFrame { ts_us: 1, ifindex: 2, pkttype, proto, orig_len: data.len() as u32, data }
    }

    #[test]
    fn tcp_syn_is_understood() {
        let d = build::ipv4_tcp([10, 0, 0, 2], [1, 1, 1, 1], 40000, 443, 7, 0, TCP_SYN, &[]);
        let p = parse(frame(d, 0x0800, 4));
        assert_eq!(p.proto, Proto::Tcp);
        assert_eq!(p.dir, Dir::Out);
        assert_eq!((p.sport, p.dport, p.seq), (40000, 443, 7));
        assert_eq!(p.app, "TLS");
        assert!(p.info.contains("SYN"));
    }

    #[test]
    fn tls_client_hello_reveals_site_but_stays_encrypted() {
        let hello = build::tls_client_hello("exemple.fr", [7; 32]);
        let d = build::ipv4_tcp([10, 0, 0, 2], [1, 1, 1, 1], 40000, 443, 1, 1, TCP_PSH | TCP_ACK, &hello);
        let p = parse(frame(d, 0x0800, 4));
        assert_eq!(p.app, "TLS");
        assert_eq!(p.crypto, Crypto::Yes);
        assert_eq!(p.sni.as_deref(), Some("exemple.fr"));
        assert!(p.info.contains("exemple.fr") && p.info.contains("h2"), "{}", p.info);
        assert_eq!(parse_client_hello(&hello[5..]).unwrap().random, [7; 32]);
    }

    #[test]
    fn tls_application_data_is_flagged_encrypted() {
        let mut rec = vec![23, 3, 3, 0, 100];
        rec.extend_from_slice(&[0x5a; 100]);
        let d = build::ipv4_tcp([1, 1, 1, 1], [10, 0, 0, 2], 443, 40000, 1, 1, TCP_ACK, &rec);
        let p = parse(frame(d, 0x0800, 0));
        assert_eq!(p.dir, Dir::In);
        assert_eq!(p.crypto, Crypto::Yes);
        assert!(p.info.contains("chiffrées"));
    }

    #[test]
    fn http_is_readable() {
        let d = build::ipv4_tcp(
            [10, 0, 0, 2],
            [93, 184, 216, 34],
            40000,
            80,
            1,
            1,
            TCP_PSH | TCP_ACK,
            b"GET /page HTTP/1.1\r\nHost: exemple.fr\r\n\r\n",
        );
        let p = parse(frame(d, 0x0800, 4));
        assert_eq!(p.app, "HTTP");
        assert_eq!(p.crypto, Crypto::No);
        assert_eq!(p.http_host.as_deref(), Some("exemple.fr"));
        assert_eq!(p.info, "GET /page HTTP/1.1");
    }

    #[test]
    fn dns_question_and_answer() {
        let d = build::ipv4_udp([10, 0, 0, 2], [8, 8, 8, 8], 5000, 53, &build::dns(9, "exemple.fr", None));
        let p = parse(frame(d, 0x0800, 4));
        assert_eq!(p.app, "DNS");
        assert!(p.info.contains("Question A : exemple.fr"), "{}", p.info);
        let d = build::ipv4_udp([8, 8, 8, 8], [10, 0, 0, 2], 53, 5000, &build::dns(9, "exemple.fr", Some([1, 2, 3, 4])));
        let p = parse(frame(d, 0x0800, 0));
        assert!(p.info.contains("1.2.3.4"), "{}", p.info);
        assert_eq!(p.dns.unwrap().answers[0].2, "1.2.3.4");
    }

    #[test]
    fn ssh_banner_and_quic() {
        let d = build::ipv4_tcp([10, 0, 0, 2], [5, 5, 5, 5], 40000, 22, 1, 1, TCP_PSH, b"SSH-2.0-OpenSSH_9.6\r\n");
        let p = parse(frame(d, 0x0800, 4));
        assert_eq!(p.app, "SSH");
        assert!(p.info.contains("OpenSSH_9.6"));
        let d = build::ipv4_udp([10, 0, 0, 2], [1, 1, 1, 1], 40000, 443, &[0xc0, 0, 0, 0, 1]);
        let p = parse(frame(d, 0x0800, 4));
        assert_eq!(p.app, "QUIC");
        assert_eq!(p.crypto, Crypto::Yes);
    }

    #[test]
    fn arp_and_truncated_never_panic() {
        let mut arp = vec![0, 1, 8, 0, 6, 4, 0, 1];
        arp.extend_from_slice(&[1, 2, 3, 4, 5, 6, 192, 168, 1, 10, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1]);
        let p = parse(frame(arp, 0x0806, 1));
        assert_eq!(p.proto, Proto::Arp);
        assert!(p.info.contains("192.168.1.1"));
        // Découpe un paquet réel à chaque longueur : jamais de plantage.
        let hello = build::tls_client_hello("exemple.fr", [1; 32]);
        let full = build::ipv4_tcp([10, 0, 0, 2], [1, 1, 1, 1], 40000, 443, 1, 1, TCP_PSH, &hello);
        for n in 0..full.len() {
            let _ = parse(frame(full[..n].to_vec(), 0x0800, 4));
        }
        let dns_full = build::ipv4_udp([8, 8, 8, 8], [10, 0, 0, 2], 53, 5000, &build::dns(9, "exemple.fr", Some([1, 2, 3, 4])));
        for n in 0..dns_full.len() {
            let _ = parse(frame(dns_full[..n].to_vec(), 0x0800, 0));
        }
    }

    #[test]
    fn crypto_guess() {
        assert_eq!(guess_crypto(b"short"), Crypto::Unknown);
        let text = "bonjour tout le monde, ceci est un message parfaitement lisible.".repeat(4);
        assert_eq!(guess_crypto(text.as_bytes()), Crypto::No);
        let mut x: u32 = 12345;
        let random: Vec<u8> = (0..1000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        assert_eq!(guess_crypto(&random), Crypto::Probable);
    }

    #[test]
    fn hexdump_format() {
        let s = hex_dump(b"ABC", 100);
        assert!(s.starts_with("0000  41 42 43"));
        assert!(s.trim_end().ends_with("ABC"));
    }
}
