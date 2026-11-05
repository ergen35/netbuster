//! Qui est cette IP ? Nom inverse, opérateur (AS) via le DNS de Team Cymru, détails via RDAP.

use crate::packet::parse_dns;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpScope {
    Public,
    Loopback,
    Private,
    LinkLocal,
    Multicast,
    Cgnat,
    Unspecified,
    Reserved,
}

impl IpScope {
    pub fn label(self) -> &'static str {
        match self {
            IpScope::Public => "Adresse publique",
            IpScope::Loopback => "Ce PC (boucle locale)",
            IpScope::Private => "Réseau local privé",
            IpScope::LinkLocal => "Lien local",
            IpScope::Multicast => "Multidiffusion",
            IpScope::Cgnat => "Partagée par l'opérateur (CGNAT)",
            IpScope::Unspecified => "Non précisée",
            IpScope::Reserved => "Réservée",
        }
    }
}

pub fn ip_scope(ip: IpAddr) -> IpScope {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            if a.is_unspecified() {
                IpScope::Unspecified
            } else if a.is_loopback() {
                IpScope::Loopback
            } else if a.is_private() {
                IpScope::Private
            } else if a.is_link_local() {
                IpScope::LinkLocal
            } else if a.is_multicast() || a.is_broadcast() {
                IpScope::Multicast
            } else if o[0] == 100 && (64..128).contains(&o[1]) {
                IpScope::Cgnat
            } else if o[0] >= 240 || o[0] == 0 || (o[0] == 192 && o[1] == 0 && o[2] == 2) || (o[0] == 198 && o[1] == 51) || (o[0] == 203 && o[1] == 0 && o[2] == 113) {
                IpScope::Reserved
            } else {
                IpScope::Public
            }
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            if a.is_unspecified() {
                IpScope::Unspecified
            } else if a.is_loopback() {
                IpScope::Loopback
            } else if a.is_multicast() {
                IpScope::Multicast
            } else if s[0] & 0xffc0 == 0xfe80 {
                IpScope::LinkLocal
            } else if s[0] & 0xfe00 == 0xfc00 {
                IpScope::Private
            } else if s[0] == 0x2001 && s[1] == 0xdb8 {
                IpScope::Reserved
            } else if let Some(v4) = a.to_ipv4_mapped() {
                ip_scope(IpAddr::V4(v4))
            } else {
                IpScope::Public
            }
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AsInfo {
    pub asn: u32,
    pub prefix: String,
    pub country: String,
    pub registry: String,
    pub allocated: String,
    pub as_name: String,
}

impl AsInfo {
    /// `GOOGLE - Google LLC, US` → `Google LLC`
    pub fn provider(&self) -> String {
        clean_as_name(&self.as_name)
    }
}

pub fn clean_as_name(raw: &str) -> String {
    let mut s = raw.trim();
    if let Some((head, tail)) = s.rsplit_once(", ") {
        if tail.len() == 2 && tail.chars().all(|c| c.is_ascii_uppercase()) {
            s = head;
        }
    }
    let s = match s.split_once(" - ") {
        Some((_, name)) => name,
        None => s,
    };
    s.trim().to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RdapInfo {
    pub name: String,
    pub handle: String,
    pub range: String,
    pub kind: String,
    pub country: String,
    pub organisation: String,
    pub abuse: String,
    pub registered: String,
    pub last_changed: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpInfo {
    pub rdns: Option<String>,
    pub as_info: Option<AsInfo>,
    pub rdap: Option<RdapInfo>,
    pub rdap_error: Option<String>,
    pub done: bool,
    pub failed: bool,
    #[serde(skip)]
    pub rdap_pending: bool,
}

impl IpInfo {
    pub fn provider(&self) -> Option<String> {
        self.as_info.as_ref().map(|a| a.provider()).filter(|s| !s.is_empty())
    }
}

/// Service reconnaissable à partir d'un nom de machine.
pub fn service_from_host(host: &str) -> Option<String> {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    const KNOWN: &[(&str, &str)] = &[
        ("1e100.net", "Google"),
        ("googleusercontent.com", "Google"),
        ("googlevideo.com", "YouTube"),
        ("youtube.com", "YouTube"),
        ("google.com", "Google"),
        ("gstatic.com", "Google"),
        ("amazonaws.com", "Amazon Web Services"),
        ("cloudfront.net", "Amazon CloudFront"),
        ("akamaitechnologies.com", "Akamai"),
        ("akamaiedge.net", "Akamai"),
        ("fastly.net", "Fastly"),
        ("cloudflare.com", "Cloudflare"),
        ("github.com", "GitHub"),
        ("githubusercontent.com", "GitHub"),
        ("microsoft.com", "Microsoft"),
        ("azure.com", "Microsoft Azure"),
        ("office.com", "Microsoft Office"),
        ("facebook.com", "Facebook"),
        ("fbcdn.net", "Facebook"),
        ("whatsapp.net", "WhatsApp"),
        ("apple.com", "Apple"),
        ("icloud.com", "Apple iCloud"),
        ("anthropic.com", "Anthropic"),
        ("claude.ai", "Anthropic"),
        ("openai.com", "OpenAI"),
        ("spotify.com", "Spotify"),
        ("netflix.com", "Netflix"),
        ("nflxvideo.net", "Netflix"),
        ("ubuntu.com", "Ubuntu"),
        ("canonical.com", "Canonical"),
        ("docker.io", "Docker"),
        ("docker.com", "Docker"),
    ];
    for (suffix, name) in KNOWN {
        if h == *suffix || h.ends_with(&format!(".{suffix}")) {
            return Some((*name).to_string());
        }
    }
    None
}

// ---------- Requêtes DNS directes ----------

fn encode_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut m = id.to_be_bytes().to_vec();
    m.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for l in name.trim_end_matches('.').split('.') {
        m.push(l.len() as u8);
        m.extend_from_slice(l.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&[0, 1]);
    m
}

fn resolvers() -> Vec<IpAddr> {
    let mut out = crate::platform::dns_servers();
    if out.is_empty() {
        out.push(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)));
    }
    out
}

pub fn dns_txt(name: &str) -> Option<Vec<String>> {
    for server in resolvers() {
        let bind: SocketAddr = if server.is_ipv4() { "0.0.0.0:0".parse().ok()? } else { "[::]:0".parse().ok()? };
        let Ok(sock) = UdpSocket::bind(bind) else { continue };
        let _ = sock.set_read_timeout(Some(Duration::from_millis(2500)));
        let id = (std::process::id() as u16) ^ (std::time::UNIX_EPOCH.elapsed().map(|d| d.subsec_nanos()).unwrap_or(0) as u16);
        let q = encode_query(id, name, 16);
        for _ in 0..2 {
            if sock.send_to(&q, (server, 53)).is_err() {
                break;
            }
            let mut buf = [0u8; 1500];
            if let Ok((n, _)) = sock.recv_from(&mut buf) {
                if let Some(m) = parse_dns(&buf[..n]) {
                    if m.id == id {
                        return Some(m.answers.into_iter().filter(|a| a.1 == 16).map(|a| a.2).collect());
                    }
                }
            }
        }
    }
    None
}

/// `15169 | 8.8.8.0/24 | US | arin | 2023-12-28`
pub fn parse_origin_txt(txt: &str) -> Option<AsInfo> {
    let parts: Vec<&str> = txt.split('|').map(str::trim).collect();
    if parts.len() < 3 {
        return None;
    }
    Some(AsInfo {
        asn: parts[0].split_whitespace().next()?.parse().ok()?,
        prefix: parts[1].to_string(),
        country: parts[2].to_string(),
        registry: parts.get(3).unwrap_or(&"").to_string(),
        allocated: parts.get(4).unwrap_or(&"").to_string(),
        as_name: String::new(),
    })
}

pub fn origin_query_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(a) => {
            let mut s = String::new();
            for b in a.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", b & 0xf, b >> 4));
            }
            s + "origin6.asn.cymru.com"
        }
    }
}

fn lookup_as(ip: IpAddr) -> Option<AsInfo> {
    let answers = dns_txt(&origin_query_name(ip))?;
    let mut info = parse_origin_txt(answers.first()?)?;
    if let Some(txt) = dns_txt(&format!("AS{}.asn.cymru.com", info.asn)) {
        if let Some(line) = txt.first() {
            info.as_name = line.split('|').next_back().unwrap_or("").trim().to_string();
        }
    }
    Some(info)
}

/// Sous Windows, la bibliothèque réseau doit être prête : la bibliothèque standard s'en charge
/// à l'ouverture de sa première prise.
#[cfg(windows)]
pub fn reverse_dns(ip: IpAddr) -> Option<String> {
    use windows_sys::Win32::Networking::WinSock as ws;
    let _ = UdpSocket::bind("127.0.0.1:0");
    let mut host = [0u8; 1025];
    let rc = unsafe {
        match ip {
            IpAddr::V4(a) => {
                let mut raw: ws::SOCKADDR_IN = std::mem::zeroed();
                raw.sin_family = ws::AF_INET;
                raw.sin_addr.S_un.S_addr = u32::from_ne_bytes(a.octets());
                ws::getnameinfo(&raw as *const _ as *const ws::SOCKADDR, std::mem::size_of_val(&raw) as i32, host.as_mut_ptr(), host.len() as u32, std::ptr::null_mut(), 0, ws::NI_NAMEREQD as i32)
            }
            IpAddr::V6(a) => {
                let mut raw: ws::SOCKADDR_IN6 = std::mem::zeroed();
                raw.sin6_family = ws::AF_INET6;
                raw.sin6_addr.u.Byte = a.octets();
                ws::getnameinfo(&raw as *const _ as *const ws::SOCKADDR, std::mem::size_of_val(&raw) as i32, host.as_mut_ptr(), host.len() as u32, std::ptr::null_mut(), 0, ws::NI_NAMEREQD as i32)
            }
        }
    };
    if rc != 0 {
        return None;
    }
    let end = host.iter().position(|c| *c == 0)?;
    let s = String::from_utf8_lossy(&host[..end]).into_owned();
    (!s.is_empty()).then_some(s)
}

#[cfg(unix)]
pub fn reverse_dns(ip: IpAddr) -> Option<String> {
    let sa = SocketAddr::new(ip, 0);
    let mut host = [0 as libc::c_char; 1025];
    let rc = unsafe {
        match sa {
            SocketAddr::V4(a) => {
                // Les champs diffèrent selon le système : partir de zéros les couvre tous.
                let mut raw: libc::sockaddr_in = std::mem::zeroed();
                raw.sin_family = libc::AF_INET as libc::sa_family_t;
                raw.sin_addr = libc::in_addr { s_addr: u32::from_ne_bytes(a.ip().octets()) };
                #[cfg(target_os = "macos")]
                {
                    raw.sin_len = std::mem::size_of_val(&raw) as u8;
                }
                libc::getnameinfo(
                    &raw as *const _ as *const libc::sockaddr,
                    std::mem::size_of_val(&raw) as u32,
                    host.as_mut_ptr(),
                    host.len() as u32,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
            SocketAddr::V6(a) => {
                let mut raw: libc::sockaddr_in6 = std::mem::zeroed();
                raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                raw.sin6_addr = libc::in6_addr { s6_addr: a.ip().octets() };
                #[cfg(target_os = "macos")]
                {
                    raw.sin6_len = std::mem::size_of_val(&raw) as u8;
                }
                libc::getnameinfo(
                    &raw as *const _ as *const libc::sockaddr,
                    std::mem::size_of_val(&raw) as u32,
                    host.as_mut_ptr(),
                    host.len() as u32,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };
    if rc != 0 {
        return None;
    }
    let s = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) }.to_string_lossy().into_owned();
    (!s.is_empty()).then_some(s)
}

// ---------- RDAP ----------

pub fn parse_rdap(v: &serde_json::Value) -> RdapInfo {
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let mut out = RdapInfo {
        name: s("name"),
        handle: s("handle"),
        kind: s("type"),
        country: s("country"),
        ..Default::default()
    };
    let (a, b) = (s("startAddress"), s("endAddress"));
    if !a.is_empty() {
        out.range = format!("{a} – {b}");
    }
    if let Some(events) = v.get("events").and_then(|e| e.as_array()) {
        for e in events {
            let date = e.get("eventDate").and_then(|d| d.as_str()).unwrap_or("");
            let date = date.split('T').next().unwrap_or("").to_string();
            match e.get("eventAction").and_then(|a| a.as_str()) {
                Some("registration") => out.registered = date,
                Some("last changed") => out.last_changed = date,
                _ => {}
            }
        }
    }
    fn walk(ents: &serde_json::Value, out: &mut RdapInfo) {
        let Some(list) = ents.as_array() else { return };
        for e in list {
            let roles: Vec<&str> = e.get("roles").and_then(|r| r.as_array()).map(|r| r.iter().filter_map(|x| x.as_str()).collect()).unwrap_or_default();
            let (mut fname, mut email) = (String::new(), String::new());
            if let Some(card) = e.get("vcardArray").and_then(|c| c.get(1)).and_then(|c| c.as_array()) {
                for f in card {
                    match f.get(0).and_then(|x| x.as_str()) {
                        Some("fn") => fname = f.get(3).and_then(|x| x.as_str()).unwrap_or("").to_string(),
                        Some("email") => email = f.get(3).and_then(|x| x.as_str()).unwrap_or("").to_string(),
                        _ => {}
                    }
                }
            }
            if out.organisation.is_empty() && roles.iter().any(|r| matches!(*r, "registrant" | "administrative" | "owner")) && !fname.is_empty() {
                out.organisation = fname.clone();
            }
            if out.abuse.is_empty() && roles.contains(&"abuse") && !email.is_empty() {
                out.abuse = email;
            }
            if let Some(sub) = e.get("entities") {
                walk(sub, out);
            }
        }
    }
    if let Some(e) = v.get("entities") {
        walk(e, &mut out);
    }
    out
}

fn fetch_rdap(ip: IpAddr) -> Result<RdapInfo, String> {
    let url = format!("https://rdap.org/ip/{ip}");
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(12))).build().into();
    let mut resp = agent
        .get(&url)
        .header("User-Agent", "NetBuster")
        .header("Accept", "application/rdap+json, application/json")
        .call()
        .map_err(|e| format!("Registre injoignable : {e}"))?;
    let v: serde_json::Value = resp.body_mut().read_json().map_err(|e| format!("Réponse illisible : {e}"))?;
    Ok(parse_rdap(&v))
}

// ---------- File de travail ----------

pub struct Enricher {
    pub cache: Mutex<HashMap<IpAddr, IpInfo>>,
    queue: Mutex<VecDeque<IpAddr>>,
    queued: Mutex<HashSet<IpAddr>>,
    wake: Condvar,
    pub auto: AtomicBool,
    dirty: AtomicBool,
}

impl Enricher {
    pub fn start() -> Arc<Self> {
        let cache = load_cache();
        let me = Arc::new(Enricher {
            cache: Mutex::new(cache),
            queue: Mutex::new(VecDeque::new()),
            queued: Mutex::new(HashSet::new()),
            wake: Condvar::new(),
            auto: AtomicBool::new(true),
            dirty: AtomicBool::new(false),
        });
        for _ in 0..3 {
            let m = me.clone();
            std::thread::spawn(move || m.worker());
        }
        let m = me.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(30));
            m.save();
        });
        me
    }

    fn worker(&self) {
        loop {
            let ip = {
                let mut q = self.queue.lock().unwrap();
                loop {
                    if let Some(ip) = q.pop_front() {
                        break ip;
                    }
                    q = self.wake.wait(q).unwrap();
                }
            };
            let rdns = reverse_dns(ip);
            let as_info = lookup_as(ip);
            let failed = as_info.is_none() && rdns.is_none();
            {
                let mut c = self.cache.lock().unwrap();
                let e = c.entry(ip).or_default();
                e.rdns = rdns;
                e.as_info = as_info;
                e.done = true;
                e.failed = failed;
            }
            self.queued.lock().unwrap().remove(&ip);
            self.dirty.store(true, Ordering::Relaxed);
        }
    }

    /// Infos connues pour cette IP ; si l'identification automatique est active, la demande si besoin.
    pub fn info(&self, ip: IpAddr) -> Option<IpInfo> {
        let known = self.cache.lock().unwrap().get(&ip).cloned();
        if known.as_ref().is_none_or(|k| !k.done) && self.auto.load(Ordering::Relaxed) {
            self.request(ip);
        }
        known
    }

    /// Demande explicite, même si l'identification automatique est coupée.
    pub fn request(&self, ip: IpAddr) {
        if ip_scope(ip) != IpScope::Public {
            return;
        }
        if self.cache.lock().unwrap().get(&ip).is_some_and(|k| k.done && !k.failed) {
            return;
        }
        if self.queued.lock().unwrap().insert(ip) {
            self.queue.lock().unwrap().push_back(ip);
            self.wake.notify_one();
        }
    }

    pub fn request_rdap(self: &Arc<Self>, ip: IpAddr) {
        {
            let mut c = self.cache.lock().unwrap();
            let e = c.entry(ip).or_default();
            if e.rdap_pending || e.rdap.is_some() {
                return;
            }
            e.rdap_pending = true;
            e.rdap_error = None;
        }
        let me = self.clone();
        std::thread::spawn(move || {
            let res = fetch_rdap(ip);
            let mut c = me.cache.lock().unwrap();
            let e = c.entry(ip).or_default();
            e.rdap_pending = false;
            match res {
                Ok(r) => e.rdap = Some(r),
                Err(m) => e.rdap_error = Some(m),
            }
            me.dirty.store(true, Ordering::Relaxed);
        });
    }

    pub fn provider_of(&self, ip: IpAddr) -> Option<String> {
        self.info(ip).and_then(|i| i.provider())
    }

    pub fn save(&self) {
        if !self.dirty.swap(false, Ordering::Relaxed) {
            return;
        }
        let map: HashMap<String, IpInfo> = self
            .cache
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, v)| v.done && !v.failed)
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect();
        if let Ok(text) = serde_json::to_string(&map) {
            let dir = crate::util::data_dir();
            let _ = std::fs::create_dir_all(&dir);
            let tmp = dir.join("ip-cache.tmp");
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(tmp, dir.join("ip-cache.json"));
            }
        }
    }
}

fn load_cache() -> HashMap<IpAddr, IpInfo> {
    let Ok(text) = std::fs::read_to_string(crate::util::data_dir().join("ip-cache.json")) else { return HashMap::new() };
    let raw: HashMap<String, IpInfo> = serde_json::from_str(&text).unwrap_or_default();
    raw.into_iter().filter_map(|(k, v)| Some((k.parse().ok()?, v))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes() {
        assert_eq!(ip_scope("8.8.8.8".parse().unwrap()), IpScope::Public);
        assert_eq!(ip_scope("192.168.1.1".parse().unwrap()), IpScope::Private);
        assert_eq!(ip_scope("127.0.0.1".parse().unwrap()), IpScope::Loopback);
        assert_eq!(ip_scope("100.70.1.1".parse().unwrap()), IpScope::Cgnat);
        assert_eq!(ip_scope("224.0.0.1".parse().unwrap()), IpScope::Multicast);
        assert_eq!(ip_scope("fe80::1".parse().unwrap()), IpScope::LinkLocal);
        assert_eq!(ip_scope("2a00:1450::1".parse().unwrap()), IpScope::Public);
        assert_eq!(ip_scope("fd00::1".parse().unwrap()), IpScope::Private);
    }

    #[test]
    fn cymru_formats() {
        let a = parse_origin_txt("15169 | 8.8.8.0/24 | US | arin | 2023-12-28").unwrap();
        assert_eq!(a.asn, 15169);
        assert_eq!(a.prefix, "8.8.8.0/24");
        assert_eq!(a.country, "US");
        assert_eq!(clean_as_name("GOOGLE - Google LLC, US"), "Google LLC");
        assert_eq!(clean_as_name("AKAMAI-AS, US"), "AKAMAI-AS");
        assert_eq!(clean_as_name("CLOUDFLARENET - Cloudflare, Inc., US"), "Cloudflare, Inc.");
        assert_eq!(origin_query_name("8.8.4.4".parse().unwrap()), "4.4.8.8.origin.asn.cymru.com");
        assert!(origin_query_name("2001:db8::1".parse().unwrap()).starts_with("1.0.0.0."));
        assert!(origin_query_name("2001:db8::1".parse().unwrap()).ends_with("8.b.d.0.1.0.0.2.origin6.asn.cymru.com"));
    }

    #[test]
    fn services() {
        assert_eq!(service_from_host("par10s34-in-f14.1e100.net").as_deref(), Some("Google"));
        assert_eq!(service_from_host("exemple.fr"), None);
        assert_eq!(service_from_host("rr3.googlevideo.com.").as_deref(), Some("YouTube"));
    }

    #[test]
    fn rdap_real_shape() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"name":"GOGL","handle":"NET-8-8-8-0-2","type":"DIRECT ALLOCATION","startAddress":"8.8.8.0","endAddress":"8.8.8.255",
            "events":[{"eventAction":"registration","eventDate":"2023-12-28T17:24:33-05:00"}],
            "entities":[{"roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Google LLC"]]],
              "entities":[{"roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text","Abuse"],["email",{},"text","network-abuse@google.com"]]]}]}]}"#,
        )
        .unwrap();
        let r = parse_rdap(&v);
        assert_eq!(r.name, "GOGL");
        assert_eq!(r.organisation, "Google LLC");
        assert_eq!(r.abuse, "network-abuse@google.com");
        assert_eq!(r.range, "8.8.8.0 – 8.8.8.255");
        assert_eq!(r.registered, "2023-12-28");
    }

    #[test]
    fn query_encoding_parses_back() {
        let q = encode_query(7, "4.4.8.8.origin.asn.cymru.com", 16);
        let m = parse_dns(&q).unwrap();
        assert_eq!(m.questions[0].0, "4.4.8.8.origin.asn.cymru.com");
        assert_eq!(m.questions[0].1, 16);
    }
}
