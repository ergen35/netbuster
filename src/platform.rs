//! Ce qui change d'un système à l'autre : le relevé des interfaces et des connexions.
//!
//! Linux lit `/sys`, `ip` et `ss`. Windows interroge PowerShell, macOS `netstat` et `lsof`.
//! Les lectures de sortie ne dépendent pas du système où elles tournent : elles sont testées partout
//! sur des exemples, et un test propre à chaque système vérifie le relevé réel de la machine.

use crate::admin::Admin;
use crate::collect::{read_interfaces, IfSnapshot};
use crate::model::IfKind;
use crate::packet::Proto;
use crate::ss::{self, SockEntry, SockInfo, SS_ARGS};
use crate::util::run;
use serde_json::Value;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub type AddrMap = HashMap<String, Vec<(IpAddr, u8)>>;

/// Le temps entre deux relevés : lancer PowerShell coûte bien plus cher que lire `/sys`.
pub const SAMPLE_EVERY: Duration = if cfg!(windows) {
    Duration::from_secs(2)
} else if cfg!(target_os = "macos") {
    Duration::from_secs(1)
} else {
    Duration::from_millis(500)
};

static PREVIEW_LIMITED: AtomicBool = AtomicBool::new(false);

/// Capture de paquets, pare-feu, configuration réseau, SSH et service : aujourd'hui, sous Linux seulement.
pub fn full_features() -> bool {
    cfg!(target_os = "linux") && !PREVIEW_LIMITED.load(Ordering::Relaxed)
}

/// Pour vérifier depuis Linux les écrans que voient Windows et macOS.
pub fn preview_limited() {
    PREVIEW_LIMITED.store(true, Ordering::Relaxed);
}

pub fn system_name() -> &'static str {
    if cfg!(windows) {
        "Windows"
    } else if cfg!(target_os = "macos") {
        "macOS"
    } else {
        "ce système"
    }
}

/// Le compte qui fait tourner NetBuster, là où le système a cette notion.
pub fn own_uid() -> Option<u32> {
    #[cfg(unix)]
    {
        Some(unsafe { libc::getuid() })
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Fait les relevés du système. Sous Windows, une seule commande répond à tout : les connexions lues
/// avec les interfaces attendent ici la question suivante.
#[derive(Default)]
pub struct Collector {
    waiting_sockets: Option<Vec<SockEntry>>,
    mac_ports: Option<HashMap<String, IfKind>>,
}

impl Collector {
    pub fn interfaces(&mut self, want_addrs: bool) -> (Vec<IfSnapshot>, Option<AddrMap>) {
        if cfg!(windows) {
            let r = run("powershell", &["-NoProfile", "-NonInteractive", "-Command", WINDOWS_SNAPSHOT]);
            let snap = parse_windows_snapshot(&r.stdout);
            self.waiting_sockets = Some(snap.sockets);
            (snap.ifaces, want_addrs.then_some(snap.addrs))
        } else if cfg!(target_os = "macos") {
            let ports = self.mac_ports.get_or_insert_with(|| parse_mac_hardware_ports(&run("networksetup", &["-listallhardwareports"]).stdout));
            let (ifaces, addrs) = parse_mac_netstat(&run("netstat", &["-ibn"]).stdout, ports);
            (ifaces, want_addrs.then_some(addrs))
        } else {
            let addrs = want_addrs.then(|| run("ip", &["-j", "addr"])).filter(|r| r.ok).map(|r| crate::collect::parse_ip_addr_json(&r.stdout));
            (read_interfaces(Path::new("/sys/class/net")), addrs)
        }
    }

    pub fn sockets(&mut self, admin: &Admin) -> Vec<SockEntry> {
        if cfg!(windows) {
            self.waiting_sockets.take().unwrap_or_default()
        } else if cfg!(target_os = "macos") {
            parse_lsof(&run("lsof", &["-nP", "+c0", "-iTCP", "-iUDP", "-FcufPnT"]).stdout)
        } else {
            ss::parse_output(&admin.exec_best("ss", SS_ARGS).stdout)
        }
    }
}

/// Les serveurs DNS du PC, pour demander à qui appartient une adresse.
pub fn dns_servers() -> Vec<IpAddr> {
    if cfg!(windows) {
        static CACHE: Mutex<Option<(Instant, Vec<IpAddr>)>> = Mutex::new(None);
        let mut cache = CACHE.lock().unwrap();
        if let Some((at, list)) = cache.as_ref() {
            if at.elapsed() < Duration::from_secs(300) {
                return list.clone();
            }
        }
        let r = run("powershell", &["-NoProfile", "-NonInteractive", "-Command", WINDOWS_DNS]);
        let list: Vec<IpAddr> = r.stdout.lines().filter_map(|l| l.trim().parse().ok()).collect();
        // Une liste vide vient souvent d'un réseau pas encore prêt : elle ne reste pas en mémoire.
        if !list.is_empty() {
            *cache = Some((Instant::now(), list.clone()));
        }
        list
    } else {
        parse_resolv_conf(&std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default())
    }
}

pub fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    text.lines().filter_map(|l| l.trim().strip_prefix("nameserver")).filter_map(|s| s.trim().parse().ok()).collect()
}

/// Le fichier des noms de ports.
pub fn services_file() -> std::path::PathBuf {
    if cfg!(windows) {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        Path::new(&root).join("System32").join("drivers").join("etc").join("services")
    } else {
        "/etc/services".into()
    }
}

// ---------- Windows ----------

const WINDOWS_DNS: &str = "(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses";

/// Une seule réponse en JSON : les noms de champs et d'états ne changent pas avec la langue de Windows,
/// contrairement au texte de `netstat`.
const WINDOWS_SNAPSHOT: &str = "$ErrorActionPreference='SilentlyContinue';\
[Console]::OutputEncoding=[Text.Encoding]::UTF8;\
$s=@{};foreach($x in Get-NetAdapterStatistics){$s[$x.Name]=$x};\
$a=@(Get-NetAdapter|ForEach-Object{$c=$s[$_.Name];[pscustomobject]@{n=$_.Name;i=[uint32]$_.ifIndex;st=[string]$_.Status;m=[string]$_.MacAddress;mtu=[uint32]$_.MtuSize;sp=[uint64]$_.Speed;mt=[string]$_.MediaType;v=[bool]$_.Virtual;d=[string]$_.InterfaceDescription;rx=[uint64]$c.ReceivedBytes;tx=[uint64]$c.SentBytes;rp=[uint64]$c.ReceivedUnicastPackets;tp=[uint64]$c.SentUnicastPackets;re=[uint64]$c.ReceivedPacketErrors;te=[uint64]$c.OutboundPacketErrors;rd=[uint64]$c.ReceivedDiscardedPackets;td=[uint64]$c.OutboundDiscardedPackets}});\
$ip=@(Get-NetIPAddress|ForEach-Object{[pscustomobject]@{n=$_.InterfaceAlias;a=$_.IPAddress;p=[int]$_.PrefixLength}});\
$t=@(Get-NetTCPConnection|ForEach-Object{[pscustomobject]@{la=$_.LocalAddress;lp=[int]$_.LocalPort;ra=$_.RemoteAddress;rp=[int]$_.RemotePort;st=$_.State.ToString();pid=[uint32]$_.OwningProcess}});\
$u=@(Get-NetUDPEndpoint|ForEach-Object{[pscustomobject]@{la=$_.LocalAddress;lp=[int]$_.LocalPort;pid=[uint32]$_.OwningProcess}});\
$p=@(Get-Process|ForEach-Object{[pscustomobject]@{id=[uint32]$_.Id;n=$_.ProcessName}});\
@{a=$a;ip=$ip;t=$t;u=$u;p=$p}|ConvertTo-Json -Compress -Depth 3";

#[derive(Default)]
pub struct WindowsSnapshot {
    pub ifaces: Vec<IfSnapshot>,
    pub addrs: AddrMap,
    pub sockets: Vec<SockEntry>,
}

fn strip_scope(ip: &str) -> Option<IpAddr> {
    let ip: IpAddr = ip.split('%').next()?.trim().parse().ok()?;
    Some(match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    })
}

fn windows_kind(media: &str, is_virtual: bool, description: &str) -> IfKind {
    let d = description.to_lowercase();
    if ["vpn", "tap-", "wireguard", "wintun", "tunnel", "openvpn"].iter().any(|w| d.contains(w)) {
        IfKind::Tunnel
    } else if is_virtual || ["virtual", "hyper-v", "vmware", "virtualbox", "vethernet"].iter().any(|w| d.contains(w)) {
        IfKind::Virtual
    } else if media.contains("802.11") || media.to_lowercase().contains("wireless") {
        IfKind::Wifi
    } else {
        IfKind::Ethernet
    }
}

/// Le vocabulaire de `ss`, celui que le reste du programme connaît.
fn windows_state(state: &str) -> Option<&'static str> {
    Some(match state {
        "Listen" => "LISTEN",
        "Established" => "ESTAB",
        "SynSent" => "SYN-SENT",
        "SynReceived" => "SYN-RECV",
        "FinWait1" => "FIN-WAIT-1",
        "FinWait2" => "FIN-WAIT-2",
        "CloseWait" => "CLOSE-WAIT",
        "Closing" => "CLOSING",
        "LastAck" => "LAST-ACK",
        "TimeWait" => "TIME-WAIT",
        "Closed" => "CLOSED",
        // « Bound » est un port réservé sans connexion, « DeleteTCB » une connexion déjà finie.
        _ => return None,
    })
}

fn plain_entry(proto: Proto, state: &str, local: SocketAddr, remote: SocketAddr, procs: Vec<(String, u32, u32)>, uid: Option<u32>) -> SockEntry {
    SockEntry { proto, state: state.into(), recv_q: 0, send_q: 0, local, remote, scope_if: None, procs, uid, inode: None, service: None, info: SockInfo::default() }
}

fn windows_list(v: &Value, key: &str) -> Vec<Value> {
    match v.get(key) {
        Some(Value::Array(a)) => a.clone(),
        // Selon la version de PowerShell, une liste d'un seul élément perd ses crochets.
        Some(o @ Value::Object(_)) => vec![o.clone()],
        _ => vec![],
    }
}

pub fn parse_windows_snapshot(text: &str) -> WindowsSnapshot {
    let v: Value = serde_json::from_str(text.trim_start_matches('\u{feff}').trim()).unwrap_or_default();
    let mut out = WindowsSnapshot::default();
    let s = |o: &Value, k: &str| o.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let n = |o: &Value, k: &str| o.get(k).and_then(Value::as_u64).unwrap_or(0);

    for a in windows_list(&v, "a") {
        let name = s(&a, "n");
        if name.is_empty() {
            continue;
        }
        let speed = n(&a, "sp") / 1_000_000;
        out.ifaces.push(IfSnapshot {
            index: n(&a, "i") as u32,
            kind: windows_kind(&s(&a, "mt"), a.get("v").and_then(Value::as_bool).unwrap_or(false), &s(&a, "d")),
            state: if s(&a, "st").eq_ignore_ascii_case("up") { "up".into() } else { "down".into() },
            mac: s(&a, "m").replace('-', ":").to_lowercase(),
            mtu: n(&a, "mtu") as u32,
            speed: (speed > 0).then_some(speed as i64),
            bridge_port: false,
            rx: n(&a, "rx"),
            tx: n(&a, "tx"),
            rx_p: n(&a, "rp"),
            tx_p: n(&a, "tp"),
            rx_e: n(&a, "re"),
            tx_e: n(&a, "te"),
            rx_d: n(&a, "rd"),
            tx_d: n(&a, "td"),
            name,
        });
    }

    for a in windows_list(&v, "ip") {
        if let Some(ip) = strip_scope(&s(&a, "a")) {
            out.addrs.entry(s(&a, "n")).or_default().push((ip, n(&a, "p") as u8));
        }
    }

    let names: HashMap<u64, String> = windows_list(&v, "p").iter().map(|p| (n(p, "id"), s(p, "n"))).collect();
    let procs = |pid: u64| match names.get(&pid) {
        Some(name) if !name.is_empty() => vec![(name.clone(), pid as u32, 0)],
        _ => vec![],
    };
    let unspecified = |ip: IpAddr| if ip.is_ipv4() { IpAddr::V4(Ipv4Addr::UNSPECIFIED) } else { IpAddr::V6(Ipv6Addr::UNSPECIFIED) };

    for c in windows_list(&v, "t") {
        let Some(state) = windows_state(&s(&c, "st")) else { continue };
        let Some(la) = strip_scope(&s(&c, "la")) else { continue };
        let remote = SocketAddr::new(strip_scope(&s(&c, "ra")).unwrap_or(unspecified(la)), n(&c, "rp") as u16);
        out.sockets.push(plain_entry(Proto::Tcp, state, SocketAddr::new(la, n(&c, "lp") as u16), remote, procs(n(&c, "pid")), None));
    }
    for c in windows_list(&v, "u") {
        let Some(la) = strip_scope(&s(&c, "la")) else { continue };
        let remote = SocketAddr::new(unspecified(la), 0);
        out.sockets.push(plain_entry(Proto::Udp, "UNCONN", SocketAddr::new(la, n(&c, "lp") as u16), remote, procs(n(&c, "pid")), None));
    }
    out
}

// ---------- macOS ----------

/// `networksetup -listallhardwareports` : seul moyen simple de distinguer le Wi-Fi de l'Ethernet.
pub fn parse_mac_hardware_ports(text: &str) -> HashMap<String, IfKind> {
    let mut out = HashMap::new();
    let mut port = "";
    for l in text.lines() {
        if let Some(p) = l.strip_prefix("Hardware Port:") {
            port = p.trim();
        } else if let Some(d) = l.strip_prefix("Device:") {
            let kind = if port == "Wi-Fi" || port == "AirPort" { IfKind::Wifi } else { IfKind::Ethernet };
            out.insert(d.trim().to_string(), kind);
        }
    }
    out
}

fn mac_kind(name: &str, ports: &HashMap<String, IfKind>) -> IfKind {
    if let Some(k) = ports.get(name) {
        return *k;
    }
    let family: String = name.chars().take_while(|c| !c.is_ascii_digit()).collect();
    match family.as_str() {
        "lo" => IfKind::Loopback,
        "utun" | "ipsec" | "ppp" | "tun" | "tap" => IfKind::Tunnel,
        "bridge" => IfKind::Bridge,
        "en" => IfKind::Ethernet,
        _ => IfKind::Virtual,
    }
}

/// macOS glisse le numéro d'interface dans les adresses de lien local : `fe80:6::1` veut dire `fe80::1`.
fn mac_address(text: &str) -> Option<IpAddr> {
    match strip_scope(text)? {
        IpAddr::V6(v6) if v6.segments()[0] == 0xfe80 => {
            let mut seg = v6.segments();
            seg[1] = 0;
            Some(IpAddr::V6(Ipv6Addr::from(seg)))
        }
        other => Some(other),
    }
}

/// `192.168.1/24`, `fe80::%en0/64` ou, sur les anciennes versions, `192.168.1` sans préfixe.
fn mac_prefix(network: &str, ip: IpAddr) -> u8 {
    if let Some(p) = network.rsplit_once('/').and_then(|(_, p)| p.parse().ok()) {
        return p;
    }
    match ip {
        IpAddr::V4(_) => (network.split('.').count() * 8).min(32) as u8,
        IpAddr::V6(_) => 128,
    }
}

/// `netstat -ibn` : une ligne `<Link#n>` porte les compteurs, les suivantes les adresses.
pub fn parse_mac_netstat(text: &str, ports: &HashMap<String, IfKind>) -> (Vec<IfSnapshot>, AddrMap) {
    let mut ifaces = vec![];
    let mut addrs = AddrMap::new();
    for l in text.lines().skip(1) {
        let t: Vec<&str> = l.split_whitespace().collect();
        // Nom, MTU, réseau, [adresse], puis sept colonnes de compteurs.
        if t.len() < 10 {
            continue;
        }
        let (raw_name, network) = (t[0], t[2]);
        let name = raw_name.trim_end_matches('*');
        let num = |i: usize| t[t.len() - 7 + i].parse::<u64>().unwrap_or(0);
        if let Some(index) = network.strip_prefix("<Link#").and_then(|x| x.strip_suffix('>')) {
            ifaces.push(IfSnapshot {
                name: name.to_string(),
                index: index.parse().unwrap_or(0),
                kind: mac_kind(name, ports),
                state: if raw_name.ends_with('*') { "down".into() } else { "up".into() },
                mac: if t.len() >= 11 { t[3].to_string() } else { String::new() },
                mtu: t[1].parse().unwrap_or(0),
                speed: None,
                bridge_port: false,
                rx_p: num(0),
                rx_e: num(1),
                rx: num(2),
                tx_p: num(3),
                tx_e: num(4),
                tx: num(5),
                rx_d: 0,
                tx_d: 0,
            });
        } else if t.len() >= 11 {
            if let Some(ip) = mac_address(t[3]) {
                addrs.entry(name.to_string()).or_default().push((ip, mac_prefix(network, ip)));
            }
        }
    }
    (ifaces, addrs)
}

fn mac_state(state: &str) -> &'static str {
    match state {
        "LISTEN" => "LISTEN",
        "ESTABLISHED" => "ESTAB",
        "SYN_SENT" => "SYN-SENT",
        "SYN_RCVD" => "SYN-RECV",
        "FIN_WAIT_1" => "FIN-WAIT-1",
        "FIN_WAIT_2" => "FIN-WAIT-2",
        "CLOSE_WAIT" => "CLOSE-WAIT",
        "CLOSING" => "CLOSING",
        "LAST_ACK" => "LAST-ACK",
        "TIME_WAIT" => "TIME-WAIT",
        _ => "CLOSED",
    }
}

/// La sortie champ par champ de `lsof -F` : son format ne change pas, contrairement aux colonnes.
pub fn parse_lsof(text: &str) -> Vec<SockEntry> {
    #[derive(Default)]
    struct Socket {
        tcp: bool,
        udp: bool,
        name: String,
        state: String,
    }
    let mut out = vec![];
    let (mut pid, mut command, mut uid) = (0u32, String::new(), None);
    let mut current: Option<Socket> = None;
    let mut seen = std::collections::HashSet::new();
    let mut flush = |s: Socket, pid: u32, command: &str, uid: Option<u32>| {
        let (proto, state) = match (s.tcp, s.udp) {
            (true, _) => (Proto::Tcp, mac_state(&s.state)),
            (_, true) => (Proto::Udp, if s.name.contains("->") { "ESTAB" } else { "UNCONN" }),
            _ => return,
        };
        let (local, remote) = match s.name.split_once("->") {
            Some((l, r)) => (l, Some(r)),
            None => (s.name.as_str(), None),
        };
        let Some((local, scope)) = ss::parse_addr(local) else { return };
        let remote = match remote.and_then(ss::parse_addr) {
            Some((r, _)) => r,
            None if local.is_ipv4() => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            None => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        // Un même socket partagé entre plusieurs programmes apparaît une fois par programme.
        if !seen.insert((proto, local, remote)) {
            return;
        }
        let mut e = plain_entry(proto, state, local, remote, vec![(command.to_string(), pid, 0)], uid);
        e.scope_if = scope;
        out.push(e);
    };
    for line in text.lines() {
        let Some(kind) = line.chars().next() else { continue };
        let value = &line[kind.len_utf8()..];
        match kind {
            'p' => {
                if let Some(s) = current.take() {
                    flush(s, pid, &command, uid);
                }
                pid = value.parse().unwrap_or(0);
                command.clear();
                uid = None;
            }
            'c' => command = value.replace("\\x20", " "),
            'u' => uid = value.parse().ok(),
            'f' => {
                if let Some(s) = current.take() {
                    flush(s, pid, &command, uid);
                }
                current = Some(Socket::default());
            }
            'P' => {
                if let Some(s) = current.as_mut() {
                    s.tcp = value == "TCP";
                    s.udp = value == "UDP";
                }
            }
            'n' => {
                if let Some(s) = current.as_mut() {
                    s.name = value.to_string();
                }
            }
            'T' => {
                if let (Some(s), Some(st)) = (current.as_mut(), value.strip_prefix("ST=")) {
                    s.state = st.to_string();
                }
            }
            _ => {}
        }
    }
    if let Some(s) = current.take() {
        flush(s, pid, &command, uid);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOWS: &str = "\u{feff}{\"a\":[{\"n\":\"Wi-Fi\",\"i\":12,\"st\":\"Up\",\"m\":\"A4-83-E7-11-22-33\",\"mtu\":1500,\"sp\":866700000,\"mt\":\"Native 802.11\",\"v\":false,\"d\":\"Intel(R) Wi-Fi 6 AX201\",\"rx\":1000,\"tx\":500,\"rp\":10,\"tp\":5,\"re\":1,\"te\":2,\"rd\":3,\"td\":4},\
{\"n\":\"Ethernet 2\",\"i\":7,\"st\":\"Disconnected\",\"m\":\"00-11-22-33-44-55\",\"mtu\":1500,\"sp\":0,\"mt\":\"802.3\",\"v\":false,\"d\":\"TAP-Windows Adapter V9\",\"rx\":0,\"tx\":0,\"rp\":0,\"tp\":0,\"re\":0,\"te\":0,\"rd\":0,\"td\":0},\
{\"n\":\"vEthernet (WSL)\",\"i\":30,\"st\":\"Up\",\"m\":\"00-15-5D-00-00-00\",\"mtu\":1500,\"sp\":10000000000,\"mt\":\"802.3\",\"v\":true,\"d\":\"Hyper-V Virtual Ethernet Adapter\",\"rx\":9,\"tx\":9,\"rp\":0,\"tp\":0,\"re\":0,\"te\":0,\"rd\":0,\"td\":0}],\
\"ip\":[{\"n\":\"Wi-Fi\",\"a\":\"192.168.1.20\",\"p\":24},{\"n\":\"Wi-Fi\",\"a\":\"fe80::1c2:3%12\",\"p\":64}],\
\"t\":[{\"la\":\"192.168.1.20\",\"lp\":50000,\"ra\":\"140.82.121.4\",\"rp\":443,\"st\":\"Established\",\"pid\":4242},\
{\"la\":\"0.0.0.0\",\"lp\":135,\"ra\":\"0.0.0.0\",\"rp\":0,\"st\":\"Listen\",\"pid\":900},\
{\"la\":\"::\",\"lp\":445,\"ra\":\"::\",\"rp\":0,\"st\":\"Listen\",\"pid\":4},\
{\"la\":\"::ffff:192.168.1.20\",\"lp\":50001,\"ra\":\"::ffff:1.1.1.1\",\"rp\":443,\"st\":\"TimeWait\",\"pid\":0},\
{\"la\":\"0.0.0.0\",\"lp\":50002,\"ra\":\"0.0.0.0\",\"rp\":0,\"st\":\"Bound\",\"pid\":4242}],\
\"u\":[{\"la\":\"0.0.0.0\",\"lp\":5353,\"pid\":4242}],\
\"p\":[{\"id\":4242,\"n\":\"firefox\"},{\"id\":900,\"n\":\"svchost\"},{\"id\":4,\"n\":\"System\"},{\"id\":0,\"n\":\"Idle\"}]}";

    #[test]
    fn windows_interfaces_and_their_kinds() {
        let s = parse_windows_snapshot(WINDOWS);
        assert_eq!(s.ifaces.len(), 3);
        let wifi = &s.ifaces[0];
        assert_eq!((wifi.name.as_str(), wifi.kind, wifi.state.as_str()), ("Wi-Fi", IfKind::Wifi, "up"));
        assert_eq!((wifi.mac.as_str(), wifi.mtu, wifi.speed), ("a4:83:e7:11:22:33", 1500, Some(866)));
        assert_eq!((wifi.rx, wifi.tx, wifi.rx_p, wifi.tx_p, wifi.rx_e, wifi.tx_e, wifi.rx_d, wifi.tx_d), (1000, 500, 10, 5, 1, 2, 3, 4));
        assert_eq!((s.ifaces[1].kind, s.ifaces[1].state.as_str(), s.ifaces[1].speed), (IfKind::Tunnel, "down", None));
        assert_eq!(s.ifaces[2].kind, IfKind::Virtual);
        assert_eq!(s.addrs["Wi-Fi"], vec![("192.168.1.20".parse().unwrap(), 24), ("fe80::1c2:3".parse().unwrap(), 64)]);
    }

    #[test]
    fn windows_connections_speak_the_same_language_as_linux() {
        let s = parse_windows_snapshot(WINDOWS);
        // Le port simplement réservé (« Bound ») n'est pas une connexion.
        assert_eq!(s.sockets.len(), 5);
        let web = &s.sockets[0];
        assert_eq!((web.proto, web.state.as_str()), (Proto::Tcp, "ESTAB"));
        assert_eq!(web.remote, "140.82.121.4:443".parse().unwrap());
        assert_eq!(web.procs, vec![("firefox".to_string(), 4242, 0)]);
        assert!(!web.is_listener());
        assert!(s.sockets[1].is_listener());
        assert_eq!(s.sockets[2].local, "[::]:445".parse().unwrap());
        assert_eq!(s.sockets[3].local, "192.168.1.20:50001".parse().unwrap());
        assert_eq!(s.sockets[3].state, "TIME-WAIT");
        assert!(s.sockets[4].is_listener());
        assert_eq!(s.sockets[4].proto, Proto::Udp);
    }

    #[test]
    fn a_failed_or_partial_windows_answer_is_not_a_crash() {
        assert!(parse_windows_snapshot("").ifaces.is_empty());
        assert!(parse_windows_snapshot("Accès refusé").sockets.is_empty());
        // Une seule entrée, sans crochets.
        let s = parse_windows_snapshot(r#"{"a":{"n":"Ethernet","st":"Up","mt":"802.3","d":"Realtek"}}"#);
        assert_eq!(s.ifaces[0].kind, IfKind::Ethernet);
    }

    const NETSTAT: &str = "Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
lo0        16384 <Link#1>                         1234     0     567890     1235     0     567891     0
lo0        16384 127           127.0.0.1          1234     -     567890     1235     -     567891     -
lo0        16384 ::1/128       ::1                1234     -     567890     1235     -     567891     -
en0        1500  <Link#6>      a4:83:e7:11:22:33 90000     2   80000000    70000     3    6000000     0
en0        1500  fe80::%en0/64 fe80:6::1c2:3     90000     -   80000000    70000     -    6000000     -
en0        1500  192.168.1/24  192.168.1.20      90000     -   80000000    70000     -    6000000     -
en5*       1500  <Link#9>      00:11:22:33:44:55     0     0          0        0     0          0     0
utun3      1380  <Link#20>                           5     0        500        6     0        600     0
awdl0      1484  <Link#11>     aa:bb:cc:dd:ee:ff     1     0        100        2     0        200     0
";

    #[test]
    fn mac_interfaces_counters_and_addresses() {
        let ports = parse_mac_hardware_ports("\nHardware Port: Wi-Fi\nDevice: en0\nEthernet Address: a4:83:e7:11:22:33\n\nHardware Port: Thunderbolt 1\nDevice: en5\n");
        assert_eq!(ports["en0"], IfKind::Wifi);
        let (ifaces, addrs) = parse_mac_netstat(NETSTAT, &ports);
        assert_eq!(ifaces.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), ["lo0", "en0", "en5", "utun3", "awdl0"]);
        let lo = &ifaces[0];
        assert_eq!((lo.kind, lo.index, lo.mac.as_str(), lo.rx, lo.tx), (IfKind::Loopback, 1, "", 567890, 567891));
        let en0 = &ifaces[1];
        assert_eq!((en0.kind, en0.index, en0.mac.as_str(), en0.mtu), (IfKind::Wifi, 6, "a4:83:e7:11:22:33", 1500));
        assert_eq!((en0.rx_p, en0.rx_e, en0.rx, en0.tx_p, en0.tx_e, en0.tx), (90000, 2, 80000000, 70000, 3, 6000000));
        assert_eq!((ifaces[2].kind, ifaces[2].state.as_str()), (IfKind::Ethernet, "down"));
        assert_eq!(ifaces[3].kind, IfKind::Tunnel);
        assert_eq!(ifaces[4].kind, IfKind::Virtual);
        assert_eq!(addrs["en0"], vec![("fe80::1c2:3".parse().unwrap(), 64), ("192.168.1.20".parse().unwrap(), 24)]);
        assert_eq!(addrs["lo0"], vec![("127.0.0.1".parse().unwrap(), 8), ("::1".parse().unwrap(), 128)]);
    }

    const LSOF: &str = "p501
cGoogle\\x20Chrome
u501
f23
PTCP
n192.168.1.20:50000->140.82.121.4:443
TST=ESTABLISHED
TQR=0
TQS=0
f24
PTCP
n[::1]:8080
TST=LISTEN
f25
PUDP
n*:5353
p777
csshd
u0
f3
PTCP
n*:22
TST=LISTEN
f4
PUDP
n192.168.1.20:51000->1.1.1.1:53
f5
PTCP
n192.168.1.20:50000->140.82.121.4:443
TST=ESTABLISHED
";

    #[test]
    fn mac_connections_from_lsof() {
        let list = parse_lsof(LSOF);
        // Le socket partagé par les deux programmes ne compte qu'une fois.
        assert_eq!(list.len(), 5);
        let web = &list[0];
        assert_eq!((web.proto, web.state.as_str(), web.uid), (Proto::Tcp, "ESTAB", Some(501)));
        assert_eq!(web.procs, vec![("Google Chrome".to_string(), 501, 0)]);
        assert_eq!(web.remote, "140.82.121.4:443".parse().unwrap());
        assert!(list[1].is_listener());
        assert_eq!(list[1].local, "[::1]:8080".parse().unwrap());
        assert_eq!((list[2].proto, list[2].state.as_str()), (Proto::Udp, "UNCONN"));
        assert!(list[2].is_listener());
        assert_eq!(list[3].procs[0].0, "sshd");
        assert_eq!(list[3].local.port(), 22);
        assert_eq!((list[4].proto, list[4].state.as_str()), (Proto::Udp, "ESTAB"));
        assert!(!list[4].is_listener());
    }

    #[test]
    fn resolvers_come_from_the_system_file() {
        let list = parse_resolv_conf("# commentaire\nnameserver 127.0.0.53\noptions edns0\nnameserver ::1\nnameserver pas-une-adresse\n");
        assert_eq!(list, vec!["127.0.0.53".parse::<IpAddr>().unwrap(), "::1".parse().unwrap()]);
    }

    /// Le vrai relevé de la machine : c'est ce test qui vérifie Windows et macOS sur leurs propres systèmes.
    #[test]
    fn this_machine_answers() {
        let admin = Admin::with_command(vec!["netbuster-absent".into()]);
        let mut c = Collector::default();
        let (ifaces, addrs) = c.interfaces(true);
        assert!(!ifaces.is_empty(), "aucune interface lue");
        assert!(addrs.is_some_and(|a| !a.is_empty()), "aucune adresse lue");
        let _ = c.sockets(&admin);
    }
}
