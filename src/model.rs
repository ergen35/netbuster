//! L'état vivant de NetBuster : interfaces, connexions, processus, paquets, consommation.

use crate::packet::{self, Crypto, Dir, Packet, Proto};
use crate::ss::SockEntry;
use crate::tls::{KeyLog, TlsSession};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

pub const HISTORY_CAP: usize = 7200;
pub const SPARK_CAP: usize = 120;
const PACKET_RING_MAX: usize = 50_000;
const PACKET_RING_BYTES: usize = 192 * 1024 * 1024;
const FLOW_LINGER_SECS: f64 = 60.0;
const UDP_IDLE_SECS: f64 = 30.0;
const STREAM_MAX_BYTES: usize = 2 * 1024 * 1024;
const STREAMS_MAX: usize = 300;

#[derive(Debug, Clone, Copy, Default)]
pub struct Sample {
    pub t: f64,
    pub rx: f32,
    pub tx: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IfKind {
    Wifi,
    Ethernet,
    Loopback,
    Bridge,
    Veth,
    Tunnel,
    #[default]
    Virtual,
}

impl IfKind {
    pub fn label(self) -> &'static str {
        match self {
            IfKind::Wifi => "Wi-Fi",
            IfKind::Ethernet => "Ethernet",
            IfKind::Loopback => "Boucle locale",
            IfKind::Bridge => "Pont",
            IfKind::Veth => "Conteneur",
            IfKind::Tunnel => "Tunnel / VPN",
            IfKind::Virtual => "Virtuelle",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Iface {
    pub name: String,
    pub index: u32,
    pub kind: IfKind,
    pub state: String,
    pub mac: String,
    pub mtu: u32,
    pub speed_mbps: Option<i64>,
    pub addrs: Vec<(IpAddr, u8)>,
    pub bridge_port: bool,
    pub rx_total: u64,
    pub tx_total: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub rx_rate: f64,
    pub tx_rate: f64,
    pub session_rx: u64,
    pub session_tx: u64,
    pub history: VecDeque<Sample>,
    pub started: bool,
}

impl Iface {
    pub fn is_up(&self) -> bool {
        self.state == "up" || (self.kind == IfKind::Loopback && self.state != "down")
    }
    /// Une interface comptée dans le total : les interfaces virtuelles répéteraient le même trafic.
    pub fn counted(&self) -> bool {
        matches!(self.kind, IfKind::Wifi | IfKind::Ethernet)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    pub proto: Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowDir {
    Incoming,
    Outgoing,
    Listening,
    Local,
}

impl FlowDir {
    pub fn label(self) -> &'static str {
        match self {
            FlowDir::Incoming => "Entrante",
            FlowDir::Outgoing => "Sortante",
            FlowDir::Listening => "En écoute",
            FlowDir::Local => "Locale",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Flow {
    pub key: FlowKey,
    pub state: String,
    pub pid: Option<u32>,
    pub fd: u32,
    pub proc_name: Option<String>,
    pub service: Option<String>,
    pub uid: Option<u32>,
    pub inode: Option<u64>,
    pub iface: Option<String>,
    pub dir: FlowDir,
    pub open: bool,
    pub from_ss: bool,
    pub first_seen: f64,
    pub last_active: f64,
    pub closed_at: Option<f64>,
    pub tx_total: u64,
    pub rx_total: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_rate: f64,
    pub rx_rate: f64,
    tick_tx: u64,
    tick_rx: u64,
    ss_tx: Option<u64>,
    ss_rx: Option<u64>,
    pub rtt_ms: Option<f32>,
    pub retrans: Option<u32>,
    pub recv_q: u64,
    pub send_q: u64,
    pub hist: VecDeque<(f32, f32)>,
    pub host: Option<String>,
    pub app_proto: &'static str,
    pub crypto: Crypto,
}

impl Flow {
    pub fn new(key: FlowKey, now: f64) -> Self {
        Flow {
            key,
            state: String::new(),
            pid: None,
            fd: 0,
            proc_name: None,
            service: None,
            uid: None,
            inode: None,
            iface: None,
            dir: FlowDir::Outgoing,
            open: true,
            from_ss: false,
            first_seen: now,
            last_active: now,
            closed_at: None,
            tx_total: 0,
            rx_total: 0,
            tx_packets: 0,
            rx_packets: 0,
            tx_rate: 0.0,
            rx_rate: 0.0,
            tick_tx: 0,
            tick_rx: 0,
            ss_tx: None,
            ss_rx: None,
            rtt_ms: None,
            retrans: None,
            recv_q: 0,
            send_q: 0,
            hist: VecDeque::new(),
            host: None,
            app_proto: "",
            crypto: Crypto::Unknown,
        }
    }

    pub fn app_name(&self) -> String {
        if let Some(n) = &self.proc_name {
            return n.clone();
        }
        if let Some(s) = &self.service {
            return s.clone();
        }
        "Processus masqué".to_string()
    }

    pub fn is_listener(&self) -> bool {
        self.dir == FlowDir::Listening
    }

    pub fn is_loopback(&self) -> bool {
        self.key.local.ip().is_loopback() || self.iface.as_deref() == Some("lo")
    }

    pub fn state_label(&self) -> &str {
        if !self.open {
            return "Fermée";
        }
        match self.state.as_str() {
            "ESTAB" => "Établie",
            "LISTEN" => "En écoute",
            "UNCONN" => "Ouverte",
            "TIME-WAIT" => "Fin d'attente",
            "CLOSE-WAIT" => "Fermeture distante",
            "SYN-SENT" => "Connexion…",
            "SYN-RECV" => "Connexion reçue",
            "FIN-WAIT-1" | "FIN-WAIT-2" => "Fermeture…",
            "LAST-ACK" | "CLOSING" => "Fermeture…",
            "" => "Active",
            other => other,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub user: String,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub at: f64,
    pub wall: String,
    pub opened: bool,
    pub app: String,
    pub remote: SocketAddr,
    pub proto: Proto,
    pub dir: FlowDir,
}

#[derive(Debug, Clone)]
pub struct PacketRow {
    pub id: u64,
    pub pkt: Packet,
    pub iface: Arc<str>,
    pub app: Option<Arc<str>>,
    pub pid: Option<u32>,
    pub stream: Option<StreamKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamKey(pub Proto, pub SocketAddr, pub SocketAddr);

impl StreamKey {
    pub fn new(proto: Proto, a: SocketAddr, b: SocketAddr) -> Self {
        if (a.ip(), a.port()) <= (b.ip(), b.port()) {
            StreamKey(proto, a, b)
        } else {
            StreamKey(proto, b, a)
        }
    }
}

#[derive(Debug, Clone)]
pub struct Chunk {
    pub ts_us: u64,
    pub from_client: bool,
    pub decrypted: bool,
    pub data: Vec<u8>,
}

#[derive(Default)]
struct Reasm {
    next: Option<u32>,
    out_of_order: BTreeMap<u32, Vec<u8>>,
    held: usize,
}

impl Reasm {
    /// Rend les octets qu'on peut livrer dans l'ordre, en écartant les retransmissions.
    fn push(&mut self, seq: u32, data: &[u8]) -> Vec<u8> {
        let mut out = vec![];
        let next = *self.next.get_or_insert(seq);
        let d = seq.wrapping_sub(next) as i32;
        if d > 0 {
            if self.held < 4 * 1024 * 1024 && !self.out_of_order.contains_key(&seq) {
                self.held += data.len();
                self.out_of_order.insert(seq, data.to_vec());
            }
            return out;
        }
        let skip = (-d) as usize;
        if skip < data.len() {
            out.extend_from_slice(&data[skip..]);
        }
        let mut cursor = next.wrapping_add(out.len() as u32);
        // Les segments en attente peuvent maintenant suivre.
        loop {
            let found = self.out_of_order.keys().copied().find(|k| (k.wrapping_sub(cursor) as i32) <= 0);
            let Some(k) = found else { break };
            let seg = self.out_of_order.remove(&k).unwrap();
            self.held -= seg.len();
            let skip = cursor.wrapping_sub(k) as usize;
            if skip < seg.len() {
                out.extend_from_slice(&seg[skip..]);
                cursor = cursor.wrapping_add((seg.len() - skip) as u32);
            }
        }
        self.next = Some(cursor);
        out
    }
}

pub struct Stream {
    pub key: StreamKey,
    pub client: SocketAddr,
    pub server: SocketAddr,
    pub is_tls: bool,
    pub chunks: Vec<Chunk>,
    pub bytes: usize,
    pub last_ts: u64,
    pub truncated_capture: bool,
    pub overflow: bool,
    pub sni: Option<String>,
    pub tls: Option<TlsSession>,
    reasm: [Reasm; 2],
}

impl Stream {
    fn add_plain(&mut self, ts_us: u64, from_client: bool, decrypted: bool, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        if self.bytes + data.len() > STREAM_MAX_BYTES {
            self.overflow = true;
            return;
        }
        self.bytes += data.len();
        self.last_ts = ts_us;
        if let Some(last) = self.chunks.last_mut() {
            if last.from_client == from_client && last.decrypted == decrypted {
                last.data.extend_from_slice(data);
                return;
            }
        }
        self.chunks.push(Chunk { ts_us, from_client, decrypted, data: data.to_vec() });
    }
}

#[derive(Debug, Clone, Default)]
pub struct CaptureStatus {
    pub running: bool,
    pub error: Option<String>,
    pub kernel_packets: u64,
    pub kernel_drops: u64,
    pub seen_packets: u64,
    pub seen_bytes: u64,
}

// ---------- Consommation enregistrée ----------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DayUsage {
    pub ifaces: BTreeMap<String, (u64, u64)>,
    pub apps: BTreeMap<String, (u64, u64)>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Usage {
    pub days: BTreeMap<String, DayUsage>,
}

pub fn today() -> String {
    chrono::Local::now().format("%Y-%m-%d").to_string()
}

impl Usage {
    pub fn load() -> Usage {
        std::fs::read_to_string(crate::util::data_dir().join("usage.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) {
        let dir = crate::util::data_dir();
        let _ = std::fs::create_dir_all(&dir);
        if let Ok(text) = serde_json::to_string(self) {
            let tmp = dir.join("usage.tmp");
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(tmp, dir.join("usage.json"));
            }
        }
    }

    pub fn add_iface(&mut self, day: &str, name: &str, rx: u64, tx: u64) {
        let e = self.days.entry(day.to_string()).or_default().ifaces.entry(name.to_string()).or_default();
        e.0 += rx;
        e.1 += tx;
    }

    pub fn add_app(&mut self, day: &str, name: &str, rx: u64, tx: u64) {
        let e = self.days.entry(day.to_string()).or_default().apps.entry(name.to_string()).or_default();
        e.0 += rx;
        e.1 += tx;
    }

    /// Reçu et envoyé pour ce jour : tout ce qui est compté, ou une seule interface.
    pub fn day_total(&self, day: &str, iface: Option<&str>, counted: &HashSet<String>) -> (u64, u64) {
        let Some(d) = self.days.get(day) else { return (0, 0) };
        let mut out = (0, 0);
        for (name, v) in &d.ifaces {
            let keep = match iface {
                Some(i) => i == name,
                None => counted.contains(name),
            };
            if keep {
                out.0 += v.0;
                out.1 += v.1;
            }
        }
        out
    }
}

// ---------- Vue arborescente pour l'écran Applications ----------

#[derive(Debug, Clone, Default)]
pub struct PidRow {
    pub pid: Option<u32>,
    pub rx_rate: f64,
    pub tx_rate: f64,
    pub rx_total: u64,
    pub tx_total: u64,
    pub flows: Vec<FlowKey>,
    pub open_flows: usize,
}

#[derive(Debug, Clone, Default)]
pub struct AppRow {
    pub name: String,
    pub rx_rate: f64,
    pub tx_rate: f64,
    pub rx_total: u64,
    pub tx_total: u64,
    pub open_flows: usize,
    pub pids: Vec<PidRow>,
}

impl AppRow {
    pub fn rate(&self) -> f64 {
        self.rx_rate + self.tx_rate
    }
}

pub struct Model {
    pub started: std::time::Instant,
    pub ifaces: BTreeMap<String, Iface>,
    pub ifindex: HashMap<u32, Arc<str>>,
    pub total_history: VecDeque<Sample>,
    pub local_ips: HashSet<IpAddr>,
    pub ip_iface: HashMap<IpAddr, String>,
    pub flows: HashMap<FlowKey, Flow>,
    pub listeners: HashSet<(Proto, u16)>,
    pub procs: HashMap<u32, ProcInfo>,
    pub app_hist: HashMap<(String, String), VecDeque<(f32, f32)>>,
    pub app_session: HashMap<String, (u64, u64)>,
    pub pid_session: HashMap<u32, (u64, u64)>,
    pub events: VecDeque<Event>,
    pub packets: VecDeque<Arc<PacketRow>>,
    pub packets_bytes: usize,
    pub next_packet_id: u64,
    pub paused: bool,
    pub capture: CaptureStatus,
    pub dns_names: HashMap<IpAddr, String>,
    pub streams: HashMap<StreamKey, Stream>,
    pub keylog: KeyLog,
    pub usage: Usage,
    pub tick_id: u64,
    pub sample_count: u64,
    pub uid_names: HashMap<u32, String>,
}

impl Default for Model {
    fn default() -> Self {
        Self::new()
    }
}

impl Model {
    pub fn new() -> Self {
        Model {
            started: std::time::Instant::now(),
            ifaces: BTreeMap::new(),
            ifindex: HashMap::new(),
            total_history: VecDeque::new(),
            local_ips: HashSet::new(),
            ip_iface: HashMap::new(),
            flows: HashMap::new(),
            listeners: HashSet::new(),
            procs: HashMap::new(),
            app_hist: HashMap::new(),
            app_session: HashMap::new(),
            pid_session: HashMap::new(),
            events: VecDeque::new(),
            packets: VecDeque::new(),
            packets_bytes: 0,
            next_packet_id: 1,
            paused: false,
            capture: CaptureStatus::default(),
            dns_names: HashMap::new(),
            streams: HashMap::new(),
            keylog: KeyLog::default(),
            usage: Usage::default(),
            tick_id: 0,
            sample_count: 0,
            uid_names: load_uid_names(),
        }
    }

    pub fn now(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    pub fn counted_names(&self) -> HashSet<String> {
        self.ifaces.values().filter(|i| i.counted()).map(|i| i.name.clone()).collect()
    }

    pub fn iface_or_total_history(&self, iface: Option<&str>) -> Option<&VecDeque<Sample>> {
        match iface {
            Some(n) => self.ifaces.get(n).map(|i| &i.history),
            None => Some(&self.total_history),
        }
    }

    pub fn current_rates(&self, iface: Option<&str>) -> (f64, f64) {
        match iface {
            Some(n) => self.ifaces.get(n).map(|i| (i.rx_rate, i.tx_rate)).unwrap_or((0.0, 0.0)),
            None => self.ifaces.values().filter(|i| i.counted()).fold((0.0, 0.0), |a, i| (a.0 + i.rx_rate, a.1 + i.tx_rate)),
        }
    }

    pub fn iface_of_ip(&self, ip: IpAddr) -> Option<String> {
        if ip.is_loopback() {
            return Some("lo".into());
        }
        self.ip_iface.get(&ip).cloned()
    }

    // ---------- Sockets vus par `ss` ----------

    /// Applique la liste complète des sockets. `dt` : secondes depuis l'échantillon précédent.
    pub fn apply_sockets(&mut self, entries: Vec<SockEntry>) {
        let now = self.now();
        let capturing = self.capture.running;
        let mut seen: HashSet<FlowKey> = HashSet::with_capacity(entries.len());

        self.listeners = entries.iter().filter(|e| e.state == "LISTEN" || (e.proto == Proto::Udp && e.is_listener())).map(|e| (e.proto, e.local.port())).collect();

        for e in entries {
            let key = FlowKey { proto: e.proto, local: e.local, remote: e.remote };
            seen.insert(key);
            let listener = e.is_listener();
            let iface = e.scope_if.clone().or_else(|| self.iface_of_ip(e.local.ip()));
            let is_new = !self.flows.contains_key(&key);
            let dir = if listener {
                FlowDir::Listening
            } else if e.local.ip().is_loopback() && e.remote.ip().is_loopback() {
                FlowDir::Local
            } else if self.listeners.contains(&(e.proto, e.local.port())) {
                FlowDir::Incoming
            } else {
                FlowDir::Outgoing
            };
            let f = self.flows.entry(key).or_insert_with(|| Flow::new(key, now));
            f.state = e.state;
            f.open = true;
            f.closed_at = None;
            f.from_ss = true;
            f.dir = dir;
            f.iface = iface;
            f.recv_q = e.recv_q;
            f.send_q = e.send_q;
            f.uid = e.uid;
            f.inode = e.inode;
            if let Some(s) = e.service {
                f.service = Some(s);
            }
            if let Some((name, pid, fd)) = e.procs.first() {
                f.proc_name = Some(name.clone());
                f.pid = Some(*pid);
                f.fd = *fd;
            }
            f.rtt_ms = e.info.rtt_ms;
            f.retrans = e.info.retrans;

            // Compteurs du noyau, disponibles sans droits pour chaque connexion TCP.
            // `ss` n'écrit pas un compteur tant qu'il vaut zéro : absent veut dire 0 pour une connexion TCP.
            if e.proto == Proto::Tcp && !listener {
                let (tx, rx) = (e.info.bytes_sent.unwrap_or(0), e.info.bytes_received.unwrap_or(0));
                match (f.ss_tx, f.ss_rx) {
                    (Some(ptx), Some(prx)) => {
                        let (dtx, drx) = (tx.saturating_sub(ptx), rx.saturating_sub(prx));
                        if !capturing {
                            f.tx_total += dtx;
                            f.rx_total += drx;
                            f.tick_tx += dtx;
                            f.tick_rx += drx;
                        }
                        if dtx + drx > 0 {
                            f.last_active = now;
                        }
                    }
                    _ => {
                        // Première vue : ce que la connexion a déjà échangé, sans fausse pointe de vitesse.
                        f.tx_total = f.tx_total.max(tx);
                        f.rx_total = f.rx_total.max(rx);
                    }
                }
                f.ss_tx = Some(tx);
                f.ss_rx = Some(rx);
            }

            if is_new && !listener && dir != FlowDir::Local {
                let ev = Event {
                    at: now,
                    wall: chrono::Local::now().format("%H:%M:%S").to_string(),
                    opened: true,
                    app: self.flows[&key].app_name(),
                    remote: key.remote,
                    proto: key.proto,
                    dir,
                };
                self.push_event(ev);
            }
        }

        // Ce qui a disparu de la liste est fermé.
        let mut closed = vec![];
        for (k, f) in self.flows.iter_mut() {
            if f.from_ss && f.open && !seen.contains(k) {
                f.open = false;
                f.closed_at = Some(now);
                f.state = "CLOSED".into();
                if f.dir != FlowDir::Listening && f.dir != FlowDir::Local {
                    closed.push(Event {
                        at: now,
                        wall: chrono::Local::now().format("%H:%M:%S").to_string(),
                        opened: false,
                        app: f.app_name(),
                        remote: k.remote,
                        proto: k.proto,
                        dir: f.dir,
                    });
                }
            }
            // Échange vu seulement par la capture : se referme après un silence.
            if !f.from_ss && f.open && now - f.last_active > UDP_IDLE_SECS {
                f.open = false;
                f.closed_at = Some(now);
            }
        }
        for ev in closed {
            self.push_event(ev);
        }
        self.flows.retain(|_, f| f.closed_at.is_none_or(|t| now - t < FLOW_LINGER_SECS));
    }

    fn push_event(&mut self, ev: Event) {
        self.events.push_back(ev);
        if self.events.len() > 400 {
            self.events.pop_front();
        }
    }

    /// Une fois par seconde : vitesses par connexion, par processus, consommation.
    pub fn tick_flows(&mut self, dt: f64) {
        self.tick_id += 1;
        let day = today();
        let mut per_app: HashMap<(String, String), (u64, u64)> = HashMap::new();
        let mut per_pid: HashMap<u32, (u64, u64)> = HashMap::new();
        let mut usage_app: HashMap<String, (u64, u64)> = HashMap::new();
        for f in self.flows.values_mut() {
            let (tx, rx) = (f.tick_tx, f.tick_rx);
            f.tick_tx = 0;
            f.tick_rx = 0;
            f.tx_rate = tx as f64 / dt;
            f.rx_rate = rx as f64 / dt;
            f.hist.push_back((f.rx_rate as f32, f.tx_rate as f32));
            if f.hist.len() > SPARK_CAP {
                f.hist.pop_front();
            }
            if tx + rx == 0 {
                continue;
            }
            let app = f.app_name();
            let loopback = f.is_loopback();
            if !loopback {
                let e = per_app.entry((String::new(), app.clone())).or_default();
                e.0 += rx;
                e.1 += tx;
                let e = usage_app.entry(app.clone()).or_default();
                e.0 += rx;
                e.1 += tx;
            }
            if let Some(i) = &f.iface {
                let e = per_app.entry((i.clone(), app.clone())).or_default();
                e.0 += rx;
                e.1 += tx;
            }
            if let Some(pid) = f.pid {
                let e = per_pid.entry(pid).or_default();
                e.0 += rx;
                e.1 += tx;
            }
        }
        for (app, (rx, tx)) in usage_app {
            let e = self.app_session.entry(app.clone()).or_default();
            e.0 += rx;
            e.1 += tx;
            self.usage.add_app(&day, &app, rx, tx);
        }
        for (pid, (rx, tx)) in per_pid {
            let e = self.pid_session.entry(pid).or_default();
            e.0 += rx;
            e.1 += tx;
        }
        for (k, v) in self.app_hist.iter_mut() {
            let val = per_app.remove(k).unwrap_or((0, 0));
            v.push_back(((val.0 as f64 / dt) as f32, (val.1 as f64 / dt) as f32));
            if v.len() > SPARK_CAP {
                v.pop_front();
            }
        }
        for (k, (rx, tx)) in per_app {
            let mut v = VecDeque::new();
            v.push_back(((rx as f64 / dt) as f32, (tx as f64 / dt) as f32));
            self.app_hist.insert(k, v);
        }
        self.app_hist.retain(|_, v| v.len() < SPARK_CAP || v.iter().any(|x| x.0 > 0.0 || x.1 > 0.0));
    }

    /// Applications et processus, avec leurs connexions, pour une interface ou pour toutes.
    pub fn app_tree(&self, iface: Option<&str>, show_local: bool, show_listeners: bool) -> Vec<AppRow> {
        let mut apps: HashMap<String, AppRow> = HashMap::new();
        let mut pid_rows: HashMap<(String, Option<u32>), PidRow> = HashMap::new();
        for f in self.flows.values() {
            if !self.flow_visible(f, iface, show_local) {
                continue;
            }
            if f.is_listener() && !show_listeners && f.tx_total + f.rx_total == 0 {
                continue;
            }
            let name = f.app_name();
            let a = apps.entry(name.clone()).or_default();
            a.name = name.clone();
            a.rx_rate += f.rx_rate;
            a.tx_rate += f.tx_rate;
            a.rx_total += f.rx_total;
            a.tx_total += f.tx_total;
            if f.open && !f.is_listener() {
                a.open_flows += 1;
            }
            let p = pid_rows.entry((name, f.pid)).or_default();
            p.pid = f.pid;
            p.rx_rate += f.rx_rate;
            p.tx_rate += f.tx_rate;
            p.rx_total += f.rx_total;
            p.tx_total += f.tx_total;
            if f.open && !f.is_listener() {
                p.open_flows += 1;
            }
            p.flows.push(f.key);
        }
        for ((name, _), mut p) in pid_rows {
            p.flows.sort_by(|x, y| {
                let (a, b) = (&self.flows[x], &self.flows[y]);
                (b.rx_rate + b.tx_rate)
                    .total_cmp(&(a.rx_rate + a.tx_rate))
                    .then((b.rx_total + b.tx_total).cmp(&(a.rx_total + a.tx_total)))
                    .then(x.cmp(y))
            });
            apps.get_mut(&name).unwrap().pids.push(p);
        }
        let mut out: Vec<AppRow> = apps.into_values().collect();
        for a in &mut out {
            a.pids.sort_by(|x, y| (y.rx_rate + y.tx_rate).total_cmp(&(x.rx_rate + x.tx_rate)).then(x.pid.cmp(&y.pid)));
        }
        out.sort_by(|a, b| b.rate().total_cmp(&a.rate()).then((b.rx_total + b.tx_total).cmp(&(a.rx_total + a.tx_total))).then(a.name.cmp(&b.name)));
        out
    }

    pub fn flow_visible(&self, f: &Flow, iface: Option<&str>, show_local: bool) -> bool {
        match iface {
            Some(i) => {
                // Un socket à l'écoute sur toutes les adresses concerne toutes les interfaces.
                f.iface.as_deref() == Some(i) || (f.iface.is_none() && f.key.local.ip().is_unspecified())
            }
            None => show_local || !f.is_loopback(),
        }
    }

    // ---------- Paquets capturés ----------

    pub fn ingest(&mut self, mut p: Packet) {
        let iface: Arc<str> = self.ifindex.get(&p.ifindex).cloned().unwrap_or_else(|| Arc::from(format!("if{}", p.ifindex)));
        let info = self.ifaces.get(&*iface);
        let is_lo = info.is_some_and(|i| i.kind == IfKind::Loopback);
        let is_bridge_port = info.is_some_and(|i| i.bridge_port);
        // Sur la boucle locale le noyau livre chaque paquet deux fois.
        if is_lo && p.dir == Dir::Out {
            return;
        }
        let now = self.now();
        self.capture.seen_packets += 1;
        self.capture.seen_bytes += p.orig_len as u64;

        if let Some(m) = &p.dns {
            if m.response {
                let name = m.questions.first().map(|q| q.0.clone()).unwrap_or_default();
                for (_, t, val) in &m.answers {
                    if matches!(t, 1 | 28) {
                        if let Ok(ip) = val.parse::<IpAddr>() {
                            self.dns_names.insert(ip, name.clone());
                        }
                    }
                }
            }
        }

        let mut app: Option<Arc<str>> = None;
        let mut pid = None;
        let mut stream = None;
        if let (Some(src), Some(dst)) = (p.src, p.dst) {
            if p.proto != Proto::Arp && !is_bridge_port {
                let s = SocketAddr::new(src, p.sport);
                let d = SocketAddr::new(dst, p.dport);
                let s_local = self.local_ips.contains(&src);
                let d_local = self.local_ips.contains(&dst);
                let len = p.orig_len as u64;
                if is_lo || (s_local && d_local) {
                    let a = self.account(&p, s, d, len, true, &iface, now);
                    let b = self.account(&p, d, s, len, false, &iface, now);
                    if let Some(x) = a.or(b) {
                        app = Some(x.0);
                        pid = x.1;
                    }
                } else if s_local {
                    if let Some(x) = self.account(&p, s, d, len, true, &iface, now) {
                        app = Some(x.0);
                        pid = x.1;
                    }
                } else if d_local || (p.dir == Dir::In && (dst.is_multicast() || is_broadcast(dst))) {
                    if let Some(x) = self.account(&p, d, s, len, false, &iface, now) {
                        app = Some(x.0);
                        pid = x.1;
                    }
                }
                // Un flux TLS sur un port inhabituel reste reconnu pour ses paquets suivants.
                if p.app == "TCP" || p.app == "UDP" {
                    let key = if d_local && !s_local {
                        FlowKey { proto: p.proto, local: d, remote: s }
                    } else {
                        FlowKey { proto: p.proto, local: s, remote: d }
                    };
                    if let Some(f) = self.flows.get(&key) {
                        if !f.app_proto.is_empty() && f.app_proto != "TCP" && f.app_proto != "UDP" {
                            p.app = f.app_proto;
                            if f.crypto == Crypto::Yes {
                                p.crypto = Crypto::Yes;
                            }
                        }
                    }
                }
                if p.proto == Proto::Tcp {
                    stream = self.track_stream(&p, s, d);
                } else if p.sport != 0 || p.dport != 0 {
                    stream = Some(StreamKey::new(p.proto, s, d));
                }
            }
        }

        if self.paused {
            return;
        }
        let bytes = p.data.len() + 256;
        let row = PacketRow { id: self.next_packet_id, pkt: p, iface, app, pid, stream };
        self.next_packet_id += 1;
        self.packets.push_back(Arc::new(row));
        self.packets_bytes += bytes;
        while self.packets.len() > PACKET_RING_MAX || self.packets_bytes > PACKET_RING_BYTES {
            match self.packets.pop_front() {
                Some(r) => self.packets_bytes -= r.pkt.data.len() + 256,
                None => break,
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn account(&mut self, p: &Packet, local: SocketAddr, remote: SocketAddr, len: u64, tx: bool, iface: &Arc<str>, now: f64) -> Option<(Arc<str>, Option<u32>)> {
        let key = FlowKey { proto: p.proto, local, remote };
        if !self.flows.contains_key(&key) {
            // Socket UDP non connecté : chaque correspondant devient un « appel » de ce socket.
            let parent = self.find_listener(p.proto, local);
            let mut f = Flow::new(key, now);
            f.iface = Some(iface.to_string());
            f.state = "".into();
            f.dir = if local.ip().is_loopback() && remote.ip().is_loopback() {
                FlowDir::Local
            } else if parent.is_some() || self.listeners.contains(&(p.proto, local.port())) {
                FlowDir::Incoming
            } else {
                FlowDir::Outgoing
            };
            if let Some(par) = parent {
                let par = &self.flows[&par];
                f.pid = par.pid;
                f.fd = par.fd;
                f.proc_name = par.proc_name.clone();
                f.service = par.service.clone();
                f.uid = par.uid;
                f.inode = par.inode;
            } else if matches!(p.proto, Proto::Icmp | Proto::Icmp6 | Proto::Igmp) {
                f.service = Some("Système (ICMP)".into());
            }
            self.flows.insert(key, f);
        }
        let f = self.flows.get_mut(&key)?;
        if tx {
            f.tx_total += len;
            f.tick_tx += len;
            f.tx_packets += 1;
        } else {
            f.rx_total += len;
            f.tick_rx += len;
            f.rx_packets += 1;
        }
        f.last_active = now;
        if f.iface.is_none() {
            f.iface = Some(iface.to_string());
        }
        if !f.open && f.closed_at.is_some() && !f.from_ss {
            f.open = true;
            f.closed_at = None;
        }
        if let Some(h) = p.sni.as_ref().or(p.http_host.as_ref()) {
            f.host = Some(h.clone());
        }
        if f.host.is_none() {
            if let Some(n) = self.dns_names.get(&remote.ip()) {
                f.host = Some(n.clone());
            }
        }
        if p.app != "TCP" && p.app != "UDP" {
            f.app_proto = p.app;
        }
        if p.crypto != Crypto::Unknown && (f.crypto != Crypto::Yes || p.crypto == Crypto::Yes) {
            f.crypto = p.crypto;
        }
        Some((Arc::from(f.app_name()), f.pid))
    }

    fn find_listener(&self, proto: Proto, local: SocketAddr) -> Option<FlowKey> {
        let port = local.port();
        if port == 0 {
            return None;
        }
        let wild_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let wild_v6 = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0);
        let candidates = [
            FlowKey { proto, local, remote: wild_v4 },
            FlowKey { proto, local, remote: wild_v6 },
            FlowKey { proto, local: SocketAddr::new(wild_v4.ip(), port), remote: wild_v4 },
            FlowKey { proto, local: SocketAddr::new(wild_v6.ip(), port), remote: wild_v6 },
            FlowKey { proto, local: SocketAddr::new(wild_v4.ip(), port), remote: wild_v6 },
            FlowKey { proto, local: SocketAddr::new(wild_v6.ip(), port), remote: wild_v4 },
        ];
        candidates.into_iter().find(|k| self.flows.contains_key(k))
    }

    fn track_stream(&mut self, p: &Packet, s: SocketAddr, d: SocketAddr) -> Option<StreamKey> {
        let key = StreamKey::new(Proto::Tcp, s, d);
        let payload = p.payload();
        if payload.is_empty() {
            return Some(key);
        }
        let truncated = (p.orig_len as usize) > p.data.len();
        if !self.streams.contains_key(&key) {
            let is_hello = payload.len() > 5 && payload[0] == 22 && payload[5] == 1;
            let tracking_tls = self.keylog.path.is_some();
            let tls_start = is_hello && tracking_tls;
            let readable = !is_hello
                && p.crypto != Crypto::Yes
                && (p.app == "HTTP" || packet::guess_crypto(payload) == Crypto::No);
            if !tls_start && !readable {
                return Some(key);
            }
            // Celui qui parle en premier ou qui écrit vers le plus petit port est le client.
            let client_is_src = tls_start || p.info.contains(" HTTP/") || s.port() > d.port();
            let (client, server) = if client_is_src { (s, d) } else { (d, s) };
            self.streams.insert(
                key,
                Stream {
                    key,
                    client,
                    server,
                    is_tls: tls_start,
                    chunks: vec![],
                    bytes: 0,
                    last_ts: p.ts_us,
                    truncated_capture: false,
                    overflow: false,
                    sni: p.sni.clone(),
                    tls: tls_start.then(TlsSession::new),
                    reasm: Default::default(),
                },
            );
            if self.streams.len() > STREAMS_MAX {
                if let Some(old) = self.streams.values().min_by_key(|x| x.last_ts).map(|x| x.key) {
                    self.streams.remove(&old);
                }
            }
        }
        let keylog = &self.keylog;
        let st = self.streams.get_mut(&key)?;
        st.last_ts = p.ts_us;
        if truncated {
            st.truncated_capture = true;
        }
        let from_client = s == st.client;
        let dir = usize::from(!from_client);
        let ordered = st.reasm[dir].push(p.seq, payload);
        if ordered.is_empty() {
            return Some(key);
        }
        if let Some(mut session) = st.tls.take() {
            for chunk in session.feed(dir as u8, &ordered, keylog) {
                st.add_plain(p.ts_us, chunk.dir == 0, true, &chunk.data);
            }
            st.tls = Some(session);
        } else {
            st.add_plain(p.ts_us, from_client, false, &ordered);
        }
        Some(key)
    }

    /// Cherche de nouvelles clés et déchiffre ce qui attendait.
    pub fn poll_keys(&mut self) {
        let before = self.keylog.keys.len();
        self.keylog.poll();
        if self.keylog.keys.len() == before {
            return;
        }
        let keylog = &self.keylog;
        for st in self.streams.values_mut() {
            let Some(mut session) = st.tls.take() else { continue };
            let ts = st.last_ts;
            for chunk in session.drain(keylog) {
                st.add_plain(ts, chunk.dir == 0, true, &chunk.data);
            }
            st.tls = Some(session);
        }
    }

    pub fn clear_packets(&mut self) {
        self.packets.clear();
        self.packets_bytes = 0;
    }
}

fn is_broadcast(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(a) if a.is_broadcast() || a.octets()[3] == 255)
}

fn load_uid_names() -> HashMap<u32, String> {
    let text = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    text.lines()
        .filter_map(|l| {
            let mut it = l.split(':');
            let name = it.next()?;
            let uid = it.nth(1)?.parse().ok()?;
            Some((uid, name.to_string()))
        })
        .collect()
}

/// Écrit la capture au format pcap, ouvrable dans Wireshark ou tcpdump.
pub fn write_pcap(path: &std::path::Path, packets: &[Arc<PacketRow>]) -> std::io::Result<usize> {
    use std::io::Write;
    let mut w = std::io::BufWriter::new(std::fs::File::create(path)?);
    w.write_all(&0xa1b2c3d4u32.to_le_bytes())?;
    w.write_all(&2u16.to_le_bytes())?;
    w.write_all(&4u16.to_le_bytes())?;
    w.write_all(&0i32.to_le_bytes())?;
    w.write_all(&0u32.to_le_bytes())?;
    w.write_all(&262_144u32.to_le_bytes())?;
    w.write_all(&113u32.to_le_bytes())?; // LINKTYPE_LINUX_SLL
    for r in packets {
        let p = &r.pkt;
        let incl = p.data.len() as u32 + 16;
        let orig = p.orig_len + 16;
        w.write_all(&((p.ts_us / 1_000_000) as u32).to_le_bytes())?;
        w.write_all(&((p.ts_us % 1_000_000) as u32).to_le_bytes())?;
        w.write_all(&incl.to_le_bytes())?;
        w.write_all(&orig.to_le_bytes())?;
        let pkttype: u16 = match p.dir {
            Dir::In => 0,
            Dir::Out => 4,
            Dir::Other => 3,
        };
        w.write_all(&pkttype.to_be_bytes())?;
        w.write_all(&1u16.to_be_bytes())?;
        w.write_all(&0u16.to_be_bytes())?;
        w.write_all(&[0u8; 8])?;
        w.write_all(&p.l3_proto.to_be_bytes())?;
        w.write_all(&p.data)?;
    }
    w.flush()?;
    Ok(packets.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::build;
    use crate::proto::RawFrame;

    fn setup() -> Model {
        let mut m = Model::new();
        let lo = Iface { name: "lo".into(), index: 1, kind: IfKind::Loopback, ..Default::default() };
        let wifi = Iface { name: "wlo1".into(), index: 2, kind: IfKind::Wifi, state: "up".into(), ..Default::default() };
        m.ifaces.insert("lo".into(), lo);
        m.ifaces.insert("wlo1".into(), wifi);
        m.ifindex.insert(1, "lo".into());
        m.ifindex.insert(2, "wlo1".into());
        let me: IpAddr = "192.168.1.5".parse().unwrap();
        m.local_ips.insert(me);
        m.local_ips.insert("127.0.0.1".parse().unwrap());
        m.ip_iface.insert(me, "wlo1".into());
        m
    }

    fn tcp_line(proc_: &str, pid: u32, sent: u64, recv: u64) -> String {
        format!(
            "tcp ESTAB 0 0 192.168.1.5:40000 1.1.1.1:443 users:((\"{proc_}\",pid={pid},fd=7)) uid:1000 ino:9 bytes_sent:{sent} bytes_received:{recv}"
        )
    }

    fn frame(data: Vec<u8>, pkttype: u8, ifindex: u32) -> Packet {
        packet::parse(RawFrame { ts_us: 1, ifindex, pkttype, proto: 0x0800, orig_len: data.len() as u32, data })
    }

    #[test]
    fn tcp_counters_give_per_connection_speed_without_capture() {
        let mut m = setup();
        m.apply_sockets(crate::ss::parse_output(&tcp_line("firefox", 42, 1000, 5000)));
        m.tick_flows(1.0);
        let key = *m.flows.keys().next().unwrap();
        // Premier relevé : le passé compte dans le total, mais pas dans la vitesse.
        assert_eq!(m.flows[&key].rx_total, 5000);
        assert_eq!(m.flows[&key].rx_rate, 0.0);
        m.apply_sockets(crate::ss::parse_output(&tcp_line("firefox", 42, 1500, 8000)));
        m.tick_flows(1.0);
        let f = &m.flows[&key];
        assert_eq!(f.rx_rate, 3000.0);
        assert_eq!(f.tx_rate, 500.0);
        assert_eq!(f.dir, FlowDir::Outgoing);
        assert_eq!(f.iface.as_deref(), Some("wlo1"));
        let tree = m.app_tree(None, false, false);
        assert_eq!(tree[0].name, "firefox");
        assert_eq!(tree[0].pids[0].pid, Some(42));
        assert_eq!(tree[0].pids[0].flows, vec![key]);
        assert_eq!(tree[0].rx_rate, 3000.0);
        assert_eq!(m.app_session["firefox"], (3000, 500));
    }

    #[test]
    fn a_connection_that_only_sends_is_counted() {
        let mut m = setup();
        let line = |extra: &str| format!("tcp ESTAB 0 0 192.168.1.5:40000 1.1.1.1:443 users:((\"curl\",pid=5,fd=3)) {extra}");
        m.apply_sockets(crate::ss::parse_output(&line("")));
        m.apply_sockets(crate::ss::parse_output(&line("bytes_sent:9000")));
        m.tick_flows(1.0);
        let f = m.flows.values().next().unwrap();
        assert_eq!(f.tx_total, 9000);
        assert_eq!(f.tx_rate, 9000.0);
    }

    #[test]
    fn closed_connections_linger_and_emit_events() {
        let mut m = setup();
        m.apply_sockets(crate::ss::parse_output(&tcp_line("curl", 7, 10, 10)));
        assert_eq!(m.events.len(), 1);
        assert!(m.events[0].opened);
        m.apply_sockets(vec![]);
        assert_eq!(m.events.len(), 2);
        assert!(!m.events[1].opened);
        let f = m.flows.values().next().unwrap();
        assert!(!f.open);
        assert_eq!(f.state_label(), "Fermée");
    }

    #[test]
    fn incoming_connection_detected_from_listener() {
        let mut m = setup();
        let text = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* uid:0\ntcp ESTAB 0 0 192.168.1.5:22 8.8.8.8:5555 uid:0";
        m.apply_sockets(crate::ss::parse_output(text));
        let est = m.flows.values().find(|f| f.state == "ESTAB").unwrap();
        assert_eq!(est.dir, FlowDir::Incoming);
        let lis = m.flows.values().find(|f| f.state == "LISTEN").unwrap();
        assert_eq!(lis.dir, FlowDir::Listening);
    }

    #[test]
    fn packets_are_attributed_to_the_right_process_and_direction() {
        let mut m = setup();
        m.apply_sockets(crate::ss::parse_output(&tcp_line("firefox", 42, 0, 0)));
        m.capture.running = true;
        let hello = build::tls_client_hello("exemple.fr", [1; 32]);
        let out = build::ipv4_tcp([192, 168, 1, 5], [1, 1, 1, 1], 40000, 443, 1, 1, packet::TCP_PSH, &hello);
        let out_len = out.len() as u64;
        m.ingest(frame(out, 4, 2));
        let inc = build::ipv4_tcp([1, 1, 1, 1], [192, 168, 1, 5], 443, 40000, 1, 1, packet::TCP_ACK, &[0u8; 100]);
        let inc_len = inc.len() as u64;
        m.ingest(frame(inc, 0, 2));
        let f = m.flows.values().find(|f| f.pid == Some(42)).unwrap();
        assert_eq!(f.tx_total, out_len);
        assert_eq!(f.rx_total, inc_len);
        assert_eq!(f.host.as_deref(), Some("exemple.fr"));
        assert_eq!(f.crypto, Crypto::Yes);
        let rows: Vec<_> = m.packets.iter().collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].app.as_deref(), Some("firefox"));
        assert_eq!(rows[0].pid, Some(42));
        assert_eq!(&*rows[0].iface, "wlo1");
        m.tick_flows(1.0);
        let f = m.flows.values().find(|f| f.pid == Some(42)).unwrap();
        assert_eq!(f.tx_rate, out_len as f64);
    }

    #[test]
    fn udp_socket_calls_are_children_of_the_socket() {
        let mut m = setup();
        m.apply_sockets(crate::ss::parse_output("udp UNCONN 0 0 0.0.0.0:5000 0.0.0.0:* users:((\"dnsapp\",pid=9,fd=4))"));
        let q = build::ipv4_udp([192, 168, 1, 5], [8, 8, 8, 8], 5000, 53, &build::dns(1, "exemple.fr", None));
        m.ingest(frame(q, 4, 2));
        let call = m.flows.values().find(|f| f.key.remote.port() == 53).unwrap();
        assert_eq!(call.pid, Some(9));
        assert_eq!(call.proc_name.as_deref(), Some("dnsapp"));
    }

    #[test]
    fn dns_answers_name_later_connections() {
        let mut m = setup();
        let r = build::ipv4_udp([8, 8, 8, 8], [192, 168, 1, 5], 53, 5000, &build::dns(1, "site.exemple.fr", Some([9, 9, 9, 9])));
        m.ingest(frame(r, 0, 2));
        assert_eq!(m.dns_names[&"9.9.9.9".parse::<IpAddr>().unwrap()], "site.exemple.fr");
        let d = build::ipv4_tcp([192, 168, 1, 5], [9, 9, 9, 9], 41000, 443, 1, 1, packet::TCP_SYN, &[]);
        m.ingest(frame(d, 4, 2));
        let f = m.flows.values().find(|f| f.key.remote.port() == 443).unwrap();
        assert_eq!(f.host.as_deref(), Some("site.exemple.fr"));
    }

    #[test]
    fn loopback_is_not_counted_twice() {
        let mut m = setup();
        let d = build::ipv4_tcp([127, 0, 0, 1], [127, 0, 0, 1], 41000, 5432, 1, 1, packet::TCP_ACK, &[1; 10]);
        m.ingest(frame(d.clone(), 4, 1));
        assert!(m.packets.is_empty());
        m.ingest(frame(d, 0, 1));
        assert_eq!(m.packets.len(), 1);
    }

    #[test]
    fn plain_http_stream_is_followed_in_order() {
        let mut m = setup();
        let c = [192, 168, 1, 5];
        let s = [93, 184, 216, 34];
        let req = b"GET / HTTP/1.1\r\nHost: exemple.fr\r\n\r\n";
        m.ingest(frame(build::ipv4_tcp(c, s, 41000, 80, 100, 1, packet::TCP_PSH, req), 4, 2));
        // La réponse arrive dans le désordre, avec une retransmission.
        let (a, b) = (b"HTTP/1.1 200 OK\r\n".as_slice(), b"\r\nBonjour".as_slice());
        let seq2 = 500 + a.len() as u32;
        m.ingest(frame(build::ipv4_tcp(s, c, 80, 41000, 500, 1, packet::TCP_PSH, a), 0, 2));
        m.ingest(frame(build::ipv4_tcp(s, c, 80, 41000, seq2, 1, packet::TCP_PSH, b), 0, 2));
        m.ingest(frame(build::ipv4_tcp(s, c, 80, 41000, 500, 1, packet::TCP_PSH, a), 0, 2));
        let st = m.streams.values().next().unwrap();
        assert_eq!(st.client.port(), 41000);
        assert_eq!(st.chunks.len(), 2);
        assert!(st.chunks[0].from_client);
        assert_eq!(String::from_utf8_lossy(&st.chunks[1].data), "HTTP/1.1 200 OK\r\n\r\nBonjour");
    }

    #[test]
    fn reassembly_handles_out_of_order_and_wraparound() {
        let mut r = Reasm::default();
        let start = u32::MAX - 2;
        assert_eq!(r.push(start, b"abc"), b"abc");
        let after = start.wrapping_add(3);
        assert_eq!(r.push(after.wrapping_add(3), b"ghi"), b"");
        assert_eq!(r.push(after, b"def"), b"defghi");
        assert_eq!(r.push(after, b"def"), b"");
    }

    #[test]
    fn iface_filter_keeps_only_its_connections() {
        let mut m = setup();
        m.apply_sockets(crate::ss::parse_output(&tcp_line("firefox", 42, 1, 1)));
        assert_eq!(m.app_tree(Some("wlo1"), false, false).len(), 1);
        assert_eq!(m.app_tree(Some("lo"), false, false).len(), 0);
    }

    #[test]
    fn pcap_file_opens_in_tcpdump() {
        let mut m = setup();
        let d = build::ipv4_udp([192, 168, 1, 5], [8, 8, 8, 8], 5000, 53, &build::dns(1, "exemple.fr", None));
        m.ingest(frame(d, 4, 2));
        let rows: Vec<_> = m.packets.iter().cloned().collect();
        let path = std::env::temp_dir().join(format!("netbuster-test-{}.pcap", std::process::id()));
        write_pcap(&path, &rows).unwrap();
        if crate::util::which("tcpdump").is_some() {
            let r = crate::util::run("tcpdump", &["-nn", "-r", path.to_str().unwrap()]);
            assert!(r.stdout.contains("8.8.8.8.53"), "{} {}", r.stdout, r.stderr);
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn usage_sums_only_counted_interfaces() {
        let mut u = Usage::default();
        u.add_iface("2026-11-04", "wlo1", 100, 10);
        u.add_iface("2026-11-04", "docker0", 999, 999);
        let counted: HashSet<String> = ["wlo1".to_string()].into();
        assert_eq!(u.day_total("2026-11-04", None, &counted), (100, 10));
        assert_eq!(u.day_total("2026-11-04", Some("docker0"), &counted), (999, 999));
    }
}
