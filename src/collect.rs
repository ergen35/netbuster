//! Boucles de collecte : lisent le système en continu sans jamais bloquer la fenêtre.

use crate::admin::{Admin, AdminState, Incoming};
use crate::enrich::Enricher;
use crate::manage::{self, ActionResult, FirewallData, NetConfigData, SshData};
use crate::model::{IfKind, Iface, Model, Sample, Usage, HISTORY_CAP};
#[cfg(target_os = "linux")]
use crate::proto::{read_frame, TAG_EVENT, TAG_PACKET};
use crate::proto::{Cmd, Event, RawFrame, ServiceStats};
use crate::service::ServicePaths;
use crate::trace::Tracer;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const PANEL_NONE: u8 = 0;
pub const PANEL_FIREWALL: u8 = 1;
pub const PANEL_CONFIG: u8 = 2;
pub const PANEL_SSH: u8 = 3;

/// Ordres donnés à la fenêtre par l'icône de la barre d'état ou par un second lancement.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Ctl {
    Show,
    Hide,
    Quit,
}

#[derive(Default)]
pub struct Control {
    queue: Mutex<std::collections::VecDeque<Ctl>>,
    ready: std::sync::Condvar,
}

impl Control {
    pub fn push(&self, c: Ctl) {
        self.queue.lock().unwrap().push_back(c);
        self.ready.notify_all();
    }

    pub fn try_pop(&self) -> Option<Ctl> {
        self.queue.lock().unwrap().pop_front()
    }

    /// Attend un ordre : c'est ce que fait NetBuster quand aucune fenêtre n'est ouverte.
    pub fn wait(&self) -> Ctl {
        let mut q = self.queue.lock().unwrap();
        loop {
            if let Some(c) = q.pop_front() {
                return c;
            }
            q = self.ready.wait(q).unwrap();
        }
    }
}

#[derive(Default)]
pub struct Panels {
    pub firewall: FirewallData,
    pub config: NetConfigData,
    pub ssh: SshData,
}

pub struct Shared {
    pub model: Mutex<Model>,
    pub admin: Arc<Admin>,
    pub enrich: Arc<Enricher>,
    pub tracer: Tracer,
    pub panels: Mutex<Panels>,
    pub visible_panel: AtomicU8,
    pub refresh_panels: AtomicBool,
    pub incoming: Sender<Incoming>,
    pub capture_snap: AtomicU32,
    pub action_log: Mutex<Vec<ActionResult>>,
    pub action_running: AtomicBool,
    pub repaint: Mutex<Option<eframe::egui::Context>>,
    pub control: Control,
    pub service_paths: ServicePaths,
    /// La fenêtre reçoit les paquets du service : pas besoin de capture en administrateur.
    pub service_up: AtomicBool,
    pub tray_available: AtomicBool,
}

impl Shared {
    pub fn start(mock_dir: Option<String>) -> Arc<Shared> {
        let paths = match &mock_dir {
            Some(dir) => ServicePaths::under(Path::new(dir)),
            None => ServicePaths::system(),
        };
        Self::start_with_paths(Admin::new(mock_dir), paths)
    }

    pub fn start_with(admin: Arc<Admin>) -> Arc<Shared> {
        Self::start_with_paths(admin, ServicePaths::system())
    }

    pub fn start_with_paths(admin: Arc<Admin>, service_paths: ServicePaths) -> Arc<Shared> {
        let (tx, rx) = channel();
        let mut model = Model::new();
        model.usage = Usage::load();
        let shared = Arc::new(Shared {
            model: Mutex::new(model),
            admin,
            enrich: Enricher::start(),
            tracer: Tracer::default(),
            panels: Mutex::new(Panels::default()),
            visible_panel: AtomicU8::new(PANEL_NONE),
            refresh_panels: AtomicBool::new(true),
            incoming: tx,
            capture_snap: AtomicU32::new(65_535),
            action_log: Mutex::new(vec![]),
            action_running: AtomicBool::new(false),
            repaint: Mutex::new(None),
            control: Control::default(),
            service_paths,
            service_up: AtomicBool::new(false),
            tray_available: AtomicBool::new(false),
        });
        let s = shared.clone();
        std::thread::spawn(move || sampler_loop(s));
        let s = shared.clone();
        std::thread::spawn(move || ingest_loop(s, rx));
        let s = shared.clone();
        std::thread::spawn(move || panels_loop(s));
        #[cfg(target_os = "linux")]
        {
            let s = shared.clone();
            std::thread::spawn(move || service_client_loop(s));
        }
        shared
    }

    /// Demande le mode administrateur, puis lance la capture quand il répond.
    pub fn enable_admin(self: &Arc<Self>) {
        self.admin.start(self.incoming.clone());
        let me = self.clone();
        std::thread::spawn(move || {
            for _ in 0..1200 {
                match me.admin.state() {
                    AdminState::On { .. } => {
                        me.start_capture();
                        me.refresh_panels.store(true, Ordering::Relaxed);
                        return;
                    }
                    AdminState::Asking => std::thread::sleep(Duration::from_millis(100)),
                    _ => return,
                }
            }
        });
    }

    pub fn start_capture(&self) {
        // Le service capture déjà tout : une seconde capture montrerait chaque paquet en double.
        if self.service_up.load(Ordering::Relaxed) {
            return;
        }
        let snap = self.capture_snap.load(Ordering::Relaxed);
        self.admin.send(&Cmd::StartCapture { snap });
    }

    pub fn stop_capture(&self) {
        self.admin.send(&Cmd::StopCapture);
    }

    /// Le réglage « capturer dès l'ouverture » : laisse d'abord au service le temps de répondre,
    /// car lui ne demande pas de mot de passe.
    pub fn capture_at_open(self: &Arc<Self>) {
        let me = self.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(1500));
            if !me.service_up.load(Ordering::Relaxed) {
                me.enable_admin();
            }
        });
    }

    /// Relit un fichier de l'historique et l'ajoute à la liste des paquets.
    pub fn load_history(self: &Arc<Self>, path: std::path::PathBuf) {
        let me = self.clone();
        std::thread::spawn(move || {
            // Ce qui a suivi la connexion au service est déjà affiché.
            let cutoff = {
                let m = me.model.lock().unwrap();
                if m.capture.service { m.capture.service_live_since_us } else { u64::MAX }
            };
            let mut count = 0;
            let res = crate::service::read_capture_file(&path, &mut |f: RawFrame| {
                if f.ts_us < cutoff {
                    count += 1;
                    let _ = me.incoming.send(Incoming::History(f));
                }
            });
            let event = match res {
                Ok(_) => Event::HistoryLoaded { path: path.to_string_lossy().into_owned(), count },
                Err(e) => Event::CaptureError(format!("{} : {e}", path.display())),
            };
            let _ = me.incoming.send(Incoming::Event(event));
            me.request_repaint();
        });
    }

    pub fn run_action(self: &Arc<Self>, action: manage::Action) {
        self.action_running.store(true, Ordering::Relaxed);
        let me = self.clone();
        std::thread::spawn(move || {
            let res = manage::run_action(&action, &me.admin);
            me.action_log.lock().unwrap().push(res);
            me.action_running.store(false, Ordering::Relaxed);
            me.refresh_panels.store(true, Ordering::Relaxed);
            me.request_repaint();
        });
    }

    pub fn request_repaint(&self) {
        if let Some(c) = self.repaint.lock().unwrap().as_ref() {
            c.request_repaint();
        }
    }
}

fn read_trim(p: &Path) -> String {
    std::fs::read_to_string(p).map(|s| s.trim().to_string()).unwrap_or_default()
}

fn read_u64(p: &Path) -> u64 {
    read_trim(p).parse().unwrap_or(0)
}

#[derive(Default)]
pub struct IfSnapshot {
    pub name: String,
    pub index: u32,
    pub kind: IfKind,
    pub state: String,
    pub mac: String,
    pub mtu: u32,
    pub speed: Option<i64>,
    pub bridge_port: bool,
    pub rx: u64,
    pub tx: u64,
    pub rx_p: u64,
    pub tx_p: u64,
    pub rx_e: u64,
    pub tx_e: u64,
    pub rx_d: u64,
    pub tx_d: u64,
}

pub fn read_interfaces(root: &Path) -> Vec<IfSnapshot> {
    let Ok(rd) = std::fs::read_dir(root) else { return vec![] };
    let mut out = vec![];
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let d = e.path();
        let s = d.join("statistics");
        let dev_type = read_trim(&d.join("type"));
        let has_device = d.join("device").exists();
        let kind = if dev_type == "772" {
            IfKind::Loopback
        } else if d.join("wireless").exists() || d.join("phy80211").exists() {
            IfKind::Wifi
        } else if d.join("bridge").exists() {
            IfKind::Bridge
        } else if has_device {
            IfKind::Ethernet
        } else if name.starts_with("veth") {
            IfKind::Veth
        } else if name.starts_with("tun") || name.starts_with("tap") || name.starts_with("wg") || dev_type == "65534" {
            IfKind::Tunnel
        } else {
            IfKind::Virtual
        };
        out.push(IfSnapshot {
            index: read_trim(&d.join("ifindex")).parse().unwrap_or(0),
            kind,
            state: read_trim(&d.join("operstate")),
            mac: read_trim(&d.join("address")),
            mtu: read_trim(&d.join("mtu")).parse().unwrap_or(0),
            speed: read_trim(&d.join("speed")).parse().ok().filter(|v: &i64| *v > 0),
            bridge_port: d.join("brport").exists(),
            rx: read_u64(&s.join("rx_bytes")),
            tx: read_u64(&s.join("tx_bytes")),
            rx_p: read_u64(&s.join("rx_packets")),
            tx_p: read_u64(&s.join("tx_packets")),
            rx_e: read_u64(&s.join("rx_errors")),
            tx_e: read_u64(&s.join("tx_errors")),
            rx_d: read_u64(&s.join("rx_dropped")),
            tx_d: read_u64(&s.join("tx_dropped")),
            name,
        });
    }
    out
}

pub fn parse_ip_addr_json(text: &str) -> HashMap<String, Vec<(IpAddr, u8)>> {
    let v: serde_json::Value = serde_json::from_str(text).unwrap_or_default();
    let mut out: HashMap<String, Vec<(IpAddr, u8)>> = HashMap::new();
    for link in v.as_array().map(Vec::as_slice).unwrap_or(&[]) {
        let Some(name) = link.get("ifname").and_then(|x| x.as_str()) else { continue };
        let e = out.entry(name.to_string()).or_default();
        for a in link.get("addr_info").and_then(|x| x.as_array()).map(Vec::as_slice).unwrap_or(&[]) {
            let ip = a.get("local").and_then(|x| x.as_str()).and_then(|x| x.parse().ok());
            let p = a.get("prefixlen").and_then(|x| x.as_u64()).unwrap_or(0) as u8;
            if let Some(ip) = ip {
                e.push((ip, p));
            }
        }
    }
    out
}

fn apply_interfaces(m: &mut Model, snaps: Vec<IfSnapshot>, dt: f64, day: &str) {
    let t = m.now();
    let mut names = vec![];
    let mut delta_usage = vec![];
    for s in snaps {
        names.push(s.name.clone());
        m.ifindex.insert(s.index, Arc::from(s.name.as_str()));
        let i = m.ifaces.entry(s.name.clone()).or_insert_with(|| Iface { name: s.name.clone(), ..Default::default() });
        i.index = s.index;
        i.kind = s.kind;
        i.state = s.state;
        i.mac = s.mac;
        i.mtu = s.mtu;
        i.speed_mbps = s.speed;
        i.bridge_port = s.bridge_port;
        // Les compteurs peuvent repartir de zéro si l'interface a été recréée.
        let (drx, dtx) = if i.started { (s.rx.saturating_sub(i.rx_total), s.tx.saturating_sub(i.tx_total)) } else { (0, 0) };
        if i.started {
            i.rx_rate = drx as f64 / dt;
            i.tx_rate = dtx as f64 / dt;
            i.session_rx += drx;
            i.session_tx += dtx;
            i.history.push_back(Sample { t, rx: i.rx_rate as f32, tx: i.tx_rate as f32 });
            if i.history.len() > HISTORY_CAP {
                i.history.pop_front();
            }
            if drx + dtx > 0 {
                delta_usage.push((s.name.clone(), drx, dtx));
            }
        }
        i.started = true;
        i.rx_total = s.rx;
        i.tx_total = s.tx;
        i.rx_packets = s.rx_p;
        i.tx_packets = s.tx_p;
        i.rx_errors = s.rx_e;
        i.tx_errors = s.tx_e;
        i.rx_dropped = s.rx_d;
        i.tx_dropped = s.tx_d;
    }
    m.ifaces.retain(|n, _| names.contains(n));
    for (name, rx, tx) in delta_usage {
        m.usage.add_iface(day, &name, rx, tx);
    }
    let (rx, tx) = m.current_rates(None);
    m.total_history.push_back(Sample { t, rx: rx as f32, tx: tx as f32 });
    if m.total_history.len() > HISTORY_CAP {
        m.total_history.pop_front();
    }
    m.sample_count += 1;
}

fn apply_addresses(m: &mut Model, map: HashMap<String, Vec<(IpAddr, u8)>>) {
    m.local_ips.clear();
    m.ip_iface.clear();
    for (name, addrs) in &map {
        for (ip, _) in addrs {
            m.local_ips.insert(*ip);
            m.ip_iface.insert(*ip, name.clone());
        }
    }
    for (name, addrs) in map {
        if let Some(i) = m.ifaces.get_mut(&name) {
            i.addrs = addrs;
        }
    }
}

fn sampler_loop(s: Arc<Shared>) {
    let mut collector = crate::platform::Collector::default();
    let mut last_if = Instant::now();
    let mut last_flows = Instant::now();
    let mut last_addr: Option<Instant> = None;
    let mut last_save = Instant::now();
    let mut first_ss = true;
    loop {
        let want_addrs = last_addr.is_none_or(|t| t.elapsed() >= Duration::from_secs(3));
        if want_addrs {
            last_addr = Some(Instant::now());
        }
        let (snaps, addr_map) = collector.interfaces(want_addrs);
        let dt = last_if.elapsed().as_secs_f64().max(0.05);
        last_if = Instant::now();
        let day = crate::model::today();
        {
            let mut m = s.model.lock().unwrap();
            apply_interfaces(&mut m, snaps, dt, &day);
            if let Some(map) = addr_map {
                apply_addresses(&mut m, map);
            }
        }

        if first_ss || last_flows.elapsed() >= Duration::from_millis(950) {
            // Hors verrou : un relevé qui ne doit pas figer l'affichage.
            let entries = collector.sockets(&s.admin);
            let dt = last_flows.elapsed().as_secs_f64().max(0.05);
            last_flows = Instant::now();
            let want: Vec<IpAddr> = {
                let mut m = s.model.lock().unwrap();
                m.apply_sockets(entries);
                if !first_ss {
                    m.tick_flows(dt);
                }
                m.poll_keys();
                refresh_proc_infos(&mut m);
                m.flows.values().filter(|f| f.open).map(|f| f.key.remote.ip()).collect()
            };
            first_ss = false;
            if s.enrich.auto.load(Ordering::Relaxed) {
                for ip in want {
                    s.enrich.request(ip);
                }
            }
        }

        if last_save.elapsed() >= Duration::from_secs(30) {
            last_save = Instant::now();
            let usage = s.model.lock().unwrap().usage.clone();
            usage.save();
        }
        s.request_repaint();
        std::thread::sleep(crate::platform::SAMPLE_EVERY);
    }
}

fn refresh_proc_infos(m: &mut Model) {
    let pids: std::collections::HashSet<u32> = m.flows.values().filter_map(|f| f.pid).collect();
    m.procs.retain(|p, _| pids.contains(p));
    for pid in pids {
        if m.procs.contains_key(&pid) {
            continue;
        }
        if !cfg!(target_os = "linux") {
            // Pas de `/proc` ici : le nom vient du relevé des connexions.
            let flow = m.flows.values().find(|f| f.pid == Some(pid));
            let Some((name, uid)) = flow.and_then(|f| Some((f.proc_name.clone()?, f.uid))) else { continue };
            let user = uid.map(|u| m.uid_names.get(&u).cloned().unwrap_or_else(|| u.to_string())).unwrap_or_default();
            m.procs.insert(pid, crate::model::ProcInfo { pid, name, cmdline: String::new(), user });
            continue;
        }
        let dir = format!("/proc/{pid}");
        let name = read_trim(Path::new(&format!("{dir}/comm")));
        if name.is_empty() {
            continue;
        }
        let cmdline = std::fs::read(format!("{dir}/cmdline"))
            .map(|b| String::from_utf8_lossy(&b).replace('\0', " ").trim().to_string())
            .unwrap_or_default();
        let status = std::fs::read_to_string(format!("{dir}/status")).unwrap_or_default();
        let uid = status.lines().find_map(|l| l.strip_prefix("Uid:")).and_then(|v| v.split_whitespace().next()).and_then(|v| v.parse::<u32>().ok());
        let user = uid.map(|u| m.uid_names.get(&u).cloned().unwrap_or_else(|| u.to_string())).unwrap_or_default();
        m.procs.insert(pid, crate::model::ProcInfo { pid, name, cmdline, user });
    }
}

enum Parsed {
    Live(crate::packet::Packet),
    Old(crate::packet::Packet),
    Event(Event),
}

/// Reste relié au service de capture tant qu'il tourne, et se reconnecte s'il redémarre.
#[cfg(target_os = "linux")]
fn service_client_loop(s: Arc<Shared>) {
    let socket = s.service_paths.socket();
    loop {
        let Ok(stream) = std::os::unix::net::UnixStream::connect(&socket) else {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        };
        // Avant toute chose : `start_capture` doit savoir que le service a pris le relais.
        s.service_up.store(true, Ordering::Relaxed);
        s.stop_capture();
        let _ = s.incoming.send(Incoming::Event(Event::ServiceUp));
        s.request_repaint();
        let mut reader = std::io::BufReader::with_capacity(256 * 1024, stream);
        while let Ok(Some((tag, data))) = read_frame(&mut reader) {
            match tag {
                TAG_PACKET => {
                    if let Some(f) = RawFrame::decode(&data) {
                        let _ = s.incoming.send(Incoming::ServiceFrame(f));
                    }
                }
                TAG_EVENT => {
                    if let Ok(ev) = serde_json::from_slice::<Event>(&data) {
                        let _ = s.incoming.send(Incoming::Event(ev));
                    }
                }
                _ => {}
            }
        }
        s.service_up.store(false, Ordering::Relaxed);
        let _ = s.incoming.send(Incoming::Event(Event::ServiceDown));
        // Le service vient de s'arrêter : si l'administrateur est actif, la capture reprend par lui.
        if s.admin.is_on() {
            s.start_capture();
        }
        s.request_repaint();
    }
}

fn ingest_loop(s: Arc<Shared>, rx: Receiver<Incoming>) {
    let mut last_repaint = Instant::now();
    loop {
        let first = match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(x) => x,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        // Par lots : le verrou reste court même à fort débit.
        let mut batch = vec![first];
        while batch.len() < 512 {
            match rx.try_recv() {
                Ok(x) => batch.push(x),
                Err(_) => break,
            }
        }
        // Au moment où le service prend le relais, l'assistant envoie encore quelques paquets
        // que le service voit aussi : on les écarte pour ne rien afficher en double.
        let service_up = s.service_up.load(Ordering::Relaxed);
        let parsed: Vec<_> = batch
            .into_iter()
            .filter(|x| !(service_up && matches!(x, Incoming::Frame(_))))
            .map(|x| match x {
                Incoming::Frame(f) | Incoming::ServiceFrame(f) => Parsed::Live(crate::packet::parse(f)),
                Incoming::History(f) => Parsed::Old(crate::packet::parse(f)),
                Incoming::Event(e) => Parsed::Event(e),
            })
            .collect();
        let mut loaded = vec![];
        let mut m = s.model.lock().unwrap();
        for item in parsed {
            let event = match item {
                Parsed::Live(p) => {
                    m.ingest(p);
                    continue;
                }
                Parsed::Old(p) => {
                    m.replaying = true;
                    m.ingest(p);
                    m.replaying = false;
                    continue;
                }
                Parsed::Event(e) => e,
            };
            match event {
                Event::CaptureStarted => {
                    m.capture.running = true;
                    m.capture.error = None;
                }
                // Si le service est là, la capture continue par lui.
                Event::CaptureStopped => m.capture.running = m.capture.service,
                Event::CaptureError(e) => {
                    m.capture.running = m.capture.service;
                    m.capture.error = Some(e);
                }
                Event::CaptureStats { packets, drops } => {
                    m.capture.kernel_packets = packets;
                    m.capture.kernel_drops = drops;
                }
                Event::Hello { .. } => {}
                Event::ServiceUp => {
                    m.capture.service = true;
                    m.capture.running = true;
                    m.capture.error = None;
                    m.capture.service_live_since_us = crate::util::now_us();
                }
                Event::ServiceDown => {
                    m.capture.service = false;
                    m.capture.running = false;
                    m.capture.service_stats = ServiceStats::default();
                }
                Event::ServiceStats(st) => {
                    m.capture.kernel_packets = st.packets;
                    m.capture.kernel_drops = st.drops;
                    m.capture.service_stats = st;
                }
                Event::HistoryLoaded { path, count } => {
                    m.sort_packets_by_time();
                    m.history_loaded.insert(path.into());
                    loaded.push(count);
                }
            }
        }
        drop(m);
        for count in loaded {
            s.action_log.lock().unwrap().push(ActionResult {
                title: "Historique chargé".into(),
                ok: true,
                detail: format!("{count} paquets ajoutés à la liste."),
                at: chrono::Local::now().format("%H:%M:%S").to_string(),
            });
        }
        if last_repaint.elapsed() >= Duration::from_millis(200) {
            last_repaint = Instant::now();
            s.request_repaint();
        }
    }
}

fn panels_loop(s: Arc<Shared>) {
    let mut last = [Instant::now() - Duration::from_secs(60); 4];
    loop {
        let panel = s.visible_panel.load(Ordering::Relaxed);
        let forced = s.refresh_panels.swap(false, Ordering::Relaxed);
        let due = |i: usize, every: u64| forced || last[i].elapsed() >= Duration::from_secs(every);
        match panel {
            PANEL_FIREWALL if due(1, 3) => {
                last[1] = Instant::now();
                let d = manage::load_firewall(&s.admin);
                s.panels.lock().unwrap().firewall = d;
                s.request_repaint();
            }
            PANEL_CONFIG if due(2, 3) => {
                last[2] = Instant::now();
                let d = manage::load_netconfig();
                s.panels.lock().unwrap().config = d;
                s.request_repaint();
            }
            PANEL_SSH if due(3, 4) => {
                last[3] = Instant::now();
                let d = manage::load_ssh(&s.admin);
                s.panels.lock().unwrap().ssh = d;
                s.request_repaint();
            }
            _ => {}
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn this_machine_interfaces_are_readable() {
        let list = read_interfaces(Path::new("/sys/class/net"));
        let lo = list.iter().find(|i| i.name == "lo").expect("lo existe partout");
        assert_eq!(lo.kind, IfKind::Loopback);
        assert!(lo.index > 0);
    }

    #[test]
    fn ip_json() {
        let m = parse_ip_addr_json(r#"[{"ifname":"wlo1","addr_info":[{"family":"inet","local":"192.168.43.242","prefixlen":24}]}]"#);
        assert_eq!(m["wlo1"], vec![("192.168.43.242".parse().unwrap(), 24)]);
    }

    #[test]
    fn rates_come_from_counter_differences() {
        let mut m = Model::new();
        let snap = |rx, tx| vec![IfSnapshot { name: "wlo1".into(), index: 2, kind: IfKind::Wifi, state: "up".into(), rx, tx, ..Default::default() }];
        apply_interfaces(&mut m, snap(1000, 500), 1.0, "2026-11-04");
        assert_eq!(m.ifaces["wlo1"].rx_rate, 0.0);
        apply_interfaces(&mut m, snap(3000, 700), 0.5, "2026-11-04");
        assert_eq!(m.ifaces["wlo1"].rx_rate, 4000.0);
        assert_eq!(m.ifaces["wlo1"].tx_rate, 400.0);
        assert_eq!(m.current_rates(None), (4000.0, 400.0));
        assert_eq!(m.usage.days["2026-11-04"].ifaces["wlo1"], (2000, 200));
        // Compteur revenu à zéro : pas de valeur aberrante.
        apply_interfaces(&mut m, snap(10, 10), 1.0, "2026-11-04");
        assert_eq!(m.ifaces["wlo1"].rx_rate, 0.0);
    }
}
