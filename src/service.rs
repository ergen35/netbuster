//! Le service de capture : `netbuster --daemon`, lancé par le système dès le démarrage du PC.
//!
//! Il lit tous les paquets et les écrit dans des fichiers pcap tournants, sous une limite de place.
//! La fenêtre s'y relie par une prise locale pour voir le trafic en direct sans mot de passe.
//!
//! Il tourne sous le compte de la personne, avec la seule capacité de lire le réseau, et non en
//! administrateur : ses fichiers lui appartiennent et un défaut ici ne donne pas la main sur le PC.
//!
//! `--mock <dossier>` (tests, refusé en root) rejoue `<dossier>/frames.bin` au lieu du réseau.

use crate::helper::{kernel_capture, now_us, replay_frames, CaptureEvent};
use crate::proto::*;
use std::io::{BufWriter, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const UNIT_NAME: &str = "netbuster-capture.service";
pub const UNIT_PATH: &str = "/etc/systemd/system/netbuster-capture.service";
pub const INSTALL_DIR: &str = "/usr/local/lib/netbuster";
const STATE_DIR: &str = "/var/lib/netbuster";
const RUN_DIR: &str = "/run/netbuster";

const MIB: u64 = 1024 * 1024;
pub const DEFAULT_LIMIT_MB: u64 = 2048;
pub const LIMIT_CHOICES_MB: [u64; 6] = [512, 1024, 2048, 5120, 10240, 20480];
const MIN_LIMIT_MB: u64 = 64;
/// En dessous, plus rien n'est écrit : remplir le disque casserait tout le PC.
const MIN_FREE_BYTES: u64 = 256 * MIB;
const ROTATE_AFTER: Duration = Duration::from_secs(3600);
const MAX_CLIENTS: usize = 8;

/// Où se trouvent les fichiers du service. Les tests les placent dans un dossier temporaire.
#[derive(Debug, Clone, PartialEq)]
pub struct ServicePaths {
    pub unit: PathBuf,
    pub state: PathBuf,
    pub run: PathBuf,
}

impl ServicePaths {
    pub fn system() -> ServicePaths {
        ServicePaths { unit: UNIT_PATH.into(), state: STATE_DIR.into(), run: RUN_DIR.into() }
    }

    pub fn under(root: &Path) -> ServicePaths {
        let base = root.join("service");
        ServicePaths { unit: base.join(UNIT_NAME), state: base.join("state"), run: base.join("run") }
    }

    pub fn socket(&self) -> PathBuf {
        self.run.join("capture.sock")
    }

    pub fn limit_file(&self) -> PathBuf {
        self.state.join("limit-mb")
    }
}

pub fn valid_user_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && !name.starts_with('-') && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// La fiche du service pour le système.
///
/// Elle se place avant `network-pre.target` : le réseau ne démarre qu'une fois la capture prête.
/// `Wants` et non `Requires`, et un délai court : un service en panne ne bloque jamais le démarrage.
pub fn unit_text(user: &str, exe: &str) -> String {
    format!(
        "[Unit]
Description=NetBuster : capture du trafic réseau en arrière-plan
Documentation={repo}
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target shutdown.target
Wants=network-pre.target
Conflicts=shutdown.target

[Service]
Type=notify
ExecStart={exe} --daemon
User={user}
Restart=on-failure
RestartSec=5
TimeoutStartSec=15
StateDirectory=netbuster
StateDirectoryMode=0700
RuntimeDirectory=netbuster
RuntimeDirectoryMode=0700
UMask=0077
# CAP_NET_ADMIN sert uniquement à agrandir le tampon de réception : le service ne peut pas
# reconfigurer le réseau, car il n'a accès ni à netlink ni aux sockets IP.
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
RestrictAddressFamilies=AF_PACKET AF_UNIX
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
",
        repo = env!("CARGO_PKG_REPOSITORY"),
    )
}

/// Copie le programme en remplaçant atomiquement l'ancienne version, même si elle tourne.
pub fn install_binary(src: &Path, dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    let tmp = dir.join("netbuster.new");
    std::fs::copy(src, &tmp)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    std::fs::rename(tmp, dir.join("netbuster"))
}

// ---------- Fichiers de capture ----------

const LINKTYPE_LINUX_SLL2: u32 = 276;
const SLL2_HEADER: usize = 20;
const MAX_RECORD: usize = 1024 * 1024;

fn write_pcap_header(w: &mut impl Write) -> std::io::Result<()> {
    w.write_all(&0xa1b2c3d4u32.to_le_bytes())?;
    w.write_all(&2u16.to_le_bytes())?;
    w.write_all(&4u16.to_le_bytes())?;
    w.write_all(&0i32.to_le_bytes())?;
    w.write_all(&0u32.to_le_bytes())?;
    w.write_all(&262_144u32.to_le_bytes())?;
    w.write_all(&LINKTYPE_LINUX_SLL2.to_le_bytes())
}

/// SLL2 garde le numéro de l'interface : le trafic reste rangé par interface après coup.
fn write_pcap_record(w: &mut impl Write, f: &RawFrame) -> std::io::Result<u64> {
    let incl = f.data.len() as u32 + SLL2_HEADER as u32;
    let orig = f.orig_len + SLL2_HEADER as u32;
    w.write_all(&((f.ts_us / 1_000_000) as u32).to_le_bytes())?;
    w.write_all(&((f.ts_us % 1_000_000) as u32).to_le_bytes())?;
    w.write_all(&incl.to_le_bytes())?;
    w.write_all(&orig.to_le_bytes())?;
    w.write_all(&f.proto.to_be_bytes())?;
    w.write_all(&0u16.to_be_bytes())?;
    w.write_all(&f.ifindex.to_be_bytes())?;
    w.write_all(&1u16.to_be_bytes())?;
    w.write_all(&[f.pkttype, 0])?;
    w.write_all(&[0u8; 8])?;
    w.write_all(&f.data)?;
    Ok(16 + incl as u64)
}

/// Relit un fichier du service. Un fichier coupé net (panne de courant) rend ce qu'il contient.
pub fn read_capture_file(path: &Path, on_frame: &mut dyn FnMut(RawFrame)) -> std::io::Result<usize> {
    use std::io::Read;
    let mut r = std::io::BufReader::with_capacity(256 * 1024, std::fs::File::open(path)?);
    let mut head = [0u8; 24];
    r.read_exact(&mut head)?;
    let magic = u32::from_le_bytes(head[0..4].try_into().unwrap());
    let link = u32::from_le_bytes(head[20..24].try_into().unwrap());
    if magic != 0xa1b2c3d4 || link != LINKTYPE_LINUX_SLL2 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "ce n'est pas un fichier du service NetBuster"));
    }
    let mut count = 0;
    let mut rec = [0u8; 16];
    let mut body = vec![];
    while r.read_exact(&mut rec).is_ok() {
        let sec = u32::from_le_bytes(rec[0..4].try_into().unwrap()) as u64;
        let usec = u32::from_le_bytes(rec[4..8].try_into().unwrap()) as u64;
        let incl = u32::from_le_bytes(rec[8..12].try_into().unwrap()) as usize;
        let orig = u32::from_le_bytes(rec[12..16].try_into().unwrap());
        if !(SLL2_HEADER..=MAX_RECORD).contains(&incl) {
            break;
        }
        body.resize(incl, 0);
        if r.read_exact(&mut body).is_err() {
            break;
        }
        on_frame(RawFrame {
            ts_us: sec * 1_000_000 + usec,
            ifindex: u32::from_be_bytes(body[4..8].try_into().unwrap()),
            pkttype: body[10],
            proto: u16::from_be_bytes(body[0..2].try_into().unwrap()),
            orig_len: orig.saturating_sub(SLL2_HEADER as u32),
            data: body[SLL2_HEADER..].to_vec(),
        });
        count += 1;
    }
    Ok(count)
}

#[derive(Debug, Clone, PartialEq)]
pub struct CaptureFile {
    pub path: PathBuf,
    pub bytes: u64,
    pub modified: std::time::SystemTime,
}

impl CaptureFile {
    /// `capture-20261105-081500.pcap` → `05/11/2026 08:15:00`
    pub fn started_label(&self) -> String {
        let name = self.path.file_stem().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let d: Vec<char> = name.trim_start_matches("capture-").chars().collect();
        if d.len() < 15 || d[8] != '-' {
            return name;
        }
        let part = |a: usize, b: usize| d[a..b].iter().collect::<String>();
        format!("{}/{}/{} {}:{}:{}", part(6, 8), part(4, 6), part(0, 4), part(9, 11), part(11, 13), part(13, 15))
    }

    pub fn ended_label(&self) -> String {
        chrono::DateTime::<chrono::Local>::from(self.modified).format("%d/%m/%Y %H:%M:%S").to_string()
    }
}

/// Les fichiers de capture, du plus ancien au plus récent.
pub fn list_capture_files(dir: &Path) -> Vec<CaptureFile> {
    let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };
    let mut out: Vec<CaptureFile> = rd
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            if !(name.starts_with("capture-") && name.ends_with(".pcap")) {
                return None;
            }
            let md = e.metadata().ok()?;
            Some(CaptureFile { path: e.path(), bytes: md.len(), modified: md.modified().ok()? })
        })
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

pub fn clear_history(dir: &Path, keep_newest: bool) -> std::io::Result<usize> {
    let mut files = list_capture_files(dir);
    if keep_newest {
        files.pop();
    }
    for f in &files {
        std::fs::remove_file(&f.path)?;
    }
    Ok(files.len())
}

/// Les plus anciens fichiers à supprimer pour libérer `excess` octets, sans toucher au fichier en cours.
pub fn files_to_prune(files: &[CaptureFile], active: Option<&Path>, excess: u64) -> Vec<PathBuf> {
    let mut freed = 0;
    let mut out = vec![];
    for f in files {
        if freed >= excess {
            break;
        }
        if Some(f.path.as_path()) == active {
            continue;
        }
        freed += f.bytes;
        out.push(f.path.clone());
    }
    out
}

pub fn read_limit_mb(paths: &ServicePaths) -> u64 {
    std::fs::read_to_string(paths.limit_file()).ok().and_then(|t| t.trim().parse().ok()).unwrap_or(DEFAULT_LIMIT_MB).max(MIN_LIMIT_MB)
}

/// Le service relit cette limite toute seule : la modifier ne demande pas de mot de passe.
pub fn write_limit_mb(paths: &ServicePaths, mb: u64) -> std::io::Result<()> {
    std::fs::write(paths.limit_file(), format!("{}\n", mb.max(MIN_LIMIT_MB)))
}

fn free_bytes(dir: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
    (rc == 0).then(|| st.f_bavail as u64 * st.f_frsize as u64)
}

/// Écrit dans des fichiers tournants et garde la place occupée sous la limite.
pub struct Ring {
    paths: ServicePaths,
    limit: u64,
    writer: Option<BufWriter<std::fs::File>>,
    active: Option<PathBuf>,
    active_bytes: u64,
    opened: Instant,
    pub disk_low: bool,
    pub stored_bytes: u64,
    pub files: u32,
}

impl Ring {
    pub fn new(paths: ServicePaths) -> Ring {
        let limit = read_limit_mb(&paths) * MIB;
        Ring { paths, limit, writer: None, active: None, active_bytes: 0, opened: Instant::now(), disk_low: false, stored_bytes: 0, files: 0 }
    }

    fn file_limit(&self) -> u64 {
        (self.limit / 8).clamp(8 * MIB, 256 * MIB)
    }

    fn open_next(&mut self) -> std::io::Result<()> {
        self.close();
        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
        let mut path = self.paths.state.join(format!("capture-{stamp}.pcap"));
        let mut n = 1;
        while path.exists() {
            path = self.paths.state.join(format!("capture-{stamp}-{n}.pcap"));
            n += 1;
        }
        let file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;
        let mut w = BufWriter::with_capacity(256 * 1024, file);
        write_pcap_header(&mut w)?;
        self.writer = Some(w);
        self.active = Some(path);
        self.active_bytes = 24;
        self.opened = Instant::now();
        Ok(())
    }

    fn close(&mut self) {
        if let Some(mut w) = self.writer.take() {
            let _ = w.flush();
        }
        self.active = None;
    }

    pub fn write(&mut self, f: &RawFrame) -> std::io::Result<()> {
        if self.disk_low {
            return Err(std::io::Error::other("disque presque plein"));
        }
        if self.writer.is_none() || self.active_bytes >= self.file_limit() || self.opened.elapsed() >= ROTATE_AFTER {
            self.open_next()?;
        }
        let w = self.writer.as_mut().expect("fichier ouvert juste au-dessus");
        match write_pcap_record(w, f) {
            Ok(n) => {
                self.active_bytes += n;
                Ok(())
            }
            Err(e) => {
                // Écriture ratée (disque plein) : la suite repart dans un fichier sain.
                self.close();
                Err(e)
            }
        }
    }

    /// Une fois par seconde : met le fichier à jour sur le disque et applique les limites.
    pub fn housekeeping(&mut self) {
        if let Some(w) = self.writer.as_mut() {
            if w.flush().is_err() {
                self.close();
            }
        }
        self.limit = read_limit_mb(&self.paths) * MIB;
        let mut files = list_capture_files(&self.paths.state);
        let total: u64 = files.iter().map(|f| f.bytes).sum();
        let free = free_bytes(&self.paths.state).unwrap_or(u64::MAX);
        let excess = total.saturating_sub(self.limit).max(MIN_FREE_BYTES.saturating_sub(free));
        if excess > 0 {
            for p in files_to_prune(&files, self.active.as_deref(), excess) {
                let _ = std::fs::remove_file(p);
            }
            files = list_capture_files(&self.paths.state);
        }
        self.disk_low = free_bytes(&self.paths.state).unwrap_or(u64::MAX) < MIN_FREE_BYTES;
        if self.disk_low {
            self.close();
        }
        self.stored_bytes = files.iter().map(|f| f.bytes).sum();
        self.files = files.len() as u32;
    }
}

// ---------- Le service ----------

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_terminate(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// Prévient le système que la capture est prête, pour qu'il poursuive le démarrage du réseau.
fn notify_ready() {
    use std::os::linux::net::SocketAddrExt;
    let Some(target) = std::env::var_os("NOTIFY_SOCKET") else { return };
    let target = target.to_string_lossy().into_owned();
    let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() else { return };
    let addr = match target.strip_prefix('@') {
        Some(abs) => std::os::unix::net::SocketAddr::from_abstract_name(abs.as_bytes()),
        None => std::os::unix::net::SocketAddr::from_pathname(&target),
    };
    if let Ok(addr) = addr {
        let _ = sock.send_to_addr(b"READY=1", &addr);
    }
}

fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

#[derive(Default)]
struct Counters {
    packets: AtomicU64,
    kernel_drops: AtomicU64,
    lost: AtomicU64,
    stored: AtomicU64,
    files: AtomicU32,
    limit: AtomicU64,
    disk_low: AtomicBool,
}

enum ToClient {
    Frame(Arc<RawFrame>),
    Stats(Vec<u8>),
}

fn client_thread(mut stream: UnixStream, rx: std::sync::mpsc::Receiver<ToClient>) {
    let mut encoded = Vec::with_capacity(4096);
    while let Ok(msg) = rx.recv() {
        let res = match msg {
            ToClient::Frame(f) => {
                encoded.clear();
                f.encode(&mut encoded);
                write_frame(&mut stream, TAG_PACKET, &encoded)
            }
            ToClient::Stats(json) => write_frame(&mut stream, TAG_EVENT, &json),
        };
        if res.is_err() {
            return;
        }
    }
}

pub fn run_daemon(mock: Option<PathBuf>) -> i32 {
    if mock.is_some() && unsafe { libc::geteuid() } == 0 {
        eprintln!("le mode test est refusé en administrateur");
        return 2;
    }
    unsafe {
        libc::umask(0o077);
        libc::signal(libc::SIGTERM, on_terminate as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_terminate as *const () as libc::sighandler_t);
    }
    let paths = match &mock {
        Some(dir) => ServicePaths::under(dir),
        None => ServicePaths::system(),
    };
    for dir in [&paths.state, &paths.run] {
        if let Err(e) = ensure_private_dir(dir) {
            eprintln!("{} : {e}", dir.display());
            return 1;
        }
    }

    let counters = Arc::new(Counters::default());
    counters.limit.store(read_limit_mb(&paths) * MIB, Ordering::Relaxed);
    let clients: Arc<Mutex<Vec<SyncSender<ToClient>>>> = Arc::new(Mutex::new(vec![]));

    // Le disque a son propre fil : une écriture lente ne doit pas faire perdre de paquets.
    let (disk_tx, disk_rx) = sync_channel::<Arc<RawFrame>>(16_384);
    let writer = {
        let (paths, counters, clients) = (paths.clone(), counters.clone(), clients.clone());
        let since_us = now_us();
        std::thread::spawn(move || {
            let mut ring = Ring::new(paths);
            let mut last = Instant::now() - Duration::from_secs(2);
            loop {
                let closed = match disk_rx.recv_timeout(Duration::from_millis(250)) {
                    Ok(f) => {
                        if ring.write(&f).is_err() {
                            counters.lost.fetch_add(1, Ordering::Relaxed);
                        }
                        false
                    }
                    Err(RecvTimeoutError::Timeout) => false,
                    Err(RecvTimeoutError::Disconnected) => true,
                };
                if closed || last.elapsed() >= Duration::from_secs(1) {
                    last = Instant::now();
                    ring.housekeeping();
                    counters.stored.store(ring.stored_bytes, Ordering::Relaxed);
                    counters.files.store(ring.files, Ordering::Relaxed);
                    counters.limit.store(ring.limit, Ordering::Relaxed);
                    counters.disk_low.store(ring.disk_low, Ordering::Relaxed);
                    let stats = ServiceStats {
                        packets: counters.packets.load(Ordering::Relaxed),
                        drops: counters.kernel_drops.load(Ordering::Relaxed) + counters.lost.load(Ordering::Relaxed),
                        stored_bytes: ring.stored_bytes,
                        files: ring.files,
                        limit_bytes: ring.limit,
                        disk_low: ring.disk_low,
                        since_us,
                    };
                    if let Ok(json) = serde_json::to_vec(&Event::ServiceStats(stats)) {
                        clients.lock().unwrap().retain(|c| !matches!(c.try_send(ToClient::Stats(json.clone())), Err(TrySendError::Disconnected(_))));
                    }
                }
                if closed {
                    ring.close();
                    return;
                }
            }
        })
    };

    // La prise : le dossier qui la contient n'est accessible qu'au compte de la personne.
    let socket = paths.socket();
    let _ = std::fs::remove_file(&socket);
    let listener = match UnixListener::bind(&socket) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{} : {e}", socket.display());
            return 1;
        }
    };
    let _ = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600));
    {
        let clients = clients.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut list = clients.lock().unwrap();
                if list.len() >= MAX_CLIENTS {
                    continue;
                }
                let (tx, rx) = sync_channel(8192);
                std::thread::spawn(move || client_thread(stream, rx));
                list.push(tx);
            }
        });
    }

    let mut on_event = |ev: CaptureEvent| match ev {
        CaptureEvent::Started => notify_ready(),
        CaptureEvent::Frame(f) => {
            counters.packets.fetch_add(1, Ordering::Relaxed);
            let f = Arc::new(f.clone());
            if disk_tx.try_send(f.clone()).is_err() {
                counters.lost.fetch_add(1, Ordering::Relaxed);
            }
            // Une fenêtre lente perd de l'affichage, jamais de capture : tout reste écrit sur le disque.
            let mut list = clients.lock().unwrap();
            list.retain(|c| !matches!(c.try_send(ToClient::Frame(f.clone())), Err(TrySendError::Disconnected(_))));
        }
        CaptureEvent::Idle => {}
        CaptureEvent::Stats { drops, .. } => counters.kernel_drops.store(drops, Ordering::Relaxed),
    };
    let result = match &mock {
        Some(dir) => {
            // Pour que les tests soient exacts : la fenêtre voit tous les paquets rejoués.
            let t = Instant::now();
            while clients.lock().unwrap().is_empty() && t.elapsed() < Duration::from_secs(5) {
                std::thread::sleep(Duration::from_millis(20));
            }
            replay_frames(&dir.join("frames.bin"), &STOP, &mut on_event)
        }
        None => kernel_capture(65_535, &STOP, &mut on_event),
    };
    drop(disk_tx);
    let _ = writer.join();
    let _ = std::fs::remove_file(&socket);
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("netbuster-svc-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn frame(ts_us: u64, len: usize) -> RawFrame {
        RawFrame { ts_us, ifindex: 3, pkttype: 4, proto: 0x0800, orig_len: len as u32 + 7, data: vec![0x45; len] }
    }

    #[test]
    fn user_names_cannot_inject_into_the_unit_file() {
        assert!(valid_user_name("ergen35"));
        assert!(valid_user_name("jean.dupont_2"));
        assert!(!valid_user_name(""));
        assert!(!valid_user_name("-root"));
        assert!(!valid_user_name("a\nExecStartPre=/bin/sh"));
        assert!(!valid_user_name("a b"));
    }

    #[test]
    fn the_unit_runs_the_protected_copy_with_only_network_reading_rights() {
        let u = unit_text("ergen35", "/usr/local/lib/netbuster/netbuster");
        assert!(u.contains("ExecStart=/usr/local/lib/netbuster/netbuster --daemon\n"));
        assert!(u.contains("User=ergen35\n"));
        assert!(u.contains("CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN\n"));
        assert!(u.contains("RestrictAddressFamilies=AF_PACKET AF_UNIX\n"));
        assert!(u.contains("Before=network-pre.target"));
        assert!(!u.contains("Requires="));
    }

    #[test]
    fn capture_files_keep_every_field_and_survive_a_power_cut() {
        let d = tmp("roundtrip");
        let path = d.join("capture-20261105-081500.pcap");
        let mut w = std::fs::File::create(&path).unwrap();
        write_pcap_header(&mut w).unwrap();
        write_pcap_record(&mut w, &frame(1_700_000_000_000_123, 40)).unwrap();
        write_pcap_record(&mut w, &frame(1_700_000_001_000_456, 60)).unwrap();
        drop(w);
        let mut back = vec![];
        assert_eq!(read_capture_file(&path, &mut |f| back.push(f)).unwrap(), 2);
        assert_eq!(back[0].ts_us, 1_700_000_000_000_123);
        assert_eq!(back[1].ifindex, 3);
        assert_eq!(back[1].pkttype, 4);
        assert_eq!(back[1].proto, 0x0800);
        assert_eq!(back[1].orig_len, 67);
        assert_eq!(back[1].data.len(), 60);

        // Coupure au milieu du dernier paquet : le premier reste lisible.
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() - 10]).unwrap();
        assert_eq!(read_capture_file(&path, &mut |_| {}).unwrap(), 1);
    }

    #[test]
    fn capture_files_open_in_tcpdump() {
        if crate::util::which("tcpdump").is_none() {
            return;
        }
        let d = tmp("tcpdump");
        let path = d.join("capture-20261105-081500.pcap");
        let mut w = std::fs::File::create(&path).unwrap();
        write_pcap_header(&mut w).unwrap();
        let data = crate::packet::build::ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5000, 53, b"bonjour");
        write_pcap_record(&mut w, &RawFrame { ts_us: 1_700_000_000_000_000, ifindex: 2, pkttype: 4, proto: 0x0800, orig_len: data.len() as u32, data }).unwrap();
        drop(w);
        let out = std::process::Command::new("tcpdump").args(["-nn", "-r"]).arg(&path).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert!(text.contains("10.0.0.1.5000 > 10.0.0.2.53"), "{text}");
    }

    #[test]
    fn the_ring_rotates_and_stays_under_its_limit() {
        let d = tmp("ring");
        let paths = ServicePaths::under(&d);
        std::fs::create_dir_all(&paths.state).unwrap();
        // Limite minimale : 64 Mo, soit des fichiers de 8 Mo.
        write_limit_mb(&paths, MIN_LIMIT_MB).unwrap();
        let mut ring = Ring::new(paths.clone());
        ring.housekeeping();
        let big = frame(1_700_000_000_000_000, 60_000);
        for i in 0..(100 * MIB / 60_000) {
            ring.write(&big).unwrap();
            if i % 500 == 0 {
                ring.housekeeping();
            }
        }
        ring.housekeeping();
        ring.close();
        let files = list_capture_files(&paths.state);
        let total: u64 = files.iter().map(|f| f.bytes).sum();
        assert!(files.len() > 3, "{} fichiers", files.len());
        // Une marge d'un fichier : celui en cours d'écriture peut dépasser.
        assert!(total <= (MIN_LIMIT_MB + 16) * MIB, "{total}");
        assert_eq!(ring.files as usize, files.len());
    }

    #[test]
    fn pruning_removes_the_oldest_but_never_the_active_file() {
        let f = |n: &str, bytes| CaptureFile { path: PathBuf::from(n), bytes, modified: std::time::UNIX_EPOCH };
        let files = [f("a", 10), f("b", 10), f("c", 10)];
        assert_eq!(files_to_prune(&files, Some(Path::new("c")), 15), vec![PathBuf::from("a"), PathBuf::from("b")]);
        assert_eq!(files_to_prune(&files, Some(Path::new("a")), 5), vec![PathBuf::from("b")]);
        assert!(files_to_prune(&files, None, 0).is_empty());
        assert_eq!(files_to_prune(&files, Some(Path::new("c")), 1000).len(), 2);
    }

    #[test]
    fn clearing_the_history_only_touches_capture_files() {
        let d = tmp("clear");
        std::fs::write(d.join("capture-20260101-000000.pcap"), b"x").unwrap();
        std::fs::write(d.join("capture-20260102-000000.pcap"), b"y").unwrap();
        std::fs::write(d.join("limit-mb"), b"64").unwrap();
        assert_eq!(clear_history(&d, true).unwrap(), 1);
        assert!(d.join("capture-20260102-000000.pcap").exists());
        assert_eq!(clear_history(&d, false).unwrap(), 1);
        assert!(d.join("limit-mb").exists());
    }

    #[test]
    fn dates_of_a_file_are_readable() {
        let f = CaptureFile { path: PathBuf::from("/x/capture-20261105-081502.pcap"), bytes: 1, modified: std::time::UNIX_EPOCH };
        assert_eq!(f.started_label(), "05/11/2026 08:15:02");
    }

    #[test]
    fn the_program_is_replaced_atomically() {
        let d = tmp("binary");
        let src = d.join("source");
        std::fs::write(&src, b"v1").unwrap();
        let dest = d.join("lib");
        install_binary(&src, &dest).unwrap();
        std::fs::write(&src, b"v2").unwrap();
        install_binary(&src, &dest).unwrap();
        assert_eq!(std::fs::read(dest.join("netbuster")).unwrap(), b"v2");
        let mode = std::fs::metadata(dest.join("netbuster")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
        assert!(!dest.join("netbuster.new").exists());
    }
}
