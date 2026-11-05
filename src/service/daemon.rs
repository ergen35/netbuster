//! Le service lui-même : ce qui s'exécute à chaque démarrage du PC, sous Linux.

use super::*;
use crate::helper::{kernel_capture, now_us, replay_frames, CaptureEvent};
use std::io::{BufWriter, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Copie le programme en remplaçant atomiquement l'ancienne version, même si elle tourne.
pub fn install_binary(src: &Path, dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    let tmp = dir.join("netbuster.new");
    std::fs::copy(src, &tmp)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    std::fs::rename(tmp, dir.join("netbuster"))
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

    pub fn close(&mut self) {
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

