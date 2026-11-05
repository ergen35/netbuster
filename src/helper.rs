//! Assistant administrateur : lancé via `pkexec netbuster --helper`, seul morceau qui tourne en root.
//!
//! Il n'exécute que des programmes d'une liste fixe, sans shell. Il n'écrit que le réglage SSH et,
//! sur demande, le service de capture avec sa copie du programme.
//! Il s'arrête dès que la fenêtre se ferme (fin de son entrée standard).
//!
//! `--mock <dossier>` (tests, refusé en root) remplace les programmes par ceux du dossier et lit
//! les paquets depuis `<dossier>/frames.bin`, pour tout vérifier sans toucher au système.

use crate::manage::SSHD_DROPIN;
use crate::proto::*;
pub use crate::util::now_us;
use std::io::{BufRead, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const ALLOWED_PROGRAMS: &[&str] = &[
    "iptables", "ip6tables", "nft", "ufw", "ip", "ss", "systemctl", "kill", "nmcli", "sshd", "journalctl", "apt-get",
    "resolvectl",
];
const SYSTEM_DIRS: &[&str] = &["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

type Out = Arc<Mutex<BufWriter<std::io::Stdout>>>;

fn send(out: &Out, tag: u8, payload: &[u8]) {
    if let Ok(mut w) = out.lock() {
        if write_frame(&mut *w, tag, payload).is_err() {
            std::process::exit(0);
        }
        if tag != TAG_PACKET && w.flush().is_err() {
            std::process::exit(0);
        }
    }
}

fn send_event(out: &Out, ev: &Event) {
    if let Ok(j) = serde_json::to_vec(ev) {
        send(out, TAG_EVENT, &j);
    }
}

fn send_reply(out: &Out, r: &Reply) {
    if let Ok(j) = serde_json::to_vec(r) {
        send(out, TAG_REPLY, &j);
    }
}

pub fn resolve_program(name: &str, mock: Option<&Path>) -> Option<PathBuf> {
    if !ALLOWED_PROGRAMS.contains(&name) {
        return None;
    }
    if let Some(dir) = mock {
        let p = dir.join(name);
        return p.exists().then_some(p);
    }
    SYSTEM_DIRS.iter().map(|d| Path::new(d).join(name)).find(|p| p.exists())
}

pub fn run_helper(mock: Option<PathBuf>) -> i32 {
    let uid = unsafe { libc::geteuid() };
    if mock.is_some() && uid == 0 {
        eprintln!("le mode test est refusé en administrateur");
        return 2;
    }
    if mock.is_none() {
        // Un assistant root ne doit jamais survivre à la fenêtre qui l'a lancé.
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
    }
    let out: Out = Arc::new(Mutex::new(BufWriter::with_capacity(256 * 1024, std::io::stdout())));
    send_event(&out, &Event::Hello { uid });

    let capture_stop: Arc<Mutex<Option<Arc<AtomicBool>>>> = Arc::new(Mutex::new(None));
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let Ok(cmd) = serde_json::from_str::<Cmd>(&line) else { continue };
        match cmd {
            Cmd::Exec { id, prog, args } => {
                let (out2, mock2) = (out.clone(), mock.clone());
                std::thread::spawn(move || {
                    send_reply(&out2, &exec(id, &prog, &args, mock2.as_deref()));
                });
            }
            Cmd::WriteFile { id, path, content } => {
                send_reply(&out, &write_file(id, &path, &content, mock.as_deref()));
            }
            Cmd::StartCapture { snap } => {
                let mut guard = capture_stop.lock().unwrap();
                if guard.is_none() {
                    let stop = Arc::new(AtomicBool::new(false));
                    *guard = Some(stop.clone());
                    let (out2, mock2) = (out.clone(), mock.clone());
                    std::thread::spawn(move || {
                        let mut since_flush = 0u32;
                        let mut on_event = |ev: CaptureEvent| match ev {
                            CaptureEvent::Started => send_event(&out2, &Event::CaptureStarted),
                            CaptureEvent::Frame(f) => {
                                let mut encoded = Vec::with_capacity(f.data.len() + 32);
                                f.encode(&mut encoded);
                                send(&out2, TAG_PACKET, &encoded);
                                since_flush += 1;
                                if since_flush >= 32 {
                                    since_flush = 0;
                                    if let Ok(mut w) = out2.lock() {
                                        let _ = w.flush();
                                    }
                                }
                            }
                            CaptureEvent::Idle => {
                                since_flush = 0;
                                if let Ok(mut w) = out2.lock() {
                                    let _ = w.flush();
                                }
                            }
                            CaptureEvent::Stats { packets, drops } => send_event(&out2, &Event::CaptureStats { packets, drops }),
                        };
                        let res = match &mock2 {
                            Some(dir) => replay_frames(&dir.join("frames.bin"), &stop, &mut on_event),
                            None => kernel_capture(snap, &stop, &mut on_event),
                        };
                        if let Err(e) = res {
                            send_event(&out2, &Event::CaptureError(e));
                        }
                        if let Ok(mut w) = out2.lock() {
                            let _ = w.flush();
                        }
                        send_event(&out2, &Event::CaptureStopped);
                    });
                }
            }
            Cmd::StopCapture => {
                if let Some(stop) = capture_stop.lock().unwrap().take() {
                    stop.store(true, Ordering::SeqCst);
                }
            }
            Cmd::ServiceInstall { id } => {
                let (out2, mock2) = (out.clone(), mock.clone());
                std::thread::spawn(move || send_reply(&out2, &service_install(id, mock2.as_deref())));
            }
            Cmd::ServiceRemove { id } => {
                let (out2, mock2) = (out.clone(), mock.clone());
                std::thread::spawn(move || send_reply(&out2, &service_remove(id, mock2.as_deref())));
            }
        }
    }
    0
}

fn exec(id: u64, prog: &str, args: &[String], mock: Option<&Path>) -> Reply {
    let Some(path) = resolve_program(prog, mock) else {
        return Reply { id, ok: false, code: 127, stderr: format!("{prog} : programme non disponible"), ..Default::default() };
    };
    let output = Command::new(path)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .stdin(Stdio::null())
        .output();
    match output {
        Ok(o) => Reply {
            id,
            ok: o.status.success(),
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        },
        Err(e) => Reply { id, ok: false, code: -1, stderr: e.to_string(), ..Default::default() },
    }
}

fn write_file(id: u64, path: &str, content: &str, mock: Option<&Path>) -> Reply {
    if path != SSHD_DROPIN {
        return Reply { id, ok: false, code: 1, stderr: format!("écriture refusée : {path}"), ..Default::default() };
    }
    let real: PathBuf = match mock {
        Some(dir) => dir.join("00-netbuster.conf"),
        None => PathBuf::from(path),
    };
    if let Some(parent) = real.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::write(&real, content) {
        Ok(()) => Reply { id, ok: true, ..Default::default() },
        Err(e) => Reply { id, ok: false, code: 1, stderr: e.to_string(), ..Default::default() },
    }
}

#[repr(C)]
struct TpacketStats {
    tp_packets: u32,
    tp_drops: u32,
}

const ETH_P_ALL: u16 = 0x0003;
const SOL_PACKET: i32 = 263;
const PACKET_STATISTICS: i32 = 6;

/// Ce que la lecture des paquets signale à celui qui l'a lancée.
pub enum CaptureEvent<'a> {
    Started,
    Frame(&'a RawFrame),
    /// Rien à lire pour l'instant : le bon moment pour vider les tampons.
    Idle,
    Stats { packets: u64, drops: u64 },
}

/// Lit tous les paquets de toutes les interfaces, y compris celles qui apparaîtront plus tard.
pub fn kernel_capture(snap: u32, stop: &AtomicBool, on: &mut dyn FnMut(CaptureEvent)) -> Result<(), String> {
    // SOCK_DGRAM : le noyau retire l'en-tête de liaison, ce qui traite pareil Wi-Fi, Ethernet et tunnels.
    let fd = unsafe {
        libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, ETH_P_ALL.to_be() as i32)
    };
    if fd < 0 {
        return Err(format!("capture impossible : {}", std::io::Error::last_os_error()));
    }
    struct Guard(i32);
    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }
    let _guard = Guard(fd);

    unsafe {
        let size: libc::c_int = 32 * 1024 * 1024;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            &size as *const _ as *const libc::c_void,
            std::mem::size_of_val(&size) as u32,
        );
        let tv = libc::timeval { tv_sec: 0, tv_usec: 100_000 };
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of_val(&tv) as u32,
        );
    }

    on(CaptureEvent::Started);
    let mut buf = vec![0u8; 262_144];
    let mut last_stats = Instant::now();
    let (mut total_packets, mut total_drops) = (0u64, 0u64);

    while !stop.load(Ordering::SeqCst) {
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut addr_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        // MSG_TRUNC : le retour donne la vraie longueur, même si le paquet dépasse le tampon.
        let n = unsafe {
            libc::recvfrom(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_TRUNC,
                &mut addr as *mut _ as *mut libc::sockaddr,
                &mut addr_len,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) => on(CaptureEvent::Idle),
                // Une interface qui disparaît ne doit pas arrêter la capture des autres.
                Some(libc::ENETDOWN) => {}
                _ => return Err(format!("lecture interrompue : {err}")),
            }
        } else {
            let orig = n as usize;
            let keep = orig.min(buf.len()).min(snap as usize);
            let frame = RawFrame {
                ts_us: now_us(),
                ifindex: addr.sll_ifindex as u32,
                pkttype: addr.sll_pkttype,
                proto: u16::from_be(addr.sll_protocol),
                orig_len: orig as u32,
                data: buf[..keep].to_vec(),
            };
            on(CaptureEvent::Frame(&frame));
        }
        if last_stats.elapsed() >= Duration::from_secs(1) {
            last_stats = Instant::now();
            let mut st = TpacketStats { tp_packets: 0, tp_drops: 0 };
            let mut len = std::mem::size_of::<TpacketStats>() as libc::socklen_t;
            let rc = unsafe {
                libc::getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &mut st as *mut _ as *mut libc::c_void, &mut len)
            };
            if rc == 0 {
                // Ces compteurs repartent de zéro à chaque lecture.
                total_packets += st.tp_packets as u64;
                total_drops += st.tp_drops as u64;
                on(CaptureEvent::Stats { packets: total_packets, drops: total_drops });
            }
        }
    }
    Ok(())
}

/// Rejoue des paquets depuis un fichier : `[len u32 LE][RawFrame encodée]…`
pub fn replay_frames(path: &Path, stop: &AtomicBool, on: &mut dyn FnMut(CaptureEvent)) -> Result<(), String> {
    let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    on(CaptureEvent::Started);
    let mut pos = 0;
    while pos + 4 <= data.len() && !stop.load(Ordering::SeqCst) {
        let len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let Some(mut frame) = data.get(pos..pos + len).and_then(RawFrame::decode) else { break };
        pos += len;
        frame.ts_us = now_us();
        on(CaptureEvent::Frame(&frame));
        on(CaptureEvent::Idle);
        std::thread::sleep(Duration::from_millis(2));
    }
    while !stop.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

// ---------- Installation du service de capture ----------

/// Le compte de la personne qui a validé son mot de passe, donné par pkexec.
fn requesting_user(mock: Option<&Path>) -> Result<String, String> {
    let uid = match mock {
        Some(_) => unsafe { libc::getuid() },
        None => std::env::var("PKEXEC_UID")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .ok_or("le compte qui fait la demande est inconnu (PKEXEC_UID absent)")?,
    };
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return Err(format!("le compte {uid} est inconnu"));
    }
    let name = unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) }.to_string_lossy().into_owned();
    if crate::service::valid_user_name(&name) {
        Ok(name)
    } else {
        Err(format!("nom de compte inattendu : {name}"))
    }
}

fn reply_err(id: u64, stderr: String) -> Reply {
    Reply { id, ok: false, code: 1, stderr, ..Default::default() }
}

/// Une copie de ce programme, à un endroit que seul l'administrateur peut modifier : sans cela,
/// n'importe quel logiciel du compte pourrait remplacer ce que le système lance à chaque démarrage.
fn service_install(id: u64, mock: Option<&Path>) -> Reply {
    use crate::service::{install_binary, unit_text, ServicePaths, INSTALL_DIR, UNIT_NAME};
    let user = match requesting_user(mock) {
        Ok(u) => u,
        Err(e) => return reply_err(id, e),
    };
    let paths = match mock {
        Some(dir) => ServicePaths::under(dir),
        None => ServicePaths::system(),
    };
    let install_dir = match mock {
        Some(dir) => dir.join("service/installed"),
        None => PathBuf::from(INSTALL_DIR),
    };
    if mock.is_none() {
        if let Err(e) = install_binary(Path::new("/proc/self/exe"), &install_dir) {
            return reply_err(id, format!("copie du programme impossible : {e}"));
        }
    }
    let exe = PathBuf::from(INSTALL_DIR).join("netbuster");
    if let Some(parent) = paths.unit.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let tmp = paths.unit.with_extension("tmp");
    let written = std::fs::write(&tmp, unit_text(&user, &exe.to_string_lossy()))
        .and_then(|_| std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o644)))
        .and_then(|_| std::fs::rename(&tmp, &paths.unit));
    if let Err(e) = written {
        return reply_err(id, format!("écriture du service impossible : {e}"));
    }
    let reload = exec(id, "systemctl", &["daemon-reload".to_string()], mock);
    if !reload.ok {
        return reload;
    }
    let enable = exec(id, "systemctl", &["enable".to_string(), "--now".to_string(), UNIT_NAME.to_string()], mock);
    if !enable.ok {
        // Rien ne doit rester à moitié installé.
        let _ = std::fs::remove_file(&paths.unit);
        let _ = exec(id, "systemctl", &["daemon-reload".to_string()], mock);
    }
    enable
}

fn service_remove(id: u64, mock: Option<&Path>) -> Reply {
    use crate::service::{ServicePaths, INSTALL_DIR, UNIT_NAME};
    let paths = match mock {
        Some(dir) => ServicePaths::under(dir),
        None => ServicePaths::system(),
    };
    let disable = exec(id, "systemctl", &["disable".to_string(), "--now".to_string(), UNIT_NAME.to_string()], mock);
    if !disable.ok && paths.unit.exists() && !disable.stderr.contains("not loaded") && !disable.stderr.contains("does not exist") {
        return disable;
    }
    if let Err(e) = std::fs::remove_file(&paths.unit) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return reply_err(id, format!("suppression du service impossible : {e}"));
        }
    }
    let reload = exec(id, "systemctl", &["daemon-reload".to_string()], mock);
    if mock.is_none() {
        // Seule la copie du programme part : l'historique reste, il appartient à la personne.
        if let Err(e) = std::fs::remove_dir_all(INSTALL_DIR) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return reply_err(id, format!("suppression de {INSTALL_DIR} impossible : {e}"));
            }
        }
    }
    Reply { id, ..reload }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_listed_programs_run() {
        assert!(resolve_program("sh", None).is_none());
        assert!(resolve_program("/bin/sh", None).is_none());
        assert!(resolve_program("../../bin/sh", None).is_none());
        assert!(resolve_program("bash", None).is_none());
    }

    #[test]
    fn only_the_ssh_dropin_can_be_written() {
        let r = write_file(1, "/etc/passwd", "x", None);
        assert!(!r.ok);
        let r = write_file(1, "/etc/ssh/sshd_config", "x", None);
        assert!(!r.ok);
    }
}
