//! Assistant administrateur : lancé via `pkexec netbuster --helper`, seul morceau qui tourne en root.
//!
//! Il n'exécute que des programmes d'une liste fixe, sans shell, et n'écrit qu'un seul fichier.
//! Il s'arrête dès que la fenêtre se ferme (fin de son entrée standard).
//!
//! `--mock <dossier>` (tests, refusé en root) remplace les programmes par ceux du dossier et lit
//! les paquets depuis `<dossier>/frames.bin`, pour tout vérifier sans toucher au système.

use crate::proto::*;
use std::io::{BufRead, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const ALLOWED_PROGRAMS: &[&str] = &[
    "iptables", "ip6tables", "nft", "ufw", "ip", "ss", "systemctl", "kill", "nmcli", "sshd", "journalctl", "apt-get",
    "resolvectl",
];
pub const SSHD_DROPIN: &str = "/etc/ssh/sshd_config.d/00-netbuster.conf";
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
                        let res = match &mock2 {
                            Some(dir) => mock_capture(&dir.join("frames.bin"), &stop, &out2),
                            None => capture_loop(snap, &stop, &out2),
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

fn now_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
}

#[repr(C)]
struct TpacketStats {
    tp_packets: u32,
    tp_drops: u32,
}

const ETH_P_ALL: u16 = 0x0003;
const SOL_PACKET: i32 = 263;
const PACKET_STATISTICS: i32 = 6;

fn capture_loop(snap: u32, stop: &AtomicBool, out: &Out) -> Result<(), String> {
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

    send_event(out, &Event::CaptureStarted);
    let mut buf = vec![0u8; 262_144];
    let mut encoded = Vec::with_capacity(70_000);
    let mut since_flush = 0u32;
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
                Some(libc::EAGAIN) | Some(libc::EINTR) => {
                    if let Ok(mut w) = out.lock() {
                        let _ = w.flush();
                    }
                    since_flush = 0;
                }
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
            encoded.clear();
            frame.encode(&mut encoded);
            send(out, TAG_PACKET, &encoded);
            since_flush += 1;
            if since_flush >= 32 {
                if let Ok(mut w) = out.lock() {
                    let _ = w.flush();
                }
                since_flush = 0;
            }
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
                send_event(out, &Event::CaptureStats { packets: total_packets, drops: total_drops });
            }
        }
    }
    Ok(())
}

/// Rejoue des paquets depuis un fichier : `[len u32 LE][RawFrame encodée]…`
fn mock_capture(path: &Path, stop: &AtomicBool, out: &Out) -> Result<(), String> {
    let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    send_event(out, &Event::CaptureStarted);
    let mut pos = 0;
    while pos + 4 <= data.len() && !stop.load(Ordering::SeqCst) {
        let len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let Some(mut frame) = data.get(pos..pos + len).and_then(RawFrame::decode) else { break };
        pos += len;
        frame.ts_us = now_us();
        let mut enc = Vec::new();
        frame.encode(&mut enc);
        send(out, TAG_PACKET, &enc);
        if let Ok(mut w) = out.lock() {
            let _ = w.flush();
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    while !stop.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
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
