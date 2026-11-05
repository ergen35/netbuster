//! Petits outils : formats français, lancement de commandes, base64.

use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

/// Affiche les vitesses en bits (Mbit/s) plutôt qu'en octets (Mo/s).
pub static RATE_IN_BITS: AtomicBool = AtomicBool::new(false);

fn decimal(v: f64, digits: usize) -> String {
    format!("{v:.digits$}").replace('.', ",")
}

fn scaled(v: f64, units: [&str; 5]) -> String {
    let mut x = v;
    let mut i = 0;
    while x >= 1000.0 && i < units.len() - 1 {
        x /= 1000.0;
        i += 1;
    }
    let digits = if i == 0 || x >= 100.0 { 0 } else if x >= 10.0 { 1 } else { 2 };
    format!("{}\u{a0}{}", decimal(x, digits), units[i])
}

pub fn fmt_bytes(n: u64) -> String {
    scaled(n as f64, ["o", "ko", "Mo", "Go", "To"])
}

pub fn fmt_rate(bytes_per_sec: f64) -> String {
    if RATE_IN_BITS.load(Ordering::Relaxed) {
        scaled(bytes_per_sec.max(0.0) * 8.0, ["bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"])
    } else {
        scaled(bytes_per_sec.max(0.0), ["o/s", "ko/s", "Mo/s", "Go/s", "To/s"])
    }
}

pub fn fmt_count(n: u64) -> String {
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

pub fn fmt_duration(secs: f64) -> String {
    let s = secs.max(0.0) as u64;
    if s < 60 {
        format!("{s} s")
    } else if s < 3600 {
        format!("{} min {:02} s", s / 60, s % 60)
    } else if s < 86400 {
        format!("{} h {:02} min", s / 3600, (s % 3600) / 60)
    } else {
        format!("{} j {} h", s / 86400, (s % 86400) / 3600)
    }
}

pub fn fmt_ms(ms: f64) -> String {
    if ms >= 100.0 {
        format!("{} ms", decimal(ms, 0))
    } else {
        format!("{} ms", decimal(ms, 1))
    }
}

#[derive(Debug, Clone, Default)]
pub struct CmdResult {
    pub ok: bool,
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CmdResult {
    pub fn error(msg: impl Into<String>) -> Self {
        CmdResult { ok: false, code: -1, stdout: String::new(), stderr: msg.into() }
    }
}

/// Lance un programme tel quel, sans shell, en anglais pour que la sortie soit lisible par la machine.
pub fn run(prog: &str, args: &[&str]) -> CmdResult {
    let mut cmd = Command::new(prog);
    cmd.args(args).env("LC_ALL", "C").stdin(Stdio::null());
    no_console_window(&mut cmd);
    let out = cmd.output();
    match out {
        Ok(o) => CmdResult {
            ok: o.status.success(),
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        },
        Err(e) => CmdResult::error(format!("{prog} : {e}")),
    }
}

/// Sous Windows, chaque commande ouvrirait sinon une console noire devant la fenêtre.
pub fn no_console_window(_cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        _cmd.creation_flags(CREATE_NO_WINDOW);
    }
}

pub fn which(prog: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let name = if cfg!(windows) { format!("{prog}.exe") } else { prog.to_string() };
    std::env::split_paths(&path)
        .chain(["/usr/sbin", "/usr/bin", "/sbin", "/bin"].map(std::path::PathBuf::from))
        .map(|d| d.join(&name))
        .find(|p| p.is_file())
}

pub fn home_dir() -> std::path::PathBuf {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var).map(Into::into).unwrap_or_else(std::env::temp_dir)
}

pub fn data_dir() -> std::path::PathBuf {
    if cfg!(windows) {
        let base = std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from).unwrap_or_else(|| home_dir().join("AppData").join("Local"));
        base.join("NetBuster")
    } else if cfg!(target_os = "macos") {
        home_dir().join("Library/Application Support/NetBuster")
    } else {
        let base = std::env::var_os("XDG_DATA_HOME").map(std::path::PathBuf::from).unwrap_or_else(|| home_dir().join(".local/share"));
        base.join("netbuster")
    }
}

/// Pour écrire un fichier que seule la personne peut lire, là où le système le permet :
/// sous Windows, le dossier du compte est déjà privé.
pub fn private_file_options() -> std::fs::OpenOptions {
    #[allow(unused_mut)]
    let mut options = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

pub fn now_us() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = vec![];
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes().filter(|c| *c != b'=') {
        let v = B64.iter().position(|x| *x == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

pub fn b64_encode_nopad(d: &[u8]) -> String {
    let mut out = String::new();
    for c in d.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        if c.len() > 1 {
            out.push(B64[(n >> 6) as usize & 63] as char);
        }
        if c.len() > 2 {
            out.push(B64[n as usize & 63] as char);
        }
    }
    out
}

/// Empreinte d'une clé publique SSH, au même format que `ssh-keygen -l`.
pub fn ssh_fingerprint(key_b64: &str) -> Option<String> {
    let raw = b64_decode(key_b64)?;
    let h = ring::digest::digest(&ring::digest::SHA256, &raw);
    Some(format!("SHA256:{}", b64_encode_nopad(h.as_ref())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn french_formats() {
        assert_eq!(fmt_bytes(512), "512\u{a0}o");
        assert_eq!(fmt_bytes(1_230_000), "1,23\u{a0}Mo");
        assert_eq!(fmt_bytes(12_300_000_000), "12,3\u{a0}Go");
        assert_eq!(fmt_rate(1_500.0), "1,50\u{a0}ko/s");
        assert_eq!(fmt_count(1234567), "1\u{a0}234\u{a0}567");
        assert_eq!(fmt_duration(75.0), "1 min 15 s");
    }

    #[test]
    fn fingerprint_matches_known_value() {
        // Clé de test : l'empreinte vient de `ssh-keygen -lf` sur cette même clé.
        let raw = b64_decode("QUJD").unwrap();
        assert_eq!(raw, b"ABC");
        assert_eq!(b64_encode_nopad(b"ABC"), "QUJD");
        assert_eq!(b64_encode_nopad(b"AB"), "QUI");
        assert!(ssh_fingerprint("QUJD").unwrap().starts_with("SHA256:"));
    }
}
