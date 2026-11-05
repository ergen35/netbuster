//! Déchiffrement TLS à partir d'un fichier de clés (`SSLKEYLOGFILE`), pour le trafic de ses propres
//! applications. Prend en charge TLS 1.3 et TLS 1.2 avec AES-GCM ou ChaCha20-Poly1305.

use crate::packet::{parse_client_hello, parse_server_hello};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::{hkdf, hmac};
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

#[derive(Default, Clone, Debug)]
pub struct Secrets {
    pub master: Option<Vec<u8>>,
    pub client_hs: Option<Vec<u8>>,
    pub server_hs: Option<Vec<u8>>,
    pub client_app: Option<Vec<u8>>,
    pub server_app: Option<Vec<u8>>,
}

#[derive(Default)]
pub struct KeyLog {
    pub path: Option<PathBuf>,
    pos: u64,
    partial: String,
    pub keys: HashMap<[u8; 32], Secrets>,
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

impl KeyLog {
    pub fn add_line(&mut self, line: &str) {
        let mut it = line.split_whitespace();
        let (Some(label), Some(cr), Some(secret)) = (it.next(), it.next(), it.next()) else { return };
        let (Some(cr), Some(secret)) = (unhex(cr), unhex(secret)) else { return };
        let Ok(cr): Result<[u8; 32], _> = cr.try_into() else { return };
        let e = self.keys.entry(cr).or_default();
        match label {
            "CLIENT_RANDOM" => e.master = Some(secret),
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => e.client_hs = Some(secret),
            "SERVER_HANDSHAKE_TRAFFIC_SECRET" => e.server_hs = Some(secret),
            "CLIENT_TRAFFIC_SECRET_0" => e.client_app = Some(secret),
            "SERVER_TRAFFIC_SECRET_0" => e.server_app = Some(secret),
            _ => {}
        }
    }

    /// Lit les lignes ajoutées depuis la dernière fois.
    pub fn poll(&mut self) {
        let Some(path) = &self.path else { return };
        let Ok(mut f) = std::fs::File::open(path) else { return };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        if len < self.pos {
            self.pos = 0;
        }
        if len == self.pos || f.seek(SeekFrom::Start(self.pos)).is_err() {
            return;
        }
        let mut s = String::new();
        if f.read_to_string(&mut s).is_err() {
            return;
        }
        self.pos = len;
        let text = std::mem::take(&mut self.partial) + &s;
        let complete = text.ends_with('\n');
        let mut lines: Vec<&str> = text.lines().collect();
        if !complete {
            self.partial = lines.pop().unwrap_or("").to_string();
        }
        for l in lines {
            self.add_line(l);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Algo {
    Aes128,
    Aes256,
    Chacha,
}

struct Suite {
    algo: Algo,
    sha384: bool,
}

fn suite(c: u16) -> Option<Suite> {
    Some(match c {
        0x1301 | 0xc02f | 0xc02b | 0x009c => Suite { algo: Algo::Aes128, sha384: false },
        0x1302 | 0xc030 | 0xc02c | 0x009d => Suite { algo: Algo::Aes256, sha384: true },
        0x1303 | 0xcca8 | 0xcca9 => Suite { algo: Algo::Chacha, sha384: false },
        _ => return None,
    })
}

fn make_key(a: Algo, k: &[u8]) -> Option<LessSafeKey> {
    let alg = match a {
        Algo::Aes128 => &aead::AES_128_GCM,
        Algo::Aes256 => &aead::AES_256_GCM,
        Algo::Chacha => &aead::CHACHA20_POLY1305,
    };
    Some(LessSafeKey::new(UnboundKey::new(alg, k).ok()?))
}

struct Len(usize);
impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf_label(secret: &[u8], label: &str, len: usize, sha384: bool) -> Option<Vec<u8>> {
    let alg = if sha384 { hkdf::HKDF_SHA384 } else { hkdf::HKDF_SHA256 };
    let prk = hkdf::Prk::new_less_safe(alg, secret);
    let full = format!("tls13 {label}");
    let mut info = vec![];
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    let parts = [&info[..]];
    let okm = prk.expand(&parts, Len(len)).ok()?;
    let mut out = vec![0u8; len];
    okm.fill(&mut out).ok()?;
    Some(out)
}

fn prf12(secret: &[u8], label: &[u8], seed: &[u8], len: usize, sha384: bool) -> Vec<u8> {
    let alg = if sha384 { hmac::HMAC_SHA384 } else { hmac::HMAC_SHA256 };
    let key = hmac::Key::new(alg, secret);
    let mut full_seed = label.to_vec();
    full_seed.extend_from_slice(seed);
    let mut out = Vec::with_capacity(len + 48);
    let mut a = hmac::sign(&key, &full_seed).as_ref().to_vec();
    while out.len() < len {
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(&a);
        ctx.update(&full_seed);
        out.extend_from_slice(ctx.sign().as_ref());
        a = hmac::sign(&key, &a).as_ref().to_vec();
    }
    out.truncate(len);
    out
}

struct DirKeys {
    key: LessSafeKey,
    iv: Vec<u8>,
    seq: u64,
}

fn keys13(secret: &[u8], s: &Suite) -> Option<DirKeys> {
    let klen = if s.algo == Algo::Aes128 { 16 } else { 32 };
    Some(DirKeys {
        key: make_key(s.algo, &hkdf_label(secret, "key", klen, s.sha384)?)?,
        iv: hkdf_label(secret, "iv", 12, s.sha384)?,
        seq: 0,
    })
}

#[derive(PartialEq, Clone, Copy, Debug)]
enum Stage13 {
    Handshake,
    App,
}

#[derive(Default)]
struct DirState {
    buf: Vec<u8>,
    pending: VecDeque<(u8, u16, Vec<u8>)>, // type, version, contenu
    pending_bytes: usize,
    ccs_seen: bool,
    keys: Option<DirKeys>,
    stage: Option<Stage13>,
    secret: Vec<u8>,
    bad: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Plain {
    /// 0 : du client vers le serveur, 1 : du serveur vers le client.
    pub dir: u8,
    pub data: Vec<u8>,
}

#[derive(Default)]
pub struct TlsSession {
    client_random: Option<[u8; 32]>,
    server_random: Option<[u8; 32]>,
    cipher: u16,
    tls13: bool,
    dirs: [DirState; 2],
    pub decrypted_bytes: u64,
    pub failures: u32,
    pub version: Option<&'static str>,
}

const MAX_PENDING: usize = 4 * 1024 * 1024;
/// Après tant d'échecs d'affilée dans un sens, on considère que le flux est illisible.
const MAX_BAD: u32 = 8;

impl TlsSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_unsupported_cipher(&self) -> bool {
        self.server_random.is_some() && suite(self.cipher).is_none()
    }

    pub fn has_keys(&self, keys: &KeyLog) -> bool {
        self.client_random.is_some_and(|c| keys.keys.contains_key(&c))
    }

    /// Ajoute des octets du flux TCP, dans l'ordre. Rend ce qui peut déjà être lu.
    pub fn feed(&mut self, dir: u8, data: &[u8], keys: &KeyLog) -> Vec<Plain> {
        let d = dir as usize & 1;
        self.dirs[d].buf.extend_from_slice(data);
        loop {
            let buf = &self.dirs[d].buf;
            if buf.len() < 5 {
                break;
            }
            let ctype = buf[0];
            let version = u16::from_be_bytes([buf[1], buf[2]]);
            let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            if !(20..=24).contains(&ctype) || buf[1] != 3 || len > 18432 {
                // Flux qui n'est pas (ou plus) aligné sur des enregistrements TLS.
                self.dirs[d].buf.clear();
                self.failures += 1;
                break;
            }
            if buf.len() < 5 + len {
                break;
            }
            let body = buf[5..5 + len].to_vec();
            self.dirs[d].buf.drain(..5 + len);
            self.on_record(d, ctype, version, body);
        }
        self.drain(keys)
    }

    fn on_record(&mut self, d: usize, ctype: u8, version: u16, body: Vec<u8>) {
        match ctype {
            20 => self.dirs[d].ccs_seen = true,
            22 if !(self.dirs[d].ccs_seen && !self.tls13) && self.dirs[d].stage.is_none() => {
                self.on_clear_handshake(&body);
            }
            _ => {
                let enc = ctype == 23 || (self.dirs[d].ccs_seen && !self.tls13);
                if enc && self.dirs[d].pending_bytes + body.len() <= MAX_PENDING {
                    self.dirs[d].pending_bytes += body.len();
                    self.dirs[d].pending.push_back((ctype, version, body));
                }
            }
        }
    }

    fn on_clear_handshake(&mut self, body: &[u8]) {
        if let Some(h) = parse_client_hello(body) {
            self.client_random = Some(h.random);
        } else if let Some(h) = parse_server_hello(body) {
            self.server_random = Some(h.random);
            self.cipher = h.cipher;
            self.tls13 = h.tls13;
            self.version = Some(h.version_label());
        }
    }

    /// À rappeler quand de nouvelles clés arrivent dans le fichier.
    pub fn drain(&mut self, keys: &KeyLog) -> Vec<Plain> {
        let mut out = vec![];
        let (Some(cr), Some(sr)) = (self.client_random, self.server_random) else { return out };
        let Some(s) = suite(self.cipher) else { return out };
        let Some(secrets) = keys.keys.get(&cr) else { return out };
        for d in 0..2 {
            if self.tls13 {
                self.drain13(d, &s, secrets, &mut out);
            } else {
                self.drain12(d, &s, secrets, &cr, &sr, &mut out);
            }
        }
        out
    }

    fn drain13(&mut self, d: usize, s: &Suite, secrets: &Secrets, out: &mut Vec<Plain>) {
        let (hs, app) = if d == 0 {
            (&secrets.client_hs, &secrets.client_app)
        } else {
            (&secrets.server_hs, &secrets.server_app)
        };
        let state = &mut self.dirs[d];
        while let Some((_, version, body)) = state.pending.front().cloned() {
            if state.bad >= MAX_BAD {
                state.pending.clear();
                state.pending_bytes = 0;
                break;
            }
            if state.stage.is_none() {
                let Some(secret) = hs.as_ref().or(app.as_ref()) else { break };
                let Some(k) = keys13(secret, s) else { break };
                state.stage = Some(if hs.is_some() { Stage13::Handshake } else { Stage13::App });
                state.secret = secret.clone();
                state.keys = Some(k);
            }
            let mut plain = state.keys.as_mut().and_then(|k| open13(k, version, &body));
            if plain.is_none() && state.stage == Some(Stage13::Handshake) {
                // Fin de la négociation : on passe aux clés de données.
                let Some(secret) = app.as_ref() else { break };
                if let Some(mut k) = keys13(secret, s) {
                    plain = open13(&mut k, version, &body);
                    if plain.is_some() {
                        state.stage = Some(Stage13::App);
                        state.secret = secret.clone();
                        state.keys = Some(k);
                    }
                }
            } else if plain.is_none() {
                // Renouvellement de clé en cours de connexion.
                if let Some(next) = hkdf_label(&state.secret, "traffic upd", if s.sha384 { 48 } else { 32 }, s.sha384) {
                    if let Some(mut k) = keys13(&next, s) {
                        plain = open13(&mut k, version, &body);
                        if plain.is_some() {
                            state.secret = next;
                            state.keys = Some(k);
                        }
                    }
                }
            }
            state.pending_bytes -= body.len();
            state.pending.pop_front();
            match plain {
                Some((inner, data)) => {
                    state.bad = 0;
                    if inner == 23 && !data.is_empty() {
                        self.decrypted_bytes += data.len() as u64;
                        out.push(Plain { dir: d as u8, data });
                    }
                }
                None => {
                    state.bad += 1;
                    self.failures += 1;
                }
            }
        }
    }

    fn drain12(&mut self, d: usize, s: &Suite, secrets: &Secrets, cr: &[u8; 32], sr: &[u8; 32], out: &mut Vec<Plain>) {
        let Some(master) = &secrets.master else { return };
        if self.dirs[d].keys.is_none() {
            let klen = if s.algo == Algo::Aes128 { 16 } else { 32 };
            let ivlen = if s.algo == Algo::Chacha { 12 } else { 4 };
            let mut seed = sr.to_vec();
            seed.extend_from_slice(cr);
            let block = prf12(master, b"key expansion", &seed, 2 * klen + 2 * ivlen, s.sha384);
            let key = &block[d * klen..(d + 1) * klen];
            let iv = block[2 * klen + d * ivlen..2 * klen + (d + 1) * ivlen].to_vec();
            let Some(key) = make_key(s.algo, key) else { return };
            self.dirs[d].keys = Some(DirKeys { key, iv, seq: 0 });
        }
        let state = &mut self.dirs[d];
        while let Some((ctype, version, body)) = state.pending.pop_front() {
            state.pending_bytes -= body.len();
            if state.bad >= MAX_BAD {
                state.pending.clear();
                state.pending_bytes = 0;
                break;
            }
            let k = state.keys.as_mut().unwrap();
            match open12(k, s.algo, ctype, version, &body) {
                Some(data) => {
                    state.bad = 0;
                    if ctype == 23 && !data.is_empty() {
                        self.decrypted_bytes += data.len() as u64;
                        out.push(Plain { dir: d as u8, data });
                    }
                }
                None => {
                    state.bad += 1;
                    self.failures += 1;
                }
            }
        }
    }
}

fn nonce_from(iv: &[u8], seq: u64) -> Option<Nonce> {
    let mut n = [0u8; 12];
    n.copy_from_slice(iv.get(..12)?);
    for (i, b) in seq.to_be_bytes().iter().enumerate() {
        n[4 + i] ^= b;
    }
    Some(Nonce::assume_unique_for_key(n))
}

fn open13(k: &mut DirKeys, version: u16, body: &[u8]) -> Option<(u8, Vec<u8>)> {
    let nonce = nonce_from(&k.iv, k.seq)?;
    let mut aad = [23u8, 0, 0, 0, 0];
    aad[1..3].copy_from_slice(&version.to_be_bytes());
    aad[3..5].copy_from_slice(&(body.len() as u16).to_be_bytes());
    let mut buf = body.to_vec();
    let plain = k.key.open_in_place(nonce, Aad::from(aad), &mut buf).ok()?;
    k.seq += 1;
    // Contenu réel : le dernier octet non nul donne le type, le reste est du remplissage.
    let end = plain.iter().rposition(|b| *b != 0)?;
    let inner = plain[end];
    Some((inner, plain[..end].to_vec()))
}

fn open12(k: &mut DirKeys, algo: Algo, ctype: u8, version: u16, body: &[u8]) -> Option<Vec<u8>> {
    let (nonce, ct): (Nonce, &[u8]) = if algo == Algo::Chacha {
        (nonce_from(&k.iv, k.seq)?, body)
    } else {
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(k.iv.get(..4)?);
        n[4..].copy_from_slice(body.get(..8)?);
        (Nonce::assume_unique_for_key(n), &body[8..])
    };
    let plain_len = ct.len().checked_sub(16)?;
    let mut aad = [0u8; 13];
    aad[..8].copy_from_slice(&k.seq.to_be_bytes());
    aad[8] = ctype;
    aad[9..11].copy_from_slice(&version.to_be_bytes());
    aad[11..13].copy_from_slice(&(plain_len as u16).to_be_bytes());
    let mut buf = ct.to_vec();
    let plain = k.key.open_in_place(nonce, Aad::from(aad), &mut buf).ok()?.to_vec();
    k.seq += 1;
    Some(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Écrites par `tests/make_tls_fixture.py` : vraies sessions Python/OpenSSL enregistrées par un relais.
    fn fixtures() -> Vec<serde_json::Value> {
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/tls_fixture.json");
        let t = std::fs::read_to_string(p).expect("tests/make_tls_fixture.py doit avoir été lancé");
        serde_json::from_str(&t).unwrap()
    }

    fn replay(fx: &serde_json::Value, keys_first: bool) -> (Vec<u8>, Vec<u8>, TlsSession) {
        let mut log = KeyLog::default();
        if keys_first {
            for l in fx["keylog"].as_str().unwrap().lines() {
                log.add_line(l);
            }
        }
        let mut s = TlsSession::new();
        let (mut to_server, mut to_client) = (vec![], vec![]);
        let mut sink = |plain: Vec<Plain>| {
            for p in plain {
                if p.dir == 0 {
                    to_server.extend_from_slice(&p.data);
                } else {
                    to_client.extend_from_slice(&p.data);
                }
            }
        };
        for e in fx["events"].as_array().unwrap() {
            let dir = e[0].as_u64().unwrap() as u8;
            let data = unhex(e[1].as_str().unwrap()).unwrap();
            sink(s.feed(dir, &data, &log));
        }
        if !keys_first {
            for l in fx["keylog"].as_str().unwrap().lines() {
                log.add_line(l);
            }
            sink(s.drain(&log));
        }
        (to_server, to_client, s)
    }

    #[test]
    fn decrypts_real_sessions_with_keys() {
        let all = fixtures();
        assert!(all.len() >= 4);
        for fx in &all {
            let name = fx["name"].as_str().unwrap();
            let (to_server, to_client, s) = replay(fx, true);
            assert_eq!(String::from_utf8_lossy(&to_server), fx["client_says"].as_str().unwrap(), "{name}");
            assert_eq!(String::from_utf8_lossy(&to_client), fx["server_says"].as_str().unwrap(), "{name}");
            assert_eq!(s.failures, 0, "{name}");
        }
    }

    #[test]
    fn keys_may_arrive_after_the_packets() {
        for fx in &fixtures() {
            let (to_server, to_client, _) = replay(fx, false);
            assert_eq!(String::from_utf8_lossy(&to_server), fx["client_says"].as_str().unwrap());
            assert_eq!(String::from_utf8_lossy(&to_client), fx["server_says"].as_str().unwrap());
        }
    }

    #[test]
    fn without_keys_nothing_is_revealed() {
        for fx in &fixtures() {
            let mut s = TlsSession::new();
            let log = KeyLog::default();
            for e in fx["events"].as_array().unwrap() {
                let plain = s.feed(e[0].as_u64().unwrap() as u8, &unhex(e[1].as_str().unwrap()).unwrap(), &log);
                assert!(plain.is_empty());
            }
        }
    }

    #[test]
    fn wrong_keys_fail_without_panic() {
        let fx = &fixtures()[0];
        let mut log = KeyLog::default();
        for l in fx["keylog"].as_str().unwrap().lines() {
            // Même identifiant de session, secret faux.
            let mut parts: Vec<String> = l.split_whitespace().map(String::from).collect();
            if parts.len() == 3 {
                parts[2] = "ab".repeat(parts[2].len() / 2);
                log.add_line(&parts.join(" "));
            }
        }
        let mut s = TlsSession::new();
        let mut got = vec![];
        for e in fx["events"].as_array().unwrap() {
            got.extend(s.feed(e[0].as_u64().unwrap() as u8, &unhex(e[1].as_str().unwrap()).unwrap(), &log));
        }
        assert!(got.is_empty());
        assert!(s.failures > 0);
    }
}
