//! Traceroute en direct, à partir de `mtr --raw` (ou `traceroute` si mtr est absent).

use crate::util::which;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, ToSocketAddrs};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Default)]
pub struct Hop {
    pub ips: Vec<IpAddr>,
    pub sent: u32,
    pub recv: u32,
    pub last_ms: f32,
    pub best_ms: f32,
    pub worst_ms: f32,
    pub sum_ms: f64,
    pub history: Vec<f32>,
}

impl Hop {
    pub fn avg_ms(&self) -> f32 {
        if self.recv == 0 {
            0.0
        } else {
            (self.sum_ms / self.recv as f64) as f32
        }
    }
    pub fn loss_pct(&self) -> f32 {
        if self.sent == 0 {
            0.0
        } else {
            100.0 * (1.0 - (self.recv as f32 / self.sent as f32).min(1.0))
        }
    }
    pub fn jitter_ms(&self) -> f32 {
        if self.history.len() < 2 {
            return 0.0;
        }
        let d: f32 = self.history.windows(2).map(|w| (w[1] - w[0]).abs()).sum();
        d / (self.history.len() - 1) as f32
    }
    fn add_sample(&mut self, ms: f32) {
        self.recv += 1;
        self.last_ms = ms;
        self.best_ms = if self.recv == 1 { ms } else { self.best_ms.min(ms) };
        self.worst_ms = self.worst_ms.max(ms);
        self.sum_ms += ms as f64;
        self.history.push(ms);
        if self.history.len() > 120 {
            self.history.remove(0);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum TraceMode {
    #[default]
    Icmp,
    Udp,
    Tcp(u16),
}

#[derive(Debug, Default)]
pub struct TraceState {
    pub target: String,
    pub target_ip: Option<IpAddr>,
    pub iface: Option<String>,
    pub running: bool,
    pub error: Option<String>,
    pub hops: Vec<Hop>,
    pub source: &'static str,
    pub started: Option<std::time::Instant>,
}

impl TraceState {
    /// Étapes utiles : s'arrête à la destination, retire les étapes muettes de la fin.
    pub fn visible_hops(&self) -> &[Hop] {
        let mut end = self.hops.len();
        if let Some(t) = self.target_ip {
            if let Some(pos) = self.hops.iter().position(|h| h.ips.contains(&t)) {
                end = pos + 1;
            }
        }
        while end > 0 && self.hops[end - 1].ips.is_empty() {
            end -= 1;
        }
        // Une étape muette après la dernière réponse montre que le trajet continue.
        if end < self.hops.len() && !self.reached() {
            end += 1;
        }
        &self.hops[..end.min(self.hops.len())]
    }

    pub fn reached(&self) -> bool {
        self.target_ip.is_some_and(|t| self.hops.iter().any(|h| h.ips.contains(&t)))
    }

    fn hop_mut(&mut self, n: usize) -> Option<&mut Hop> {
        if n >= 64 {
            return None;
        }
        if self.hops.len() <= n {
            self.hops.resize_with(n + 1, Hop::default);
        }
        self.hops.get_mut(n)
    }

    /// Une ligne de `mtr --raw`.
    pub fn apply_mtr_line(&mut self, line: &str) {
        let mut it = line.split_whitespace();
        let (Some(kind), Some(n)) = (it.next(), it.next().and_then(|x| x.parse::<usize>().ok())) else { return };
        let Some(hop) = self.hop_mut(n) else { return };
        match kind {
            "x" => hop.sent += 1,
            "h" => {
                if let Some(ip) = it.next().and_then(|x| x.parse::<IpAddr>().ok()) {
                    if !hop.ips.contains(&ip) {
                        hop.ips.push(ip);
                    }
                }
            }
            "p" => {
                if let Some(us) = it.next().and_then(|x| x.parse::<f32>().ok()) {
                    hop.add_sample(us / 1000.0);
                }
            }
            _ => {}
        }
    }

    /// Une ligne de `traceroute -n` : ` 3  10.0.0.1  4.059 ms  3.1 ms * `
    pub fn apply_traceroute_line(&mut self, line: &str) {
        let toks: Vec<&str> = line.split_whitespace().collect();
        let Some(n) = toks.first().and_then(|t| t.parse::<usize>().ok()) else { return };
        if n == 0 {
            return;
        }
        let Some(hop) = self.hop_mut(n - 1) else { return };
        let mut i = 1;
        while i < toks.len() {
            let t = toks[i];
            if t == "*" {
                hop.sent += 1;
            } else if let Ok(ip) = t.parse::<IpAddr>() {
                if !hop.ips.contains(&ip) {
                    hop.ips.push(ip);
                }
            } else if let Ok(ms) = t.parse::<f32>() {
                hop.sent += 1;
                hop.add_sample(ms);
            }
            i += 1;
        }
    }
}

pub struct Tracer {
    pub state: Arc<Mutex<TraceState>>,
    child: Arc<Mutex<Option<Child>>>,
    run_id: Arc<Mutex<u64>>,
}

impl Default for Tracer {
    fn default() -> Self {
        Tracer { state: Default::default(), child: Default::default(), run_id: Default::default() }
    }
}

impl Tracer {
    pub fn stop(&self) {
        if let Some(mut c) = self.child.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        self.state.lock().unwrap().running = false;
    }

    pub fn start(&self, target: &str, iface: Option<String>, mode: TraceMode) {
        self.stop();
        let target = target.trim().to_string();
        let id = {
            let mut r = self.run_id.lock().unwrap();
            *r += 1;
            *r
        };
        {
            let mut st = self.state.lock().unwrap();
            *st = TraceState { target: target.clone(), iface: iface.clone(), running: true, started: Some(std::time::Instant::now()), ..Default::default() };
        }
        let (state, child_slot, run_id) = (self.state.clone(), self.child.clone(), self.run_id.clone());
        std::thread::spawn(move || {
            // Le nom est résolu ici : une résolution lente ne doit pas figer la fenêtre.
            let ip = target
                .parse::<IpAddr>()
                .ok()
                .or_else(|| (target.as_str(), 0).to_socket_addrs().ok().and_then(|mut a| a.next()).map(|a| a.ip()));
            let Some(ip) = ip else {
                let mut st = state.lock().unwrap();
                st.running = false;
                st.error = Some(format!("Adresse introuvable : « {target} »."));
                return;
            };
            state.lock().unwrap().target_ip = Some(ip);

            let use_mtr = which("mtr").is_some();
            let mut cmd = if use_mtr {
                let mut c = Command::new("mtr");
                c.args(["--raw", "-n", "-i", "1", "-c", "100000", "-m", "40"]);
                match mode {
                    TraceMode::Icmp => {}
                    TraceMode::Udp => {
                        c.arg("--udp");
                    }
                    TraceMode::Tcp(p) => {
                        c.args(["--tcp", "--port", &p.to_string()]);
                    }
                }
                if let Some(i) = &iface {
                    c.args(["-I", i]);
                }
                c.arg(ip.to_string());
                c
            } else {
                let mut c = Command::new("traceroute");
                c.args(["-n", "-q", "3", "-w", "2", "-m", "40"]);
                if let Some(i) = &iface {
                    c.args(["-i", i]);
                }
                c.arg(ip.to_string());
                c
            };
            cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).env("LC_ALL", "C");
            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    let mut st = state.lock().unwrap();
                    st.running = false;
                    st.error = Some(format!("Ni mtr ni traceroute n'ont pu démarrer : {e}"));
                    return;
                }
            };
            let stdout = child.stdout.take().unwrap();
            let stderr = child.stderr.take();
            state.lock().unwrap().source = if use_mtr { "mtr" } else { "traceroute" };
            *child_slot.lock().unwrap() = Some(child);
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if *run_id.lock().unwrap() != id {
                    return;
                }
                let mut st = state.lock().unwrap();
                if use_mtr {
                    st.apply_mtr_line(&line);
                } else {
                    st.apply_traceroute_line(&line);
                }
            }
            if *run_id.lock().unwrap() == id {
                let mut err = String::new();
                if let Some(mut e) = stderr {
                    let _ = std::io::Read::read_to_string(&mut e, &mut err);
                }
                let mut st = state.lock().unwrap();
                st.running = false;
                if !err.trim().is_empty() && st.hops.iter().all(|h| h.ips.is_empty()) {
                    st.error = Some(err.trim().to_string());
                }
            }
        });
    }
}

impl Drop for Tracer {
    fn drop(&mut self) {
        if let Ok(mut c) = self.child.lock() {
            if let Some(mut c) = c.take() {
                let _ = c.kill();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtr_raw_stream() {
        let mut s = TraceState { target_ip: "1.1.1.1".parse().ok(), ..Default::default() };
        for l in ["x 0 33000", "h 0 192.168.43.1", "h 0 192.168.43.1", "p 0 4059 33000", "x 1 33001", "x 2 33002", "h 2 1.1.1.1", "p 2 20000 33002", "x 3 33003", "x 4 33004"] {
            s.apply_mtr_line(l);
        }
        assert_eq!(s.hops[0].ips.len(), 1);
        assert!((s.hops[0].last_ms - 4.059).abs() < 0.001);
        assert_eq!(s.hops[0].loss_pct(), 0.0);
        assert_eq!(s.hops[1].loss_pct(), 100.0);
        assert!(s.reached());
        // Destination à l'étape 3 : les sondes au-delà ne s'affichent pas.
        assert_eq!(s.visible_hops().len(), 3);
    }

    #[test]
    fn unreachable_keeps_one_silent_hop() {
        let mut s = TraceState { target_ip: "9.9.9.9".parse().ok(), ..Default::default() };
        for l in ["x 0 1", "h 0 10.0.0.1", "p 0 1000 1", "x 1 2", "x 2 3", "x 3 4"] {
            s.apply_mtr_line(l);
        }
        assert!(!s.reached());
        assert_eq!(s.visible_hops().len(), 2);
    }

    #[test]
    fn traceroute_fallback() {
        let mut s = TraceState::default();
        s.apply_traceroute_line("traceroute to 1.1.1.1 (1.1.1.1), 30 hops max");
        s.apply_traceroute_line(" 1  192.168.43.1  4.059 ms  3.100 ms *");
        s.apply_traceroute_line(" 2  * * *");
        assert_eq!(s.hops[0].recv, 2);
        assert_eq!(s.hops[0].sent, 3);
        assert_eq!(s.hops[1].loss_pct(), 100.0);
    }

    #[test]
    fn stats() {
        let mut h = Hop::default();
        h.sent = 4;
        for v in [10.0, 20.0, 30.0] {
            h.add_sample(v);
        }
        assert_eq!(h.best_ms, 10.0);
        assert_eq!(h.worst_ms, 30.0);
        assert_eq!(h.avg_ms(), 20.0);
        assert_eq!(h.loss_pct(), 25.0);
        assert_eq!(h.jitter_ms(), 10.0);
    }
}
