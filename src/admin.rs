//! Côté fenêtre : démarre l'assistant administrateur et lui parle.

use crate::proto::*;
use crate::util::{run, CmdResult};
use std::collections::HashMap;
use std::io::{BufReader, Write};
use std::os::fd::AsRawFd;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub enum AdminState {
    Off,
    Asking,
    On { uid: u32 },
    Failed(String),
}

pub enum Incoming {
    Frame(RawFrame),
    Event(Event),
}

pub struct Admin {
    state: Mutex<AdminState>,
    stdin: Mutex<Option<ChildStdin>>,
    child: Mutex<Option<Child>>,
    pending: Mutex<HashMap<u64, Sender<Reply>>>,
    next_id: AtomicU64,
    /// Commande complète de démarrage. Les tests la remplacent par le mode simulé.
    pub spawn_cmd: Vec<String>,
}

impl Admin {
    pub fn new(mock_dir: Option<String>) -> Arc<Self> {
        let exe = std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| "netbuster".into());
        Self::with_command(match mock_dir {
            Some(dir) => vec![exe, "--helper".into(), "--mock".into(), dir],
            None => vec!["pkexec".into(), exe, "--helper".into()],
        })
    }

    pub fn with_command(spawn_cmd: Vec<String>) -> Arc<Self> {
        Arc::new(Admin {
            state: Mutex::new(AdminState::Off),
            stdin: Mutex::new(None),
            child: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            spawn_cmd,
        })
    }

    pub fn state(&self) -> AdminState {
        self.state.lock().unwrap().clone()
    }

    pub fn is_on(&self) -> bool {
        matches!(*self.state.lock().unwrap(), AdminState::On { .. })
    }

    /// Lance l'assistant : le système affiche sa propre demande de mot de passe.
    pub fn start(self: &Arc<Self>, sink: Sender<Incoming>) {
        {
            let mut st = self.state.lock().unwrap();
            if matches!(*st, AdminState::Asking | AdminState::On { .. }) {
                return;
            }
            *st = AdminState::Asking;
        }
        let me = self.clone();
        std::thread::spawn(move || me.spawn_and_read(sink));
    }

    fn spawn_and_read(self: Arc<Self>, sink: Sender<Incoming>) {
        let mut cmd = Command::new(&self.spawn_cmd[0]);
        cmd.args(&self.spawn_cmd[1..]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                *self.state.lock().unwrap() = AdminState::Failed(format!("Impossible de demander les droits : {e}"));
                return;
            }
        };
        let stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        // Un tuyau plus large absorbe mieux les pics de trafic.
        unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETPIPE_SZ, 1024 * 1024) };
        *self.stdin.lock().unwrap() = child.stdin.take();
        *self.child.lock().unwrap() = Some(child);
        let err_thread = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = std::io::Read::read_to_string(&mut stderr, &mut s);
            s
        });

        let mut reader = BufReader::with_capacity(256 * 1024, stdout);
        let mut greeted = false;
        while let Ok(Some((tag, data))) = read_frame(&mut reader) {
            match tag {
                TAG_PACKET => {
                    if let Some(f) = RawFrame::decode(&data) {
                        if sink.send(Incoming::Frame(f)).is_err() {
                            break;
                        }
                    }
                }
                TAG_REPLY => {
                    if let Ok(r) = serde_json::from_slice::<Reply>(&data) {
                        if let Some(tx) = self.pending.lock().unwrap().remove(&r.id) {
                            let _ = tx.send(r);
                        }
                    }
                }
                TAG_EVENT => {
                    if let Ok(ev) = serde_json::from_slice::<Event>(&data) {
                        if let Event::Hello { uid } = ev {
                            greeted = true;
                            *self.state.lock().unwrap() = AdminState::On { uid };
                        } else {
                            let _ = sink.send(Incoming::Event(ev));
                        }
                    }
                }
                _ => {}
            }
        }

        // Fin de l'assistant.
        *self.stdin.lock().unwrap() = None;
        self.pending.lock().unwrap().clear();
        let code = self.child.lock().unwrap().take().and_then(|mut c| c.wait().ok()).and_then(|s| s.code());
        let err = err_thread.join().unwrap_or_default();
        let _ = sink.send(Incoming::Event(Event::CaptureStopped));
        *self.state.lock().unwrap() = if greeted {
            AdminState::Off
        } else {
            match code {
                Some(126) => AdminState::Failed("Demande annulée : le mot de passe n'a pas été saisi.".into()),
                Some(127) => AdminState::Failed("Ce compte n'a pas le droit de passer administrateur.".into()),
                _ => AdminState::Failed(format!("L'assistant n'a pas démarré. {}", err.trim())),
            }
        };
    }

    pub fn send(&self, cmd: &Cmd) -> bool {
        let Ok(mut line) = serde_json::to_string(cmd) else { return false };
        line.push('\n');
        match self.stdin.lock().unwrap().as_mut() {
            Some(w) => w.write_all(line.as_bytes()).and_then(|_| w.flush()).is_ok(),
            None => false,
        }
    }

    fn request(&self, make: impl FnOnce(u64) -> Cmd, timeout: Duration) -> CmdResult {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = channel();
        self.pending.lock().unwrap().insert(id, tx);
        if !self.send(&make(id)) {
            self.pending.lock().unwrap().remove(&id);
            return CmdResult::error("Le mode administrateur n'est pas actif.");
        }
        match rx.recv_timeout(timeout) {
            Ok(r) => CmdResult { ok: r.ok, code: r.code, stdout: r.stdout, stderr: r.stderr },
            Err(_) => {
                self.pending.lock().unwrap().remove(&id);
                CmdResult::error("Pas de réponse de l'assistant administrateur.")
            }
        }
    }

    /// Exécute en administrateur.
    pub fn exec_root(&self, prog: &str, args: &[&str]) -> CmdResult {
        // L'installation d'un paquet peut prendre plusieurs minutes.
        let timeout = if prog == "apt-get" { 900 } else { 30 };
        self.request(
            |id| Cmd::Exec { id, prog: prog.to_string(), args: args.iter().map(|s| s.to_string()).collect() },
            Duration::from_secs(timeout),
        )
    }

    pub fn write_root(&self, path: &str, content: &str) -> CmdResult {
        self.request(|id| Cmd::WriteFile { id, path: path.to_string(), content: content.to_string() }, Duration::from_secs(10))
    }

    /// Exécute en administrateur si possible, sinon avec les droits normaux.
    pub fn exec_best(&self, prog: &str, args: &[&str]) -> CmdResult {
        if self.is_on() {
            self.exec_root(prog, args)
        } else {
            run(prog, args)
        }
    }

    pub fn shutdown(&self) {
        *self.stdin.lock().unwrap() = None;
    }
}
