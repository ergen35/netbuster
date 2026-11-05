//! L'icône de la barre d'état, et une seule instance de NetBuster à la fois.

use crate::collect::{Ctl, Shared};
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
fn instance_socket() -> Option<PathBuf> {
    // Ce dossier n'est accessible qu'au compte : personne d'autre ne peut piloter l'application.
    let dir = if cfg!(target_os = "macos") { "TMPDIR" } else { "XDG_RUNTIME_DIR" };
    std::env::var_os(dir).map(|d| PathBuf::from(d).join("netbuster.sock"))
}

/// Si NetBuster tourne déjà, lui passe la main. Rend vrai quand il n'y a plus rien à faire ici.
pub fn hand_over(minimized: bool) -> bool {
    #[cfg(unix)]
    let stream = instance_socket().and_then(|p| std::os::unix::net::UnixStream::connect(p).ok());
    #[cfg(not(unix))]
    let stream = loopback::connect(&crate::util::data_dir());
    let Some(mut s) = stream else { return false };
    if !minimized {
        let _ = s.write_all(b"show\n");
    }
    true
}

/// Écoute les lancements suivants.
pub fn listen(shared: Arc<Shared>) {
    #[cfg(unix)]
    {
        let Some(path) = instance_socket() else { return };
        // Personne n'a répondu à `hand_over` : ce fichier est le reste d'une session terminée.
        let _ = std::fs::remove_file(&path);
        let Ok(listener) = std::os::unix::net::UnixListener::bind(&path) else { return };
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let shared = shared.clone();
                std::thread::spawn(move || serve(stream, &shared));
            }
        });
    }
    #[cfg(not(unix))]
    {
        let dir = crate::util::data_dir();
        let _ = loopback::listen(&dir, move |stream| serve(stream, &shared));
    }
}

fn serve(stream: impl Read, shared: &Shared) {
    for line in std::io::BufReader::new(stream).lines().map_while(Result::ok) {
        match line.trim() {
            "show" => shared.control.push(Ctl::Show),
            "hide" => shared.control.push(Ctl::Hide),
            "quit" => shared.control.push(Ctl::Quit),
            _ => {}
        }
        shared.request_repaint();
    }
}

/// Windows n'a pas de prise locale dans un dossier privé : une prise réseau limitée à ce PC,
/// et un mot de passe tiré au sort, rangé dans le dossier du compte.
///
/// La réponse prouve que c'est bien NetBuster : un autre programme peut avoir repris le numéro de port.
pub mod loopback {
    use super::*;
    use std::hash::{BuildHasher, Hasher};
    use std::net::{SocketAddr, TcpListener, TcpStream};

    const ANSWER: &[u8] = b"netbuster\n";

    fn file(dir: &Path) -> PathBuf {
        dir.join("instance")
    }

    pub fn connect(dir: &Path) -> Option<TcpStream> {
        let text = std::fs::read_to_string(file(dir)).ok()?;
        let (port, token) = text.trim().split_once(' ')?;
        let addr = SocketAddr::from(([127, 0, 0, 1], port.parse().ok()?));
        let mut s = TcpStream::connect_timeout(&addr, Duration::from_millis(300)).ok()?;
        s.set_read_timeout(Some(Duration::from_millis(800))).ok()?;
        s.write_all(format!("{token}\n").as_bytes()).ok()?;
        let mut answer = [0u8; ANSWER.len()];
        s.read_exact(&mut answer).ok()?;
        (answer == ANSWER).then_some(s)
    }

    /// `on_client` lit ce que le lancement suivant envoie, une fois le mot de passe vérifié.
    pub fn listen(dir: &Path, on_client: impl Fn(std::io::BufReader<TcpStream>) + Send + Sync + 'static) -> std::io::Result<()> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u32(std::process::id());
        let token = format!("{:016x}", hasher.finish());
        std::fs::create_dir_all(dir)?;
        std::fs::write(file(dir), format!("{} {token}\n", listener.local_addr()?.port()))?;
        let on_client = Arc::new(on_client);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (on_client, token) = (on_client.clone(), token.clone());
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let Ok(mut answer) = stream.try_clone() else { return };
                    let mut reader = std::io::BufReader::new(stream);
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() || line.trim() != token || answer.write_all(ANSWER).is_err() {
                        return;
                    }
                    on_client(reader);
                });
            }
        });
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod icon {
use super::*;
use crate::util::fmt_rate;
use ksni::blocking::TrayMethods;

struct NetTray {
    shared: Arc<Shared>,
    icons: Vec<ksni::Icon>,
}

impl NetTray {
    fn send(&self, c: Ctl) {
        self.shared.control.push(c);
        self.shared.request_repaint();
    }

    fn status_line(&self) -> String {
        let (rx, tx, capture, service) = match self.shared.model.lock() {
            Ok(m) => {
                let (rx, tx) = m.current_rates(None);
                (rx, tx, m.capture.running, m.capture.service)
            }
            Err(_) => return String::new(),
        };
        let state = match (service, capture) {
            (true, _) => "Capture : service actif",
            (false, true) => "Capture en cours",
            (false, false) => "Capture à l'arrêt",
        };
        format!("↓ {}   ↑ {}\n{state}", fmt_rate(rx), fmt_rate(tx))
    }
}

impl ksni::Tray for NetTray {
    fn id(&self) -> String {
        crate::desktop::APP_ID.into()
    }

    fn title(&self) -> String {
        "NetBuster".into()
    }

    fn category(&self) -> ksni::Category {
        ksni::Category::SystemServices
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        self.icons.clone()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip { title: "NetBuster".into(), description: self.status_line(), ..Default::default() }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.send(Ctl::Show);
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::StandardItem;
        let status = self.status_line().replace('\n', "  ·  ");
        vec![
            StandardItem { label: "Ouvrir NetBuster".into(), activate: Box::new(|t: &mut Self| t.send(Ctl::Show)), ..Default::default() }.into(),
            StandardItem { label: "Masquer la fenêtre".into(), activate: Box::new(|t: &mut Self| t.send(Ctl::Hide)), ..Default::default() }.into(),
            ksni::MenuItem::Separator,
            StandardItem { label: status, enabled: false, ..Default::default() }.into(),
            ksni::MenuItem::Separator,
            StandardItem { label: "Quitter NetBuster".into(), activate: Box::new(|t: &mut Self| t.send(Ctl::Quit)), ..Default::default() }.into(),
        ]
    }
}

/// Le format attendu par la barre d'état : ARGB, octet de poids fort d'abord.
pub(super) fn argb(size: u32) -> Option<ksni::Icon> {
    let (width, height, mut px) = crate::desktop::icon_rgba(size)?;
    for p in px.chunks_exact_mut(4) {
        p.rotate_right(1);
    }
    Some(ksni::Icon { width: width as i32, height: height as i32, data: px })
}

/// Pose l'icône. Rend faux si le bureau n'a pas de barre d'état.
///
/// À l'ouverture de session, la barre peut démarrer après NetBuster : `patient` lui laisse du temps.
pub(super) fn start(shared: Arc<Shared>, patient: bool) -> bool {
    let attempts = if patient { 8 } else { 1 };
    for i in 0..attempts {
        if i > 0 {
            std::thread::sleep(Duration::from_secs(1));
        }
        let icons = [16, 22, 24, 32, 48, 64].into_iter().filter_map(argb).collect();
        match (NetTray { shared: shared.clone(), icons }).spawn() {
            Ok(handle) => {
                // L'infobulle affiche les débits : elle se rafraîchit toute seule.
                std::thread::spawn(move || loop {
                    std::thread::sleep(Duration::from_secs(3));
                    handle.update(|_| {});
                });
                return true;
            }
            Err(e) => eprintln!("barre d'état indisponible : {e}"),
        }
    }
    false
}
}

/// Pose l'icône. Rend faux si le bureau n'a pas de barre d'état.
pub fn start(_shared: Arc<Shared>, _patient: bool) -> bool {
    #[cfg(target_os = "linux")]
    {
        icon::start(_shared, _patient)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_launch_reaches_the_first_through_the_loopback() {
        use std::sync::mpsc::channel;
        let dir = std::env::temp_dir().join(format!("netbuster-instance-{}", std::process::id()));
        // Personne n'écoute encore.
        assert!(loopback::connect(&dir).is_none());
        let (tx, rx) = channel();
        let tx = std::sync::Mutex::new(tx);
        loopback::listen(&dir, move |reader| {
            for line in reader.lines().map_while(Result::ok) {
                tx.lock().unwrap().send(line).unwrap();
            }
        })
        .unwrap();
        let mut s = loopback::connect(&dir).expect("la première instance répond");
        s.write_all(b"show\n").unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(3)).unwrap(), "show");

        // Sans le bon mot de passe, rien n'est écouté et la connexion échoue.
        let text = std::fs::read_to_string(dir.join("instance")).unwrap();
        let port = text.split_whitespace().next().unwrap();
        std::fs::write(dir.join("instance"), format!("{port} faux\n")).unwrap();
        assert!(loopback::connect(&dir).is_none());
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tray_icons_are_argb() {
        let icon = super::icon::argb(16).unwrap();
        let (_, _, rgba) = crate::desktop::icon_rgba(16).unwrap();
        // Un pixel opaque du centre : l'alpha passe en premier, le reste suit.
        let i = (8 * 16 + 8) * 4;
        assert_eq!(icon.data[i], rgba[i + 3]);
        assert_eq!(icon.data[i + 1], rgba[i]);
        assert_eq!(icon.data[i + 2], rgba[i + 1]);
        assert_eq!(icon.data[i + 3], rgba[i + 2]);
    }
}
