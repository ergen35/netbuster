//! L'icône de la barre d'état, et une seule instance de NetBuster à la fois.

use crate::collect::{Ctl, Shared};
use crate::util::fmt_rate;
use ksni::blocking::TrayMethods;
use std::io::{BufRead, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn instance_socket() -> Option<PathBuf> {
    // Ce dossier n'est accessible qu'au compte : personne d'autre ne peut piloter l'application.
    std::env::var_os("XDG_RUNTIME_DIR").map(|d| PathBuf::from(d).join("netbuster.sock"))
}

/// Si NetBuster tourne déjà, lui passe la main. Rend vrai quand il n'y a plus rien à faire ici.
pub fn hand_over(minimized: bool) -> bool {
    let Some(path) = instance_socket() else { return false };
    let Ok(mut s) = UnixStream::connect(path) else { return false };
    if !minimized {
        let _ = s.write_all(b"show\n");
    }
    true
}

/// Écoute les lancements suivants.
pub fn listen(shared: Arc<Shared>) {
    let Some(path) = instance_socket() else { return };
    // Personne n'a répondu à `hand_over` : ce fichier est le reste d'une session terminée.
    let _ = std::fs::remove_file(&path);
    let Ok(listener) = UnixListener::bind(&path) else { return };
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let shared = shared.clone();
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                for line in std::io::BufReader::new(stream).lines().map_while(Result::ok) {
                    match line.trim() {
                        "show" => shared.control.push(Ctl::Show),
                        "hide" => shared.control.push(Ctl::Hide),
                        "quit" => shared.control.push(Ctl::Quit),
                        _ => {}
                    }
                    shared.request_repaint();
                }
            });
        }
    });
}

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
fn argb(size: u32) -> Option<ksni::Icon> {
    let (width, height, mut px) = crate::desktop::icon_rgba(size)?;
    for p in px.chunks_exact_mut(4) {
        p.rotate_right(1);
    }
    Some(ksni::Icon { width: width as i32, height: height as i32, data: px })
}

/// Pose l'icône. Rend faux si le bureau n'a pas de barre d'état.
///
/// À l'ouverture de session, la barre peut démarrer après NetBuster : `patient` lui laisse du temps.
pub fn start(shared: Arc<Shared>, patient: bool) -> bool {
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

#[cfg(test)]
mod tests {
    #[test]
    fn tray_icons_are_argb() {
        let icon = super::argb(16).unwrap();
        let (_, _, rgba) = crate::desktop::icon_rgba(16).unwrap();
        // Un pixel opaque du centre : l'alpha passe en premier, le reste suit.
        let i = (8 * 16 + 8) * 4;
        assert_eq!(icon.data[i], rgba[i + 3]);
        assert_eq!(icon.data[i + 1], rgba[i]);
        assert_eq!(icon.data[i + 2], rgba[i + 1]);
        assert_eq!(icon.data[i + 3], rgba[i + 2]);
    }
}
