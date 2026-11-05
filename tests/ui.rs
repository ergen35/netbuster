//! Clique dans la vraie interface, avec un assistant simulé : aucune commande n'atteint le système.
#![cfg(target_os = "linux")]

use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use netbuster::admin::Admin;
use netbuster::collect::Shared;
use netbuster::desktop::ThemeChoice;
use netbuster::service::ServicePaths;
use netbuster::ui::{App, Page};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

fn setup(name: &str) -> (Harness<'static, App>, PathBuf) {
    let dir = std::env::temp_dir().join(format!("netbuster-ui-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Rien n'est écrit dans le dossier personnel pendant les tests.
    unsafe { std::env::set_var("XDG_DATA_HOME", dir.join("data")) };
    unsafe { std::env::set_var("XDG_CONFIG_HOME", std::env::temp_dir().join(format!("netbuster-ui-{}-config", std::process::id()))) };
    netbuster::mockkit::write_mock(&dir, [192, 168, 43, 242], 2);
    let admin = Admin::with_command(vec![env!("CARGO_BIN_EXE_netbuster").to_string(), "--helper".into(), "--mock".into(), dir.to_string_lossy().into_owned()]);
    // Le service de ce dossier, jamais celui du PC : s'il est actif, ses vrais paquets fausseraient tout.
    let app = App::new(Shared::start_with_paths(admin, ServicePaths::under(&dir)));
    let h = Harness::builder().with_size(egui::vec2(1440.0, 900.0)).build_ui_state(|ui, app: &mut App| app.draw(ui), app);
    (h, dir)
}

fn steps(h: &mut Harness<'static, App>, n: usize) {
    for _ in 0..n {
        h.step();
    }
}

/// Dessine jusqu'à ce que la condition soit vraie.
fn wait(h: &mut Harness<'static, App>, what: &str, mut ok: impl FnMut(&mut Harness<'static, App>) -> bool) {
    let t = Instant::now();
    while !ok(h) {
        assert!(t.elapsed() < Duration::from_secs(20), "délai dépassé : {what}");
        h.step();
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn calls(dir: &std::path::Path) -> String {
    std::fs::read_to_string(dir.join("calls.log")).unwrap_or_default()
}

fn go_admin(h: &mut Harness<'static, App>) {
    h.query_all_by_label("Passer administrateur").next().unwrap().click();
    wait(h, "mode administrateur", |h| h.state().shared.admin.is_on());
}

#[test]
fn every_page_opens_from_the_menu() {
    let (mut h, _d) = setup("pages");
    for p in Page::ALL {
        h.get_by_role_and_label(egui::Role::Button, p.title()).click();
        steps(&mut h, 3);
        assert_eq!(h.state().page, p);
    }
}

#[test]
fn about_shows_the_author_credits() {
    let (mut h, _d) = setup("about");
    assert!(!h.state().about_open);
    h.get_by_role_and_label(egui::Role::Button, "À propos").click();
    steps(&mut h, 3);
    assert!(h.state().about_open);
    h.get_by_label("Serge Eric Hotegni");
    h.get_by_label(&format!("Version {}", env!("CARGO_PKG_VERSION")));
    h.get_by_role_and_label(egui::Role::Link, "https://github.com/ergen35");
    h.get_by_role_and_label(egui::Role::Link, "https://github.com/ergen35/netbuster");
    h.get_by_label("Fermer").click();
    steps(&mut h, 3);
    assert!(!h.state().about_open);
    assert!(h.query_by_label("Serge Eric Hotegni").is_none());
}

fn setup_with_service(name: &str) -> (Harness<'static, App>, PathBuf) {
    let dir = std::env::temp_dir().join(format!("netbuster-ui-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    netbuster::mockkit::write_mock(&dir, [192, 168, 43, 242], 2);
    let admin = Admin::with_command(vec![env!("CARGO_BIN_EXE_netbuster").to_string(), "--helper".into(), "--mock".into(), dir.to_string_lossy().into_owned()]);
    let app = App::new(Shared::start_with_paths(admin, ServicePaths::under(&dir)));
    let h = Harness::builder().with_size(egui::vec2(1440.0, 900.0)).build_ui_state(|ui, app: &mut App| app.draw(ui), app);
    (h, dir)
}

/// Le service en mode simulé. Il s'arrête avec le test, même si celui-ci échoue.
struct Daemon(std::process::Child);

impl Daemon {
    fn start(dir: &std::path::Path) -> Daemon {
        Daemon(std::process::Command::new(env!("CARGO_BIN_EXE_netbuster")).args(["--daemon", "--mock"]).arg(dir).spawn().unwrap())
    }

    /// Comme le système à l'arrêt : un signal, puis on attend que le fichier soit bien fermé.
    fn stop(&mut self) -> std::process::ExitStatus {
        unsafe { libc_kill(self.0.id() as i32, 15) };
        self.0.wait().unwrap()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

#[test]
fn opening_at_login_is_a_setting() {
    let (mut h, _d) = setup("autostart");
    // Un dossier de réglages à ce test : le vrai dossier personnel n'est jamais touché.
    let config = std::env::temp_dir().join(format!("netbuster-ui-{}-config", std::process::id()));
    unsafe { std::env::set_var("XDG_CONFIG_HOME", &config) };
    let file = config.join("autostart/netbuster.desktop");
    let _ = std::fs::remove_file(&file);
    h.state_mut().page = Page::Settings;
    steps(&mut h, 3);

    let name = "Ouvrir NetBuster à l'ouverture de session";
    h.get_by_role_and_label(egui::Role::CheckBox, name).click();
    steps(&mut h, 3);
    let text = std::fs::read_to_string(&file).expect("fichier d'ouverture de session");
    assert!(text.contains("--minimized"), "{text}");
    assert!(text.contains(&*std::env::current_exe().unwrap().to_string_lossy()), "{text}");
    assert!(h.state().settings.autostart);

    h.get_by_role_and_label(egui::Role::CheckBox, name).click();
    steps(&mut h, 3);
    assert!(!file.exists());
    assert!(!h.state().settings.autostart);
}

#[test]
fn the_background_service_can_be_turned_on_used_and_turned_off() {
    let (mut h, dir) = setup_with_service("service");
    let paths = ServicePaths::under(&dir);
    h.state_mut().page = Page::Settings;
    steps(&mut h, 3);
    let name = "Capturer tout le trafic en continu";

    // Il faut confirmer, et « Annuler » ne fait rien.
    h.get_by_role_and_label(egui::Role::CheckBox, name).click();
    steps(&mut h, 3);
    assert!(h.state().confirm.is_some());
    h.get_by_label("Annuler").click();
    steps(&mut h, 3);
    assert!(!paths.unit.exists());
    assert!(!calls(&dir).contains("enable"));

    // Confirmer : le service est installé pour le compte courant, en le limitant à ce qu'il lui faut.
    h.get_by_role_and_label(egui::Role::CheckBox, name).click();
    steps(&mut h, 3);
    h.get_by_label("Confirmer").click();
    wait(&mut h, "service activé", |_| calls(&dir).contains("systemctl enable --now netbuster-capture.service"));
    let unit = std::fs::read_to_string(&paths.unit).unwrap();
    assert!(unit.contains("ExecStart=/usr/local/lib/netbuster/netbuster --daemon\n"), "{unit}");
    assert!(calls(&dir).find("daemon-reload").unwrap() < calls(&dir).find("enable --now").unwrap());

    // Le mot de passe a aussi lancé la capture par l'assistant : on repart d'une liste vide.
    wait(&mut h, "capture de l'assistant", |h| h.state().shared.model.lock().unwrap().packets.len() >= 130);
    h.state().shared.model.lock().unwrap().clear_packets();

    // Le service tourne : les paquets arrivent en direct, sans capture en administrateur.
    let mut daemon = Daemon::start(&dir);
    wait(&mut h, "fenêtre reliée au service", |h| h.state().shared.service_up.load(Ordering::Relaxed));
    wait(&mut h, "paquets du service", |h| h.state().shared.model.lock().unwrap().packets.len() >= 130);
    {
        let shared = h.state().shared.clone();
        let m = shared.model.lock().unwrap();
        assert!(m.capture.running && m.capture.service);
        // Chaque paquet une seule fois, sans double capture par l'assistant administrateur.
        assert_eq!(m.packets.len(), 130);
        assert!(m.packets.iter().any(|r| r.pkt.sni.as_deref() == Some("www.exemple.fr")));
    }
    h.state_mut().page = Page::Packets;
    steps(&mut h, 3);
    h.get_by_label("Capture par le service");
    assert!(h.query_by_label_contains("La capture des paquets demande").is_none());

    // La place maximale passe par un fichier, sans mot de passe.
    h.state_mut().page = Page::Settings;
    wait(&mut h, "statistiques du service", |h| h.state().shared.model.lock().unwrap().capture.service_stats.stored_bytes > 0);
    netbuster::service::write_limit_mb(&paths, 512).unwrap();
    wait(&mut h, "nouvelle limite appliquée", |h| h.state().shared.model.lock().unwrap().capture.service_stats.limit_bytes == 512 * 1024 * 1024);

    // Sans cela l'assistant reprendrait la capture à l'arrêt du service, et rejouerait ses paquets.
    h.state().shared.admin.shutdown();
    wait(&mut h, "fin du mode administrateur", |h| !h.state().shared.admin.is_on());

    // Arrêt propre, puis relecture de ce qui a été écrit : rien n'a été perdu.
    assert!(daemon.stop().success());
    wait(&mut h, "fin de la liaison", |h| !h.state().shared.service_up.load(Ordering::Relaxed));
    let files = netbuster::service::list_capture_files(&paths.state);
    assert_eq!(files.len(), 1);
    assert_eq!(netbuster::service::read_capture_file(&files[0].path, &mut |_| {}).unwrap(), 130);

    // L'historique se relit après coup dans la liste, sans compter deux fois dans la consommation.
    let before = {
        let shared = h.state().shared.clone();
        let m = shared.model.lock().unwrap();
        (m.capture.seen_bytes, m.packets.len())
    };
    {
        let shared = h.state().shared.clone();
        shared.model.lock().unwrap().clear_packets();
    }
    steps(&mut h, 2);
    h.state_mut().settings.refreshed = None;
    h.state_mut().page = Page::Settings;
    steps(&mut h, 3);
    h.get_by_label_contains("Voir les paquets").click();
    wait(&mut h, "historique relu", |h| h.state().shared.model.lock().unwrap().packets.len() == 130);
    steps(&mut h, 3);
    assert_eq!(h.state().page, Page::Packets);
    wait(&mut h, "message de fin", |h| h.state().toast.as_ref().is_some_and(|t| t.ok && t.detail.contains("130")));
    {
        let shared = h.state().shared.clone();
        let m = shared.model.lock().unwrap();
        assert_eq!(m.capture.seen_bytes, before.0);
        assert_eq!(before.1, 130);
        let ts: Vec<u64> = m.packets.iter().map(|r| r.pkt.ts_us).collect();
        assert!(ts.windows(2).all(|w| w[0] <= w[1]), "paquets hors de l'ordre du temps");
    }

    // Désactiver : le service part, l'historique reste.
    h.state_mut().page = Page::Settings;
    h.state_mut().settings.refreshed = None;
    steps(&mut h, 3);
    h.get_by_role_and_label(egui::Role::CheckBox, name).click();
    steps(&mut h, 3);
    h.get_by_label("Confirmer").click();
    wait(&mut h, "service désactivé", |_| calls(&dir).contains("systemctl disable --now netbuster-capture.service"));
    wait(&mut h, "fiche supprimée", |_| !paths.unit.exists());
    assert_eq!(netbuster::service::list_capture_files(&paths.state).len(), 1);
    h.state_mut().settings.refreshed = None;
    steps(&mut h, 3);

    // Supprimer l'historique demande une confirmation.
    h.get_by_label_contains("Tout supprimer").click();
    steps(&mut h, 3);
    h.get_by_label("Annuler").click();
    steps(&mut h, 3);
    assert_eq!(netbuster::service::list_capture_files(&paths.state).len(), 1);
    h.get_by_label_contains("Tout supprimer").click();
    steps(&mut h, 3);
    h.get_by_label("Confirmer").click();
    wait(&mut h, "historique supprimé", |_| netbuster::service::list_capture_files(&paths.state).is_empty());
}

/// Sans ce signal, le système considérerait que le service n'a jamais démarré et l'arrêterait.
#[test]
fn the_service_tells_the_system_when_capture_is_ready() {
    let dir = std::env::temp_dir().join(format!("netbuster-ui-{}-notify", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    netbuster::mockkit::write_mock(&dir, [192, 168, 43, 242], 2);
    let notify = dir.join("notify.sock");
    let sock = std::os::unix::net::UnixDatagram::bind(&notify).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut daemon = Daemon(
        std::process::Command::new(env!("CARGO_BIN_EXE_netbuster"))
            .args(["--daemon", "--mock"])
            .arg(&dir)
            .env("NOTIFY_SOCKET", &notify)
            .spawn()
            .unwrap(),
    );
    let mut buf = [0u8; 64];
    let n = sock.recv(&mut buf).expect("signal de démarrage");
    assert_eq!(&buf[..n], b"READY=1");
    assert!(daemon.stop().success());
    // Personne ne doit pouvoir lire les captures à part le compte de la personne.
    use std::os::unix::fs::PermissionsExt;
    let paths = ServicePaths::under(&dir);
    assert_eq!(std::fs::metadata(&paths.state).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(std::fs::metadata(&paths.run).unwrap().permissions().mode() & 0o777, 0o700);
    assert!(!paths.socket().exists());
}

/// Survole le bouton, appuie, puis relâche : rend ce qui est copié à l'appui et au relâchement.
/// La copie doit partir à l'appui, une seule fois.
fn press_copy(h: &mut Harness<'static, App>, label: &str) -> (Vec<String>, Vec<String>) {
    let pos = {
        let node = h.query_all_by_label(label).next().expect("bouton copier");
        node.hover();
        node.rect().center()
    };
    h.step();
    let mut button = |h: &mut Harness<'static, App>, pressed: bool| -> Vec<String> {
        h.event(egui::Event::PointerButton { pos, button: egui::PointerButton::Primary, pressed, modifiers: egui::Modifiers::default() });
        h.step();
        h.output()
            .platform_output
            .commands
            .iter()
            .filter_map(|c| match c {
                egui::OutputCommand::CopyText(t) => Some(t.clone()),
                _ => None,
            })
            .collect()
    };
    let at_press = button(h, true);
    let at_release = button(h, false);
    (at_press, at_release)
}

#[test]
fn the_theme_can_be_changed_in_the_settings_and_is_kept() {
    let (mut h, _d) = setup("theme");
    h.state_mut().page = Page::Settings;
    steps(&mut h, 3);
    assert_eq!(h.state().settings.settings.theme, ThemeChoice::Dark);

    h.get_by_label_contains("Clair").click();
    steps(&mut h, 3);
    assert_eq!(h.state().settings.settings.theme, ThemeChoice::Light);
    assert_eq!(h.ctx.theme(), egui::Theme::Light);
    assert!(!h.ctx.global_style().visuals.dark_mode);
    assert_eq!(h.ctx.global_style().visuals.panel_fill, netbuster::ui::theme::LIGHT.page);

    // Le raccourci du haut de la fenêtre fait la même chose.
    h.get_by_label("Passer au thème sombre").click();
    steps(&mut h, 3);
    assert_eq!(h.state().settings.settings.theme, ThemeChoice::Dark);
    assert!(h.ctx.global_style().visuals.dark_mode);
    h.get_by_label("Passer au thème clair").click();
    steps(&mut h, 3);
    assert_eq!(h.state().settings.settings.theme, ThemeChoice::Light);

    // Toutes les pages se dessinent en clair sans erreur, puis on remet le thème des autres tests.
    for p in Page::ALL {
        h.state_mut().page = p;
        steps(&mut h, 2);
    }
    let ctx = h.ctx.clone();
    h.state_mut().set_theme(&ctx, ThemeChoice::Dark);
}

#[test]
fn an_ip_address_is_copied_without_its_port_or_opening_the_row() {
    let (mut h, _d) = setup("copy");
    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr().unwrap();
    let _client = std::net::TcpStream::connect(addr).unwrap();
    let _accepted = server.accept().unwrap();
    h.state_mut().page = Page::Conns;
    h.state_mut().conns.show_local = true;
    wait(&mut h, "connexion visible", |h| {
        let shared = h.state().shared.clone();
        let m = shared.model.lock().unwrap();
        m.flows.values().any(|f| f.key.remote == addr)
    });
    steps(&mut h, 3);

    let (at_press, at_release) = press_copy(&mut h, "Copier 127.0.0.1");
    assert_eq!(at_press, vec!["127.0.0.1".to_string()]);
    assert!(at_release.is_empty(), "copié deux fois : {at_release:?}");
    steps(&mut h, 2);
    // La ligne ne s'est pas ouverte : le clic est resté sur le bouton.
    assert!(h.state().conns.selected.is_none());
}

#[test]
fn a_frozen_list_stops_moving_while_measuring_continues() {
    let (mut h, _d) = setup("freeze");
    h.state_mut().page = Page::Conns;
    h.state_mut().conns.show_local = true;
    steps(&mut h, 3);
    wait(&mut h, "premières mesures", |h| h.state().shared.model.lock().unwrap().tick_id > 0 || !h.state().shared.model.lock().unwrap().flows.is_empty());

    h.get_by_label_contains("Figer").click();
    steps(&mut h, 3);
    assert!(h.state().conns.freeze.is_on());

    // Une connexion apparaît après coup : mesurée, mais absente de la liste figée.
    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr().unwrap();
    let _client = std::net::TcpStream::connect(addr).unwrap();
    let _accepted = server.accept().unwrap();
    wait(&mut h, "connexion mesurée", |h| {
        let shared = h.state().shared.clone();
        let m = shared.model.lock().unwrap();
        m.flows.values().any(|f| f.key.remote == addr)
    });
    steps(&mut h, 3);
    // La recherche reste possible pendant que c'est figé : elle isole la ligne, quel que soit le défilement.
    let row = format!(":{}", addr.port());
    h.state_mut().conns.search = addr.port().to_string();
    steps(&mut h, 3);
    assert!(h.query_all_by_label_contains(&row).next().is_none(), "la liste figée a bougé");

    h.get_by_label_contains("Défiger").click();
    steps(&mut h, 3);
    assert!(!h.state().conns.freeze.is_on());
    assert!(h.query_all_by_label_contains(&row).next().is_some(), "la liste n'est pas repartie");
}

#[test]
fn frozen_packets_are_not_lost() {
    let (mut h, _d) = setup("freeze-packets");
    h.state_mut().page = Page::Packets;
    steps(&mut h, 2);
    go_admin(&mut h);
    wait(&mut h, "paquets rejoués", |h| h.state().shared.model.lock().unwrap().packets.len() >= 130);
    steps(&mut h, 3);
    assert_eq!(h.state().packets.cached.len(), 130);

    h.get_by_label_contains("Figer").click();
    steps(&mut h, 3);

    // Des paquets arrivent : ils sont gardés, sans entrer dans la liste affichée.
    {
        let shared = h.state().shared.clone();
        let mut m = shared.model.lock().unwrap();
        for _ in 0..5 {
            let data = netbuster::packet::build::ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5000, 53, b"x");
            let frame = netbuster::proto::RawFrame { ts_us: 1, ifindex: 2, pkttype: 4, proto: 0x0800, orig_len: data.len() as u32, data };
            m.ingest(netbuster::packet::parse(frame));
        }
    }
    steps(&mut h, 3);
    assert_eq!(h.state().shared.model.lock().unwrap().packets.len(), 135);
    assert_eq!(h.state().packets.cached.len(), 130);
    h.get_by_label_contains("5 nouveaux en attente");

    // Un filtre s'applique à ce qui est figé, sans rien faire entrer.
    h.state_mut().packets.proto = "HTTP".into();
    steps(&mut h, 3);
    let filtered = h.state().packets.cached.len();
    assert!(filtered > 0 && filtered < 130);
    h.state_mut().packets.proto.clear();
    steps(&mut h, 3);
    assert_eq!(h.state().packets.cached.len(), 130);

    // Copier depuis la liste figée : l'adresse sans le port.
    let (at_press, _) = press_copy(&mut h, "Copier 93.184.216.34");
    assert_eq!(at_press, vec!["93.184.216.34".to_string()]);

    h.get_by_label_contains("Défiger").click();
    steps(&mut h, 3);
    assert_eq!(h.state().packets.cached.len(), 135);
}

#[test]
fn orders_from_the_tray_reach_the_window() {
    let (mut h, _d) = setup("control");
    steps(&mut h, 2);
    h.state().shared.control.push(netbuster::collect::Ctl::Quit);
    steps(&mut h, 2);
    assert!(h.state().quit_requested);
}

#[test]
fn capture_runs_and_packets_are_understood() {
    let (mut h, _d) = setup("capture");
    h.get_by_role_and_label(egui::Role::Button, "Paquets").click();
    steps(&mut h, 2);
    go_admin(&mut h);
    wait(&mut h, "paquets rejoués", |h| h.state().shared.model.lock().unwrap().packets.len() >= 130);
    {
        let shared = h.state().shared.clone();
        let m = shared.model.lock().unwrap();
        assert!(m.capture.running);
        assert!(m.packets.iter().any(|r| r.pkt.sni.as_deref() == Some("www.exemple.fr")));
        assert!(m.packets.iter().any(|r| r.pkt.app == "HTTP" && r.pkt.info.starts_with("GET /index.html")));
        assert!(m.packets.iter().any(|r| r.pkt.app == "DNS"));
        assert!(m.packets.iter().any(|r| r.pkt.app == "QUIC"));
        assert!(m.packets.iter().any(|r| r.pkt.app == "SSH"));
        // Le nom de l'interface vient de la machine qui exécute le test (l'index 2 n'est pas « wlo1 » partout).
        let expected: std::sync::Arc<str> = m.ifindex.get(&2).cloned().unwrap_or_else(|| "if2".into());
        assert!(m.packets.iter().all(|r| r.iface == expected));
        // La conversation HTTP en clair est reconstituée.
        assert!(m.streams.values().any(|s| s.chunks.iter().any(|c| String::from_utf8_lossy(&c.data).contains("Bonjour"))));
        // La connexion est nommée grâce à la réponse DNS capturée.
        assert!(m.flows.values().any(|f| f.key.remote.port() == 443 && f.host.as_deref() == Some("www.exemple.fr")));
    }
    // Le filtre « En clair » écarte les paquets chiffrés.
    h.get_by_label("En clair").click();
    steps(&mut h, 3);
    assert!(h.state().packets.cached.iter().all(|r| r.pkt.crypto == netbuster::packet::Crypto::No));
    assert!(!h.state().packets.cached.is_empty());
    h.get_by_label("Tous").click();
    steps(&mut h, 3);

    // Ouvrir un paquet, puis sa conversation.
    let id = h.state().packets.cached.iter().find(|r| r.pkt.app == "HTTP").map(|r| r.id).unwrap();
    h.state_mut().packets.selected = Some(id);
    steps(&mut h, 3);
    h.get_by_label("Conversation").click();
    steps(&mut h, 3);
    h.get_by_label_contains("HTTP/1.1 200 OK");

    // L'arrêt de la capture revient au mode normal.
    h.get_by_label_contains("Arrêter").click();
    wait(&mut h, "arrêt de la capture", |h| !h.state().shared.model.lock().unwrap().capture.running);
}

#[test]
fn closing_a_port_asks_first_then_runs_the_command() {
    let (mut h, dir) = setup("port");
    h.state_mut().page = Page::Ports;
    steps(&mut h, 2);
    go_admin(&mut h);

    // Mauvaise saisie : message clair, aucune commande.
    h.state_mut().ports.new_port = "99999".into();
    steps(&mut h, 2);
    h.get_by_label_contains(" Fermer").click();
    steps(&mut h, 3);
    h.get_by_label_contains("entre 1 et 65535");
    assert!(h.state().confirm.is_none());

    h.state_mut().ports.new_port = "4242".into();
    steps(&mut h, 2);
    h.get_by_label_contains(" Fermer").click();
    steps(&mut h, 3);
    assert!(h.state().confirm.is_some());
    // Annuler : rien ne part.
    h.get_by_label("Annuler").click();
    steps(&mut h, 3);
    assert!(h.state().confirm.is_none());
    assert!(!calls(&dir).contains("4242"));

    h.get_by_label_contains(" Fermer").click();
    steps(&mut h, 3);
    h.get_by_label("Confirmer").click();
    wait(&mut h, "commande exécutée", |_| calls(&dir).contains("4242"));
    let log = calls(&dir);
    assert!(log.contains("ufw deny 4242/tcp") || log.contains("iptables -I INPUT 1 -p tcp --dport 4242 -j DROP"), "{log}");
    wait(&mut h, "message de résultat", |h| h.state().toast.is_some());
    assert!(h.state().toast.as_ref().unwrap().ok);
}

#[test]
fn firewall_rules_are_read_and_can_be_changed() {
    let (mut h, dir) = setup("fw");
    h.state_mut().page = Page::Firewall;
    steps(&mut h, 2);
    go_admin(&mut h);
    wait(&mut h, "règles chargées", |h| !h.state().shared.panels.lock().unwrap().firewall.ufw.rules.is_empty());
    steps(&mut h, 3);
    h.get_by_label("Règle 2");

    h.get_by_label("IP Tables").click();
    steps(&mut h, 3);
    h.get_by_label("INPUT règle 3");
    {
        let shared = h.state().shared.clone();
        let panels = shared.panels.lock().unwrap();
        let input = &panels.firewall.tables[&(4, "filter".to_string())][0];
        assert_eq!(input.policy.as_deref(), Some("DROP"));
        assert_eq!(input.rules[2].source, "192.168.43.0/24");
        assert!(input.rules[1].extra.contains("ctstate RELATED,ESTABLISHED"));
    }

    // Politique de la chaîne INPUT, avec avertissement.
    h.get_by_label("Passer à : tout accepter").click();
    steps(&mut h, 3);
    assert!(h.state().confirm.is_some());
    h.get_by_label("Confirmer").click();
    wait(&mut h, "politique modifiée", |_| calls(&dir).contains("iptables -t filter -P INPUT ACCEPT"));

    // Règle saisie dans le formulaire.
    h.state_mut().fw.form.port = "8443".into();
    steps(&mut h, 3);
    let add = h.query_all_by_label("Ajouter").next().unwrap();
    add.click();
    steps(&mut h, 3);
    assert!(h.state().confirm.is_some());
    h.get_by_label("Confirmer").click();
    wait(&mut h, "règle ajoutée", |_| calls(&dir).contains("iptables -I INPUT 1 -p tcp --dport 8443 -j ACCEPT"));
}

#[test]
fn a_real_process_is_visible_with_its_connection() {
    let (mut h, _d) = setup("process");
    // Un vrai serveur et un vrai client, dans ce test.
    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr().unwrap();
    let mut client = std::net::TcpStream::connect(addr).unwrap();
    let (mut srv_side, _) = server.accept().unwrap();
    use std::io::{Read, Write};
    h.state_mut().page = Page::Ports;
    wait(&mut h, "port visible dans la liste", |h| {
        h.step();
        let shared = h.state().shared.clone();
        let m = shared.model.lock().unwrap();
        m.flows.values().any(|f| f.dir == netbuster::model::FlowDir::Listening && f.key.local.port() == addr.port() && f.pid == Some(std::process::id()))
    });
    // Le volume de cette connexion doit monter tout seul, sans droits particuliers.
    let payload = vec![7u8; 200_000];
    client.write_all(&payload).unwrap();
    let mut got = vec![0u8; payload.len()];
    srv_side.read_exact(&mut got).unwrap();
    wait(&mut h, "compteurs de la connexion", |h| {
        let shared = h.state().shared.clone();
        let m = shared.model.lock().unwrap();
        m.flows.values().any(|f| f.key.remote == addr && f.tx_total >= 200_000 && f.pid == Some(std::process::id()))
    });
}
