//! Clique dans la vraie interface, avec un assistant simulé : aucune commande n'atteint le système.

use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use netbuster::admin::Admin;
use netbuster::collect::Shared;
use netbuster::ui::{App, Page};
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn setup(name: &str) -> (Harness<'static, App>, PathBuf) {
    let dir = std::env::temp_dir().join(format!("netbuster-ui-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Rien n'est écrit dans le dossier personnel pendant les tests.
    unsafe { std::env::set_var("XDG_DATA_HOME", dir.join("data")) };
    netbuster::mockkit::write_mock(&dir, [192, 168, 43, 242], 2);
    let admin = Admin::with_command(vec![env!("CARGO_BIN_EXE_netbuster").to_string(), "--helper".into(), "--mock".into(), dir.to_string_lossy().into_owned()]);
    let app = App::new(Shared::start_with(admin));
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
    h.get_by_role_and_label(egui::Role::Link, "https://github.com/ergen35/clairiere");
    h.get_by_label("Fermer").click();
    steps(&mut h, 3);
    assert!(!h.state().about_open);
    assert!(h.query_by_label("Serge Eric Hotegni").is_none());
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
        assert!(m.packets.iter().all(|r| &*r.iface == "wlo1"));
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
