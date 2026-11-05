//! Ce que voit une personne sous Windows ou macOS, vérifié depuis Linux : aucun écran ni aucun bouton
//! ne promet une fonction qui n'existe pas sur son système.
#![cfg(target_os = "linux")]

use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use netbuster::admin::Admin;
use netbuster::collect::Shared;
use netbuster::service::ServicePaths;
use netbuster::ui::{App, Page};

#[test]
fn the_limited_version_hides_what_it_cannot_do() {
    let dir = std::env::temp_dir().join(format!("netbuster-limited-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    unsafe { std::env::set_var("XDG_DATA_HOME", dir.join("data")) };
    unsafe { std::env::set_var("XDG_CONFIG_HOME", dir.join("config")) };
    netbuster::platform::preview_limited();

    let admin = Admin::with_command(vec!["netbuster-absent".to_string()]);
    let mut app = App::new(Shared::start_with_paths(admin, ServicePaths::under(&dir)));
    // Un lien vers un écran absent ramène à la vue d'ensemble, au lieu d'une page vide.
    app.page = Page::Firewall;
    let mut h = Harness::builder().with_size(egui::vec2(1440.0, 900.0)).build_ui_state(|ui, app: &mut App| app.draw(ui), app);
    h.step();
    assert_eq!(h.state().page, Page::Overview);

    for p in [Page::Packets, Page::Firewall, Page::Config, Page::Ssh] {
        assert!(!p.available());
        assert!(h.query_all_by_label(p.title()).next().is_none(), "{} ne doit pas être au menu", p.title());
    }
    assert!(h.query_all_by_label("Passer administrateur").next().is_none());

    for p in [Page::Apps, Page::Conns, Page::Ports, Page::Trace, Page::Ip, Page::Usage, Page::Settings, Page::Overview] {
        assert!(p.available());
        h.get_by_role_and_label(egui::Role::Button, p.title()).click();
        h.step();
        h.step();
        assert_eq!(h.state().page, p);
        assert!(h.query_all_by_label("Passer administrateur").next().is_none(), "bouton administrateur sur {}", p.title());
    }

    h.get_by_role_and_label(egui::Role::Button, Page::Ports.title()).click();
    h.step();
    h.step();
    assert!(h.query_all_by_label("Ouvrir ou fermer un port").next().is_none());

    h.get_by_role_and_label(egui::Role::Button, Page::Settings.title()).click();
    h.step();
    h.step();
    assert!(h.query_all_by_label("Ouvrir NetBuster à l'ouverture de session").next().is_some());
    assert!(h.query_all_by_label("Service de capture").next().is_none());
}
