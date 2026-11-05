//! NetBuster : surveillance et gestion du réseau du PC, en temps réel.

use eframe::egui;
use netbuster::collect::{Ctl, Shared};
use netbuster::ui::{App, Page, ScreenshotJob};
use std::path::PathBuf;

fn window_icon() -> Option<egui::IconData> {
    let (width, height, rgba) = netbuster::desktop::icon_rgba(256)?;
    Some(egui::IconData { rgba, width, height })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let value_of = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();

    if args.iter().any(|a| a == "--helper") {
        std::process::exit(netbuster::helper::run_helper(value_of("--mock").map(PathBuf::from)));
    }
    if args.iter().any(|a| a == "--daemon") {
        std::process::exit(netbuster::service::run_daemon(value_of("--mock").map(PathBuf::from)));
    }

    let screenshot = value_of("--screenshot").map(|p| ScreenshotJob { path: PathBuf::from(p), requested: false });
    let page = value_of("--page").and_then(|p| Page::from_slug(&p));
    let mock = value_of("--mock-helper");
    let auto_admin = args.iter().any(|a| a == "--auto-admin");
    let trace = value_of("--trace");
    let iface = value_of("--iface");
    let lookup = value_of("--lookup");
    let select_packet = value_of("--select-packet");
    let conversation = args.iter().any(|a| a == "--conversation");
    let about = args.iter().any(|a| a == "--about");
    let size = value_of("--size").and_then(|s| {
        let (w, h) = s.split_once('x')?;
        Some(egui::vec2(w.parse().ok()?, h.parse().ok()?))
    });

    let minimized = args.iter().any(|a| a == "--minimized");
    // Une capture d'écran est un passage isolé : elle ne touche ni au bureau ni à une instance en cours.
    let isolated = screenshot.is_some();

    if !isolated {
        if netbuster::tray::hand_over(minimized) {
            return;
        }
        if let Err(e) = netbuster::desktop::install_launcher() {
            eprintln!("lanceur non installé : {e}");
        }
        netbuster::desktop::refresh_autostart();
    }

    let shared = Shared::start(mock);
    let mut app = App::new(shared.clone());
    if let Some(p) = page {
        app.page = p;
    }
    app.iface = iface;
    app.screenshot = screenshot;
    if auto_admin {
        shared.enable_admin();
    }
    if let Some(t) = trace {
        app.trace.target = t.clone();
        shared.tracer.start(&t, None, netbuster::trace::TraceMode::Icmp);
    }
    if let Some(l) = lookup.and_then(|l| l.parse().ok()) {
        app.go_lookup(l);
        if let Some(p) = page {
            app.page = p;
        }
    }
    // Pour vérifier un écran dans un thème, sans changer le réglage enregistré.
    match value_of("--theme").as_deref() {
        Some("light") => app.settings.settings.theme = netbuster::desktop::ThemeChoice::Light,
        Some("dark") => app.settings.settings.theme = netbuster::desktop::ThemeChoice::Dark,
        _ => {}
    }
    app.packets.select_first = select_packet;
    app.about_open = about;
    if conversation {
        app.packets.detail_tab = netbuster::ui::DetailTab::Conversation;
    }

    let tray = !isolated && {
        netbuster::tray::listen(shared.clone());
        netbuster::tray::start(shared.clone(), minimized)
    };
    shared.tray_available.store(tray, std::sync::atomic::Ordering::Relaxed);
    if !isolated && app.settings.settings.capture_on_open {
        shared.capture_at_open();
    }

    // Sans barre d'état, « réduit » veut dire réduit dans la barre des tâches.
    app.minimize_on_open = minimized && !tray;
    let mut hidden = minimized && tray;
    let mut first = true;
    loop {
        if hidden {
            match shared.control.wait() {
                Ctl::Show => hidden = false,
                Ctl::Hide => continue,
                Ctl::Quit => break,
            }
        }
        let mut viewport = egui::ViewportBuilder::default()
            .with_title("NetBuster")
            .with_app_id(netbuster::desktop::APP_ID)
            .with_inner_size(size.unwrap_or(egui::vec2(1440.0, 900.0)))
            .with_min_inner_size([1100.0, 680.0]);
        if let Some(icon) = window_icon() {
            viewport = viewport.with_icon(icon);
        }
        let options = eframe::NativeOptions { viewport, renderer: eframe::Renderer::Glow, ..Default::default() };
        app.window_opening();
        let result = eframe::run_native("NetBuster", options, Box::new(|_cc| Ok(Box::new(netbuster::ui::Window(&mut app)))));
        if let Err(e) = result {
            eprintln!("NetBuster n'a pas pu ouvrir sa fenêtre : {e}");
            if first || !tray {
                app.shutdown();
                std::process::exit(1);
            }
        }
        first = false;
        if app.reopen_requested {
            continue;
        }
        if app.quit_requested || !tray || !app.settings.settings.close_to_tray {
            break;
        }
        hidden = true;
    }
    app.shutdown();
}
