//! NetBuster : surveillance et gestion du réseau du PC, en temps réel.

use eframe::egui;
use netbuster::collect::Shared;
use netbuster::ui::{App, Page, ScreenshotJob};
use std::path::PathBuf;

/// Petite icône de fenêtre : un signal blanc sur fond bleu.
fn window_icon() -> egui::IconData {
    const S: usize = 64;
    let mut rgba = vec![0u8; S * S * 4];
    let points = [(10.0, 36.0), (22.0, 36.0), (28.0, 18.0), (37.0, 48.0), (43.0, 36.0), (54.0, 36.0)];
    let dist = |x: f32, y: f32| -> f32 {
        points
            .windows(2)
            .map(|w| {
                let (a, b): ((f32, f32), (f32, f32)) = (w[0], w[1]);
                let (dx, dy) = (b.0 - a.0, b.1 - a.1);
                let t = (((x - a.0) * dx + (y - a.1) * dy) / (dx * dx + dy * dy)).clamp(0.0, 1.0);
                ((x - a.0 - t * dx).powi(2) + (y - a.1 - t * dy).powi(2)).sqrt()
            })
            .fold(f32::MAX, f32::min)
    };
    for y in 0..S {
        for x in 0..S {
            let i = (y * S + x) * 4;
            let (fx, fy) = (x as f32, y as f32);
            let c = (fx - 31.5).abs().max((fy - 31.5).abs());
            let corner = ((fx - 31.5).abs() - 19.5).max(0.0).hypot(((fy - 31.5).abs() - 19.5).max(0.0));
            if c > 31.5 || corner > 12.0 {
                continue;
            }
            let white = dist(fx, fy) < 2.6;
            let (r, g, b) = if white { (255, 255, 255) } else { (0x25, 0x6a, 0xbf) };
            rgba[i..i + 4].copy_from_slice(&[r, g, b, 255]);
        }
    }
    egui::IconData { rgba, width: S as u32, height: S as u32 }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let value_of = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();

    if args.iter().any(|a| a == "--helper") {
        std::process::exit(netbuster::helper::run_helper(value_of("--mock").map(PathBuf::from)));
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

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("NetBuster")
            .with_app_id("netbuster")
            .with_inner_size(size.unwrap_or(egui::vec2(1440.0, 900.0)))
            .with_min_inner_size([1100.0, 680.0])
            .with_icon(window_icon()),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };

    let result = eframe::run_native(
        "NetBuster",
        options,
        Box::new(move |_cc| {
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
            app.packets.select_first = select_packet;
            app.about_open = about;
            if conversation {
                app.packets.detail_tab = netbuster::ui::DetailTab::Conversation;
            }
            Ok(Box::new(app))
        }),
    );
    if let Err(e) = result {
        eprintln!("NetBuster n'a pas pu ouvrir sa fenêtre : {e}");
        std::process::exit(1);
    }
}
