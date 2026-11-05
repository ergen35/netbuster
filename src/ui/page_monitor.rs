//! Écrans de surveillance : vue d'ensemble, applications, connexions, ports.

use super::chart;
use super::theme::*;
use super::widgets::*;
use super::{App, ConnFilter, Page};
use crate::enrich::{ip_scope, service_from_host, IpScope};
use crate::manage;
use crate::model::{Flow, FlowDir, FlowKey, Model};
use crate::packet::{Crypto, Proto};
use crate::util::{fmt_bytes, fmt_count, fmt_duration, fmt_ms, fmt_rate};
use eframe::egui::{self, Align, Layout, Margin, Pos2, Rect, RichText, Ui, Vec2};
use egui_phosphor::regular as icon;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

pub fn tile(ui: &mut Ui, width: f32, title: &str, sym: Option<(&str, egui::Color32)>, value: &str, sub: &str) {
    ui.allocate_ui_with_layout(Vec2::new(width, 92.0), Layout::top_down(Align::Min), |ui| {
        card(ui, |ui| {
            ui.set_width(width - 30.0);
            ui.set_min_height(62.0);
            ui.spacing_mut().item_spacing.y = 3.0;
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                if let Some((s, c)) = sym {
                    ui.label(RichText::new(s).color(c).size(14.0));
                }
                ui.label(RichText::new(title).color(pal().ink2).size(12.5));
            });
            ui.label(RichText::new(value).font(bold(24.0)).color(pal().ink));
            ui.add(egui::Label::new(RichText::new(sub).color(pal().muted).size(12.0)).truncate());
        });
    });
}

fn scope_note(app: &App) -> String {
    match &app.iface {
        Some(i) => format!("Interface {i}"),
        None => "Toutes les interfaces".into(),
    }
}

/// Nom le plus parlant pour le correspondant d'une connexion.
pub fn remote_name(app: &App, m: &Model, f: &Flow) -> String {
    if let Some(h) = &f.host {
        return h.clone();
    }
    let ip = f.key.remote.ip();
    if let Some(n) = m.dns_names.get(&ip) {
        return n.clone();
    }
    if let Some(n) = app.shared.enrich.info(ip).and_then(|i| i.rdns) {
        return n;
    }
    String::new()
}

pub fn provider_label(app: &App, m: &Model, f: &Flow) -> String {
    let ip = f.key.remote.ip();
    if f.is_listener() {
        return String::new();
    }
    let scope = ip_scope(ip);
    if scope != IpScope::Public {
        return scope.label().to_string();
    }
    let name = remote_name(app, m, f);
    if let Some(s) = service_from_host(&name) {
        return s;
    }
    app.shared.enrich.provider_of(ip).unwrap_or_default()
}

pub fn dir_symbol(d: FlowDir) -> (&'static str, egui::Color32) {
    match d {
        FlowDir::Incoming => (icon::ARROW_DOWN, pal().rx),
        FlowDir::Outgoing => (icon::ARROW_UP, pal().tx),
        FlowDir::Listening => (icon::DOOR_OPEN, pal().muted),
        FlowDir::Local => (icon::ARROWS_LEFT_RIGHT, pal().muted),
    }
}

pub fn crypto_symbol(c: Crypto) -> (&'static str, egui::Color32) {
    match c {
        Crypto::Yes => (icon::LOCK, pal().good),
        Crypto::Probable => (icon::LOCK, pal().muted),
        Crypto::No => (icon::LOCK_OPEN, pal().warning),
        Crypto::Unknown => (icon::QUESTION, pal().muted),
    }
}

// ---------- Vue d'ensemble ----------

pub fn overview(app: &mut App, ui: &mut Ui) {
    let shared = app.shared.clone();
    let m = shared.model.lock().unwrap();
    let iface = app.iface.clone();
    let iface_ref = iface.as_deref();
    let (rx, tx) = m.current_rates(iface_ref);
    let counted = m.counted_names();
    let (day_rx, day_tx) = m.usage.day_total(&crate::model::today(), iface_ref, &counted);

    let visible: Vec<&Flow> = m.flows.values().filter(|f| f.open && m.flow_visible(f, iface_ref, false)).collect();
    let incoming = visible.iter().filter(|f| f.dir == FlowDir::Incoming).count();
    let outgoing = visible.iter().filter(|f| f.dir == FlowDir::Outgoing).count();
    let listening = visible.iter().filter(|f| f.dir == FlowDir::Listening).count();
    let exposed = visible.iter().filter(|f| f.dir == FlowDir::Listening && !f.key.local.ip().is_loopback()).map(|f| (f.key.proto, f.key.local.port())).collect::<HashSet<_>>().len();
    let (session_rx, session_tx) = match iface_ref {
        Some(n) => m.ifaces.get(n).map(|i| (i.session_rx, i.session_tx)).unwrap_or((0, 0)),
        None => m.ifaces.values().filter(|i| i.counted()).fold((0, 0), |a, i| (a.0 + i.session_rx, a.1 + i.session_tx)),
    };

    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        let w = ui.available_width();
        let gap = 10.0;
        let tw = (w - 4.0 * gap) / 5.0;
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            tile(ui, tw, "Reçu maintenant", Some((icon::ARROW_DOWN, pal().rx)), &fmt_rate(rx), &format!("{} depuis l'ouverture", fmt_bytes(session_rx)));
            tile(ui, tw, "Envoyé maintenant", Some((icon::ARROW_UP, pal().tx)), &fmt_rate(tx), &format!("{} depuis l'ouverture", fmt_bytes(session_tx)));
            tile(ui, tw, "Consommé aujourd'hui", None, &fmt_bytes(day_rx + day_tx), &format!("{} {}   {} {}", icon::ARROW_DOWN, fmt_bytes(day_rx), icon::ARROW_UP, fmt_bytes(day_tx)));
            tile(ui, tw, "Connexions actives", None, &fmt_count((incoming + outgoing) as u64), &format!("{} {}, {} {}", incoming, if incoming > 1 { "entrantes" } else { "entrante" }, outgoing, if outgoing > 1 { "sortantes" } else { "sortante" }));
            tile(ui, tw, "Ports exposés au réseau", None, &fmt_count(exposed as u64), &format!("{} au total", plural(listening, "point d'écoute").replace("point d'écoutes", "points d'écoute")));
        });
        ui.add_space(4.0);

        card(ui, |ui| {
            ui.horizontal(|ui| {
                section_title(ui, "Bande passante");
                ui.label(RichText::new(scope_note(app)).color(pal().muted).size(12.5));
                ui.add_space(10.0);
                chart::legend_value(ui, pal().rx, "Reçu", &fmt_rate(rx));
                chart::legend_value(ui, pal().tx, "Envoyé", &fmt_rate(tx));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    chips(ui, &mut app.range_secs, &[(60.0, "1 min"), (300.0, "5 min"), (900.0, "15 min"), (3600.0, "1 h")]);
                });
            });
            ui.add_space(4.0);
            if let Some(h) = m.iface_or_total_history(iface_ref) {
                chart::throughput(ui, h, m.now(), app.range_secs, 230.0);
            }
        });
        ui.add_space(4.0);

        let columns = (ui.available_width() - gap) / 2.0;
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            ui.allocate_ui_with_layout(Vec2::new(columns, 10.0), Layout::top_down(Align::Min), |ui| {
                ui.set_width(columns);
                // Les deux listes qui bougent : figées ensemble, la bande passante reste en direct.
                let frozen = app.overview_freeze.view.clone();
                let lists: &Model = frozen.as_deref().unwrap_or(&m);
                card(ui, |ui| {
                    ui.set_width(columns - 30.0);
                    top_apps(app, ui, lists, iface_ref);
                });
                ui.add_space(4.0);
                card(ui, |ui| {
                    ui.set_width(columns - 30.0);
                    recent_events(app, ui, lists, &m);
                });
            });
            ui.allocate_ui_with_layout(Vec2::new(columns, 10.0), Layout::top_down(Align::Min), |ui| {
                ui.set_width(columns);
                card(ui, |ui| {
                    ui.set_width(columns - 30.0);
                    interfaces_list(app, ui, &m);
                });
            });
        });
    });
}

fn top_apps(app: &mut App, ui: &mut Ui, m: &Model, iface: Option<&str>) {
    ui.horizontal(|ui| {
        section_title(ui, "Applications les plus actives");
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if small_button(ui, "Tout voir").clicked() {
                app.page = Page::Apps;
            }
        });
    });
    if !crate::platform::full_features() {
        hint(ui, &format!("Sous {}, le volume de chaque programme n'est pas encore mesuré. Leurs connexions sont dans l'écran Applications.", crate::platform::system_name()));
        return;
    }
    let tree = m.app_tree(iface, false, false);
    if tree.is_empty() {
        hint(ui, "Aucune application n'échange de données pour le moment.");
        return;
    }
    let scale = tree.iter().map(|a| a.rate()).fold(0.0, f64::max);
    let cols = [flex("", 1.2), flex("", 1.0), col_r("", 76.0), col_r("", 76.0)];
    for a in tree.iter().take(6) {
        let (rect, resp) = table_row(ui, 28.0, false, &a.name);
        let r = col_rects(rect, &cols);
        cell(ui, r[0], &a.name, &body(13.0), pal().ink, false);
        chart::split_bar(ui, r[1].shrink2(Vec2::new(4.0, 0.0)), a.rx_rate, a.tx_rate, scale);
        cell(ui, r[2], &fmt_rate(a.rx_rate), &mono(11.5), pal().ink2, true);
        cell(ui, r[3], &fmt_rate(a.tx_rate), &mono(11.5), pal().ink2, true);
        if resp.clicked() {
            app.apps.expanded.insert(a.name.clone());
            app.page = Page::Apps;
        }
    }
}

fn recent_events(app: &mut App, ui: &mut Ui, m: &Model, live: &Model) {
    ui.horizontal(|ui| {
        section_title(ui, "Activité récente");
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            // Dans cette zone, le dernier ajouté se place à gauche : le bouton reste contre le bord.
            freeze_button(ui, &mut app.overview_freeze, live);
        });
    });
    if m.events.is_empty() {
        hint(ui, "Les connexions qui s'ouvrent et se ferment apparaîtront ici.");
        return;
    }
    for e in m.events.iter().rev().take(8) {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            ui.label(RichText::new(&e.wall).font(mono(11.5)).color(pal().muted));
            let (sym, c) = if e.opened { (icon::PLUS_CIRCLE, pal().good) } else { (icon::MINUS_CIRCLE, pal().muted) };
            ui.label(RichText::new(sym).color(c).size(14.0));
            ui.add(egui::Label::new(RichText::new(&e.app).color(pal().ink).size(12.5)).truncate());
            ui.label(RichText::new(if e.opened { "ouvre" } else { "ferme" }).font(mono(11.5)).color(pal().ink2));
            copy_inline(ui, &e.remote.ip().to_string());
            ui.label(RichText::new(e.remote.to_string()).font(mono(11.5)).color(pal().ink2));
        });
    }
}

fn interfaces_list(app: &mut App, ui: &mut Ui, m: &Model) {
    section_title(ui, "Interfaces");
    let mut list: Vec<_> = m.ifaces.values().filter(|i| !i.bridge_port).collect();
    list.sort_by_key(|i| (!i.counted(), i.kind == crate::model::IfKind::Loopback, i.name.clone()));
    let cols = [flex("Nom", 1.0), col("État", 92.0), col_r("Reçu", 80.0), col_r("Envoyé", 80.0), col("Activité", 96.0)];
    table_header(ui, &cols, None);
    for i in list {
        let selected = app.iface.as_deref() == Some(i.name.as_str());
        let (rect, resp) = table_row(ui, 42.0, selected, &i.name);
        let r = col_rects(rect, &cols);
        let top = Rect::from_min_size(r[0].min, Vec2::new(r[0].width(), 24.0));
        let bottom = Rect::from_min_max(Pos2::new(r[0].left(), r[0].top() + 21.0), r[0].max);
        cell(ui, top, &i.name, &body(13.0), pal().ink, false);
        let addr = i.addrs.iter().find(|a| a.0.is_ipv4()).or(i.addrs.first()).map(|a| a.0.to_string());
        match &addr {
            Some(a) => ip_cell(ui, bottom, a, &format!("{}  {a}", i.kind.label()), &body(11.5), pal().muted),
            None => cell(ui, bottom, i.kind.label(), &body(11.5), pal().muted, false),
        }
        let (sym, c, label) = if i.is_up() { (icon::CHECK_CIRCLE, pal().good, "Active") } else { (icon::MINUS_CIRCLE, pal().muted, "Inactive") };
        icon_cell(ui, r[1], sym, c, label, &body(12.0), pal().ink2);
        cell(ui, r[2], &fmt_rate(i.rx_rate), &mono(11.5), pal().ink2, true);
        cell(ui, r[3], &fmt_rate(i.tx_rate), &mono(11.5), pal().ink2, true);
        chart::spark_samples_in(ui, r[4], &i.history, 120);
        if resp.clicked() {
            app.iface = if selected { None } else { Some(i.name.clone()) };
        }
        resp.on_hover_text(format!(
            "Depuis le démarrage du PC : {down} {}  {up} {}\nPaquets : {down} {}  {up} {}\nErreurs : {}  Perdus : {}",
            fmt_bytes(i.rx_total),
            fmt_bytes(i.tx_total),
            fmt_count(i.rx_packets),
            fmt_count(i.tx_packets),
            i.rx_errors + i.tx_errors,
            i.rx_dropped + i.tx_dropped,
            down = icon::ARROW_DOWN,
            up = icon::ARROW_UP,
        ));
    }
}

// ---------- Applications ----------

enum TreeRow {
    App(usize),
    Pid(usize, usize),
    Flow(FlowKey, u8),
}

pub fn apps(app: &mut App, ui: &mut Ui) {
    let shared = app.shared.clone();
    let live = shared.model.lock().unwrap();
    let frozen = app.apps.freeze.view.clone();
    let m: &Model = frozen.as_deref().unwrap_or(&live);
    let capturing = m.capture.running;
    let iface = app.iface.clone();
    let mut tree = m.app_tree(iface.as_deref(), app.apps.show_local, false);
    let q = app.apps.search.to_lowercase();
    if !q.is_empty() {
        tree.retain(|a| {
            a.name.to_lowercase().contains(&q)
                || a.pids.iter().any(|p| {
                    p.pid.is_some_and(|x| x.to_string().contains(&q))
                        || p.flows.iter().any(|k| {
                            k.remote.to_string().contains(&q) || m.flows[k].host.as_deref().is_some_and(|h| h.to_lowercase().contains(&q))
                        })
                })
        });
    }

    ui.horizontal(|ui| {
        search_box(ui, &mut app.apps.search, "Programme, PID, adresse, site…", 300.0);
        ui.checkbox(&mut app.apps.show_local, "Boucle locale").on_hover_text("Le trafic qu'un programme échange avec un autre programme de ce PC.");
        freeze_button(ui, &mut app.apps.freeze, &live);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if crate::platform::full_features() {
                let (text, c) = if capturing { ("Mesure au paquet près, TCP et UDP", pal().good) } else { ("Mesure par compteurs TCP", pal().warning) };
                status_badge(ui, if capturing { icon::CHECK_CIRCLE } else { icon::INFO }, c, text);
            }
        });
    });
    if !capturing {
        let (rx, tx) = m.current_rates(iface.as_deref());
        let attributed: (f64, f64) = tree.iter().fold((0.0, 0.0), |s, a| (s.0 + a.rx_rate, s.1 + a.tx_rate));
        let missing = (rx - attributed.0).max(0.0) + (tx - attributed.1).max(0.0);
        if !crate::platform::full_features() {
            let t = format!(
                "Sous {}, NetBuster mesure le débit de chaque interface et liste les connexions de chaque programme, mais pas encore le volume de chaque programme.",
                crate::platform::system_name()
            );
            notice(ui, icon::INFO, pal().rx, "Débits par interface", &t, None);
        } else if iface.as_deref() != Some("lo") && missing > 2048.0 {
            let t = format!(
                "{} ne sont liés à aucun programme : c'est du trafic UDP (HTTP/3, visioconférence, DNS), des en-têtes, ou le trafic de services système. Le mode administrateur mesure tout, paquet par paquet.",
                fmt_rate(missing)
            );
            if notice(ui, icon::INFO, pal().warning, "Une partie du trafic n'est pas attribuée", &t, Some("Passer administrateur")) {
                shared.enable_admin();
            }
        }
    }
    ui.add_space(2.0);

    let mut rows: Vec<TreeRow> = vec![];
    for (ai, a) in tree.iter().enumerate() {
        rows.push(TreeRow::App(ai));
        if !app.apps.expanded.contains(&a.name) {
            continue;
        }
        if a.pids.len() > 1 {
            for (pi, p) in a.pids.iter().enumerate() {
                rows.push(TreeRow::Pid(ai, pi));
                if !app.apps.collapsed_pids.contains(&(a.name.clone(), p.pid)) {
                    for k in &p.flows {
                        rows.push(TreeRow::Flow(*k, 2));
                    }
                }
            }
        } else if let Some(p) = a.pids.first() {
            for k in &p.flows {
                rows.push(TreeRow::Flow(*k, 1));
            }
        }
    }

    let cols = [flex("Programme et appels ouverts", 1.0), col_r("Reçu", 86.0), col_r("Envoyé", 86.0), col_r("Total reçu", 84.0), col_r("Total envoyé", 88.0), col("Activité", 116.0), col("", 112.0)];

    let selected_flow = app.apps.selected.and_then(|k| m.flows.get(&k).cloned());
    if selected_flow.is_some() {
        egui::Panel::bottom("apps_detail")
            .exact_size(214.0)
            .resizable(false)
            .show_separator_line(false)
            .frame(egui::Frame::new().inner_margin(Margin { top: 8, ..Default::default() }))
            .show(ui, |ui| {
                if let Some(f) = &selected_flow {
                    if flow_detail(app, ui, &m, f) {
                        app.apps.selected = None;
                    }
                }
            });
    }

    table_header(ui, &cols, None);
    if rows.is_empty() {
        ui.add_space(14.0);
        hint(ui, if q.is_empty() { "Aucun programme n'a de connexion ouverte sur cette interface." } else { "Aucun résultat pour cette recherche." });
        return;
    }
    egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, 32.0, rows.len(), |ui, range| {
        ui.spacing_mut().item_spacing.y = 0.0;
        for row in &rows[range] {
            match row {
                TreeRow::App(ai) => {
                    let a = &tree[*ai];
                    let open = app.apps.expanded.contains(&a.name);
                    let (rect, resp) = table_row(ui, 32.0, false, &a.name);
                    let r = col_rects(rect, &cols);
                    ui.painter().text(Pos2::new(r[0].left() + 10.0, r[0].center().y), egui::Align2::CENTER_CENTER, if open { icon::CARET_DOWN } else { icon::CARET_RIGHT }, body(12.0), pal().ink2);
                    let name_r = Rect::from_min_max(Pos2::new(r[0].left() + 18.0, r[0].top()), r[0].max);
                    let suffix = match a.pids.as_slice() {
                        [one] => one.pid.map(|p| format!("  ·  processus {p}")).unwrap_or_default(),
                        many => format!("  ·  {} processus", many.len()),
                    };
                    cell(ui, name_r, &format!("{}{}  ·  {}", a.name, suffix, plural(a.open_flows, "appel")), &bold(13.0), pal().ink, false);
                    cell(ui, r[1], &fmt_rate(a.rx_rate), &mono(12.0), pal().ink, true);
                    cell(ui, r[2], &fmt_rate(a.tx_rate), &mono(12.0), pal().ink, true);
                    cell(ui, r[3], &fmt_bytes(a.rx_total), &mono(12.0), pal().ink2, true);
                    cell(ui, r[4], &fmt_bytes(a.tx_total), &mono(12.0), pal().ink2, true);
                    let key = (iface.clone().unwrap_or_default(), a.name.clone());
                    if let Some(h) = m.app_hist.get(&key) {
                        chart::spark_in(ui, r[5], h);
                    }
                    if resp.clicked() {
                        if open {
                            app.apps.expanded.remove(&a.name);
                        } else {
                            app.apps.expanded.insert(a.name.clone());
                        }
                    }
                }
                TreeRow::Pid(ai, pi) => {
                    let a = &tree[*ai];
                    let p = &a.pids[*pi];
                    let k = (a.name.clone(), p.pid);
                    let open = !app.apps.collapsed_pids.contains(&k);
                    let label = p.pid.map(|x| format!("Processus {x}")).unwrap_or_else(|| "Processus inconnu".into());
                    let (rect, resp) = table_row(ui, 32.0, false, &label);
                    let r = col_rects(rect, &cols);
                    ui.painter().text(Pos2::new(r[0].left() + 28.0, r[0].center().y), egui::Align2::CENTER_CENTER, if open { icon::CARET_DOWN } else { icon::CARET_RIGHT }, body(12.0), pal().ink2);
                    let name_r = Rect::from_min_max(Pos2::new(r[0].left() + 36.0, r[0].top()), r[0].max);
                    let extra = p.pid.and_then(|x| m.procs.get(&x)).map(|i| i.cmdline.clone()).unwrap_or_default();
                    cell(ui, name_r, &format!("{label}  ·  {}  {extra}", plural(p.open_flows, "appel")), &body(12.5), pal().ink2, false);
                    cell(ui, r[1], &fmt_rate(p.rx_rate), &mono(12.0), pal().ink2, true);
                    cell(ui, r[2], &fmt_rate(p.tx_rate), &mono(12.0), pal().ink2, true);
                    cell(ui, r[3], &fmt_bytes(p.rx_total), &mono(12.0), pal().muted, true);
                    cell(ui, r[4], &fmt_bytes(p.tx_total), &mono(12.0), pal().muted, true);
                    if resp.clicked() {
                        if open {
                            app.apps.collapsed_pids.insert(k);
                        } else {
                            app.apps.collapsed_pids.remove(&k);
                        }
                    }
                }
                TreeRow::Flow(key, depth) => {
                    let Some(f) = m.flows.get(key) else { continue };
                    let selected = app.apps.selected == Some(*key);
                    let name = remote_name(app, &m, f);
                    let provider = provider_label(app, &m, f);
                    let label = format!("Appel vers {}", f.key.remote);
                    let (rect, resp) = table_row(ui, 32.0, selected, &label);
                    let r = col_rects(rect, &cols);
                    let indent = 20.0 + 16.0 * *depth as f32;
                    let (sym, c) = dir_symbol(f.dir);
                    ui.painter().text(Pos2::new(r[0].left() + indent, r[0].center().y), egui::Align2::CENTER_CENTER, sym, body(13.0), c);
                    let text_r = Rect::from_min_max(Pos2::new(r[0].left() + indent + 10.0, r[0].top()), r[0].max);
                    let who = if name.is_empty() { f.key.remote.to_string() } else { format!("{name}  ({})", f.key.remote) };
                    let proto = if f.app_proto.is_empty() { f.key.proto.label() } else { f.app_proto };
                    let tail = if provider.is_empty() { String::new() } else { format!("  ·  {provider}") };
                    let color = if f.open { pal().ink2 } else { pal().muted };
                    ip_cell(ui, text_r, &f.key.remote.ip().to_string(), &format!("{proto}  {who}{tail}"), &body(12.5), color);
                    cell(ui, r[1], &fmt_rate(f.rx_rate), &mono(11.5), color, true);
                    cell(ui, r[2], &fmt_rate(f.tx_rate), &mono(11.5), color, true);
                    cell(ui, r[3], &fmt_bytes(f.rx_total), &mono(11.5), pal().muted, true);
                    cell(ui, r[4], &fmt_bytes(f.tx_total), &mono(11.5), pal().muted, true);
                    chart::spark_in(ui, r[5], &f.hist);
                    if !f.is_listener() && ip_scope(f.key.remote.ip()) == IpScope::Public {
                        let ip = f.key.remote.ip();
                        let (ifn, port) = (f.iface.clone(), (f.key.proto == Proto::Tcp).then_some(f.key.remote.port()));
                        in_cell(ui, r[6], |ui| {
                            ui.spacing_mut().item_spacing.x = 3.0;
                            if small_button(ui, "Tracer").clicked() {
                                app.go_trace(ip, ifn, port);
                            }
                            if small_button(ui, "Qui ?").clicked() {
                                app.go_lookup(ip);
                            }
                        });
                    }
                    if resp.clicked() {
                        app.apps.selected = if selected { None } else { Some(*key) };
                    }
                }
            }
        }
    });
}

/// Fiche d'une connexion. Rend vrai si l'on demande sa fermeture.
pub fn flow_detail(app: &mut App, ui: &mut Ui, m: &Model, f: &Flow) -> bool {
    let mut close = false;
    card(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            let (sym, c) = dir_symbol(f.dir);
            ui.label(RichText::new(sym).color(c).size(16.0));
            ui.label(RichText::new(format!("{} — {} {}", f.app_name(), f.dir.label().to_lowercase(), f.key.proto.label())).font(bold(14.0)).color(pal().ink));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if small_button(ui, icon::X).on_hover_text("Fermer cette fiche").clicked() {
                    close = true;
                }
                if crate::platform::full_features() && f.open && !f.is_listener() {
                    if let Some(pid) = f.pid {
                        if small_button(ui, "Arrêter le programme").clicked() {
                            let mine = f.uid == crate::platform::own_uid();
                            app.ask(manage::kill_process_action(pid, &f.app_name(), !mine));
                        }
                    }
                    if f.key.proto == Proto::Tcp && small_button(ui, "Couper la connexion").clicked() {
                        app.ask(manage::kill_socket_action(&f.key.local.to_string(), &f.key.remote.to_string(), &f.app_name()));
                    }
                }
                if crate::platform::full_features() && f.key.remote.port() != 0 && small_button(ui, "Voir ses paquets").clicked() {
                    app.packets.flow_filter = Some(crate::model::StreamKey::new(f.key.proto, f.key.local, f.key.remote));
                    app.packets.selected = None;
                    app.page = Page::Packets;
                }
                if ip_scope(f.key.remote.ip()) == IpScope::Public {
                    if small_button(ui, "Qui est-ce ?").clicked() {
                        app.go_lookup(f.key.remote.ip());
                    }
                    if small_button(ui, "Tracer la route").clicked() {
                        app.go_trace(f.key.remote.ip(), f.iface.clone(), (f.key.proto == Proto::Tcp).then_some(f.key.remote.port()));
                    }
                }
            });
        });
        ui.add_space(4.0);
        let columns = ui.available_width() / 3.0;
        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(Vec2::new(columns, 120.0), Layout::top_down(Align::Min), |ui| {
                ui.set_width(columns);
                ui.spacing_mut().item_spacing.y = 2.0;
                kv_ip(ui, "Adresse locale", &f.key.local.to_string());
                kv_ip(ui, "Correspondant", &f.key.remote.to_string());
                kv(ui, "Nom", &non_empty(remote_name(app, m, f)));
                kv(ui, "Fournisseur", &non_empty(provider_label(app, m, f)));
                kv(ui, "Interface", f.iface.as_deref().unwrap_or("Toutes"));
            });
            ui.allocate_ui_with_layout(Vec2::new(columns, 120.0), Layout::top_down(Align::Min), |ui| {
                ui.set_width(columns);
                ui.spacing_mut().item_spacing.y = 2.0;
                kv(ui, "État", f.state_label());
                kv(ui, "Ouverte depuis", &fmt_duration(m.now() - f.first_seen));
                kv(ui, "Protocole", if f.app_proto.is_empty() { f.key.proto.label() } else { f.app_proto });
                kv(ui, "Chiffrement", f.crypto.label());
                kv(ui, "Latence", &f.rtt_ms.map(|r| fmt_ms(r as f64)).unwrap_or_else(|| "—".into()));
            });
            ui.allocate_ui_with_layout(Vec2::new(columns - 16.0, 120.0), Layout::top_down(Align::Min), |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                kv(ui, "Processus", &f.pid.map(|p| format!("{p}, descripteur {}", f.fd)).unwrap_or_else(|| "Masqué sans droits".into()));
                if let Some(info) = f.pid.and_then(|p| m.procs.get(&p)) {
                    kv(ui, "Utilisateur", &info.user);
                }
                kv(ui, "Reçu", &format!("{} ({})", fmt_bytes(f.rx_total), fmt_rate(f.rx_rate)));
                kv(ui, "Envoyé", &format!("{} ({})", fmt_bytes(f.tx_total), fmt_rate(f.tx_rate)));
                let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 34.0), egui::Sense::hover());
                chart::spark_in(ui, rect, &f.hist);
            });
        });
    });
    close
}

fn non_empty(s: String) -> String {
    if s.is_empty() {
        "—".into()
    } else {
        s
    }
}

// ---------- Connexions ----------

pub fn connections(app: &mut App, ui: &mut Ui) {
    let shared = app.shared.clone();
    let live = shared.model.lock().unwrap();
    let frozen = app.conns.freeze.view.clone();
    let m: &Model = frozen.as_deref().unwrap_or(&live);
    let iface = app.iface.clone();

    let all: Vec<&Flow> = m.flows.values().filter(|f| m.flow_visible(f, iface.as_deref(), app.conns.show_local)).collect();
    let n_in = all.iter().filter(|f| f.open && f.dir == FlowDir::Incoming).count();
    let n_out = all.iter().filter(|f| f.open && f.dir == FlowDir::Outgoing).count();
    let n_listen = all.iter().filter(|f| f.open && f.dir == FlowDir::Listening).count();

    // Passe à la ligne sur une fenêtre étroite : le bouton « Figer » doit rester accessible.
    ui.horizontal_wrapped(|ui| {
        let (a, b, c, d) = (format!("Actives  {}", n_in + n_out), format!("Entrantes  {n_in}"), format!("Sortantes  {n_out}"), format!("En écoute  {n_listen}"));
        chips(ui, &mut app.conns.filter, &[(ConnFilter::All, a.as_str()), (ConnFilter::In, b.as_str()), (ConnFilter::Out, c.as_str()), (ConnFilter::Listen, d.as_str())]);
        search_box(ui, &mut app.conns.search, "Programme, adresse, port, site…", 260.0);
        ui.checkbox(&mut app.conns.show_local, "Boucle locale");
        ui.checkbox(&mut app.conns.show_closed, "Fermées récemment");
        freeze_button(ui, &mut app.conns.freeze, &live);
    });
    ui.add_space(2.0);

    let q = app.conns.search.to_lowercase();
    let mut rows: Vec<(&Flow, String, String)> = all
        .into_iter()
        .filter(|f| match app.conns.filter {
            ConnFilter::All => !f.is_listener(),
            ConnFilter::In => f.dir == FlowDir::Incoming,
            ConnFilter::Out => f.dir == FlowDir::Outgoing,
            ConnFilter::Listen => f.dir == FlowDir::Listening,
        })
        .filter(|f| f.open || app.conns.show_closed)
        .map(|f| (f, remote_name(app, &m, f), provider_label(app, &m, f)))
        .filter(|(f, name, prov)| {
            q.is_empty()
                || f.app_name().to_lowercase().contains(&q)
                || f.key.local.to_string().contains(&q)
                || f.key.remote.to_string().contains(&q)
                || name.to_lowercase().contains(&q)
                || prov.to_lowercase().contains(&q)
                || f.pid.is_some_and(|p| p.to_string() == q)
        })
        .collect();

    // Sur une fenêtre étroite, les colonnes fixes se serrent pour laisser le nom et le fournisseur visibles.
    let narrow = ui.available_width() < 1000.0;
    let cols = [
        col("Programme", if narrow { 118.0 } else { 150.0 }),
        col("Sens", if narrow { 78.0 } else { 90.0 }),
        col("Proto", if narrow { 48.0 } else { 62.0 }),
        col("Correspondant", 190.0),
        flex("Nom", 1.2),
        flex("Fournisseur", 1.0),
        col("État", if narrow { 76.0 } else { 100.0 }),
        col_r("Reçu", if narrow { 76.0 } else { 84.0 }),
        col_r("Envoyé", if narrow { 76.0 } else { 84.0 }),
        col_r("Latence", if narrow { 60.0 } else { 72.0 }),
    ];
    let sort = app.conns.sort.clone();
    rows.sort_by(|a, b| {
        let (x, y) = (a.0, b.0);
        let o = match sort.col {
            0 => x.app_name().to_lowercase().cmp(&y.app_name().to_lowercase()),
            1 => x.dir.label().cmp(y.dir.label()),
            2 => x.key.proto.cmp(&y.key.proto),
            3 => x.key.remote.cmp(&y.key.remote),
            4 => a.1.cmp(&b.1),
            5 => a.2.cmp(&b.2),
            6 => x.state_label().cmp(y.state_label()),
            7 => x.rx_rate.total_cmp(&y.rx_rate).then(x.rx_total.cmp(&y.rx_total)),
            8 => x.tx_rate.total_cmp(&y.tx_rate).then(x.tx_total.cmp(&y.tx_total)),
            _ => x.rtt_ms.unwrap_or(-1.0).total_cmp(&y.rtt_ms.unwrap_or(-1.0)),
        };
        let o = if sort.desc { o.reverse() } else { o };
        o.then_with(|| x.key.cmp(&y.key))
    });

    let selected = app.conns.selected.and_then(|k| m.flows.get(&k).cloned());
    if let Some(f) = &selected {
        egui::Panel::bottom("conn_detail")
            .exact_size(214.0)
            .resizable(false)
            .show_separator_line(false)
            .frame(egui::Frame::new().inner_margin(Margin { top: 8, ..Default::default() }))
            .show(ui, |ui| {
                if flow_detail(app, ui, &m, f) {
                    app.conns.selected = None;
                }
            });
    }

    table_header(ui, &cols, Some(&mut app.conns.sort));
    if rows.is_empty() {
        ui.add_space(14.0);
        hint(ui, "Aucune connexion ne correspond à ces critères.");
        return;
    }
    egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, 30.0, rows.len(), |ui, range| {
        ui.spacing_mut().item_spacing.y = 0.0;
        for (f, name, prov) in &rows[range] {
            let is_sel = app.conns.selected == Some(f.key);
            let (rect, resp) = table_row(ui, 30.0, is_sel, &format!("{} {}", f.app_name(), f.key.remote));
            let r = col_rects(rect, &cols);
            let ink = if f.open { pal().ink } else { pal().muted };
            let ink2 = if f.open { pal().ink2 } else { pal().muted };
            cell(ui, r[0], &f.app_name(), &body(13.0), ink, false);
            let (sym, c) = dir_symbol(f.dir);
            icon_cell(ui, r[1], sym, c, f.dir.label(), &body(12.0), ink2);
            cell(ui, r[2], if f.app_proto.is_empty() { f.key.proto.label() } else { f.app_proto }, &body(12.0), ink2, false);
            let shown = if f.is_listener() { f.key.local } else { f.key.remote };
            ip_cell(ui, r[3], &shown.ip().to_string(), &shown.to_string(), &mono(12.0), ink2);
            cell(ui, r[4], name, &body(12.5), ink2, false);
            cell(ui, r[5], prov, &body(12.5), ink2, false);
            cell(ui, r[6], f.state_label(), &body(12.0), ink2, false);
            cell(ui, r[7], &fmt_rate(f.rx_rate), &mono(11.5), ink2, true);
            cell(ui, r[8], &fmt_rate(f.tx_rate), &mono(11.5), ink2, true);
            cell(ui, r[9], &f.rtt_ms.map(|v| fmt_ms(v as f64)).unwrap_or_default(), &mono(11.5), ink2, true);
            if resp.clicked() {
                app.conns.selected = if is_sel { None } else { Some(f.key) };
            }
        }
    });
}

// ---------- Ports ----------

fn services() -> &'static HashMap<(u16, String), String> {
    static MAP: OnceLock<HashMap<(u16, String), String>> = OnceLock::new();
    MAP.get_or_init(|| {
        let text = std::fs::read_to_string(crate::platform::services_file()).unwrap_or_default();
        let mut out = HashMap::new();
        for l in text.lines() {
            let l = l.split('#').next().unwrap_or("").trim();
            let mut it = l.split_whitespace();
            let (Some(name), Some(pp)) = (it.next(), it.next()) else { continue };
            let Some((port, proto)) = pp.split_once('/') else { continue };
            if let Ok(p) = port.parse() {
                out.insert((p, proto.to_string()), name.to_string());
            }
        }
        out
    })
}

fn port_exposure(f: &Flow) -> (&'static str, egui::Color32, String) {
    let ip = f.key.local.ip();
    if ip.is_loopback() {
        (icon::HOUSE, pal().good, "Ce PC seulement".to_string())
    } else if ip.is_unspecified() {
        (icon::GLOBE, pal().warning, "Tout le réseau".to_string())
    } else {
        (icon::SHARE_NETWORK, pal().serious, format!("Via {}", f.iface.clone().unwrap_or_else(|| ip.to_string())))
    }
}

pub fn ports(app: &mut App, ui: &mut Ui) {
    let shared = app.shared.clone();
    let live = shared.model.lock().unwrap();
    let frozen = app.ports.freeze.view.clone();
    let m: &Model = frozen.as_deref().unwrap_or(&live);
    let iface = app.iface.clone();
    let ufw_active = manage::ufw_conf_enabled();

    let mut rows: Vec<&Flow> = m.flows.values().filter(|f| f.open && f.dir == FlowDir::Listening && m.flow_visible(f, iface.as_deref(), true)).collect();
    // Un même port peut écouter à la fois en IPv4 et en IPv6 : on compte des ports, pas des sockets.
    let exposed_set: HashSet<(Proto, u16)> = rows.iter().filter(|f| !f.key.local.ip().is_loopback()).map(|f| (f.key.proto, f.key.local.port())).collect();
    let local_set: HashSet<(Proto, u16)> = rows.iter().filter(|f| f.key.local.ip().is_loopback()).map(|f| (f.key.proto, f.key.local.port())).filter(|k| !exposed_set.contains(k)).collect();

    ui.horizontal(|ui| {
        status_badge(ui, icon::GLOBE, pal().warning, &format!("{} joignables depuis le réseau", plural(exposed_set.len(), "port")));
        ui.add_space(6.0);
        status_badge(ui, icon::HOUSE, pal().good, &format!("{} limités à ce PC", plural(local_set.len(), "port")));
        ui.add_space(6.0);
        if crate::platform::full_features() {
            status_badge(ui, icon::SHIELD_CHECK, if ufw_active { pal().good } else { pal().muted }, if ufw_active { "Pare-feu UFW actif" } else { "UFW inactif" });
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            search_box(ui, &mut app.ports.search, "Port, programme…", 200.0);
            freeze_button(ui, &mut app.ports.freeze, &live);
        });
    });

    // Formulaire : ouvrir ou fermer n'importe quel port.
    if crate::platform::full_features() {
    ui.add_space(4.0);
    card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Ouvrir ou fermer un port").font(bold(13.5)).color(pal().ink));
            ui.add(egui::TextEdit::singleline(&mut app.ports.new_port).hint_text("Port, ex. 8080").desired_width(110.0));
            chips(ui, &mut app.ports.new_proto, &[("tcp".to_string(), "TCP"), ("udp".to_string(), "UDP")]);
            let scope_label = app.ports.new_scope.clone().unwrap_or_else(|| "Toutes les interfaces".into());
            let r = egui::ComboBox::from_id_salt("port_scope").selected_text(scope_label).width(170.0).show_ui(ui, |ui| {
                ui.selectable_value(&mut app.ports.new_scope, None, "Toutes les interfaces");
                for i in m.ifaces.values().filter(|i| !i.bridge_port) {
                    ui.selectable_value(&mut app.ports.new_scope, Some(i.name.clone()), &i.name);
                }
            });
            named(&r.response, "Interface du port");
            let mut chosen = None;
            if ui.button(format!("{} Ouvrir", icon::LOCK_OPEN)).clicked() {
                chosen = Some(true);
            }
            if ui.button(format!("{} Fermer", icon::LOCK)).clicked() {
                chosen = Some(false);
            }
            if let Some(allow) = chosen {
                match app.ports.new_port.trim().parse::<u16>() {
                    Ok(p) if p > 0 => {
                        app.ports.error = None;
                        let a = manage::port_rule_action(p, &app.ports.new_proto, app.ports.new_scope.as_deref(), allow, ufw_active);
                        app.ask(a);
                    }
                    _ => app.ports.error = Some("Indiquez un numéro de port entre 1 et 65535.".into()),
                }
            }
            if let Some(e) = &app.ports.error {
                ui.label(RichText::new(e).color(pal().critical_text).size(12.5));
            }
        });
    });
    }
    ui.add_space(4.0);

    let q = app.ports.search.to_lowercase();
    rows.retain(|f| q.is_empty() || f.key.local.port().to_string().contains(&q) || f.app_name().to_lowercase().contains(&q));
    let sv = services();
    let svc = |f: &Flow| sv.get(&(f.key.local.port(), f.key.proto.label().to_lowercase())).cloned().unwrap_or_default();
    let sort = app.ports.sort.clone();
    rows.sort_by(|x, y| {
        let o = match sort.col {
            0 => x.key.local.port().cmp(&y.key.local.port()),
            1 => x.key.proto.cmp(&y.key.proto),
            2 => svc(x).cmp(&svc(y)),
            3 => x.key.local.ip().cmp(&y.key.local.ip()),
            4 => port_exposure(x).2.cmp(&port_exposure(y).2),
            5 => x.app_name().to_lowercase().cmp(&y.app_name().to_lowercase()),
            _ => x.pid.cmp(&y.pid),
        };
        let o = if sort.desc { o.reverse() } else { o };
        o.then_with(|| x.key.cmp(&y.key))
    });

    let active: HashMap<(Proto, u16), usize> = m.flows.values().filter(|f| f.open && f.dir == FlowDir::Incoming).fold(HashMap::new(), |mut acc, f| {
        *acc.entry((f.key.proto, f.key.local.port())).or_insert(0) += 1;
        acc
    });

    let cols = [
        col_r("Port", 70.0),
        col("Proto", 58.0),
        flex("Service", 0.7),
        col("Adresse", 180.0),
        col("Joignable par", 140.0),
        flex("Programme", 1.0),
        col_r("Processus", 80.0),
        col_r("Clients", 60.0),
        col("", 204.0),
    ];
    table_header(ui, &cols, Some(&mut app.ports.sort));
    if rows.is_empty() {
        ui.add_space(14.0);
        hint(ui, "Aucun port en écoute sur cette interface.");
        return;
    }
    egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, 32.0, rows.len(), |ui, range| {
        ui.spacing_mut().item_spacing.y = 0.0;
        for f in &rows[range] {
            let port = f.key.local.port();
            let (rect, _) = table_row(ui, 32.0, false, &format!("Port {port}"));
            let r = col_rects(rect, &cols);
            cell(ui, r[0], &port.to_string(), &mono(12.5), pal().ink, true);
            cell(ui, r[1], f.key.proto.label(), &body(12.0), pal().ink2, false);
            cell(ui, r[2], &svc(f), &body(12.5), pal().ink2, false);
            ip_cell(ui, r[3], &f.key.local.ip().to_string(), &f.key.local.ip().to_string(), &mono(12.0), pal().ink2);
            let (sym, c, text) = port_exposure(f);
            icon_cell(ui, r[4], sym, c, &text, &body(12.0), pal().ink2);
            cell(ui, r[5], &f.app_name(), &body(13.0), pal().ink, false);
            cell(ui, r[6], &f.pid.map(|p| p.to_string()).unwrap_or_else(|| "—".into()), &mono(12.0), pal().ink2, true);
            let clients = active.get(&(f.key.proto, port)).copied().unwrap_or(0);
            cell(ui, r[7], &clients.to_string(), &mono(12.0), pal().ink2, true);
            let proto = f.key.proto.label().to_lowercase();
            let scope = f.iface.clone().filter(|_| !f.key.local.ip().is_unspecified() && !f.key.local.ip().is_loopback());
            let (pid, name, mine) = (f.pid, f.app_name(), f.uid == crate::platform::own_uid());
            let is_docker = name.to_lowercase().contains("docker");
            if !crate::platform::full_features() {
                continue;
            }
            in_cell(ui, r[8], |ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                if small_button(ui, "Fermer").on_hover_text("Bloque ce port dans le pare-feu").clicked() {
                    let mut a = manage::port_rule_action(port, &proto, scope.as_deref(), false, ufw_active);
                    if is_docker {
                        a = a.warn("Les ports publiés par Docker contournent en partie le pare-feu : la règle peut rester sans effet. Arrêtez plutôt le conteneur.");
                    }
                    app.ask(a);
                }
                if small_button(ui, "Ouvrir").on_hover_text("Autorise ce port dans le pare-feu").clicked() {
                    app.ask(manage::port_rule_action(port, &proto, scope.as_deref(), true, ufw_active));
                }
                if let Some(pid) = pid {
                    if small_button(ui, "Arrêter").on_hover_text("Arrête le programme qui écoute").clicked() {
                        app.ask(manage::kill_process_action(pid, &name, !mine));
                    }
                }
            });
        }
    });
}
