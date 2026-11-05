//! Écrans d'analyse : traceroute graphique, identification des IP, consommation.

use super::chart;
use super::theme::*;
use super::widgets::*;
use super::{App, TraceModeChoice};
use crate::enrich::{ip_scope, service_from_host, IpInfo, IpScope};
use crate::model::{FlowDir, Model};
use crate::trace::{Hop, TraceState};
use crate::util::{fmt_bytes, fmt_duration, fmt_ms};
use eframe::egui::{self, Align, Color32, CornerRadius, Layout, Pos2, Rect, RichText, Sense, Stroke, Ui, Vec2};
use egui_phosphor::regular as icon;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

// ---------- Traceroute ----------

struct Node {
    title: String,
    ip: Option<IpAddr>,
    subtitle: String,
    metric: String,
    provider: Option<String>,
    color: Color32,
    hollow: bool,
    hop_index: Option<usize>,
    sym: Option<&'static str>,
}

fn hop_status(h: &Hop) -> (Color32, bool, &'static str) {
    if h.ips.is_empty() {
        return (pal().muted, true, "Ne répond pas");
    }
    let l = h.loss_pct();
    if l >= 20.0 {
        (pal().critical, false, "Pertes élevées")
    } else if l > 0.0 {
        (pal().warning, false, "Quelques pertes")
    } else {
        (pal().good, false, "Sans perte")
    }
}

fn build_nodes(app: &App, st: &TraceState, hops: &[Hop]) -> Vec<Node> {
    let mut nodes = vec![Node {
        title: "Ce PC".into(),
        ip: None,
        subtitle: st.iface.clone().map(|i| format!("Par {i}")).unwrap_or_else(|| "Départ".into()),
        metric: String::new(),
        provider: None,
        color: pal().rx,
        hollow: false,
        hop_index: None,
        sym: Some(icon::DESKTOP),
    }];
    for (i, h) in hops.iter().enumerate() {
        let ip = h.ips.first().copied();
        let info = ip.and_then(|a| app.shared.enrich.info(a));
        let scope = ip.map(ip_scope);
        let provider = info.as_ref().and_then(|x| x.provider());
        let label_provider = match scope {
            Some(IpScope::Public) | None => provider.clone(),
            Some(s) => Some(s.label().to_string()),
        };
        let name = info.as_ref().and_then(|x| x.rdns.clone()).unwrap_or_default();
        let (color, hollow, _) = hop_status(h);
        let is_target = ip.is_some() && ip == st.target_ip;
        nodes.push(Node {
            title: if is_target { format!("Arrivée · étape {}", i + 1) } else { format!("Étape {}", i + 1) },
            ip,
            subtitle: if ip.is_none() { "Ne répond pas".into() } else if !name.is_empty() { name } else { label_provider.clone().unwrap_or_default() },
            metric: if h.recv > 0 { format!("{}  ·  {:.0} % perdus", fmt_ms(h.avg_ms() as f64), h.loss_pct()) } else if h.sent > 0 { format!("{:.0} % perdus", h.loss_pct()) } else { String::new() },
            provider: label_provider,
            color,
            hollow,
            hop_index: Some(i),
            sym: None,
        });
    }
    nodes
}

/// Le dessin du trajet : un serpent de haut en bas, groupé par opérateur.
fn route_graph(app: &mut App, ui: &mut Ui, nodes: &[Node]) {
    let width = ui.available_width();
    let per_row = ((width / 178.0).floor() as usize).clamp(2, 12);
    let rows = nodes.len().div_ceil(per_row).max(1);
    let row_h = 132.0;
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, rows as f32 * row_h), Sense::hover());
    let painter = ui.painter_at(rect);
    let slot = width / per_row as f32;
    let center_of = |i: usize| -> Pos2 {
        let row = i / per_row;
        let col = i % per_row;
        let col = if row % 2 == 0 { col } else { per_row - 1 - col };
        Pos2::new(rect.left() + slot * (col as f32 + 0.5), rect.top() + row as f32 * row_h + 44.0)
    };

    // Bandeaux d'opérateur : les étapes voisines d'un même réseau sont regroupées.
    let mut i = 1;
    while i < nodes.len() {
        let Some(p) = nodes[i].provider.clone() else {
            i += 1;
            continue;
        };
        let mut j = i;
        while j + 1 < nodes.len() && nodes[j + 1].provider.as_deref() == Some(p.as_str()) && (j + 1) / per_row == i / per_row {
            j += 1;
        }
        let (a, b) = (center_of(i), center_of(j));
        let (lx, rx) = (a.x.min(b.x) - slot * 0.46, a.x.max(b.x) + slot * 0.46);
        let band = Rect::from_min_max(Pos2::new(lx, a.y - 40.0), Pos2::new(rx, a.y + 80.0));
        painter.rect_filled(band, CornerRadius::same(8), pal().band);
        let text_rect = Rect::from_min_max(Pos2::new(band.left() + 2.0, band.top() + 1.0), Pos2::new(band.right() - 2.0, band.top() + 19.0));
        cell(ui, text_rect, &p, &bold(11.5), pal().ink2, false);
        i = j + 1;
    }

    // Liaisons, avec un coude au changement de rangée.
    for w in 0..nodes.len().saturating_sub(1) {
        let (a, b) = (center_of(w), center_of(w + 1));
        let silent = nodes[w + 1].hollow || nodes[w].hollow;
        let stroke = Stroke::new(2.0, if silent { pal().axis } else { pal().connector });
        if (a.y - b.y).abs() < 1.0 {
            painter.line_segment([a, b], stroke);
        } else {
            // Passe sur le côté, à l'extérieur des bandeaux, pour ne pas barrer le texte.
            let side = if w / per_row % 2 == 0 { 1.0 } else { -1.0 };
            let x = a.x + side * slot * 0.485;
            painter.add(egui::epaint::PathShape::line(vec![a, Pos2::new(x, a.y), Pos2::new(x, b.y), b], stroke));
        }
    }

    for (i, n) in nodes.iter().enumerate() {
        let c = center_of(i);
        let radius = if n.sym.is_some() { 14.0 } else { 9.0 };
        let hit = Rect::from_center_size(c + Vec2::new(0.0, 28.0), Vec2::new(slot - 6.0, 90.0));
        let resp = ui.interact(hit, ui.scope_id().with(("hop", i)), Sense::click());
        let selected = n.hop_index.is_some() && app.trace.selected_hop == n.hop_index;
        if selected {
            painter.circle_stroke(c, radius + 5.0, Stroke::new(2.0, pal().ink));
        }
        if n.hollow {
            painter.circle(c, radius, pal().surface, Stroke::new(2.0, pal().muted));
        } else {
            painter.circle(c, radius, n.color, Stroke::new(3.0, pal().surface));
        }
        if let Some(s) = n.sym {
            painter.text(c, egui::Align2::CENTER_CENTER, s, body(15.0), Color32::WHITE);
        }
        let w = slot - 10.0;
        let line = |dy: f32, text: &str, font: egui::FontId, color: Color32| {
            let r = Rect::from_center_size(Pos2::new(c.x, c.y + dy), Vec2::new(w, 16.0));
            let g = {
                let mut job = egui::text::LayoutJob::simple_singleline(text.to_string(), font, color);
                job.wrap = egui::text::TextWrapping { max_width: w, max_rows: 1, break_anywhere: true, overflow_character: Some('…') };
                painter.layout_job(job)
            };
            painter.galley(Pos2::new(r.center().x - g.size().x / 2.0, r.top()), g, color);
        };
        line(20.0, &n.title, bold(12.0), pal().ink);
        if let Some(ip) = n.ip {
            line(36.0, &ip.to_string(), mono(11.5), pal().ink2);
        }
        line(if n.ip.is_some() { 52.0 } else { 36.0 }, &n.subtitle, body(11.5), pal().muted);
        if !n.metric.is_empty() {
            line(if n.ip.is_some() { 67.0 } else { 52.0 }, &n.metric, body(11.5), pal().ink2);
        }
        if n.hop_index.is_some() && resp.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        if resp.clicked() {
            app.trace.selected_hop = if selected { None } else { n.hop_index };
        }
    }
}

pub fn traceroute(app: &mut App, ui: &mut Ui) {
    let shared = app.shared.clone();
    let (running, started, error, target_ip, target_name, reached, source) = {
        let st = shared.tracer.state.lock().unwrap();
        (st.running, st.started, st.error.clone(), st.target_ip, st.target.clone(), st.reached(), st.source)
    };

    ui.horizontal(|ui| {
        let edit = ui.add(egui::TextEdit::singleline(&mut app.trace.target).hint_text("Site ou adresse IP, ex. exemple.fr").desired_width(280.0));
        let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        chips(ui, &mut app.trace.mode, &[(TraceModeChoice::Icmp, "Ping"), (TraceModeChoice::Udp, "UDP"), (TraceModeChoice::Tcp, "TCP")]);
        if app.trace.mode == TraceModeChoice::Tcp {
            ui.label(RichText::new("port").color(pal().muted).size(12.5));
            ui.add(egui::TextEdit::singleline(&mut app.trace.tcp_port).desired_width(52.0));
        }
        let can_start = !app.trace.target.trim().is_empty();
        if running {
            if danger_button(ui, &format!("{} Arrêter", icon::STOP)).clicked() {
                shared.tracer.stop();
            }
            if ui.add_enabled(can_start, egui::Button::new("Relancer")).clicked() {
                shared.tracer.start(&app.trace.target, app.iface.clone(), app.trace_mode());
                app.trace.selected_hop = None;
            }
        } else if (ui.add_enabled(can_start, egui::Button::new(RichText::new(format!("{} Tracer", icon::PLAY)).color(Color32::WHITE)).fill(pal().primary)).clicked() || enter) && can_start {
            shared.tracer.start(&app.trace.target, app.iface.clone(), app.trace_mode());
            app.trace.selected_hop = None;
        }
        if running {
            ui.add(egui::Spinner::new().size(14.0));
            ui.label(RichText::new(format!("Mesure en continu depuis {}", fmt_duration(started.map(|s| s.elapsed().as_secs_f64()).unwrap_or(0.0)))).color(pal().ink2).size(12.5));
        }
    });
    ui.add_space(4.0);
    if let Some(e) = error {
        ui.horizontal(|ui| {
            ui.label(RichText::new(icon::WARNING).color(pal().critical_text));
            ui.add(egui::Label::new(RichText::new(e).color(pal().critical_text)).wrap());
        });
    }

    let (hops, nodes) = {
        let st = shared.tracer.state.lock().unwrap();
        let hops = st.visible_hops().to_vec();
        let nodes = build_nodes(app, &st, &hops);
        (hops, nodes)
    };

    if target_name.is_empty() {
        ui.add_space(30.0);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new(icon::PATH).size(44.0).color(pal().axis));
            ui.label(RichText::new("Aucun trajet en cours").font(bold(15.0)).color(pal().ink2));
            ui.label(RichText::new("Saisissez une adresse ci-dessus, ou cliquez sur « Tracer » à côté d'une connexion.").color(pal().muted));
        });
        return;
    }

    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        card(ui, |ui| {
            ui.horizontal(|ui| {
                let dest = match target_ip {
                    Some(ip) if ip.to_string() != target_name => format!("{target_name} ({ip})"),
                    _ => target_name.clone(),
                };
                section_title(ui, &format!("Trajet vers {dest}"));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if !source.is_empty() {
                        if reached {
                            status_badge(ui, icon::CHECK_CIRCLE, pal().good, "Destination atteinte");
                        } else if running {
                            status_badge(ui, icon::HOURGLASS, pal().muted, "Destination pas encore atteinte");
                        } else {
                            status_badge(ui, icon::X_CIRCLE, pal().muted, "Destination non atteinte");
                        }
                    }
                });
            });
            ui.add_space(6.0);
            route_graph(app, ui, &nodes);
            ui.horizontal(|ui| {
                chart::legend_value(ui, pal().good, "Sans perte", "");
                chart::legend_value(ui, pal().warning, "Quelques pertes", "");
                chart::legend_value(ui, pal().critical, "20 % de pertes ou plus", "");
                chart::legend_value(ui, pal().muted, "Ne répond pas", "");
            });
            hint(ui, "Beaucoup de routeurs limitent leurs réponses à ces sondes : des pertes sur une étape intermédiaire ne gênent pas forcément le trafic si les étapes suivantes n'en ont pas.");
        });
        ui.add_space(6.0);
        card(ui, |ui| hop_table(app, ui, &hops));
    });
}

fn hop_table(app: &mut App, ui: &mut Ui, hops: &[Hop]) {
    section_title(ui, "Détail de chaque étape");
    let cols = [
        col_r("Étape", 50.0),
        col("Adresse", 170.0),
        flex("Nom", 1.0),
        flex("Opérateur", 1.0),
        col("Pays", 46.0),
        col_r("Perdus", 62.0),
        col_r("Dernier", 74.0),
        col_r("Moyen", 74.0),
        col_r("Meilleur", 74.0),
        col_r("Pire", 74.0),
        col("Latence", 110.0),
        col("", 64.0),
    ];
    table_header(ui, &cols, None);
    for (i, h) in hops.iter().enumerate() {
        let ip = h.ips.first().copied();
        let info = ip.and_then(|a| app.shared.enrich.info(a));
        let selected = app.trace.selected_hop == Some(i);
        let (rect, resp) = table_row(ui, 30.0, selected, &format!("Étape {}", i + 1));
        let r = col_rects(rect, &cols);
        cell(ui, r[0], &(i + 1).to_string(), &mono(12.0), pal().ink, true);
        match ip {
            Some(a) => ip_cell(ui, r[1], &a.to_string(), &a.to_string(), &mono(12.0), pal().ink2),
            None => cell(ui, r[1], "Pas de réponse", &mono(12.0), pal().muted, false),
        }
        cell(ui, r[2], info.as_ref().and_then(|x| x.rdns.as_deref()).unwrap_or(""), &body(12.5), pal().ink2, false);
        let oper = match ip.map(ip_scope) {
            Some(IpScope::Public) | None => info.as_ref().and_then(|x| x.provider()).unwrap_or_default(),
            Some(s) => s.label().to_string(),
        };
        cell(ui, r[3], &oper, &body(12.5), pal().ink2, false);
        cell(ui, r[4], info.as_ref().and_then(|x| x.as_info.as_ref()).map(|a| a.country.as_str()).unwrap_or(""), &body(12.0), pal().ink2, false);
        cell(ui, r[5], &format!("{:.0} %", h.loss_pct()), &mono(12.0), pal().ink2, true);
        if h.recv > 0 {
            cell(ui, r[6], &fmt_ms(h.last_ms as f64), &mono(11.5), pal().ink2, true);
            cell(ui, r[7], &fmt_ms(h.avg_ms() as f64), &mono(11.5), pal().ink, true);
            cell(ui, r[8], &fmt_ms(h.best_ms as f64), &mono(11.5), pal().ink2, true);
            cell(ui, r[9], &fmt_ms(h.worst_ms as f64), &mono(11.5), pal().ink2, true);
            let hist: std::collections::VecDeque<(f32, f32)> = h.history.iter().map(|v| (*v, 0.0)).collect();
            let painter_rect = r[10].shrink2(Vec2::new(4.0, 5.0));
            latency_spark(ui, painter_rect, &hist);
        }
        if let Some(a) = ip {
            if ip_scope(a) == IpScope::Public {
                in_cell(ui, r[11], |ui| {
                    if small_button(ui, "Qui ?").clicked() {
                        app.go_lookup(a);
                    }
                });
            }
        }
        if resp.clicked() {
            app.trace.selected_hop = if selected { None } else { Some(i) };
        }
    }
}

fn latency_spark(ui: &Ui, r: Rect, hist: &std::collections::VecDeque<(f32, f32)>) {
    if hist.len() < 2 {
        return;
    }
    let max = hist.iter().map(|x| x.0).fold(1.0f32, f32::max);
    let n = hist.len().max(40);
    let pts: Vec<Pos2> = hist
        .iter()
        .enumerate()
        .map(|(i, v)| Pos2::new(r.right() - (hist.len() - 1 - i) as f32 / (n - 1) as f32 * r.width(), r.bottom() - v.0 / max * r.height()))
        .collect();
    ui.painter().add(egui::epaint::PathShape::line(pts, Stroke::new(1.25, pal().rx)));
}

// ---------- IP et fournisseurs ----------

#[derive(Default)]
struct SeenIp {
    apps: HashSet<String>,
    conns: usize,
    rx: u64,
    tx: u64,
    host: Option<String>,
}

fn seen_ips(m: &Model, iface: Option<&str>) -> HashMap<IpAddr, SeenIp> {
    let mut out: HashMap<IpAddr, SeenIp> = HashMap::new();
    for f in m.flows.values() {
        if f.dir == FlowDir::Listening || !m.flow_visible(f, iface, false) {
            continue;
        }
        let e = out.entry(f.key.remote.ip()).or_default();
        e.apps.insert(f.app_name());
        e.conns += usize::from(f.open);
        e.rx += f.rx_total;
        e.tx += f.tx_total;
        if e.host.is_none() {
            e.host = f.host.clone().or_else(|| m.dns_names.get(&f.key.remote.ip()).cloned());
        }
    }
    out
}

fn info_card(app: &mut App, ui: &mut Ui, ip: IpAddr) {
    let info = app.shared.enrich.cache.lock().unwrap().get(&ip).cloned().unwrap_or_default();
    let scope = ip_scope(ip);
    let shared = app.shared.clone();
    card(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            copy_inline(ui, &ip.to_string());
            ui.label(RichText::new(ip.to_string()).font(bold(17.0)).color(pal().ink));
            ui.label(RichText::new(scope.label()).color(pal().ink2));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if small_button(ui, icon::X).on_hover_text("Fermer cette fiche").clicked() {
                    app.ip.selected = None;
                }
                if scope == IpScope::Public && small_button(ui, "Tracer la route").clicked() {
                    app.go_trace(ip, app.iface.clone(), None);
                }
            });
        });
        if scope != IpScope::Public {
            hint(ui, "Cette adresse n'appartient à aucun opérateur public : elle n'existe que sur un réseau privé ou sur ce PC.");
            return;
        }
        ui.add_space(4.0);
        let half = ui.available_width() / 2.0;
        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(Vec2::new(half, 110.0), Layout::top_down(Align::Min), |ui| {
                ui.set_width(half);
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.label(RichText::new("Opérateur du réseau").font(bold(12.5)).color(pal().ink));
                if let Some(a) = &info.as_info {
                    kv(ui, "Fournisseur", &a.provider());
                    kv(ui, "Réseau (AS)", &format!("AS{}", a.asn));
                    kv_mono(ui, "Plage annoncée", &a.prefix);
                    kv(ui, "Pays", &a.country);
                    kv(ui, "Registre", &a.registry.to_uppercase());
                } else if info.done {
                    hint(ui, "Aucun opérateur trouvé pour cette adresse.");
                } else {
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new().size(13.0));
                        ui.label(RichText::new("Recherche…").color(pal().ink2));
                    });
                }
                if let Some(n) = &info.rdns {
                    kv(ui, "Nom inverse", n);
                    if let Some(s) = service_from_host(n) {
                        kv(ui, "Service", &s);
                    }
                }
            });
            ui.allocate_ui_with_layout(Vec2::new(half - 12.0, 110.0), Layout::top_down(Align::Min), |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.label(RichText::new("Fiche du registre").font(bold(12.5)).color(pal().ink));
                if let Some(r) = &info.rdap {
                    kv(ui, "Organisation", if r.organisation.is_empty() { "—" } else { &r.organisation });
                    kv(ui, "Nom du réseau", &r.name);
                    kv_mono(ui, "Plage", &r.range);
                    if !r.country.is_empty() {
                        kv(ui, "Pays", &r.country);
                    }
                    if !r.registered.is_empty() {
                        kv(ui, "Enregistré le", &r.registered);
                    }
                    if !r.abuse.is_empty() {
                        kv(ui, "Signaler un abus", &r.abuse);
                    }
                } else if info.rdap_pending {
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new().size(13.0));
                        ui.label(RichText::new("Interrogation du registre…").color(pal().ink2));
                    });
                } else {
                    if let Some(e) = &info.rdap_error {
                        ui.add(egui::Label::new(RichText::new(e).color(pal().critical_text).size(12.5)).wrap());
                    }
                    if ui.button("Consulter le registre").clicked() {
                        shared.enrich.request_rdap(ip);
                    }
                }
            });
        });
    });
}

pub fn ip_page(app: &mut App, ui: &mut Ui) {
    let shared = app.shared.clone();
    ui.horizontal(|ui| {
        let edit = ui.add(egui::TextEdit::singleline(&mut app.ip.query).hint_text("Adresse IP, ex. 8.8.8.8").desired_width(240.0));
        let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if primary_button(ui, &format!("{} Identifier", icon::MAGNIFYING_GLASS)).clicked() || enter {
            match app.ip.query.trim().parse::<IpAddr>() {
                Ok(ip) => {
                    let (q, shared2) = (ip, shared.clone());
                    app.ip.error = None;
                    app.ip.selected = Some(q);
                    shared2.enrich.request(q);
                    shared2.enrich.request_rdap(q);
                }
                Err(_) => app.ip.error = Some("Ce n'est pas une adresse IP valide.".into()),
            }
        }
        if let Some(e) = &app.ip.error {
            ui.label(RichText::new(e).color(pal().critical_text));
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let mut auto = shared.enrich.auto.load(std::sync::atomic::Ordering::Relaxed);
            if ui.checkbox(&mut auto, "Identifier automatiquement").on_hover_text("Chaque adresse publique contactée est envoyée à votre serveur DNS et à Team Cymru pour trouver son opérateur. Les résultats sont gardés sur ce PC.").changed() {
                shared.enrich.auto.store(auto, std::sync::atomic::Ordering::Relaxed);
            }
        });
    });
    ui.add_space(2.0);
    hint(ui, "L'identification envoie les adresses contactées à votre serveur DNS et à Team Cymru ; la fiche détaillée interroge rdap.org. Décochez la case pour tout garder sur ce PC.");
    ui.add_space(4.0);
    if let Some(ip) = app.ip.selected {
        info_card(app, ui, ip);
        ui.add_space(4.0);
    }

    let live = shared.model.lock().unwrap();
    let frozen = app.ip.freeze.view.clone();
    let m: &Model = frozen.as_deref().unwrap_or(&live);
    let seen = seen_ips(m, app.iface.as_deref());
    let mut rows: Vec<(IpAddr, &SeenIp, IpInfo)> = seen.iter().map(|(ip, s)| (*ip, s, shared.enrich.info(*ip).unwrap_or_default())).collect();
    let mut by_provider: BTreeMap<String, (u64, u64, usize)> = BTreeMap::new();
    for (ip, s, info) in &rows {
        let scope = ip_scope(*ip);
        let name = if scope == IpScope::Public { info.provider().unwrap_or_else(|| "Inconnu".into()) } else { scope.label().to_string() };
        let e = by_provider.entry(name).or_default();
        e.0 += s.rx;
        e.1 += s.tx;
        e.2 += s.conns;
    }

    let mut providers: Vec<_> = by_provider.into_iter().collect();
    providers.sort_by_key(|(n, v)| (std::cmp::Reverse(v.0 + v.1), n.clone()));

    let total_w = ui.available_width();
    let left = 360.0_f32.min(total_w * 0.34);
    egui::Panel::left("providers").exact_size(left).resizable(false).show_separator_line(false).frame(egui::Frame::new().inner_margin(egui::Margin { right: 10, ..Default::default() })).show(ui, |ui| {
        card(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.set_min_height(ui.available_height() - 30.0);
            section_title(ui, "Fournisseurs contactés");
            ui.horizontal(|ui| {
                chart::legend_value(ui, pal().rx, "Reçu", "");
                chart::legend_value(ui, pal().tx, "Envoyé", "");
            });
            ui.add_space(2.0);
            let scale = providers.iter().map(|(_, v)| (v.0 + v.1) as f64).fold(0.0, f64::max);
            egui::ScrollArea::vertical().id_salt("prov_scroll").auto_shrink([false, false]).show(ui, |ui| {
                for (name, (rx, tx, conns)) in &providers {
                    ui.add_space(5.0);
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.add(egui::Label::new(RichText::new(name).color(pal().ink).size(12.5)).truncate());
                    ui.label(RichText::new(format!("{}  ·  {}", fmt_bytes(rx + tx), plural(*conns, "connexion"))).color(pal().muted).size(11.5));
                    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 8.0), Sense::hover());
                    chart::split_bar(ui, rect, *rx as f64, *tx as f64, scale);
                }
            });
        });
    });

    ui.horizontal(|ui| {
        section_title(ui, "Adresses contactées");
        search_box(ui, &mut app.ip.search, "Adresse, nom, opérateur…", 220.0);
        freeze_button(ui, &mut app.ip.freeze, &live);
    });
    let q = app.ip.search.to_lowercase();
    if !q.is_empty() {
        rows.retain(|(ip, s, info)| {
            ip.to_string().contains(&q)
                || s.host.as_deref().is_some_and(|h| h.to_lowercase().contains(&q))
                || info.rdns.as_deref().is_some_and(|h| h.to_lowercase().contains(&q))
                || info.provider().is_some_and(|p| p.to_lowercase().contains(&q))
                || s.apps.iter().any(|a| a.to_lowercase().contains(&q))
        });
    }
    let sort = app.ip.sort.clone();
    let name_of = |s: &SeenIp, i: &IpInfo| s.host.clone().or_else(|| i.rdns.clone()).unwrap_or_default();
    rows.sort_by(|a, b| {
        let o = match sort.col {
            0 => a.0.cmp(&b.0),
            1 => name_of(a.1, &a.2).cmp(&name_of(b.1, &b.2)),
            2 => a.2.provider().cmp(&b.2.provider()),
            3 => a.2.as_info.as_ref().map(|x| x.country.clone()).cmp(&b.2.as_info.as_ref().map(|x| x.country.clone())),
            4 => a.1.conns.cmp(&b.1.conns),
            _ => (a.1.rx + a.1.tx).cmp(&(b.1.rx + b.1.tx)),
        };
        let o = if sort.desc { o.reverse() } else { o };
        o.then_with(|| a.0.cmp(&b.0))
    });
    let cols = [col("Adresse", 200.0), flex("Nom", 1.0), flex("Fournisseur", 1.0), col("Pays", 46.0), col_r("Conn.", 50.0), col_r("Volume", 84.0)];
    table_header(ui, &cols, Some(&mut app.ip.sort));
    if rows.is_empty() {
        ui.add_space(12.0);
        hint(ui, "Aucune adresse distante pour le moment.");
        return;
    }
    egui::ScrollArea::vertical().id_salt("ip_rows").auto_shrink([false, false]).show_rows(ui, 30.0, rows.len(), |ui, range| {
        ui.spacing_mut().item_spacing.y = 0.0;
        for (ip, s, info) in &rows[range] {
            let selected = app.ip.selected == Some(*ip);
            let (rect, resp) = table_row(ui, 30.0, selected, &ip.to_string());
            let r = col_rects(rect, &cols);
            ip_cell(ui, r[0], &ip.to_string(), &ip.to_string(), &mono(12.0), pal().ink);
            cell(ui, r[1], &name_of(s, info), &body(12.5), pal().ink2, false);
            let scope = ip_scope(*ip);
            let provider = if scope == IpScope::Public { info.provider().unwrap_or_else(|| if info.done { "Inconnu".into() } else { "…".into() }) } else { scope.label().to_string() };
            cell(ui, r[2], &provider, &body(12.5), pal().ink2, false);
            cell(ui, r[3], info.as_info.as_ref().map(|a| a.country.as_str()).unwrap_or(""), &body(12.0), pal().ink2, false);
            cell(ui, r[4], &s.conns.to_string(), &mono(12.0), pal().ink2, true);
            cell(ui, r[5], &fmt_bytes(s.rx + s.tx), &mono(12.0), pal().ink2, true);
            if resp.clicked() {
                app.ip.selected = Some(*ip);
                app.ip.query = ip.to_string();
                shared.enrich.request(*ip);
                if scope == IpScope::Public {
                    shared.enrich.request_rdap(*ip);
                }
            }
        }
    });
}

// ---------- Consommation ----------

pub fn usage(app: &mut App, ui: &mut Ui) {
    let shared = app.shared.clone();
    let m = shared.model.lock().unwrap();
    let iface = app.iface.clone();
    let counted = m.counted_names();
    let today = chrono::Local::now().date_naive();
    let day_key = |back: i64| (today - chrono::Duration::days(back)).format("%Y-%m-%d").to_string();
    let sum = |days: i64| -> (u64, u64) { (0..days).fold((0, 0), |a, b| {
        let d = m.usage.day_total(&day_key(b), iface.as_deref(), &counted);
        (a.0 + d.0, a.1 + d.1)
    }) };
    let (d1, d7, d30) = (sum(1), sum(7), sum(30));
    let since_boot = match iface.as_deref() {
        Some(n) => m.ifaces.get(n).map(|i| (i.rx_total, i.tx_total)).unwrap_or((0, 0)),
        None => m.ifaces.values().filter(|i| i.counted()).fold((0, 0), |a, i| (a.0 + i.rx_total, a.1 + i.tx_total)),
    };

    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        let gap = 10.0;
        let tw = (ui.available_width() - 3.0 * gap) / 4.0;
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            let sub = |v: (u64, u64)| format!("{} {}   {} {}", icon::ARROW_DOWN, fmt_bytes(v.0), icon::ARROW_UP, fmt_bytes(v.1));
            super::page_monitor::tile(ui, tw, "Aujourd'hui", None, &fmt_bytes(d1.0 + d1.1), &sub(d1));
            super::page_monitor::tile(ui, tw, "7 derniers jours", None, &fmt_bytes(d7.0 + d7.1), &sub(d7));
            super::page_monitor::tile(ui, tw, "30 derniers jours", None, &fmt_bytes(d30.0 + d30.1), &sub(d30));
            super::page_monitor::tile(ui, tw, "Depuis le démarrage du PC", None, &fmt_bytes(since_boot.0 + since_boot.1), &sub(since_boot));
        });
        ui.add_space(4.0);

        card(ui, |ui| {
            ui.horizontal(|ui| {
                section_title(ui, "Volume par jour");
                ui.label(RichText::new(iface.clone().unwrap_or_else(|| "Toutes les interfaces".into())).color(pal().muted).size(12.5));
                ui.add_space(10.0);
                chart::legend_value(ui, pal().rx, "Reçu", "");
                chart::legend_value(ui, pal().tx, "Envoyé", "");
            });
            let bars: Vec<chart::DayBar> = (0..30)
                .rev()
                .map(|back| {
                    let date = today - chrono::Duration::days(back);
                    let (rx, tx) = m.usage.day_total(&date.format("%Y-%m-%d").to_string(), iface.as_deref(), &counted);
                    chart::DayBar { label: date.format("%d/%m").to_string(), full_date: date.format("%d/%m/%Y").to_string(), rx, tx }
                })
                .collect();
            chart::day_bars(ui, &bars, 210.0);
            hint(ui, "Le volume est compté pendant que NetBuster est ouvert : les jours précédant sa première ouverture restent vides.");
        });
        ui.add_space(4.0);

        let half = (ui.available_width() - gap) / 2.0;
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            ui.allocate_ui_with_layout(Vec2::new(half, 10.0), Layout::top_down(Align::Min), |ui| {
                ui.set_width(half);
                card(ui, |ui| {
                    ui.set_width(half - 30.0);
                    section_title(ui, "Par application, sur 30 jours");
                    let mut apps: HashMap<&str, (u64, u64)> = HashMap::new();
                    for b in 0..30 {
                        if let Some(d) = m.usage.days.get(&day_key(b)) {
                            for (n, v) in &d.apps {
                                let e = apps.entry(n).or_default();
                                e.0 += v.0;
                                e.1 += v.1;
                            }
                        }
                    }
                    let mut list: Vec<_> = apps.into_iter().collect();
                    list.sort_by_key(|(n, v)| (std::cmp::Reverse(v.0 + v.1), n.to_string()));
                    if list.is_empty() {
                        hint(ui, "Rien de mesuré pour le moment.");
                    } else {
                        let scale = (list[0].1 .0 + list[0].1 .1) as f64;
                        let cols = [flex("Application", 1.0), flex("", 0.9), col_r("Reçu", 76.0), col_r("Envoyé", 76.0)];
                        table_header(ui, &cols, None);
                        for (n, v) in list.iter().take(12) {
                            let (rect, _) = table_row(ui, 26.0, false, n);
                            let r = col_rects(rect, &cols);
                            cell(ui, r[0], n, &body(12.5), pal().ink, false);
                            chart::split_bar(ui, r[1].shrink2(Vec2::new(4.0, 0.0)), v.0 as f64, v.1 as f64, scale);
                            cell(ui, r[2], &fmt_bytes(v.0), &mono(11.5), pal().ink2, true);
                            cell(ui, r[3], &fmt_bytes(v.1), &mono(11.5), pal().ink2, true);
                        }
                    }
                });
            });
            ui.allocate_ui_with_layout(Vec2::new(half, 10.0), Layout::top_down(Align::Min), |ui| {
                ui.set_width(half);
                card(ui, |ui| {
                    ui.set_width(half - 30.0);
                    section_title(ui, "Par interface");
                    let cols = [flex("Interface", 1.0), col_r("Reçu auj.", 78.0), col_r("Envoyé auj.", 82.0), col_r("Reçu au total", 92.0), col_r("Envoyé au total", 104.0)];
                    table_header(ui, &cols, None);
                    let today_key = day_key(0);
                    for i in m.ifaces.values().filter(|i| !i.bridge_port) {
                        let v = m.usage.days.get(&today_key).and_then(|d| d.ifaces.get(&i.name)).copied().unwrap_or((0, 0));
                        let (rect, _) = table_row(ui, 26.0, false, &i.name);
                        let r = col_rects(rect, &cols);
                        cell(ui, r[0], &i.name, &body(12.5), pal().ink, false);
                        cell(ui, r[1], &fmt_bytes(v.0), &mono(11.5), pal().ink2, true);
                        cell(ui, r[2], &fmt_bytes(v.1), &mono(11.5), pal().ink2, true);
                        cell(ui, r[3], &fmt_bytes(i.rx_total), &mono(11.5), pal().ink2, true);
                        cell(ui, r[4], &fmt_bytes(i.tx_total), &mono(11.5), pal().ink2, true);
                    }
                    hint(ui, "Les totaux sont ceux du système depuis le démarrage du PC. Le total général ne compte que les cartes physiques, pour ne pas compter deux fois le trafic des conteneurs.");
                });
            });
        });
    });
}
