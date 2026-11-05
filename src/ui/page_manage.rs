//! Écrans de gestion : pare-feu, configuration réseau, SSH.

use super::theme::*;
use super::widgets::*;
use super::{App, FwTab, SshTab};
use crate::manage::{self, Action, FwChain, Step, SSH_SETTINGS};
use crate::model::FlowDir;
use crate::util::{fmt_bytes, fmt_count};
use eframe::egui::{self, Align, Frame, Layout, Margin, RichText, Ui};
use egui_phosphor::regular as icon;

fn admin_gate(app: &mut App, ui: &mut Ui, text: &str) {
    if notice(ui, icon::LOCK, pal().warning, "Droits administrateur nécessaires", text, Some("Passer administrateur")) {
        app.shared.enable_admin();
    }
}

fn policy_fr(p: &str) -> &str {
    match p {
        "ACCEPT" => "Tout accepter",
        "DROP" => "Tout bloquer",
        other => other,
    }
}

fn target_style(t: &str) -> (&'static str, egui::Color32) {
    match t {
        "ACCEPT" => (icon::CHECK_CIRCLE, pal().good),
        "DROP" | "REJECT" => (icon::PROHIBIT, pal().critical_text),
        "" => (icon::MINUS, pal().muted),
        _ => (icon::CARET_RIGHT, pal().ink2),
    }
}

// ---------- Pare-feu ----------

pub fn firewall(app: &mut App, ui: &mut Ui) {
    let shared = app.shared.clone();
    let data = shared.panels.lock().unwrap().firewall.clone();

    if !data.loaded {
        ui.horizontal(|ui| {
            ui.add(egui::Spinner::new());
            ui.label("Lecture du pare-feu…");
        });
        return;
    }
    if data.admin_needed {
        admin_gate(app, ui, "Le système ne révèle les règles du pare-feu qu'à l'administrateur.");
        ui.add_space(6.0);
        card(ui, |ui| {
            ui.set_width(ui.available_width());
            section_title(ui, "Ce qui est visible sans droits");
            status_badge(ui, icon::SHIELD_CHECK, if data.ufw_conf_enabled { pal().good } else { pal().muted }, if data.ufw_conf_enabled { "UFW est activé dans sa configuration" } else { "UFW n'est pas activé dans sa configuration" });
            hint(ui, "Les politiques, les règles IP Tables et nftables s'affichent ici une fois le mode administrateur activé.");
        });
        return;
    }
    if let Some(e) = &data.error {
        ui.horizontal(|ui| {
            ui.label(RichText::new(icon::WARNING).color(pal().warning));
            ui.add(egui::Label::new(RichText::new(e).color(pal().ink2).size(12.5)).wrap());
        });
    }

    ui.horizontal(|ui| {
        chips(ui, &mut app.fw.tab, &[(FwTab::Ufw, "UFW et politiques"), (FwTab::Iptables, "IP Tables"), (FwTab::Nft, "nftables")]);
    });
    ui.add_space(4.0);
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| match app.fw.tab {
        FwTab::Ufw => ufw_tab(app, ui, &data),
        FwTab::Iptables => iptables_tab(app, ui, &data),
        FwTab::Nft => {
            card(ui, |ui| {
                ui.set_width(ui.available_width());
                section_title(ui, "Règles nftables (lecture)");
                hint(ui, "C'est la couche la plus basse du pare-feu Linux : UFW, Docker et IP Tables écrivent ici.");
                ui.add(egui::Label::new(RichText::new(if data.nft.trim().is_empty() { "Aucune règle." } else { data.nft.as_str() }).font(mono(11.5)).color(pal().ink2)).extend());
            });
        }
    });
}

fn ufw_tab(app: &mut App, ui: &mut Ui, data: &manage::FirewallData) {
    card(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            section_title(ui, "Pare-feu UFW");
            if data.ufw.active {
                status_badge(ui, icon::CHECK_CIRCLE, pal().good, "Actif");
            } else {
                status_badge(ui, icon::MINUS_CIRCLE, pal().warning, "Inactif");
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if data.ufw.active {
                    if ui.button("Désactiver UFW").clicked() {
                        app.ask(Action::new("Désactiver le pare-feu UFW", "Les règles UFW ne s'appliquent plus, ce PC devient plus exposé.", vec![Step::root("ufw", &["disable"])]).warn("Toutes les connexions entrantes peuvent redevenir possibles."));
                    }
                } else if primary_button(ui, "Activer UFW").clicked() {
                    app.ask(Action::new("Activer le pare-feu UFW", "Les règles UFW s'appliquent, y compris au démarrage du PC.", vec![Step::root("ufw", &["--force", "enable"])]).warn("Si vous êtes connecté à ce PC en SSH, vérifiez que le port SSH est autorisé avant d'activer."));
                }
            });
        });
        let defaults = manage::ufw_defaults_fr(&data.ufw.defaults);
        if !defaults.is_empty() {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Politiques par défaut").color(pal().muted).size(12.5));
                for (what, action) in &defaults {
                    let (sym, c) = if action == "Autorisé" { (icon::CHECK_CIRCLE, pal().good) } else if action == "Désactivé" { (icon::MINUS_CIRCLE, pal().muted) } else { (icon::PROHIBIT, pal().critical_text) };
                    status_badge(ui, sym, c, &format!("{what} : {action}"));
                }
            });
        }
    });
    ui.add_space(4.0);

    card(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.label(RichText::new("Nouvelle règle").font(bold(13.5)).color(pal().ink));
            ui.add(egui::TextEdit::singleline(&mut app.fw.ufw_port).hint_text("Port").desired_width(90.0));
            chips(ui, &mut app.fw.ufw_proto, &[("tcp".to_string(), "TCP"), ("udp".to_string(), "UDP")]);
            chips(ui, &mut app.fw.ufw_allow, &[(true, "Autoriser"), (false, "Bloquer")]);
            if ui.button("Ajouter").clicked() {
                match app.fw.ufw_port.trim().parse::<u16>() {
                    Ok(p) if p > 0 => {
                        app.fw.error = None;
                        let a = manage::port_rule_action(p, &app.fw.ufw_proto, None, app.fw.ufw_allow, true);
                        app.ask(a);
                    }
                    _ => app.fw.error = Some("Indiquez un port entre 1 et 65535.".into()),
                }
            }
            if let Some(e) = &app.fw.error {
                ui.label(RichText::new(e).color(pal().critical_text).size(12.5));
            }
        });
        ui.add_space(4.0);
        let cols = [col_r("N°", 40.0), flex("Port ou service", 1.0), col("Décision", 130.0), flex("Depuis", 1.0), col("", 86.0)];
        table_header(ui, &cols, None);
        if data.ufw.rules.is_empty() {
            ui.add_space(6.0);
            hint(ui, "Aucune règle UFW.");
        }
        for r in &data.ufw.rules {
            let (rect, _) = table_row(ui, 30.0, false, &format!("Règle {}", r.num));
            let c = col_rects(rect, &cols);
            cell(ui, c[0], &r.num.to_string(), &mono(12.0), pal().ink2, true);
            cell(ui, c[1], &r.to, &mono(12.0), pal().ink, false);
            let allow = r.action.starts_with("ALLOW");
            let label = r.action.replace("ALLOW", "Autorisé").replace("DENY", "Bloqué").replace("REJECT", "Refusé").replace(" IN", " entrant").replace(" OUT", " sortant");
            icon_cell(ui, c[2], if allow { icon::CHECK_CIRCLE } else { icon::PROHIBIT }, if allow { pal().good } else { pal().critical_text }, &label, &body(12.0), pal().ink2);
            cell(ui, c[3], &r.from.replace("Anywhere", "Partout"), &mono(12.0), pal().ink2, false);
            let num = r.num.to_string();
            let to = r.to.clone();
            in_cell(ui, c[4], |ui| {
                if small_button(ui, &format!("{} Retirer", icon::TRASH)).clicked() {
                    app.ask(Action::new(format!("Retirer la règle {num} ({to})"), "La politique par défaut s'applique de nouveau à ce trafic.", vec![Step::root("ufw", &["--force", "delete", &num])]));
                }
            });
        }
    });
}

fn iptables_tab(app: &mut App, ui: &mut Ui, data: &manage::FirewallData) {
    ui.horizontal(|ui| {
        chips(ui, &mut app.fw.family, &[(4u8, "IPv4"), (6u8, "IPv6")]);
        let tables: Vec<(String, &str)> = manage::FW_TABLES.iter().map(|t| (t.to_string(), *t)).collect();
        chips(ui, &mut app.fw.table, &tables);
    });
    ui.add_space(4.0);
    rule_form(app, ui);
    ui.add_space(4.0);
    let key = (app.fw.family, app.fw.table.clone());
    let Some(chains) = data.tables.get(&key) else {
        hint(ui, "Cette table n'est pas disponible sur ce système.");
        return;
    };
    let prog = if app.fw.family == 6 { "ip6tables" } else { "iptables" };
    for ch in chains {
        chain_card(app, ui, ch, prog);
        ui.add_space(4.0);
    }
}

fn rule_form(app: &mut App, ui: &mut Ui) {
    card(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(RichText::new("Ajouter une règle").font(bold(13.5)).color(pal().ink));
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 3.0;
                ui.label(RichText::new("Sens").color(pal().muted).size(12.0));
                chips(ui, &mut app.fw.form.chain, &[("INPUT".to_string(), "Entrant"), ("OUTPUT".to_string(), "Sortant"), ("FORWARD".to_string(), "Routé")]);
            });
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 3.0;
                ui.label(RichText::new("Décision").color(pal().muted).size(12.0));
                chips(ui, &mut app.fw.form.action, &[("ACCEPT".to_string(), "Autoriser"), ("DROP".to_string(), "Bloquer"), ("REJECT".to_string(), "Refuser")]);
            });
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 3.0;
                ui.label(RichText::new("Protocole").color(pal().muted).size(12.0));
                chips(ui, &mut app.fw.form.proto, &[("tcp".to_string(), "TCP"), ("udp".to_string(), "UDP"), ("icmp".to_string(), "ICMP"), ("tous".to_string(), "Tous")]);
            });
            labeled_field(ui, "Port", &mut app.fw.form.port, 70.0, "443");
            labeled_field(ui, "Source", &mut app.fw.form.source, 130.0, "Partout");
            labeled_field(ui, "Interface", &mut app.fw.form.iface, 90.0, "Toutes");
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 3.0;
                ui.label(RichText::new(" ").size(12.0));
                if primary_button(ui, "Ajouter").clicked() {
                    match manage::iptables_rule_action(app.fw.family, &app.fw.form) {
                        Ok(a) => {
                            app.fw.error = None;
                            app.ask(a);
                        }
                        Err(e) => app.fw.error = Some(e),
                    }
                }
            });
        });
        if let Some(e) = &app.fw.error {
            ui.label(RichText::new(e).color(pal().critical_text).size(12.5));
        }
    });
}

fn chain_card(app: &mut App, ui: &mut Ui, ch: &FwChain, prog: &str) {
    let table = app.fw.table.clone();
    card(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.label(RichText::new(&ch.name).font(bold(13.5)).color(pal().ink));
            if let Some(p) = &ch.policy {
                ui.label(RichText::new("Politique :").color(pal().muted).size(12.5));
                ui.label(RichText::new(policy_fr(p)).color(pal().ink).size(12.5));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let other = if p == "ACCEPT" { "DROP" } else { "ACCEPT" };
                    let label = if other == "DROP" { "Passer à : tout bloquer" } else { "Passer à : tout accepter" };
                    if small_button(ui, label).clicked() {
                        let mut a = Action::new(
                            format!("Politique de {} : {}", ch.name, policy_fr(other).to_lowercase()),
                            "S'applique au trafic qu'aucune règle de cette chaîne n'a traité.",
                            vec![Step::root(prog, &["-t", &table, "-P", &ch.name, other])],
                        );
                        if other == "DROP" {
                            a = a.warn("Sans règle d'autorisation, tout ce trafic sera bloqué, y compris un éventuel accès SSH.");
                        }
                        app.ask(a);
                    }
                });
            } else {
                ui.label(RichText::new("Chaîne personnalisée").color(pal().muted).size(12.5));
            }
        });
        if ch.rules.is_empty() {
            hint(ui, "Aucune règle dans cette chaîne.");
            return;
        }
        let cols = [
            col_r("N°", 36.0),
            col("Décision", 150.0),
            col("Proto", 62.0),
            col("Entrée", 92.0),
            col("Sortie", 92.0),
            col("Source", 130.0),
            col("Destination", 130.0),
            flex("Conditions", 1.0),
            col_r("Paquets", 70.0),
            col_r("Volume", 72.0),
            col("", 36.0),
        ];
        table_header(ui, &cols, None);
        for r in &ch.rules {
            let (rect, _) = table_row(ui, 26.0, false, &format!("{} règle {}", ch.name, r.num));
            let c = col_rects(rect, &cols);
            cell(ui, c[0], &r.num.to_string(), &mono(11.5), pal().ink2, true);
            let (sym, col_) = target_style(&r.target);
            icon_cell(ui, c[1], sym, col_, &r.target, &body(12.0), pal().ink);
            cell(ui, c[2], &r.proto, &mono(11.5), pal().ink2, false);
            cell(ui, c[3], &r.in_if, &mono(11.5), pal().ink2, false);
            cell(ui, c[4], &r.out_if, &mono(11.5), pal().ink2, false);
            cell(ui, c[5], &r.source, &mono(11.5), pal().ink2, false);
            cell(ui, c[6], &r.dest, &mono(11.5), pal().ink2, false);
            cell(ui, c[7], &r.extra, &mono(11.5), pal().ink2, false);
            cell(ui, c[8], &fmt_count(r.packets), &mono(11.5), pal().ink2, true);
            cell(ui, c[9], &fmt_bytes(r.bytes), &mono(11.5), pal().ink2, true);
            let num = r.num.to_string();
            in_cell(ui, c[10], |ui| {
                if small_button(ui, icon::TRASH).on_hover_text("Retirer cette règle").clicked() {
                    app.ask(Action::new(
                        format!("Retirer la règle {num} de {}", ch.name),
                        "La règle est supprimée immédiatement.",
                        vec![Step::root(prog, &["-t", &table, "-D", &ch.name, &num])],
                    ));
                }
            });
        }
    });
}

// ---------- Configuration réseau ----------

pub fn config(app: &mut App, ui: &mut Ui) {
    let shared = app.shared.clone();
    let data = shared.panels.lock().unwrap().config.clone();
    let mut ifaces: Vec<crate::model::Iface> = shared.model.lock().unwrap().ifaces.values().cloned().collect();
    // Les cartes réelles d'abord, les interfaces de conteneurs à la fin.
    ifaces.sort_by_key(|i| (!i.counted(), i.bridge_port, i.name.clone()));

    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        if !shared.admin.is_on() {
            hint(ui, "Modifier une interface, une adresse ou une route demandera votre mot de passe à la confirmation.");
            ui.add_space(4.0);
        }
        if let Some(e) = &app.cfg.error {
            ui.horizontal(|ui| {
                ui.label(RichText::new(icon::WARNING).color(pal().critical_text));
                ui.label(RichText::new(e).color(pal().critical_text));
            });
        }
        card(ui, |ui| {
            ui.set_width(ui.available_width());
            section_title(ui, "Interfaces");
            let cols = [flex("Nom", 0.9), col("Type", 104.0), col("État", 92.0), flex("Adresses", 1.6), col("Adresse physique", 150.0), col_r("MTU", 56.0), col_r("Débit max.", 84.0)];
            table_header(ui, &cols, None);
            for i in &ifaces {
                let selected = app.cfg.selected_iface.as_deref() == Some(i.name.as_str());
                let (rect, resp) = table_row(ui, 30.0, selected, &i.name);
                let c = col_rects(rect, &cols);
                cell(ui, c[0], &i.name, &body(13.0), pal().ink, false);
                cell(ui, c[1], i.kind.label(), &body(12.0), pal().ink2, false);
                let (sym, col_, label) = if i.is_up() { (icon::CHECK_CIRCLE, pal().good, "Active") } else { (icon::MINUS_CIRCLE, pal().muted, "Inactive") };
                icon_cell(ui, c[2], sym, col_, label, &body(12.0), pal().ink2);
                let addrs = i.addrs.iter().map(|(a, p)| format!("{a}/{p}")).collect::<Vec<_>>().join("  ");
                // Plusieurs adresses sur une ligne : l'IPv4 d'abord ; les autres ont leur bouton en dessous.
                match i.addrs.iter().find(|a| a.0.is_ipv4()).or(i.addrs.first()) {
                    Some((a, _)) => ip_cell(ui, c[3], &a.to_string(), &addrs, &mono(11.5), pal().ink2),
                    None => cell(ui, c[3], &addrs, &mono(11.5), pal().ink2, false),
                }
                cell(ui, c[4], &i.mac, &mono(11.5), pal().ink2, false);
                cell(ui, c[5], &i.mtu.to_string(), &mono(11.5), pal().ink2, true);
                cell(ui, c[6], &i.speed_mbps.map(|s| if s >= 1000 { format!("{} Gbit/s", s / 1000) } else { format!("{s} Mbit/s") }).unwrap_or_default(), &mono(11.5), pal().ink2, true);
                if resp.clicked() {
                    app.cfg.selected_iface = if selected { None } else { Some(i.name.clone()) };
                    app.cfg.mtu = i.mtu.to_string();
                }
            }
            if let Some(i) = app.cfg.selected_iface.clone().and_then(|n| ifaces.iter().find(|x| x.name == n)) {
                ui.add_space(8.0);
                Frame::new().fill(pal().field).corner_radius(8).inner_margin(Margin::same(10)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("Modifier {}", i.name)).font(bold(13.5)).color(pal().ink));
                        if i.is_up() {
                            if ui.button("Désactiver").clicked() {
                                app.ask(manage::link_action(&i.name, false));
                            }
                        } else if ui.button("Activer").clicked() {
                            app.ask(manage::link_action(&i.name, true));
                        }
                        ui.add_space(12.0);
                        ui.label(RichText::new("MTU").color(pal().muted).size(12.5));
                        ui.add(egui::TextEdit::singleline(&mut app.cfg.mtu).desired_width(64.0));
                        if ui.button("Appliquer").clicked() {
                            match manage::mtu_action(&i.name, &app.cfg.mtu) {
                                Ok(a) => {
                                    app.cfg.error = None;
                                    app.ask(a);
                                }
                                Err(e) => app.cfg.error = Some(e),
                            }
                        }
                        ui.add_space(12.0);
                        ui.label(RichText::new("Adresse").color(pal().muted).size(12.5));
                        ui.add(egui::TextEdit::singleline(&mut app.cfg.addr).hint_text("192.168.1.50/24").desired_width(150.0));
                        if ui.button("Ajouter").clicked() {
                            match manage::addr_action(&i.name, &app.cfg.addr, true) {
                                Ok(a) => {
                                    app.cfg.error = None;
                                    app.ask(a);
                                }
                                Err(e) => app.cfg.error = Some(e),
                            }
                        }
                    });
                    ui.horizontal_wrapped(|ui| {
                        for (a, p) in &i.addrs {
                            let cidr = format!("{a}/{p}");
                            copy_inline(ui, &a.to_string());
                            if small_button(ui, &format!("{cidr}  {}", icon::X)).on_hover_text("Retirer cette adresse").clicked() {
                                if let Ok(act) = manage::addr_action(&i.name, &cidr, false) {
                                    app.ask(act);
                                }
                            }
                        }
                    });
                });
            } else {
                hint(ui, "Cliquez sur une interface pour la modifier.");
            }
        });
        ui.add_space(4.0);

        card(ui, |ui| {
            ui.set_width(ui.available_width());
            section_title(ui, "Routes");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut app.cfg.route_dst).hint_text("Destination, ex. 10.0.0.0/8 ou default").desired_width(240.0));
                ui.add(egui::TextEdit::singleline(&mut app.cfg.route_via).hint_text("Passerelle").desired_width(130.0));
                ui.add(egui::TextEdit::singleline(&mut app.cfg.route_dev).hint_text("Interface").desired_width(100.0));
                if ui.button("Ajouter la route").clicked() {
                    match manage::route_add_action(&app.cfg.route_dst, &app.cfg.route_via, &app.cfg.route_dev) {
                        Ok(a) => {
                            app.cfg.error = None;
                            app.ask(a);
                        }
                        Err(e) => app.cfg.error = Some(e),
                    }
                }
            });
            let cols = [flex("Destination", 1.2), flex("Passerelle", 1.0), col("Interface", 130.0), col("Origine", 80.0), col_r("Priorité", 66.0), col("", 40.0)];
            table_header(ui, &cols, None);
            for r in &data.routes {
                let (rect, _) = table_row(ui, 26.0, false, &r.dst);
                let c = col_rects(rect, &cols);
                let dst = if r.dst == "default" { "Par défaut (Internet)" } else { r.dst.as_str() };
                cell(ui, c[0], dst, &mono(11.5), pal().ink, false);
                match ip_only(&r.via) {
                    Some(ip) => ip_cell(ui, c[1], &ip, &r.via, &mono(11.5), pal().ink2),
                    None => cell(ui, c[1], &r.via, &mono(11.5), pal().ink2, false),
                }
                cell(ui, c[2], &r.dev, &body(12.0), pal().ink2, false);
                cell(ui, c[3], &r.proto, &body(12.0), pal().ink2, false);
                cell(ui, c[4], &r.metric, &mono(11.5), pal().ink2, true);
                let row = r.clone();
                in_cell(ui, c[5], |ui| {
                    if small_button(ui, icon::TRASH).on_hover_text("Retirer cette route").clicked() {
                        app.ask(manage::route_del_action(&row));
                    }
                });
            }
        });
        ui.add_space(4.0);

        let half = (ui.available_width() - 10.0) / 2.0;
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            ui.allocate_ui_with_layout(egui::vec2(half, 10.0), Layout::top_down(Align::Min), |ui| {
                ui.set_width(half);
                card(ui, |ui| {
                    ui.set_width(half - 30.0);
                    section_title(ui, "Connexions enregistrées");
                    if !data.nm_available {
                        hint(ui, "NetworkManager n'est pas disponible sur ce PC.");
                    }
                    let cols = [flex("Nom", 1.0), col("Interface", 104.0), col("", 80.0)];
                    table_header(ui, &cols, None);
                    let shown: Vec<_> = data.connections.iter().filter(|c| c.kind != "loopback" && c.kind != "bridge").collect();
                    for con in shown {
                        let (rect, _) = table_row(ui, 28.0, false, &con.name);
                        let c = col_rects(rect, &cols);
                        icon_cell(ui, c[0], if con.active { icon::CHECK_CIRCLE } else { icon::MINUS_CIRCLE }, if con.active { pal().good } else { pal().muted }, &con.name, &body(12.5), pal().ink);
                        cell(ui, c[1], &con.device, &body(12.0), pal().ink2, false);
                        let conn = con.clone();
                        in_cell(ui, c[2], |ui| {
                            if small_button(ui, if conn.active { "Couper" } else { "Activer" }).clicked() {
                                app.ask(manage::nm_toggle_action(&conn));
                            }
                        });
                    }
                });
            });
            ui.allocate_ui_with_layout(egui::vec2(half, 10.0), Layout::top_down(Align::Min), |ui| {
                ui.set_width(half);
                card(ui, |ui| {
                    ui.set_width(half - 30.0);
                    section_title(ui, "Serveurs DNS");
                    for (who, servers) in &data.dns {
                        kv_mono(ui, who, servers);
                    }
                    if data.dns.is_empty() {
                        hint(ui, "Aucun serveur DNS trouvé.");
                    }
                    let active: Vec<_> = data.connections.iter().filter(|c| c.active && c.kind != "loopback" && c.kind != "bridge").collect();
                    if !active.is_empty() {
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            let label = app.cfg.dns_conn.clone().filter(|n| active.iter().any(|c| &c.name == n)).unwrap_or_else(|| active[0].name.clone());
                            let r = egui::ComboBox::from_id_salt("dns_conn").selected_text(&label).width(150.0).show_ui(ui, |ui| {
                                for c in &active {
                                    if ui.selectable_label(c.name == label, &c.name).clicked() {
                                        app.cfg.dns_conn = Some(c.name.clone());
                                    }
                                }
                            });
                            named(&r.response, "Connexion");
                            ui.add(egui::TextEdit::singleline(&mut app.cfg.dns_servers).hint_text("1.1.1.1 8.8.8.8").desired_width(130.0));
                            if ui.button("Appliquer").clicked() {
                                if let Some(c) = active.iter().find(|c| c.name == label) {
                                    match manage::dns_action(c, &app.cfg.dns_servers) {
                                        Ok(a) => {
                                            app.cfg.error = None;
                                            app.ask(a);
                                        }
                                        Err(e) => app.cfg.error = Some(e),
                                    }
                                }
                            }
                        });
                    }
                });
                ui.add_space(4.0);
                card(ui, |ui| {
                    ui.set_width(half - 30.0);
                    section_title(ui, "Appareils voisins");
                    let cols = [flex("Adresse", 1.0), col("Interface", 100.0), col("Adresse physique", 142.0), col("État", 88.0)];
                    table_header(ui, &cols, None);
                    for n in data.neighbors.iter().filter(|n| !n.mac.is_empty()).take(30) {
                        let (rect, _) = table_row(ui, 24.0, false, &n.ip);
                        let c = col_rects(rect, &cols);
                        cell(ui, c[0], &n.ip, &mono(11.5), pal().ink, false);
                        cell(ui, c[1], &n.dev, &body(12.0), pal().ink2, false);
                        cell(ui, c[2], &n.mac, &mono(11.5), pal().ink2, false);
                        let state = match n.state.as_str() {
                            "REACHABLE" => "Joignable",
                            "STALE" | "DELAY" | "PROBE" => "À vérifier",
                            "PERMANENT" => "Permanent",
                            "FAILED" => "Échec",
                            o => o,
                        };
                        cell(ui, c[3], state, &body(12.0), pal().ink2, false);
                    }
                });
            });
        });
    });
}

// ---------- SSH ----------

fn yes_no(ui: &mut Ui, label: &str, value: &mut String) {
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 3.0;
        ui.label(RichText::new(label).color(pal().muted).size(12.0));
        chips(ui, value, &[("yes".to_string(), "Oui"), ("no".to_string(), "Non")]);
    });
}

pub fn ssh(app: &mut App, ui: &mut Ui) {
    let shared = app.shared.clone();
    let data = shared.panels.lock().unwrap().ssh.clone();
    if !data.loaded {
        ui.horizontal(|ui| {
            ui.add(egui::Spinner::new());
            ui.label("Lecture de la configuration SSH…");
        });
        return;
    }

    // Reprend les valeurs du système dans le formulaire tant qu'elles ne sont pas modifiées.
    let fingerprint = format!("{:?}", data.settings.iter().filter(|(k, _)| SSH_SETTINGS.contains(&k.as_str())).collect::<Vec<_>>());
    if app.ssh.loaded_from.as_deref() != Some(fingerprint.as_str()) {
        app.ssh.loaded_from = Some(fingerprint);
        let get = |k: &str, d: &str| data.settings.get(k).cloned().unwrap_or_else(|| d.to_string());
        app.ssh.port = get("port", "22");
        app.ssh.root_login = get("permitrootlogin", "prohibit-password");
        app.ssh.password = get("passwordauthentication", "yes");
        app.ssh.pubkey = get("pubkeyauthentication", "yes");
        app.ssh.x11 = get("x11forwarding", "no");
        app.ssh.tries = get("maxauthtries", "6");
    }

    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        server_card(app, ui, &data);
        ui.add_space(4.0);
        let (a, b, c, d) = (
            "Sessions".to_string(),
            format!("Clés  {}", data.authorized.len() + data.own_keys.len()),
            format!("Machines  {}", data.hosts.len() + data.known_hosts.len()),
            format!("Tentatives  {}", data.logins.len()),
        );
        chips(ui, &mut app.ssh.tab, &[(SshTab::Sessions, a.as_str()), (SshTab::Keys, b.as_str()), (SshTab::Hosts, c.as_str()), (SshTab::Logins, d.as_str())]);
        ui.add_space(4.0);
        match app.ssh.tab {
            SshTab::Sessions => sessions(app, ui, &data),
            SshTab::Keys => keys(app, ui, &data),
            SshTab::Hosts => hosts(ui, &data),
            SshTab::Logins => logins(app, ui, &data),
        }
    });
}

fn server_card(app: &mut App, ui: &mut Ui, data: &manage::SshData) {
    card(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            section_title(ui, "Serveur SSH de ce PC");
            if !data.server_installed {
                status_badge(ui, icon::MINUS_CIRCLE, pal().muted, "Non installé");
            } else if data.active {
                status_badge(ui, icon::CHECK_CIRCLE, pal().good, &format!("En service, port {}", data.ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")));
            } else {
                status_badge(ui, icon::MINUS_CIRCLE, pal().muted, "Arrêté");
            }
            if data.server_installed {
                status_badge(ui, icon::POWER, if data.enabled { pal().good } else { pal().muted }, if data.enabled { "Lancé au démarrage" } else { "Pas lancé au démarrage" });
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if !data.server_installed {
                    if data.can_install && primary_button(ui, "Installer le serveur SSH").clicked() {
                        app.ask(Action::new(
                            "Installer le serveur SSH",
                            "Installe OpenSSH Server depuis les dépôts du système. Le service peut démarrer tout de suite : d'autres machines pourront alors tenter de se connecter à ce PC.",
                            vec![Step::root("apt-get", &["install", "-y", "openssh-server"])],
                        ));
                    }
                    return;
                }
                let unit = data.unit.clone();
                if data.enabled {
                    if ui.button("Ne plus lancer au démarrage").clicked() {
                        app.ask(manage::ssh_service_action(&unit, "disable"));
                    }
                } else if ui.button("Lancer au démarrage").clicked() {
                    app.ask(manage::ssh_service_action(&unit, "enable"));
                }
                if data.active {
                    if ui.button("Redémarrer").clicked() {
                        app.ask(manage::ssh_service_action(&unit, "restart"));
                    }
                    if ui.button("Arrêter").clicked() {
                        app.ask(manage::ssh_service_action(&unit, "stop"));
                    }
                } else if primary_button(ui, "Démarrer").clicked() {
                    app.ask(manage::ssh_service_action(&unit, "start"));
                }
            });
        });
        if !data.server_installed {
            hint(ui, "Sans serveur, personne ne peut entrer sur ce PC par SSH. Vos connexions sortantes, vos clés et vos machines restent gérées ci-dessous.");
            return;
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            labeled_field(ui, "Port", &mut app.ssh.port, 70.0, "22");
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 3.0;
                ui.label(RichText::new("Connexion en root").color(pal().muted).size(12.0));
                chips(ui, &mut app.ssh.root_login, &[("no".to_string(), "Interdite"), ("prohibit-password".to_string(), "Clé seulement"), ("yes".to_string(), "Autorisée")]);
            });
            yes_no(ui, "Mot de passe", &mut app.ssh.password);
            yes_no(ui, "Clés publiques", &mut app.ssh.pubkey);
            yes_no(ui, "Affichage X11", &mut app.ssh.x11);
            labeled_field(ui, "Essais max.", &mut app.ssh.tries, 60.0, "6");
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 3.0;
                ui.label(RichText::new(" ").size(12.0));
                if primary_button(ui, "Appliquer").clicked() {
                    let values = vec![
                        ("port".to_string(), app.ssh.port.trim().to_string()),
                        ("permitrootlogin".to_string(), app.ssh.root_login.clone()),
                        ("passwordauthentication".to_string(), app.ssh.password.clone()),
                        ("pubkeyauthentication".to_string(), app.ssh.pubkey.clone()),
                        ("x11forwarding".to_string(), app.ssh.x11.clone()),
                        ("maxauthtries".to_string(), app.ssh.tries.trim().to_string()),
                    ];
                    match manage::ssh_settings_action(&data.unit, &data.dropin_content, &values) {
                        Ok(mut a) => {
                            app.ssh.error = None;
                            if app.ssh.password == "no" && app.ssh.pubkey == "no" {
                                a = a.warn("Mot de passe et clés sont tous deux refusés : plus personne ne pourra se connecter.");
                            } else if app.ssh.port.trim() != data.settings.get("port").map(String::as_str).unwrap_or("22") {
                                a = a.warn("Le port change : pensez à l'ouvrir dans le pare-feu avant de vous reconnecter.");
                            }
                            app.ask(a);
                        }
                        Err(e) => app.ssh.error = Some(e),
                    }
                }
            });
        });
        if let Some(e) = &app.ssh.error {
            ui.label(RichText::new(e).color(pal().critical_text).size(12.5));
        }
        if !data.settings_effective {
            hint(ui, "Valeurs lues dans les fichiers de configuration. Le mode administrateur montre celles réellement appliquées.");
        }
        if !data.dropin_supported {
            ui.horizontal(|ui| {
                ui.label(RichText::new(icon::WARNING).color(pal().warning));
                ui.label(RichText::new("Ce serveur ne lit pas le dossier sshd_config.d : les réglages appliqués ici peuvent rester sans effet.").color(pal().ink2).size(12.5));
            });
        }
    });
}

fn sessions(app: &mut App, ui: &mut Ui, data: &manage::SshData) {
    let shared = app.shared.clone();
    let m = shared.model.lock().unwrap();
    let ports = if data.ports.is_empty() { vec![22] } else { data.ports.clone() };
    let is_ssh_client = |n: &str| matches!(n, "ssh" | "scp" | "sftp" | "rsync" | "autossh" | "mosh-client");
    let incoming: Vec<_> = m.flows.values().filter(|f| f.open && f.state == "ESTAB" && f.dir == FlowDir::Incoming && ports.contains(&f.key.local.port())).collect();
    let outgoing: Vec<_> = m.flows.values().filter(|f| f.open && f.state == "ESTAB" && f.dir == FlowDir::Outgoing && (f.key.remote.port() == 22 || f.proc_name.as_deref().is_some_and(is_ssh_client))).collect();

    card(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, &format!("Entrantes : on est connecté à ce PC ({})", incoming.len()));
        let cols = [col("Depuis", 200.0), flex("Fournisseur", 1.0), col("Programme", 120.0), col_r("Processus", 80.0), col_r("Reçu", 80.0), col_r("Envoyé", 80.0), col("", 100.0)];
        if incoming.is_empty() {
            hint(ui, "Personne n'est connecté à ce PC par SSH.");
        } else {
            table_header(ui, &cols, None);
            for f in &incoming {
                let (rect, _) = table_row(ui, 30.0, false, &f.key.remote.to_string());
                let c = col_rects(rect, &cols);
                ip_cell(ui, c[0], &f.key.remote.ip().to_string(), &f.key.remote.to_string(), &mono(12.0), pal().ink);
                cell(ui, c[1], &super::page_monitor::provider_label(app, &m, f), &body(12.5), pal().ink2, false);
                cell(ui, c[2], &f.app_name(), &body(12.5), pal().ink2, false);
                cell(ui, c[3], &f.pid.map(|p| p.to_string()).unwrap_or_else(|| "—".into()), &mono(12.0), pal().ink2, true);
                cell(ui, c[4], &fmt_bytes(f.rx_total), &mono(11.5), pal().ink2, true);
                cell(ui, c[5], &fmt_bytes(f.tx_total), &mono(11.5), pal().ink2, true);
                let (local, remote, name) = (f.key.local.to_string(), f.key.remote.to_string(), f.app_name());
                in_cell(ui, c[6], |ui| {
                    if small_button(ui, "Déconnecter").clicked() {
                        app.ask(manage::kill_socket_action(&local, &remote, &name));
                    }
                });
            }
        }
        ui.add_space(10.0);
        section_title(ui, &format!("Sortantes : ce PC est connecté ailleurs ({})", outgoing.len()));
        if outgoing.is_empty() {
            hint(ui, "Aucune session SSH sortante.");
        } else {
            let cols = [col("Vers", 200.0), flex("Fournisseur", 1.0), col("Programme", 120.0), col_r("Processus", 80.0), col_r("Reçu", 80.0), col_r("Envoyé", 80.0), col("", 100.0)];
            table_header(ui, &cols, None);
            for f in &outgoing {
                let (rect, _) = table_row(ui, 30.0, false, &f.key.remote.to_string());
                let c = col_rects(rect, &cols);
                ip_cell(ui, c[0], &f.key.remote.ip().to_string(), &f.key.remote.to_string(), &mono(12.0), pal().ink);
                cell(ui, c[1], &super::page_monitor::provider_label(app, &m, f), &body(12.5), pal().ink2, false);
                cell(ui, c[2], &f.app_name(), &body(12.5), pal().ink2, false);
                cell(ui, c[3], &f.pid.map(|p| p.to_string()).unwrap_or_else(|| "—".into()), &mono(12.0), pal().ink2, true);
                cell(ui, c[4], &fmt_bytes(f.rx_total), &mono(11.5), pal().ink2, true);
                cell(ui, c[5], &fmt_bytes(f.tx_total), &mono(11.5), pal().ink2, true);
                let (pid, name) = (f.pid, f.app_name());
                in_cell(ui, c[6], |ui| {
                    if let Some(pid) = pid {
                        if small_button(ui, "Fermer").clicked() {
                            app.ask(manage::kill_process_action(pid, &name, false));
                        }
                    }
                });
            }
        }
    });
}

fn keys(app: &mut App, ui: &mut Ui, data: &manage::SshData) {
    card(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, "Clés autorisées à entrer sur votre compte");
        let cols = [col("Type", 110.0), flex("Commentaire", 0.8), flex("Empreinte", 1.4), col("", 80.0)];
        if data.authorized.is_empty() {
            hint(ui, "Aucune clé autorisée.");
        } else {
            table_header(ui, &cols, None);
            for k in &data.authorized {
                let (rect, _) = table_row(ui, 28.0, false, &k.fingerprint);
                let c = col_rects(rect, &cols);
                cell(ui, c[0], &k.kind, &mono(11.5), pal().ink2, false);
                cell(ui, c[1], &k.comment, &body(12.5), pal().ink, false);
                cell(ui, c[2], &k.fingerprint, &mono(11.5), pal().ink2, false);
                in_cell(ui, c[3], |ui| {
                    if small_button(ui, "Retirer").clicked() {
                        app.ask(manage::remove_authorized_action(&data.authorized, k));
                    }
                });
            }
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut app.ssh.new_key).hint_text("Collez ici une clé publique : ssh-ed25519 AAAA…").desired_width(ui.available_width() - 110.0).font(mono(12.0)));
            if ui.button("Autoriser").clicked() {
                match manage::add_authorized_action(&data.authorized, &app.ssh.new_key) {
                    Ok(a) => {
                        app.ssh.error = None;
                        app.ssh.new_key.clear();
                        app.ask(a);
                    }
                    Err(e) => app.ssh.error = Some(e),
                }
            }
        });
        if let Some(e) = &app.ssh.error {
            ui.label(RichText::new(e).color(pal().critical_text).size(12.5));
        }
    });
    ui.add_space(4.0);
    card(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, "Vos clés");
        hint(ui, "Seule la partie publique est lue : NetBuster n'ouvre jamais vos clés privées.");
        let cols = [col("Fichier", 180.0), col("Type", 110.0), flex("Commentaire", 0.8), flex("Empreinte", 1.4)];
        table_header(ui, &cols, None);
        for (file, k) in &data.own_keys {
            let (rect, _) = table_row(ui, 26.0, false, file);
            let c = col_rects(rect, &cols);
            cell(ui, c[0], file, &body(12.5), pal().ink, false);
            cell(ui, c[1], &k.kind, &mono(11.5), pal().ink2, false);
            cell(ui, c[2], &k.comment, &body(12.5), pal().ink2, false);
            cell(ui, c[3], &k.fingerprint, &mono(11.5), pal().ink2, false);
        }
        if !data.agent_keys.is_empty() {
            ui.add_space(6.0);
            ui.label(RichText::new(format!("Chargées dans l'agent SSH : {}", data.agent_keys.len())).color(pal().ink2).size(12.5));
        }
    });
}

fn hosts(ui: &mut Ui, data: &manage::SshData) {
    card(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, "Machines configurées");
        if data.hosts.is_empty() {
            hint(ui, "Aucune machine dans votre configuration SSH.");
        } else {
            let cols = [flex("Nom court", 0.8), flex("Adresse", 1.2), col("Utilisateur", 140.0), col_r("Port", 60.0)];
            table_header(ui, &cols, None);
            for h in &data.hosts {
                let (rect, _) = table_row(ui, 26.0, false, &h.alias);
                let c = col_rects(rect, &cols);
                cell(ui, c[0], &h.alias, &body(12.5), pal().ink, false);
                cell(ui, c[1], &h.hostname, &mono(11.5), pal().ink2, false);
                cell(ui, c[2], &h.user, &body(12.5), pal().ink2, false);
                cell(ui, c[3], &h.port, &mono(11.5), pal().ink2, true);
            }
        }
    });
    ui.add_space(4.0);
    card(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, &format!("Machines déjà rencontrées ({})", data.known_hosts.len()));
        let hashed = data.known_hosts.iter().filter(|h| h.hashed).count();
        if hashed > 0 {
            hint(ui, format!("{hashed} noms sont volontairement masqués dans le fichier par SSH."));
        }
        let cols = [flex("Machine", 1.0), col("Type de clé", 180.0)];
        table_header(ui, &cols, None);
        for h in data.known_hosts.iter().filter(|h| !h.hashed).take(200) {
            let (rect, _) = table_row(ui, 24.0, false, &h.host);
            let c = col_rects(rect, &cols);
            cell(ui, c[0], &h.host, &mono(11.5), pal().ink2, false);
            cell(ui, c[1], &h.kind, &mono(11.5), pal().ink2, false);
        }
    });
}

fn logins(app: &mut App, ui: &mut Ui, data: &manage::SshData) {
    card(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, "Tentatives de connexion à ce PC");
        if !data.server_installed {
            hint(ui, "Le serveur SSH n'est pas installé : aucune tentative possible.");
            return;
        }
        if data.logins_need_admin && data.logins.is_empty() {
            admin_gate(app, ui, "Le journal du serveur SSH n'est lisible qu'en administrateur.");
            return;
        }
        if data.logins.is_empty() {
            hint(ui, "Aucune tentative enregistrée.");
            return;
        }
        let cols = [col("Date", 170.0), col("Résultat", 100.0), flex("Compte", 1.0), col("Depuis", 180.0), col("Méthode", 120.0), col("", 70.0)];
        table_header(ui, &cols, None);
        for e in &data.logins {
            let (rect, _) = table_row(ui, 26.0, false, &e.from);
            let c = col_rects(rect, &cols);
            cell(ui, c[0], &e.when, &mono(11.5), pal().ink2, false);
            icon_cell(ui, c[1], if e.ok { icon::CHECK_CIRCLE } else { icon::X_CIRCLE }, if e.ok { pal().good } else { pal().critical_text }, if e.ok { "Réussie" } else { "Refusée" }, &body(12.0), pal().ink2);
            cell(ui, c[2], &e.user, &body(12.5), pal().ink, false);
            match ip_only(&e.from) {
                Some(ip) => ip_cell(ui, c[3], &ip, &e.from, &mono(11.5), pal().ink2),
                None => cell(ui, c[3], &e.from, &mono(11.5), pal().ink2, false),
            }
            cell(ui, c[4], &e.method, &body(12.0), pal().ink2, false);
            if let Ok(ip) = e.from.parse::<std::net::IpAddr>() {
                in_cell(ui, c[5], |ui| {
                    if small_button(ui, "Qui ?").clicked() {
                        app.go_lookup(ip);
                    }
                });
            }
        }
    });
}
