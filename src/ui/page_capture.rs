//! Écran Paquets : capture en direct, filtres, détail, conversation, déchiffrement.

use super::page_monitor::crypto_symbol;
use super::theme::*;
use super::widgets::*;
use super::{App, CryptoFilter, DetailTab, DirFilter};
use crate::admin::AdminState;
use crate::model::{Model, PacketRow, Stream};
use crate::packet::{self, Crypto, Dir};
use crate::util::{fmt_bytes, fmt_count, home_dir, which};
use eframe::egui::{self, Align, Frame, Layout, Margin, RichText, Ui};
use egui_phosphor::regular as icon;
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// Un dossier visible : les navigateurs installés en « snap » n'ont pas accès aux dossiers cachés.
fn netbuster_home() -> std::path::PathBuf {
    home_dir().join("NetBuster")
}

fn keylog_path() -> std::path::PathBuf {
    netbuster_home().join("cles-tls.log")
}

/// Crée le fichier de clés, lisible par la personne seule, et commence à le surveiller.
pub fn enable_decryption(m: &mut Model) -> Result<(), String> {
    let path = keylog_path();
    std::fs::create_dir_all(netbuster_home()).map_err(|e| e.to_string())?;
    crate::util::private_file_options().create(true).append(true).open(&path).map_err(|e| e.to_string())?;
    m.keylog.path = Some(path);
    Ok(())
}

/// Navigateurs connus : (nom affiché, programme, famille Firefox ?)
const BROWSERS: &[(&str, &str, bool)] = &[
    ("Firefox", "firefox", true),
    ("Chrome", "google-chrome", false),
    ("Chromium", "chromium", false),
    ("Chromium", "chromium-browser", false),
    ("Brave", "brave-browser", false),
    ("Edge", "microsoft-edge", false),
];

/// Lance un navigateur dans un profil séparé, qui écrit ses clés de session dans le fichier.
fn launch_browser(prog: &str, firefox: bool) -> Result<(), String> {
    let profile = netbuster_home().join(format!("profil-{prog}"));
    std::fs::create_dir_all(&profile).map_err(|e| e.to_string())?;
    let mut c = std::process::Command::new(prog);
    c.env("SSLKEYLOGFILE", keylog_path());
    if firefox {
        // HTTP/3 (QUIC) ne se déchiffre pas ici : on demande au navigateur de rester en TCP.
        std::fs::write(profile.join("user.js"), "user_pref(\"network.http.http3.enable\", false);\n").map_err(|e| e.to_string())?;
        c.arg("--new-instance").arg("--profile").arg(&profile);
    } else {
        c.arg(format!("--user-data-dir={}", profile.display())).arg("--disable-quic").arg("--no-first-run");
    }
    c.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    c.spawn().map(|_| ()).map_err(|e| e.to_string())
}

pub fn packets(app: &mut App, ui: &mut Ui) {
    let shared = app.shared.clone();
    let state = shared.admin.state();
    let admin_on = matches!(state, AdminState::On { .. });

    {
        let mut m = shared.model.lock().unwrap();
        toolbar(app, ui, &mut m, admin_on);
    }
    if !admin_on && !shared.service_up.load(Ordering::Relaxed) {
        ui.add_space(6.0);
        if notice(
            ui,
            icon::LOCK,
            pal().warning,
            "La capture des paquets demande les droits administrateur",
            "Le noyau ne laisse lire les paquets qu'à l'administrateur. Votre mot de passe est demandé par le système, jamais par NetBuster, et les droits s'arrêtent à la fermeture de l'application.",
            Some("Démarrer la capture"),
        ) {
            shared.enable_admin();
        }
    }
    let error = shared.model.lock().unwrap().capture.error.clone();
    if let Some(e) = error {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new(icon::WARNING).color(pal().critical_text));
            ui.label(RichText::new(e).color(pal().critical_text));
        });
    }
    if let Some(msg) = app.packets.message.clone() {
        ui.horizontal(|ui| {
            ui.label(RichText::new(icon::INFO).color(pal().rx));
            ui.label(RichText::new(msg).color(pal().ink2).size(12.5));
            if small_button(ui, icon::X).clicked() {
                app.packets.message = None;
            }
        });
    }

    let m = shared.model.lock().unwrap();
    refresh_cache(app, &m);
    if let Some(wanted) = app.packets.select_first.clone() {
        let found = app.packets.cached.iter().find(|r| r.pkt.app == wanted && r.pkt.payload().len() > 5).map(|r| r.id);
        if let Some(id) = found {
            app.packets.selected = Some(id);
            app.packets.select_first = None;
        }
    }
    filters(app, ui, &m);
    ui.add_space(2.0);

    let selected = app.packets.selected.and_then(|id| app.packets.cached.iter().rev().find(|r| r.id == id).cloned().or_else(|| m.packets.iter().rev().find(|r| r.id == id).cloned()));
    if let Some(row) = &selected {
        let width = (ui.available_width() * 0.46).clamp(470.0, 640.0);
        egui::Panel::right("packet_detail")
            .exact_size(width)
            .resizable(false)
            .show_separator_line(false)
            .frame(Frame::new().inner_margin(Margin { left: 10, ..Default::default() }))
            .show(ui, |ui| detail(app, ui, &m, row));
    }

    table(app, ui);
}

fn toolbar(app: &mut App, ui: &mut Ui, m: &mut Model, admin_on: bool) {
    let shared = app.shared.clone();
    ui.horizontal(|ui| {
        if m.capture.service {
            status_badge(ui, icon::CHECK_CIRCLE, pal().good, "Capture par le service");
        } else if m.capture.running {
            if danger_button(ui, &format!("{} Arrêter", icon::STOP)).clicked() {
                shared.stop_capture();
            }
        } else if admin_on && primary_button(ui, &format!("{} Démarrer", icon::PLAY)).clicked() {
            shared.start_capture();
        }
        if freeze_toggle(ui, app.packets.frozen.is_some(), &app.packets.frozen_at) {
            if app.packets.frozen.take().is_none() {
                app.packets.frozen = Some(m.packets.iter().cloned().collect());
                app.packets.frozen_at = chrono::Local::now().format("%H:%M:%S").to_string();
                app.packets.frozen_seen = m.capture.seen_packets;
            }
        }
        if app.packets.frozen.is_some() {
            let waiting = m.capture.seen_packets.saturating_sub(app.packets.frozen_seen);
            ui.label(RichText::new(format!("{} nouveaux en attente", fmt_count(waiting))).color(pal().muted).size(12.5));
        }
        if ui.button(format!("{} Vider", icon::TRASH)).clicked() {
            m.clear_packets();
            app.packets.frozen = None;
            app.packets.selected = None;
            app.packets.flow_filter = None;
        }
        if ui.add_enabled(!m.packets.is_empty(), egui::Button::new(format!("{} Enregistrer", icon::DOWNLOAD_SIMPLE))).on_hover_text("Fichier .pcap, à ouvrir dans Wireshark").clicked() {
            app.packets.message = Some(export(m));
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            // Le service garde toujours les paquets complets.
            if !m.capture.service {
                let snap = shared.capture_snap.load(Ordering::Relaxed);
                let label = if snap >= 65535 { "Paquets complets" } else { "Début de chaque paquet" };
                let resp = egui::ComboBox::from_id_salt("snap").selected_text(label).width(170.0).show_ui(ui, |ui| {
                    let mut v = snap;
                    ui.selectable_value(&mut v, 65535, "Paquets complets");
                    ui.selectable_value(&mut v, 2048, "Début de chaque paquet");
                    v
                });
                named(&resp.response, "Taille de capture");
                if let Some(v) = resp.inner {
                    if v != snap {
                        shared.capture_snap.store(v, Ordering::Relaxed);
                        if m.capture.running {
                            // Le nouveau réglage s'applique en relançant la capture.
                            shared.stop_capture();
                            let s2 = shared.clone();
                            std::thread::spawn(move || {
                                std::thread::sleep(std::time::Duration::from_millis(400));
                                s2.start_capture();
                            });
                        }
                    }
                }
                ui.add_space(6.0);
            }
            let drops = m.capture.kernel_drops;
            ui.label(RichText::new(format!("{} paquets, {}{}", fmt_count(m.capture.seen_packets), fmt_bytes(m.capture.seen_bytes), if drops > 0 { format!(", {} perdus par le noyau", fmt_count(drops)) } else { String::new() })).color(pal().muted).size(12.5));
        });
    });
}

fn export(m: &Model) -> String {
    let dir = netbuster_home();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return format!("Enregistrement impossible : {e}");
    }
    let name = format!("capture-{}.pcap", chrono::Local::now().format("%Y-%m-%d-%H%M%S"));
    let path = dir.join(name);
    let rows: Vec<_> = m.packets.iter().cloned().collect();
    match crate::model::write_pcap(&path, &rows) {
        Ok(n) => format!("{} paquets enregistrés dans {}", fmt_count(n as u64), path.display()),
        Err(e) => format!("Enregistrement impossible : {e}"),
    }
}

fn filters(app: &mut App, ui: &mut Ui, m: &Model) {
    ui.horizontal(|ui| {
        chips(ui, &mut app.packets.dir, &[(DirFilter::All, "Tout"), (DirFilter::In, "Entrants"), (DirFilter::Out, "Sortants")]);
        chips(ui, &mut app.packets.crypto, &[(CryptoFilter::All, "Tous"), (CryptoFilter::Encrypted, "Chiffrés"), (CryptoFilter::Clear, "En clair")]);
        let label = if app.packets.proto.is_empty() { "Tout protocole".to_string() } else { app.packets.proto.clone() };
        let r = egui::ComboBox::from_id_salt("proto_filter").selected_text(label).width(120.0).show_ui(ui, |ui| {
            ui.selectable_value(&mut app.packets.proto, String::new(), "Tout protocole");
            for p in ["TLS", "QUIC", "HTTP", "DNS", "mDNS", "SSH", "TCP", "UDP", "ICMP", "ICMPv6", "ARP", "DHCP", "NTP"] {
                ui.selectable_value(&mut app.packets.proto, p.to_string(), p);
            }
        });
        named(&r.response, "Protocole");
        search_box(ui, &mut app.packets.search, "IP, port, programme, site…", 230.0);
        if let Some(k) = app.packets.flow_filter {
            let label = format!("{} {} {} {}", icon::FLOW_ARROW, k.1, icon::ARROWS_LEFT_RIGHT, k.2);
            if ui.button(format!("{label}  {}", icon::X)).on_hover_text("Revenir à tous les paquets").clicked() {
                app.packets.flow_filter = None;
            }
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.checkbox(&mut app.packets.follow_live, "Suivre en direct");
            let n = app.packets.cached.len();
            let total = app.packets.frozen.as_ref().map_or(m.packets.len(), Vec::len);
            ui.label(RichText::new(format!("{} / {}", fmt_count(n as u64), fmt_count(total as u64))).font(mono(12.0)).color(pal().muted));
        });
    });
}

fn matches(app: &App, r: &PacketRow, q: &str) -> bool {
    let p = &r.pkt;
    if let Some(i) = &app.iface {
        if &*r.iface != i.as_str() {
            return false;
        }
    }
    if let Some(k) = app.packets.flow_filter {
        if r.stream != Some(k) {
            return false;
        }
    }
    match app.packets.dir {
        DirFilter::All => {}
        DirFilter::In if p.dir == Dir::In => {}
        DirFilter::Out if p.dir == Dir::Out => {}
        _ => return false,
    }
    match app.packets.crypto {
        CryptoFilter::All => {}
        CryptoFilter::Encrypted if matches!(p.crypto, Crypto::Yes | Crypto::Probable) => {}
        CryptoFilter::Clear if p.crypto == Crypto::No => {}
        _ => return false,
    }
    if !app.packets.proto.is_empty() && p.app != app.packets.proto {
        return false;
    }
    if q.is_empty() {
        return true;
    }
    let ip_hit = p.src.is_some_and(|a| a.to_string().contains(q)) || p.dst.is_some_and(|a| a.to_string().contains(q));
    ip_hit
        || p.sport.to_string() == q
        || p.dport.to_string() == q
        || p.info.to_lowercase().contains(q)
        || p.app.to_lowercase() == q
        || r.app.as_deref().is_some_and(|a| a.to_lowercase().contains(q))
        || p.sni.as_deref().is_some_and(|a| a.contains(q))
}

fn refresh_cache(app: &mut App, m: &Model) {
    let q = app.packets.search.to_lowercase();
    // Liste figée : les filtres s'appliquent à ce qui a été figé, rien de nouveau n'entre.
    let (len, last_id) = match &app.packets.frozen {
        Some(rows) => (rows.len(), rows.last().map_or(0, |r| r.id)),
        None => (m.packets.len(), m.packets.back().map_or(0, |r| r.id)),
    };
    let signature = format!(
        "{}|{:?}|{}|{}|{}|{:?}|{q}|{}",
        app.packets.proto,
        app.iface,
        app.packets.dir as u8,
        app.packets.crypto as u8,
        len,
        app.packets.flow_filter,
        app.packets.frozen.is_some()
    );
    if (last_id, signature.clone()) == app.packets.cache_key {
        return;
    }
    app.packets.cache_key = (last_id, signature);
    app.packets.cached = match &app.packets.frozen {
        Some(rows) => rows.iter().filter(|r| matches(app, r, &q)).cloned().collect(),
        None => m.packets.iter().filter(|r| matches(app, r, &q)).cloned().collect(),
    };
}

/// Date et heure d'un moment, pour ce qui peut remonter à plusieurs jours.
pub fn time_with_date(ts_us: u64) -> String {
    use chrono::TimeZone;
    chrono::Local.timestamp_micros(ts_us as i64).single().map(|t| t.format("%d/%m/%Y %H:%M:%S").to_string()).unwrap_or_default()
}

fn time_label(ts_us: u64) -> String {
    use chrono::TimeZone;
    chrono::Local.timestamp_micros(ts_us as i64).single().map(|t| t.format("%H:%M:%S%.3f").to_string()).unwrap_or_default()
}

fn table(app: &mut App, ui: &mut Ui) {
    let cols = [
        col("Heure", 106.0),
        col("", 26.0),
        col("Interface", 78.0),
        col("Protocole", 72.0),
        col("Source", 186.0),
        col("Destination", 186.0),
        col_r("Taille", 62.0),
        col("Programme", 110.0),
        flex("Résumé", 1.0),
    ];
    let cols: Vec<Col> = if ui.available_width() < 900.0 {
        // Panneau de détail ouvert : l'essentiel seulement.
        [cols[0], cols[1], cols[3], cols[4], cols[5], cols[8]].to_vec()
    } else {
        cols.to_vec()
    };
    let compact = cols.len() < 9;
    table_header(ui, &cols, None);
    let total = app.packets.cached.len();
    if total == 0 {
        ui.add_space(14.0);
        hint(ui, "Aucun paquet à afficher pour le moment.");
        return;
    }
    let follow = app.packets.follow_live && app.packets.selected.is_none() && app.packets.frozen.is_none();
    egui::ScrollArea::vertical().auto_shrink([false, false]).stick_to_bottom(follow).show_rows(ui, 24.0, total, |ui, range| {
        ui.spacing_mut().item_spacing.y = 0.0;
        for i in range {
            let r = app.packets.cached[i].clone();
            let p = &r.pkt;
            let is_sel = app.packets.selected == Some(r.id);
            let (rect, resp) = table_row(ui, 24.0, is_sel, &format!("Paquet {}", r.id));
            let c = col_rects(rect, &cols);
            let endpoint = |ip: Option<std::net::IpAddr>, port: u16| match (ip, port) {
                (Some(a), 0) => a.to_string(),
                (Some(a), po) => std::net::SocketAddr::new(a, po).to_string(),
                _ => String::new(),
            };
            let (src, dst) = (endpoint(p.src, p.sport), endpoint(p.dst, p.dport));
            let (sym, sym_c) = match p.dir {
                Dir::In => (icon::ARROW_DOWN, pal().rx),
                Dir::Out => (icon::ARROW_UP, pal().tx),
                Dir::Other => (icon::ARROWS_LEFT_RIGHT, pal().muted),
            };
            let (lock, lock_c) = crypto_symbol(p.crypto);
            let endpoint_cell = |ui: &mut Ui, rect: egui::Rect, ip: Option<std::net::IpAddr>, text: &str| match ip {
                Some(a) => ip_cell(ui, rect, &a.to_string(), text, &mono(11.5), pal().ink2),
                None => cell(ui, rect, text, &mono(11.5), pal().ink2, false),
            };
            cell(ui, c[0], &time_label(p.ts_us), &mono(11.5), pal().muted, false);
            ui.painter().text(c[1].center(), egui::Align2::CENTER_CENTER, sym, body(13.0), sym_c);
            if compact {
                icon_cell(ui, c[2], lock, lock_c, p.app, &body(12.0), pal().ink);
                endpoint_cell(ui, c[3], p.src, &src);
                endpoint_cell(ui, c[4], p.dst, &dst);
                cell(ui, c[5], &p.info, &body(12.0), pal().ink2, false);
            } else {
                cell(ui, c[2], &r.iface, &body(12.0), pal().ink2, false);
                icon_cell(ui, c[3], lock, lock_c, p.app, &body(12.0), pal().ink);
                endpoint_cell(ui, c[4], p.src, &src);
                endpoint_cell(ui, c[5], p.dst, &dst);
                cell(ui, c[6], &p.orig_len.to_string(), &mono(11.5), pal().ink2, true);
                cell(ui, c[7], r.app.as_deref().unwrap_or(""), &body(12.0), pal().ink2, false);
                cell(ui, c[8], &p.info, &body(12.0), pal().ink2, false);
            }
            if resp.clicked() {
                app.packets.selected = if is_sel { None } else { Some(r.id) };
            }
        }
    });
}

fn detail(app: &mut App, ui: &mut Ui, m: &Model, row: &Arc<PacketRow>) {
    let p = &row.pkt;
    let stream = row.stream.and_then(|k| m.streams.get(&k));
    card(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.set_min_height(ui.available_height() - 28.0);
        ui.horizontal(|ui| {
            let (lock, c) = crypto_symbol(p.crypto);
            ui.label(RichText::new(lock).color(c).size(16.0));
            ui.label(RichText::new(format!("{} — {}", p.app, p.crypto.label())).font(bold(14.0)).color(pal().ink));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if small_button(ui, icon::X).clicked() {
                    app.packets.selected = None;
                }
                if let Some(k) = row.stream {
                    if small_button(ui, "Suivre ce flux").on_hover_text("Ne garder que les paquets de cet échange").clicked() {
                        app.packets.flow_filter = Some(k);
                    }
                }
            });
        });
        ui.add_space(2.0);
        chips(ui, &mut app.packets.detail_tab, &[(DetailTab::Packet, "Paquet"), (DetailTab::Conversation, "Conversation")]);
        ui.add_space(4.0);
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.set_width(ui.available_width());
            match app.packets.detail_tab {
                DetailTab::Packet => packet_tab(ui, row),
                DetailTab::Conversation => conversation_tab(app, ui, m, row, stream),
            }
        });
    });
}

fn packet_tab(ui: &mut Ui, row: &Arc<PacketRow>) {
    let p = &row.pkt;
    ui.spacing_mut().item_spacing.y = 2.0;
    kv(ui, "Heure", &time_label(p.ts_us));
    kv(ui, "Interface", &row.iface);
    kv(ui, "Sens", match p.dir {
        Dir::In => "Entrant",
        Dir::Out => "Sortant",
        Dir::Other => "De passage",
    });
    kv(ui, "Taille", &format!("{} octets ({} capturés)", p.orig_len, p.data.len()));
    if let Some(a) = &row.app {
        kv(ui, "Programme", &format!("{a}{}", row.pid.map(|x| format!(" (processus {x})")).unwrap_or_default()));
    }
    kv(ui, "Résumé", &p.info);
    for (title, fields) in packet::describe(p) {
        ui.add_space(8.0);
        ui.label(RichText::new(title).font(bold(13.0)).color(pal().ink));
        for (k, v) in fields {
            if ip_only(&v).is_some() {
                kv_ip(ui, &k, &v);
            } else {
                kv(ui, &k, &v);
            }
        }
    }
    ui.add_space(8.0);
    ui.label(RichText::new("Octets bruts").font(bold(13.0)).color(pal().ink));
    if matches!(p.crypto, Crypto::Yes) {
        hint(ui, "Ces octets sont chiffrés : seuls les en-têtes et les étapes de négociation ont un sens sans les clés.");
    }
    Frame::new().fill(pal().field).corner_radius(6).inner_margin(Margin::same(8)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        // Les 16 colonnes ne tiennent pas toujours : défilement horizontal plutôt que débordement.
        egui::ScrollArea::horizontal().id_salt("hexdump").auto_shrink([false, true]).show(ui, |ui| {
            ui.add(egui::Label::new(RichText::new(packet::hex_dump(&p.data, 4096)).font(mono(11.0)).color(pal().ink2)).extend());
        });
    });
}

fn conversation_tab(app: &mut App, ui: &mut Ui, m: &Model, row: &Arc<PacketRow>, stream: Option<&Stream>) {
    let p = &row.pkt;
    if stream.is_none_or(|st| st.is_tls) && matches!(p.crypto, Crypto::Yes | Crypto::Probable) {
        decrypt_controls(app, ui, m);
        ui.add_space(6.0);
    }
    let Some(st) = stream else {
        let encrypted = p.crypto == Crypto::Yes;
        let text = if encrypted && m.keylog.path.is_none() {
            "Cet échange est chiffré. Activez le déchiffrement ci-dessus, puis ouvrez un site depuis le navigateur lancé par NetBuster."
        } else if encrypted {
            "Pas de contenu pour cet échange : il a commencé avant l'activation, vient d'un autre programme, ou n'utilise pas TLS sur TCP."
        } else {
            "Rien à afficher : cet échange ne contient pas de texte reconstitué."
        };
        hint(ui, text);
        return;
    };
    if let Some(s) = &st.sni {
        kv(ui, "Site", s);
    }
    if let Some(t) = &st.tls {
        kv(ui, "Version", t.version.unwrap_or("Négociation en cours"));
        let status = if t.decrypted_bytes > 0 {
            format!("{} déchiffrés", fmt_bytes(t.decrypted_bytes))
        } else if t.is_unsupported_cipher() {
            "Chiffrement non pris en charge".to_string()
        } else if t.has_keys(&m.keylog) {
            "Clés trouvées, en attente de données".to_string()
        } else {
            "En attente des clés : ce programme ne les écrit peut-être pas dans le fichier".to_string()
        };
        kv(ui, "Déchiffrement", &status);
    }
    if st.truncated_capture {
        ui.horizontal(|ui| {
            ui.label(RichText::new(icon::WARNING).color(pal().warning));
            ui.label(RichText::new("Capture limitée au début des paquets : choisissez « Paquets complets ».").color(pal().ink2).size(12.5));
        });
    }
    if st.overflow {
        hint(ui, "Seuls les 2 premiers Mo de cet échange sont conservés.");
    }
    if st.chunks.is_empty() {
        hint(ui, "Rien à montrer pour le moment.");
        return;
    }
    for c in st.chunks.iter().rev().take(200).rev() {
        ui.add_space(6.0);
        // Le sens se lit du point de vue de ce PC.
        let (sender, receiver) = if c.from_client { (st.client, st.server) } else { (st.server, st.client) };
        let outgoing = m.local_ips.contains(&sender.ip());
        let (sym, color, who) = if outgoing { (icon::ARROW_UP, pal().tx, format!("Envoyé à {receiver}")) } else { (icon::ARROW_DOWN, pal().rx, format!("Reçu de {sender}")) };
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            ui.label(RichText::new(sym).color(color).size(13.0));
            ui.label(RichText::new(who).color(pal().ink2).size(12.0));
            ui.label(RichText::new(format!("· {}", fmt_bytes(c.data.len() as u64))).color(pal().muted).size(12.0));
            if c.decrypted {
                ui.label(RichText::new(icon::LOCK_OPEN).color(pal().good).size(13.0));
                ui.label(RichText::new("déchiffré").color(pal().ink2).size(12.0));
            }
        });
        let shown = &c.data[..c.data.len().min(16 * 1024)];
        let printable = shown.iter().filter(|b| matches!(**b, 0x20..=0x7e | b'\n' | b'\r' | b'\t') || **b >= 0xc0).count();
        let text = if printable as f32 / shown.len().max(1) as f32 > 0.85 { String::from_utf8_lossy(shown).replace('\r', "") } else { packet::hex_dump(shown, 2048) };
        let fill = if outgoing { pal().bubble_out } else { pal().bubble_in };
        Frame::new().fill(fill).corner_radius(6).inner_margin(Margin::same(8)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add(egui::Label::new(RichText::new(text).font(mono(11.5)).color(pal().ink)).wrap());
        });
    }
}

/// Les réglages du déchiffrement : le fichier de clés et les navigateurs à lancer.
fn decrypt_controls(app: &mut App, ui: &mut Ui, m: &Model) {
    Frame::new().fill(pal().field).corner_radius(6).inner_margin(Margin::same(10)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.label(RichText::new(icon::KEY).color(pal().warning).size(15.0));
            ui.label(RichText::new("Déchiffrer mon propre trafic").font(bold(13.0)).color(pal().ink));
        });
        if m.keylog.path.is_none() {
            ui.add(egui::Label::new(RichText::new("Sans les clés, le contenu reste illisible. NetBuster peut lancer votre navigateur dans un profil séparé qui note ses clés de session, pour lire uniquement ce trafic. Ces clés donnent accès aux échanges enregistrés : gardez ce fichier pour vous.").color(pal().ink2).size(12.5)).wrap());
            if primary_button(ui, "Activer le déchiffrement").clicked() {
                // Le modèle est verrouillé pendant le dessin : l'activation se fait juste après.
                let shared = app.shared.clone();
                std::thread::spawn(move || {
                    let mut m = shared.model.lock().unwrap();
                    if let Err(e) = enable_decryption(&mut m) {
                        m.capture.error = Some(format!("Déchiffrement indisponible : {e}"));
                    }
                });
            }
            return;
        }
        ui.add(egui::Label::new(RichText::new(format!("{} sessions avec clés. Les connexions ouvertes avant l'activation restent illisibles.", m.keylog.keys.len())).color(pal().ink2).size(12.5)).wrap());
        let mut seen = vec![];
        ui.horizontal_wrapped(|ui| {
            for (name, prog, firefox) in BROWSERS {
                if seen.contains(name) || which(prog).is_none() {
                    continue;
                }
                seen.push(*name);
                if ui.button(format!("Lancer {name}")).clicked() {
                    app.packets.message = Some(match launch_browser(prog, *firefox) {
                        Ok(()) => format!("{name} est lancé dans un profil séparé. Ouvrez un site pour voir son contenu ici."),
                        Err(e) => format!("Impossible de lancer {name} : {e}"),
                    });
                }
            }
        });
        if seen.is_empty() {
            hint(ui, "Aucun navigateur reconnu sur ce PC.");
        }
        hint(ui, format!("Pour un autre programme : lancez-le avec SSLKEYLOGFILE={}", keylog_path().display()));
        hint(ui, "Non pris en charge : HTTP/3 (QUIC), les programmes qui n'écrivent pas leurs clés, et les chiffrements anciens en mode CBC. SSH reste illisible.");
    });
}
