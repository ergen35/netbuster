//! Écran Réglages : démarrage avec la session, et service de capture en arrière-plan.

use super::theme::*;
use super::widgets::*;
use super::App;
use crate::desktop;
use crate::manage::{Action, Step};
use crate::service::{self, list_capture_files, read_limit_mb, write_limit_mb, CaptureFile, DEFAULT_LIMIT_MB, LIMIT_CHOICES_MB};
use crate::util::{fmt_bytes, fmt_count};
use eframe::egui::{self, Color32, CornerRadius, Pos2, Rect, RichText, Sense, Stroke, TextWrapMode, Ui, Vec2, WidgetInfo};
use egui_phosphor::regular as icon;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

pub struct SettingsUi {
    pub settings: desktop::Settings,
    pub autostart: bool,
    pub files: Vec<CaptureFile>,
    pub unit_installed: bool,
    pub limit_mb: u64,
    pub refreshed: Option<Instant>,
}

impl SettingsUi {
    pub fn new() -> SettingsUi {
        SettingsUi { settings: desktop::Settings::load(), autostart: desktop::autostart_enabled(), files: vec![], unit_installed: false, limit_mb: DEFAULT_LIMIT_MB, refreshed: None }
    }
}

impl Default for SettingsUi {
    fn default() -> Self {
        Self::new()
    }
}

fn limit_label(mb: u64) -> String {
    if mb >= 1024 {
        format!("{} Go", mb as f64 / 1024.0)
    } else {
        format!("{mb} Mo")
    }
}

/// Une ligne avec interrupteur. Toute la ligne se clique. Rend vrai si la valeur a changé.
fn toggle_row(ui: &mut Ui, on: &mut bool, title: &str, text: &str) -> bool {
    let width = ui.available_width();
    let switch = Vec2::new(36.0, 20.0);
    let text_x = switch.x + 12.0;
    let title_g = ui.painter().layout(title.to_owned(), bold(13.5), pal().ink, width - text_x);
    let text_g = ui.painter().layout(text.to_owned(), body(12.5), pal().ink2, width - text_x);
    let height = title_g.size().y + 2.0 + text_g.size().y + 8.0;
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, height), Sense::click());
    let selected = *on;
    let name = title.to_owned();
    resp.widget_info(move || WidgetInfo::selected(egui::Role::CheckBox, true, selected, &name));
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    let changed = resp.clicked();
    if changed {
        *on = !*on;
    }

    let track = Rect::from_min_size(Pos2::new(rect.left(), rect.top() + 2.0), switch);
    let fill = if *on { pal().primary } else { pal().switch_off };
    ui.painter().rect_filled(track, CornerRadius::same(10), fill);
    if resp.has_focus() {
        ui.painter().rect_stroke(track.expand(2.0), CornerRadius::same(12), Stroke::new(1.5, pal().rx), egui::StrokeKind::Outside);
    }
    let knob_x = if *on { track.right() - 10.0 } else { track.left() + 10.0 };
    ui.painter().circle_filled(Pos2::new(knob_x, track.center().y), 7.5, Color32::WHITE);

    let x = rect.left() + text_x;
    let title_h = title_g.size().y;
    ui.painter().galley(Pos2::new(x, rect.top()), title_g, pal().ink);
    ui.painter().galley(Pos2::new(x, rect.top() + title_h + 2.0), text_g, pal().ink2);
    changed
}

fn refresh(app: &mut App) {
    let s = &mut app.settings;
    if s.refreshed.is_some_and(|t| t.elapsed() < Duration::from_secs(2)) {
        return;
    }
    s.refreshed = Some(Instant::now());
    let paths = &app.shared.service_paths;
    s.files = list_capture_files(&paths.state);
    s.unit_installed = paths.unit.exists();
    s.limit_mb = read_limit_mb(paths);
    s.autostart = desktop::autostart_enabled();
}

pub fn settings(app: &mut App, ui: &mut Ui) {
    refresh(app);
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        ui.set_max_width(ui.available_width().min(920.0));
        appearance_card(app, ui);
        ui.add_space(10.0);
        startup_card(app, ui);
        ui.add_space(10.0);
        if crate::platform::full_features() {
            service_card(app, ui);
            ui.add_space(10.0);
            history_card(app, ui);
        } else {
            system_card(ui);
        }
    });
}

/// Dit franchement ce que cette version fait et ne fait pas encore sur ce système.
fn system_card(ui: &mut Ui) {
    card(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, &format!("NetBuster sous {}", crate::platform::system_name()));
        ui.add_space(6.0);
        hint(ui, "Disponible : débits de chaque interface, consommation, connexions et ports ouverts avec leur programme, traceroute, identification des adresses IP.");
        ui.add_space(4.0);
        hint(ui, "Pas encore disponible : capture des paquets, volume par programme, pare-feu, configuration réseau, SSH, icône dans la barre d'état et capture en arrière-plan. Ces fonctions existent sous Linux.");
    });
}

fn appearance_card(app: &mut App, ui: &mut Ui) {
    card(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, "Apparence");
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Thème").color(pal().ink2).size(12.5));
            let mut choice = app.settings.settings.theme;
            let (dark, light) = (format!("{} Sombre", icon::MOON), format!("{} Clair", icon::SUN));
            if chips(ui, &mut choice, &[(desktop::ThemeChoice::Dark, dark.as_str()), (desktop::ThemeChoice::Light, light.as_str())]) {
                app.set_theme(ui.ctx(), choice);
            }
        });
    });
}

fn startup_card(app: &mut App, ui: &mut Ui) {
    let tray = app.shared.tray_available.load(Ordering::Relaxed);
    card(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, "Démarrage");
        ui.add_space(8.0);
        let reduced = if tray { "réduit dans la barre d'état, sans fenêtre" } else { "réduit dans la barre des tâches" };
        if toggle_row(
            ui,
            &mut app.settings.autostart,
            "Ouvrir NetBuster à l'ouverture de session",
            &format!("NetBuster démarre {reduced}, et mesure le trafic dès que vous êtes connecté."),
        ) {
            if let Err(e) = desktop::set_autostart(app.settings.autostart) {
                app.settings.autostart = desktop::autostart_enabled();
                app.notify(false, "Ouverture de session", e.to_string());
            }
        }
        // Sans barre d'état ni capture, ces deux réglages ne feraient rien.
        let mut changed = false;
        if crate::platform::full_features() {
            changed = toggle_row(
                ui,
                &mut app.settings.settings.close_to_tray,
                "Continuer en arrière-plan quand la fenêtre se ferme",
                if tray {
                    "La mesure et la capture continuent. Pour tout arrêter, utilisez « Quitter NetBuster » dans le menu de l'icône."
                } else {
                    "Ce bureau n'a pas de barre d'état : fermer la fenêtre quitte NetBuster."
                },
            );
            changed |= toggle_row(
                ui,
                &mut app.settings.settings.capture_on_open,
                "Capturer les paquets dès l'ouverture de NetBuster",
                "Le système demandera votre mot de passe à chaque ouverture. Le service ci-dessous évite cette demande.",
            );
        }
        if changed {
            if let Err(e) = app.settings.settings.save() {
                app.notify(false, "Réglages", e.to_string());
            }
        }
    });
}

fn service_action(on: bool) -> Action {
    if on {
        Action::new(
            "Activer le service de capture",
            "NetBuster capturera tout le trafic de ce PC en continu, dès son démarrage et avant que le réseau ne soit connecté, même sans session ouverte et fenêtre fermée.",
            vec![Step::InstallService],
        )
        .warn("Les fichiers contiennent tout ce qui passe sur le réseau, y compris le trafic des autres comptes de ce PC et ce qui n'est pas chiffré. Seul votre compte peut les lire.")
    } else {
        Action::new(
            "Désactiver le service de capture",
            "La capture en arrière-plan s'arrête et ne reprendra plus au démarrage. L'historique déjà enregistré reste sur le disque, jusqu'à ce que vous le supprimiez.",
            vec![Step::RemoveService],
        )
    }
}

fn service_card(app: &mut App, ui: &mut Ui) {
    let shared = app.shared.clone();
    let up = shared.service_up.load(Ordering::Relaxed);
    let installed = app.settings.unit_installed || up;
    let stats = shared.model.lock().unwrap().capture.service_stats.clone();
    card(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            section_title(ui, "Service de capture en arrière-plan");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let (sym, color, text) = match (up, installed) {
                    (true, _) => (icon::CHECK_CIRCLE, pal().good, "Actif"),
                    (false, true) => (icon::WARNING, pal().warning, "Installé, ne répond pas"),
                    (false, false) => (icon::MINUS_CIRCLE, pal().muted, "Désactivé"),
                };
                // Cette zone se remplit de droite à gauche : le mot d'abord, son symbole à sa gauche.
                ui.spacing_mut().item_spacing.x = 4.0;
                ui.label(RichText::new(text).color(pal().ink2));
                ui.label(RichText::new(sym).color(color).size(14.0));
            });
        });
        ui.add_space(8.0);
        let mut on = installed;
        if toggle_row(
            ui,
            &mut on,
            "Capturer tout le trafic en continu",
            "Dès le démarrage du PC, sans session ouverte et sans mot de passe à saisir ensuite. La fenêtre affiche la capture en direct dès qu'elle s'ouvre, et l'historique garde ce qui s'est passé avant.",
        ) {
            app.ask(service_action(on));
        }
        if installed && !up {
            ui.add_space(4.0);
            hint(ui, format!("Le service démarre peut-être encore. S'il reste dans cet état, son journal se lit avec : journalctl -u {}", service::UNIT_NAME));
        }
        if up {
            ui.add_space(6.0);
            ui.spacing_mut().item_spacing.y = 3.0;
            kv(ui, "Paquets capturés", &fmt_count(stats.packets));
            kv(ui, "Paquets perdus", &fmt_count(stats.drops));
            kv(ui, "Depuis", &crate::ui::page_capture::time_with_date(stats.since_us));
            if stats.disk_low {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new(icon::WARNING).color(pal().critical_text));
                    ui.label(RichText::new("Disque presque plein : l'écriture est suspendue.").color(pal().critical_text).size(12.5));
                });
            }
        }
    });
}

fn history_card(app: &mut App, ui: &mut Ui) {
    let shared = app.shared.clone();
    let up = shared.service_up.load(Ordering::Relaxed);
    let total: u64 = app.settings.files.iter().map(|f| f.bytes).sum();
    let state_dir = shared.service_paths.state.clone();
    let state_exists = state_dir.exists();
    card(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            section_title(ui, "Historique de la capture");
            ui.label(RichText::new(format!("{}, {}", plural(app.settings.files.len(), "fichier"), fmt_bytes(total))).color(pal().muted).size(12.5));
        });
        ui.add_space(6.0);
        if !state_exists {
            hint(ui, "Rien pour l'instant : l'historique se remplit une fois le service activé.");
            return;
        }
        ui.horizontal(|ui| {
            ui.label(RichText::new("Place maximale").color(pal().ink2).size(12.5));
            let current = app.settings.limit_mb;
            let r = egui::ComboBox::from_id_salt("history_limit").selected_text(limit_label(current)).width(90.0).show_ui(ui, |ui| {
                let mut v = current;
                for mb in LIMIT_CHOICES_MB {
                    ui.selectable_value(&mut v, mb, limit_label(mb));
                }
                v
            });
            named(&r.response, "Place maximale");
            if let Some(v) = r.inner {
                if v != current {
                    match write_limit_mb(&shared.service_paths, v) {
                        Ok(()) => app.settings.limit_mb = v,
                        Err(e) => app.notify(false, "Place maximale", e.to_string()),
                    }
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add_enabled(!app.settings.files.is_empty(), egui::Button::new(format!("{} Tout supprimer", icon::TRASH))).clicked() {
                    let mut a = Action::new(
                        "Supprimer l'historique",
                        if up { "Tous les fichiers de capture seront supprimés, sauf celui en cours d'écriture." } else { "Tous les fichiers de capture seront supprimés." },
                        vec![Step::ClearHistory { dir: state_dir.to_string_lossy().into_owned(), keep_newest: up }],
                    );
                    a = a.warn("Cette suppression est définitive.");
                    app.ask(a);
                }
                if ui.button(format!("{} Ouvrir le dossier", icon::FOLDER_OPEN)).clicked() {
                    let dir = state_dir.to_string_lossy().into_owned();
                    if let Err(e) = super::open_external(&dir) {
                        app.notify(false, "Ouvrir le dossier", e.to_string());
                    }
                }
            });
        });
        ui.add_space(2.0);
        hint(ui, "Les plus anciens fichiers s'effacent pour rester sous cette limite. Ces fichiers s'ouvrent aussi dans Wireshark.");
        ui.add_space(6.0);
        if app.settings.files.is_empty() {
            hint(ui, "Aucun fichier de capture pour l'instant.");
            return;
        }
        const COLS: [Col; 4] = [col("Début", 190.0), col("Dernier paquet", 190.0), col_r("Taille", 100.0), flex("", 1.0)];
        table_header(ui, &COLS, None);
        let loaded = shared.model.lock().unwrap().history_loaded.clone();
        // Du plus récent au plus ancien : c'est le récent qu'on cherche.
        let files: Vec<CaptureFile> = app.settings.files.iter().rev().take(50).cloned().collect();
        let mut load = None;
        for f in &files {
            let label = f.started_label();
            let width = ui.available_width();
            let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 28.0), Sense::hover());
            ui.painter().hline(rect.x_range(), rect.bottom(), Stroke::new(1.0, pal().grid));
            let c = col_rects(rect, &COLS);
            cell(ui, c[0], &label, &mono(12.0), pal().ink, false);
            cell(ui, c[1], &f.ended_label(), &mono(12.0), pal().ink2, false);
            cell(ui, c[2], &fmt_bytes(f.bytes), &mono(12.0), pal().ink2, true);
            in_cell(ui, c[3], |ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let done = loaded.contains(&f.path);
                    let text = if done { format!("{} Chargé", icon::CHECK) } else { format!("{} Voir les paquets", icon::EYE) };
                    let button = egui::Button::new(RichText::new(text).size(12.0)).min_size(egui::vec2(0.0, 22.0)).wrap_mode(TextWrapMode::Extend);
                    if ui.add_enabled(!done, button).on_hover_text(label.as_str()).clicked() {
                        load = Some(f.path.clone());
                    }
                });
            });
        }
        if let Some(path) = load {
            shared.load_history(path);
            app.page = super::Page::Packets;
        }
    });
}
