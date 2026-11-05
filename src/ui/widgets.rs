//! Éléments réutilisables : cartes, tuiles, tableaux rapides, boutons.

use super::theme::*;
use eframe::egui::text::{LayoutJob, TextWrapping};
use eframe::egui::{self, Align, Color32, CornerRadius, FontId, Frame, Margin, Pos2, Rect, Response, RichText, Sense, Stroke, Ui, UiBuilder, Vec2, WidgetInfo};
use egui_phosphor::regular as icon;

pub fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    Frame::new()
        .fill(pal().surface)
        .stroke(Stroke::new(1.0, pal().border))
        .corner_radius(10)
        .inner_margin(Margin::same(14))
        .show(ui, add)
        .inner
}

/// Donne un nom à une liste déroulante pour les lecteurs d'écran.
pub fn named(resp: &Response, name: &'static str) {
    resp.widget_info(move || WidgetInfo::labeled(egui::Role::ComboBox, true, name));
}

/// `1 appel`, `3 appels`
pub fn plural(n: usize, word: &str) -> String {
    if n > 1 {
        format!("{n} {word}s")
    } else {
        format!("{n} {word}")
    }
}

pub fn section_title(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).font(bold(14.5)).color(pal().ink));
}

pub fn hint(ui: &mut Ui, text: impl Into<String>) {
    ui.add(egui::Label::new(RichText::new(text.into()).color(pal().muted).size(12.0)).wrap());
}

// ---------- Copier une adresse IP ----------

const COPY_SIZE: f32 = 20.0;
const COPIED_FOR: f64 = 1.5;

/// Le bouton copier, dans ce rectangle. Une liste peut bouger entre l'appui et le relâchement :
/// la copie part à l'appui, pour donner l'adresse que la personne a vue sous son curseur.
fn copy_button_at(ui: &mut Ui, r: Rect, ip: &str) {
    let id = ui.scope_id().with(("copy_ip", r.min.x as i32, r.min.y as i32));
    let resp = ui.interact(r, id, Sense::click());
    let label = format!("Copier {ip}");
    resp.widget_info(|| WidgetInfo::labeled(egui::Role::Button, true, &label));
    let memory = egui::Id::unique("netbuster_copied_ip");
    let done_at_press = id.with("done_at_press");
    let pressed = resp.hovered() && ui.input(|i| i.pointer.primary_pressed());
    if pressed {
        ui.ctx().data_mut(|d| d.insert_temp(done_at_press, true));
    }
    // Clavier, lecteur d'écran ou appui tactile très bref : le clic arrive sans appui repéré.
    let clicked_without_press = resp.clicked() && !ui.ctx().data_mut(|d| d.remove_temp::<bool>(done_at_press)).unwrap_or(false);
    let now = ui.input(|i| i.time);
    if pressed || clicked_without_press {
        ui.ctx().copy_text(ip.to_string());
        ui.ctx().data_mut(|d| d.insert_temp(memory, (ip.to_string(), now)));
    }
    let copied = ui.ctx().data(|d| d.get_temp::<(String, f64)>(memory)).is_some_and(|(last, at)| last == ip && now - at < COPIED_FOR);
    let hovered = resp.hovered();
    if hovered {
        ui.painter().rect_filled(r.shrink(1.0), CornerRadius::same(4), pal().widget_hover);
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    let (sym, color) = if copied {
        ui.ctx().request_repaint_after(std::time::Duration::from_millis(250));
        (icon::CHECK, pal().good)
    } else {
        (icon::COPY, if hovered { pal().ink } else { pal().muted })
    };
    ui.painter().text(r.center(), egui::Align2::CENTER_CENTER, sym, body(13.0), color);
    resp.on_hover_text(if copied { "Copié".to_string() } else { label });
}

/// Une cellule de tableau : le bouton copier, puis le texte. `ip` est ce qui est copié, sans le port.
pub fn ip_cell(ui: &mut Ui, rect: Rect, ip: &str, text: &str, font: &FontId, color: Color32) {
    let side = COPY_SIZE.min(rect.height());
    let button = Rect::from_center_size(Pos2::new(rect.left() + side / 2.0, rect.center().y), Vec2::splat(side));
    copy_button_at(ui, button, ip);
    let rest = Rect::from_min_max(Pos2::new(button.right() - 3.0, rect.top()), rect.max);
    cell(ui, rest, text, font, color, false);
}

/// Le bouton copier dans une ligne de texte ordinaire.
pub fn copy_inline(ui: &mut Ui, ip: &str) {
    let (r, _) = ui.allocate_exact_size(Vec2::splat(COPY_SIZE), Sense::hover());
    copy_button_at(ui, r, ip);
}

/// L'adresse seule, sans le port, à partir de ce qu'affiche une ligne.
pub fn ip_only(text: &str) -> Option<String> {
    if let Ok(ip) = text.parse::<std::net::IpAddr>() {
        return Some(ip.to_string());
    }
    if let Ok(a) = text.parse::<std::net::SocketAddr>() {
        return Some(a.ip().to_string());
    }
    let (addr, _) = text.split_once('/')?;
    addr.parse::<std::net::IpAddr>().ok().map(|ip| ip.to_string())
}

// ---------- Figer une liste ----------

/// Une liste figée montre une copie : la mesure et la capture continuent derrière.
#[derive(Default)]
pub struct Freeze {
    pub view: Option<std::sync::Arc<crate::model::Model>>,
    pub at: String,
}

impl Freeze {
    pub fn is_on(&self) -> bool {
        self.view.is_some()
    }

    fn toggle(&mut self, live: &crate::model::Model) {
        if self.view.take().is_none() {
            self.view = Some(std::sync::Arc::new(live.frozen_view()));
            self.at = chrono::Local::now().format("%H:%M:%S").to_string();
        }
    }
}

/// Le bouton commun à toutes les listes qui bougent vite. Rend vrai quand l'état a changé.
pub fn freeze_toggle(ui: &mut Ui, on: bool, at: &str) -> bool {
    let (sym, text) = if on { (icon::PLAY, "Défiger") } else { (icon::PAUSE, "Figer") };
    let label = format!("{sym} {text}");
    let hint_text = if on { "Revenir à la liste en direct" } else { "Arrêter le mouvement de cette liste, pour la lire ou copier une adresse. La mesure continue." };
    let clicked = if on { primary_button(ui, &label) } else { ui.button(label) }.on_hover_text(hint_text).clicked();
    // Sur une fenêtre étroite, le bouton « Défiger » suffit à dire que la liste est figée.
    if on && ui.available_width() > 130.0 {
        ui.label(RichText::new(format!("{} Figé à {at}", icon::PAUSE_CIRCLE)).color(pal().warning).size(12.5));
    }
    clicked
}

/// Le bouton et l'état, pour une liste tirée du modèle.
pub fn freeze_button(ui: &mut Ui, f: &mut Freeze, live: &crate::model::Model) {
    if freeze_toggle(ui, f.is_on(), &f.at) {
        f.toggle(live);
    }
}

/// Bouton principal d'un écran.
pub fn primary_button(ui: &mut Ui, text: &str) -> Response {
    ui.add(egui::Button::new(RichText::new(text).color(Color32::WHITE)).fill(pal().primary))
}

pub fn danger_button(ui: &mut Ui, text: &str) -> Response {
    ui.add(egui::Button::new(RichText::new(text).color(Color32::WHITE)).fill(pal().danger))
}

pub fn small_button(ui: &mut Ui, text: &str) -> Response {
    ui.add(egui::Button::new(RichText::new(text).size(12.0)).min_size(egui::vec2(0.0, 22.0)).corner_radius(5))
}

/// Pastille d'état : toujours un symbole et un mot, jamais la couleur seule.
pub fn status_badge(ui: &mut Ui, sym: &str, color: Color32, text: &str) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 4.0;
        ui.label(RichText::new(sym).color(color).size(14.0));
        ui.label(RichText::new(text).color(pal().ink2));
    });
}

/// Choix exclusif sous forme de pastilles.
pub fn chips<T: PartialEq + Clone>(ui: &mut Ui, value: &mut T, options: &[(T, &str)]) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 2.0;
        Frame::new().fill(pal().field).corner_radius(7).inner_margin(Margin::same(2)).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                // Dans une zone alignée à droite, egui place les éléments de droite à gauche.
                let rtl = ui.layout().prefer_right_to_left();
                let ordered: Vec<&(T, &str)> = if rtl { options.iter().rev().collect() } else { options.iter().collect() };
                for (v, label) in ordered {
                    let selected = *value == *v;
                    let text = RichText::new(*label).color(if selected { pal().ink } else { pal().ink2 }).size(12.5);
                    let mut b = egui::Button::new(text).corner_radius(5).min_size(egui::vec2(0.0, 24.0));
                    b = if selected { b.fill(pal().raised) } else { b.fill(Color32::TRANSPARENT).stroke(Stroke::NONE) };
                    if ui.add(b).clicked() && !selected {
                        *value = v.clone();
                        changed = true;
                    }
                }
            });
        });
    });
    changed
}

/// Champ de recherche avec son icône.
pub fn search_box(ui: &mut Ui, value: &mut String, placeholder: &str, width: f32) -> Response {
    ui.add(egui::TextEdit::singleline(value).hint_text(format!("{}  {placeholder}", icon::MAGNIFYING_GLASS)).desired_width(width))
}

pub fn labeled_field(ui: &mut Ui, label: &str, value: &mut String, width: f32, placeholder: &str) -> Response {
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 3.0;
        ui.label(RichText::new(label).color(pal().muted).size(12.0));
        ui.add(egui::TextEdit::singleline(value).hint_text(placeholder).desired_width(width))
    })
    .inner
}

/// Bloc « ce qu'il faut savoir » : symbole, titre, texte, et un éventuel bouton.
pub fn notice(ui: &mut Ui, sym: &str, color: Color32, title: &str, text: &str, action: Option<&str>) -> bool {
    let mut clicked = false;
    Frame::new()
        .fill(pal().notice)
        .stroke(Stroke::new(1.0, pal().border))
        .corner_radius(8)
        .inner_margin(Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new(sym).color(color).size(18.0));
                let reserve = if action.is_some() { 240.0 } else { 0.0 };
                ui.vertical(|ui| {
                    ui.set_max_width((ui.available_width() - reserve).max(120.0));
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.label(RichText::new(title).font(bold(13.5)).color(pal().ink));
                    ui.add(egui::Label::new(RichText::new(text).color(pal().ink2).size(12.5)).wrap());
                });
                if let Some(a) = action {
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        clicked = primary_button(ui, a).clicked();
                    });
                }
            });
        });
    clicked
}

// ---------- Tableaux ----------

#[derive(Clone, Copy)]
pub enum W {
    Px(f32),
    Flex(f32),
}

#[derive(Clone, Copy)]
pub struct Col {
    pub title: &'static str,
    pub width: W,
    pub right: bool,
}

pub const fn col(title: &'static str, w: f32) -> Col {
    Col { title, width: W::Px(w), right: false }
}
pub const fn col_r(title: &'static str, w: f32) -> Col {
    Col { title, width: W::Px(w), right: true }
}
pub const fn flex(title: &'static str, f: f32) -> Col {
    Col { title, width: W::Flex(f), right: false }
}

pub fn col_rects(rect: Rect, cols: &[Col]) -> Vec<Rect> {
    let fixed: f32 = cols.iter().map(|c| if let W::Px(p) = c.width { p } else { 0.0 }).sum();
    let flex_total: f32 = cols.iter().map(|c| if let W::Flex(f) = c.width { f } else { 0.0 }).sum();
    let remain = (rect.width() - fixed).max(0.0);
    let mut x = rect.left();
    cols.iter()
        .map(|c| {
            let w = match c.width {
                W::Px(p) => p,
                W::Flex(f) => remain * f / flex_total.max(0.0001),
            };
            let r = Rect::from_min_size(Pos2::new(x, rect.top()), Vec2::new(w, rect.height()));
            x += w;
            r
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq)]
pub struct Sort {
    pub col: usize,
    pub desc: bool,
}

/// En-tête de tableau. Avec `sort`, un clic sur un titre trie la colonne.
pub fn table_header(ui: &mut Ui, cols: &[Col], mut sort: Option<&mut Sort>) {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 26.0), Sense::hover());
    let rects = col_rects(rect, cols);
    for (i, (c, r)) in cols.iter().zip(&rects).enumerate() {
        let mut title = c.title.to_string();
        let mut color = pal().muted;
        if let Some(s) = sort.as_deref() {
            if s.col == i && !title.is_empty() {
                title = format!("{title} {}", if s.desc { icon::CARET_DOWN } else { icon::CARET_UP });
                color = pal().ink2;
            }
        }
        cell(ui, *r, &title, &body(12.0), color, c.right);
        if let Some(s) = sort.as_deref_mut() {
            if !c.title.is_empty() {
                let resp = ui.interact(*r, ui.scope_id().with(("sort", i)), Sense::click());
                resp.widget_info(|| WidgetInfo::labeled(egui::Role::Button, true, c.title));
                if resp.hovered() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                }
                if resp.clicked() {
                    if s.col == i {
                        s.desc = !s.desc;
                    } else {
                        s.col = i;
                        s.desc = c.right;
                    }
                }
            }
        }
    }
    ui.painter().hline(rect.x_range(), rect.bottom(), Stroke::new(1.0, pal().axis));
}

/// Texte dans une cellule, coupé proprement avec « … » s'il dépasse.
pub fn cell(ui: &Ui, rect: Rect, text: &str, font: &FontId, color: Color32, right: bool) {
    let pad = 6.0;
    let max = (rect.width() - 2.0 * pad).max(1.0);
    let mut job = LayoutJob::simple_singleline(text.to_owned(), font.clone(), color);
    job.wrap = TextWrapping { max_width: max, max_rows: 1, break_anywhere: true, overflow_character: Some('…') };
    let galley = ui.painter().layout_job(job);
    let x = if right { rect.right() - pad - galley.size().x } else { rect.left() + pad };
    let y = rect.center().y - galley.size().y / 2.0;
    ui.painter().galley(Pos2::new(x, y), galley, color);
}

/// Réserve une ligne de tableau, cliquable, avec sa surbrillance et son nom pour l'accessibilité.
pub fn table_row(ui: &mut Ui, h: f32, selected: bool, label: &str) -> (Rect, Response) {
    let width = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, h), Sense::click());
    let label = label.to_string();
    resp.widget_info(move || WidgetInfo::selected(egui::Role::Button, true, selected, &label));
    if selected {
        ui.painter().rect_filled(rect, CornerRadius::same(4), pal().row_selected);
    } else if resp.hovered() {
        ui.painter().rect_filled(rect, CornerRadius::same(4), pal().raised);
    }
    ui.painter().hline(rect.x_range(), rect.bottom(), Stroke::new(1.0, pal().grid));
    (rect, resp)
}

/// Place des widgets dans une cellule.
pub fn in_cell<R>(ui: &mut Ui, rect: Rect, add: impl FnOnce(&mut Ui) -> R) -> R {
    ui.scope_builder(UiBuilder::new().max_rect(rect.shrink2(Vec2::new(3.0, 0.0))).layout(egui::Layout::left_to_right(Align::Center)), add).inner
}

/// Cellule avec un symbole coloré et un texte.
pub fn icon_cell(ui: &Ui, rect: Rect, sym: &str, sym_color: Color32, text: &str, font: &FontId, color: Color32) {
    let r = Rect::from_min_size(rect.min, Vec2::new(24.0, rect.height()));
    ui.painter().text(r.center(), egui::Align2::CENTER_CENTER, sym, body(14.0), sym_color);
    let rest = Rect::from_min_max(Pos2::new(rect.left() + 18.0, rect.top()), rect.max);
    cell(ui, rest, text, font, color, false);
}

/// Grille simple « libellé : valeur ».
fn kv_label(ui: &mut Ui, label: &str) {
    let (r, _) = ui.allocate_exact_size(Vec2::new(136.0, 18.0), Sense::hover());
    let r = Rect::from_min_max(Pos2::new(r.left() - 6.0, r.top()), r.max);
    cell(ui, r, label, &body(12.5), pal().muted, false);
}

pub fn kv(ui: &mut Ui, label: &str, value: &str) {
    ui.horizontal_top(|ui| {
        kv_label(ui, label);
        ui.add(egui::Label::new(RichText::new(value).color(pal().ink).size(12.5)).wrap());
    });
}

/// Libellé et lien cliquable. Rend vrai quand on clique sur le lien.
pub fn kv_link(ui: &mut Ui, label: &str, url: &str) -> bool {
    ui.horizontal_top(|ui| {
        kv_label(ui, label);
        ui.add(egui::Link::new(RichText::new(url).color(pal().link).size(12.5))).on_hover_text("Ouvrir dans le navigateur").clicked()
    })
    .inner
}

pub fn kv_mono(ui: &mut Ui, label: &str, value: &str) {
    ui.horizontal_top(|ui| {
        kv_label(ui, label);
        ui.add(egui::Label::new(RichText::new(value).font(mono(12.0)).color(pal().ink)).wrap());
    });
}

/// Libellé et adresse, avec son bouton copier.
pub fn kv_ip(ui: &mut Ui, label: &str, value: &str) {
    ui.horizontal_top(|ui| {
        kv_label(ui, label);
        ui.spacing_mut().item_spacing.x = 2.0;
        if let Some(ip) = ip_only(value) {
            copy_inline(ui, &ip);
        }
        ui.add(egui::Label::new(RichText::new(value).font(mono(12.0)).color(pal().ink)).wrap());
    });
}
