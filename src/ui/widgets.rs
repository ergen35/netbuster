//! Éléments réutilisables : cartes, tuiles, tableaux rapides, boutons.

use super::theme::*;
use eframe::egui::text::{LayoutJob, TextWrapping};
use eframe::egui::{self, Align, Color32, CornerRadius, FontId, Frame, Margin, Pos2, Rect, Response, RichText, Sense, Stroke, Ui, UiBuilder, Vec2, WidgetInfo};
use egui_phosphor::regular as icon;

pub fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
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
    ui.label(RichText::new(text).font(bold(14.5)).color(INK));
}

pub fn hint(ui: &mut Ui, text: impl Into<String>) {
    ui.add(egui::Label::new(RichText::new(text.into()).color(MUTED).size(12.0)).wrap());
}

/// Bouton principal d'un écran.
pub fn primary_button(ui: &mut Ui, text: &str) -> Response {
    ui.add(egui::Button::new(RichText::new(text).color(Color32::WHITE)).fill(PRIMARY))
}

pub fn danger_button(ui: &mut Ui, text: &str) -> Response {
    ui.add(egui::Button::new(RichText::new(text).color(Color32::WHITE)).fill(Color32::from_rgb(0xa8, 0x2c, 0x2c)))
}

pub fn small_button(ui: &mut Ui, text: &str) -> Response {
    ui.add(egui::Button::new(RichText::new(text).size(12.0)).min_size(egui::vec2(0.0, 22.0)).corner_radius(5))
}

/// Pastille d'état : toujours un symbole et un mot, jamais la couleur seule.
pub fn status_badge(ui: &mut Ui, sym: &str, color: Color32, text: &str) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 4.0;
        ui.label(RichText::new(sym).color(color).size(14.0));
        ui.label(RichText::new(text).color(INK2));
    });
}

/// Choix exclusif sous forme de pastilles.
pub fn chips<T: PartialEq + Clone>(ui: &mut Ui, value: &mut T, options: &[(T, &str)]) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 2.0;
        Frame::new().fill(FIELD).corner_radius(7).inner_margin(Margin::same(2)).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                // Dans une zone alignée à droite, egui place les éléments de droite à gauche.
                let rtl = ui.layout().prefer_right_to_left();
                let ordered: Vec<&(T, &str)> = if rtl { options.iter().rev().collect() } else { options.iter().collect() };
                for (v, label) in ordered {
                    let selected = *value == *v;
                    let text = RichText::new(*label).color(if selected { INK } else { INK2 }).size(12.5);
                    let mut b = egui::Button::new(text).corner_radius(5).min_size(egui::vec2(0.0, 24.0));
                    b = if selected { b.fill(RAISED) } else { b.fill(Color32::TRANSPARENT).stroke(Stroke::NONE) };
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
        ui.label(RichText::new(label).color(MUTED).size(12.0));
        ui.add(egui::TextEdit::singleline(value).hint_text(placeholder).desired_width(width))
    })
    .inner
}

/// Bloc « ce qu'il faut savoir » : symbole, titre, texte, et un éventuel bouton.
pub fn notice(ui: &mut Ui, sym: &str, color: Color32, title: &str, text: &str, action: Option<&str>) -> bool {
    let mut clicked = false;
    Frame::new()
        .fill(Color32::from_rgb(0x20, 0x20, 0x1e))
        .stroke(Stroke::new(1.0, BORDER))
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
                    ui.label(RichText::new(title).font(bold(13.5)).color(INK));
                    ui.add(egui::Label::new(RichText::new(text).color(INK2).size(12.5)).wrap());
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
        let mut color = MUTED;
        if let Some(s) = sort.as_deref() {
            if s.col == i && !title.is_empty() {
                title = format!("{title} {}", if s.desc { icon::CARET_DOWN } else { icon::CARET_UP });
                color = INK2;
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
    ui.painter().hline(rect.x_range(), rect.bottom(), Stroke::new(1.0, AXIS));
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
        ui.painter().rect_filled(rect, CornerRadius::same(4), Color32::from_rgb(0x1f, 0x33, 0x4d));
    } else if resp.hovered() {
        ui.painter().rect_filled(rect, CornerRadius::same(4), RAISED);
    }
    ui.painter().hline(rect.x_range(), rect.bottom(), Stroke::new(1.0, GRID));
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
    cell(ui, r, label, &body(12.5), MUTED, false);
}

pub fn kv(ui: &mut Ui, label: &str, value: &str) {
    ui.horizontal_top(|ui| {
        kv_label(ui, label);
        ui.add(egui::Label::new(RichText::new(value).color(INK).size(12.5)).wrap());
    });
}

/// Libellé et lien cliquable. Rend vrai quand on clique sur le lien.
pub fn kv_link(ui: &mut Ui, label: &str, url: &str) -> bool {
    ui.horizontal_top(|ui| {
        kv_label(ui, label);
        ui.add(egui::Link::new(RichText::new(url).color(RX).size(12.5))).on_hover_text("Ouvrir dans le navigateur").clicked()
    })
    .inner
}

pub fn kv_mono(ui: &mut Ui, label: &str, value: &str) {
    ui.horizontal_top(|ui| {
        kv_label(ui, label);
        ui.add(egui::Label::new(RichText::new(value).font(mono(12.0)).color(INK)).wrap());
    });
}
