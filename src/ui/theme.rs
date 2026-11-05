//! Couleurs, polices et style de NetBuster.

use crate::desktop::ThemeChoice;
use eframe::egui::{self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Stroke, TextStyle};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Toutes les couleurs de l'interface, pour un thème.
pub struct Palette {
    pub page: Color32,
    pub surface: Color32,
    pub raised: Color32,
    pub field: Color32,
    pub border: Color32,
    pub ink: Color32,
    pub ink2: Color32,
    pub muted: Color32,
    pub grid: Color32,
    pub axis: Color32,
    /// Reçu et envoyé : les deux mêmes teintes dans toute l'application.
    pub rx: Color32,
    pub tx: Color32,
    pub series3: Color32,
    pub primary: Color32,
    pub primary_hover: Color32,
    pub good: Color32,
    pub warning: Color32,
    pub serious: Color32,
    pub critical: Color32,
    pub critical_text: Color32,
    pub link: Color32,
    pub danger: Color32,
    pub row_hover: Color32,
    pub row_selected: Color32,
    pub notice: Color32,
    pub switch_off: Color32,
    pub faint: Color32,
    pub band: Color32,
    pub connector: Color32,
    pub bubble_out: Color32,
    pub bubble_in: Color32,
    /// Cases à cocher et barres de défilement.
    pub control: Color32,
    pub widget_hover: Color32,
    pub widget_hover_line: Color32,
    pub widget_active: Color32,
    pub widget_active_line: Color32,
    pub backdrop: u8,
}

const fn rgb(v: u32) -> Color32 {
    Color32::from_rgb((v >> 16) as u8, (v >> 8) as u8, v as u8)
}

pub static DARK: Palette = Palette {
    page: rgb(0x0d0d0d),
    surface: rgb(0x1a1a19),
    raised: rgb(0x262624),
    field: rgb(0x121211),
    border: rgb(0x2f2f2d),
    ink: rgb(0xf0efec),
    ink2: rgb(0xc3c2b7),
    muted: rgb(0x96948d),
    grid: rgb(0x2c2c2a),
    axis: rgb(0x383835),
    rx: rgb(0x3987e5),
    tx: rgb(0xd95926),
    series3: rgb(0x199e70),
    primary: rgb(0x256abf),
    primary_hover: rgb(0x2a78d6),
    good: rgb(0x0ca30c),
    warning: rgb(0xfab219),
    serious: rgb(0xec835a),
    critical: rgb(0xd03b3b),
    critical_text: rgb(0xf07a7a),
    link: rgb(0x3987e5),
    danger: rgb(0xa82c2c),
    row_hover: rgb(0x222220),
    row_selected: rgb(0x1f334d),
    notice: rgb(0x20201e),
    switch_off: rgb(0x5c5c58),
    faint: rgb(0x1f1f1e),
    band: rgb(0x21211f),
    connector: rgb(0x5b5a55),
    bubble_out: rgb(0x241c18),
    bubble_in: rgb(0x171e27),
    control: rgb(0x3f3f3b),
    widget_hover: rgb(0x333330),
    widget_hover_line: rgb(0x4a4a46),
    widget_active: rgb(0x3d3d39),
    widget_active_line: rgb(0x5a5a55),
    backdrop: 150,
};

/// Teintes de `dataviz` pour fond clair. Les états sont assombris : un symbole fin doit rester
/// lisible à 3:1 au moins sur un fond presque blanc.
pub static LIGHT: Palette = Palette {
    page: rgb(0xf3f3f0),
    surface: rgb(0xfcfcfb),
    raised: rgb(0xeceae5),
    field: rgb(0xf0efeb),
    border: rgb(0xdddcd5),
    ink: rgb(0x0b0b0b),
    ink2: rgb(0x52514e),
    muted: rgb(0x6b6a64),
    grid: rgb(0xe1e0d9),
    axis: rgb(0xc3c2b7),
    rx: rgb(0x2a78d6),
    tx: rgb(0xeb6834),
    series3: rgb(0x1baf7a),
    primary: rgb(0x256abf),
    primary_hover: rgb(0x1c5cab),
    good: rgb(0x0b7f0b),
    warning: rgb(0xb26a00),
    serious: rgb(0xc4501f),
    critical: rgb(0xc62f2f),
    critical_text: rgb(0xb3261e),
    link: rgb(0x1c5cab),
    danger: rgb(0xb42525),
    row_hover: rgb(0xf0efea),
    row_selected: rgb(0xd9e7f8),
    notice: rgb(0xf6f5f1),
    switch_off: rgb(0x8a8981),
    faint: rgb(0xf5f4f0),
    band: rgb(0xf1f0eb),
    connector: rgb(0x85847c),
    bubble_out: rgb(0xfbeee7),
    bubble_in: rgb(0xe8f1fb),
    control: rgb(0xcfcec6),
    widget_hover: rgb(0xe4e3dc),
    widget_hover_line: rgb(0xbdbcb3),
    widget_active: rgb(0xd9d8d0),
    widget_active_line: rgb(0xa5a49b),
    backdrop: 90,
};

static IS_LIGHT: AtomicBool = AtomicBool::new(false);

/// La palette du thème en cours.
#[inline]
pub fn pal() -> &'static Palette {
    if IS_LIGHT.load(Ordering::Relaxed) {
        &LIGHT
    } else {
        &DARK
    }
}

pub fn set_theme(choice: ThemeChoice) {
    IS_LIGHT.store(choice == ThemeChoice::Light, Ordering::Relaxed);
}

pub fn bold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("bold".into()))
}

pub fn body(size: f32) -> FontId {
    FontId::new(size, FontFamily::Proportional)
}

pub fn mono(size: f32) -> FontId {
    FontId::new(size, FontFamily::Monospace)
}

pub fn install_fonts(ctx: &egui::Context) {
    let mut f = FontDefinitions::default();
    let mut add = |name: &str, paths: &[&str], family: Option<FontFamily>| -> bool {
        for p in paths {
            if let Ok(bytes) = std::fs::read(p) {
                f.font_data.insert(name.to_string(), Arc::new(FontData::from_owned(bytes)));
                if let Some(fam) = family {
                    f.families.entry(fam).or_default().insert(0, name.to_string());
                }
                return true;
            }
        }
        false
    };
    add(
        "text",
        &[
            "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
            "/usr/share/fonts/noto/NotoSans-Regular.ttf",
            "/usr/share/fonts/google-noto/NotoSans-Regular.ttf",
            "/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "C:\\Windows\\Fonts\\segoeui.ttf",
            "/System/Library/Fonts/Supplemental/Arial.ttf",
        ],
        Some(FontFamily::Proportional),
    );
    let has_bold = add(
        "text-bold",
        &[
            "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf",
            "/usr/share/fonts/noto/NotoSans-Bold.ttf",
            "/usr/share/fonts/google-noto/NotoSans-Bold.ttf",
            "/usr/share/fonts/truetype/ubuntu/Ubuntu-B.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "C:\\Windows\\Fonts\\segoeuib.ttf",
            "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        ],
        None,
    );
    add(
        "code",
        &[
            "/usr/share/fonts/truetype/noto/NotoSansMono-Regular.ttf",
            "/usr/share/fonts/noto/NotoSansMono-Regular.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "C:\\Windows\\Fonts\\consola.ttf",
            "/System/Library/Fonts/Supplemental/Courier New.ttf",
        ],
        Some(FontFamily::Monospace),
    );
    // Dernier recours pour les symboles absents des autres polices.
    add(
        "fallback",
        &[
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/dejavu/DejaVuSans.ttf",
            "C:\\Windows\\Fonts\\seguisym.ttf",
            "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        ],
        None,
    );
    if f.font_data.contains_key("fallback") {
        for fam in [FontFamily::Proportional, FontFamily::Monospace] {
            f.families.entry(fam).or_default().push("fallback".to_string());
        }
    }
    egui_phosphor::add_to_fonts(&mut f, egui_phosphor::Variant::Regular);
    f.families.entry(FontFamily::Monospace).or_default().push("phosphor".to_string());

    let proportional = f.families.get(&FontFamily::Proportional).cloned().unwrap_or_default();
    let mut bold_chain = proportional;
    if has_bold {
        bold_chain.insert(0, "text-bold".to_string());
    }
    f.families.insert(FontFamily::Name("bold".into()), bold_chain);
    ctx.set_fonts(f);
}

pub fn apply_style(ctx: &egui::Context, choice: ThemeChoice) {
    set_theme(choice);
    let light = choice == ThemeChoice::Light;
    let p = if light { &LIGHT } else { &DARK };
    ctx.set_theme(if light { egui::Theme::Light } else { egui::Theme::Dark });
    ctx.all_styles_mut(|s| {
        s.text_styles.insert(TextStyle::Body, body(13.5));
        s.text_styles.insert(TextStyle::Button, body(13.5));
        s.text_styles.insert(TextStyle::Small, body(11.5));
        s.text_styles.insert(TextStyle::Heading, bold(21.0));
        s.text_styles.insert(TextStyle::Monospace, mono(12.5));

        s.spacing.item_spacing = egui::vec2(8.0, 6.0);
        s.spacing.button_padding = egui::vec2(10.0, 5.0);
        s.spacing.interact_size.y = 28.0;
        s.spacing.combo_height = 320.0;
        s.spacing.scroll.bar_width = 8.0;
        s.spacing.scroll.floating = false;
        // La barre de défilement ne doit pas être l'élément le plus visible de la page :
        // elle prend la teinte des contrôles et non celle du texte.
        s.spacing.scroll.foreground_color = false;

        let v = &mut s.visuals;
        v.dark_mode = !light;
        v.panel_fill = p.page;
        v.window_fill = p.surface;
        v.window_stroke = Stroke::new(1.0, p.axis);
        v.window_corner_radius = CornerRadius::same(10);
        v.menu_corner_radius = CornerRadius::same(8);
        v.extreme_bg_color = p.field;
        v.faint_bg_color = p.faint;
        v.code_bg_color = p.field;
        v.hyperlink_color = p.link;
        v.selection.bg_fill = p.primary;
        // Le texte d'un choix sélectionné est posé sur le bleu, dans les deux thèmes.
        v.selection.stroke = Stroke::new(1.0, Color32::WHITE);
        v.override_text_color = None;

        let radius = CornerRadius::same(6);
        let w = &mut v.widgets;
        w.noninteractive.bg_fill = p.surface;
        w.noninteractive.weak_bg_fill = p.surface;
        w.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
        w.noninteractive.fg_stroke = Stroke::new(1.0, p.ink2);
        w.noninteractive.corner_radius = radius;
        w.inactive.bg_fill = p.control;
        w.inactive.weak_bg_fill = p.raised;
        w.inactive.bg_stroke = Stroke::new(1.0, p.border);
        w.inactive.fg_stroke = Stroke::new(1.0, p.ink);
        w.inactive.corner_radius = radius;
        w.hovered.bg_fill = p.widget_hover_line;
        w.hovered.weak_bg_fill = p.widget_hover;
        w.hovered.bg_stroke = Stroke::new(1.0, p.widget_hover_line);
        w.hovered.fg_stroke = Stroke::new(1.0, p.ink);
        w.hovered.corner_radius = radius;
        w.hovered.expansion = 0.0;
        w.active.bg_fill = p.widget_active_line;
        w.active.weak_bg_fill = p.widget_active;
        w.active.bg_stroke = Stroke::new(1.0, p.widget_active_line);
        w.active.fg_stroke = Stroke::new(1.0, p.ink);
        w.active.corner_radius = radius;
        w.active.expansion = 0.0;
        w.open.bg_fill = p.raised;
        w.open.weak_bg_fill = p.raised;
        w.open.bg_stroke = Stroke::new(1.0, p.axis);
        w.open.fg_stroke = Stroke::new(1.0, p.ink);
        w.open.corner_radius = radius;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lum(c: Color32) -> f64 {
        let f = |v: u8| {
            let v = v as f64 / 255.0;
            if v <= 0.03928 { v / 12.92 } else { ((v + 0.055) / 1.055).powf(2.4) }
        };
        0.2126 * f(c.r()) + 0.7152 * f(c.g()) + 0.0722 * f(c.b())
    }

    fn contrast(a: Color32, b: Color32) -> f64 {
        let (x, y) = (lum(a).max(lum(b)), lum(a).min(lum(b)));
        (x + 0.05) / (y + 0.05)
    }

    #[test]
    fn every_text_stays_readable_in_both_themes() {
        for p in [&DARK, &LIGHT] {
            for bg in [p.surface, p.page] {
                for (name, ink) in [("ink", p.ink), ("ink2", p.ink2), ("muted", p.muted), ("link", p.link), ("critical_text", p.critical_text)] {
                    assert!(contrast(ink, bg) >= 4.5, "{name} : {:.2}", contrast(ink, bg));
                }
            }
            // Le texte courant reste lisible sur un bouton et sur une ligne sélectionnée.
            assert!(contrast(p.ink, p.raised) >= 4.5);
            assert!(contrast(p.ink, p.row_selected) >= 4.5);
            assert!(contrast(Color32::WHITE, p.primary) >= 4.5);
            assert!(contrast(Color32::WHITE, p.danger) >= 4.5);
        }
    }

    #[test]
    fn symbols_and_series_stand_out_in_both_themes() {
        for p in [&DARK, &LIGHT] {
            for (name, c) in [("rx", p.rx), ("tx", p.tx), ("good", p.good), ("warning", p.warning), ("serious", p.serious), ("critical", p.critical)] {
                assert!(contrast(c, p.surface) >= 3.0, "{name} : {:.2}", contrast(c, p.surface));
            }
            assert!(contrast(p.switch_off, p.surface) >= 2.5);
        }
    }
}
