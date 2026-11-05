//! Couleurs, polices et style de NetBuster.

use eframe::egui::{self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Stroke, TextStyle};
use std::sync::Arc;

pub const PAGE: Color32 = Color32::from_rgb(0x0d, 0x0d, 0x0d);
pub const SURFACE: Color32 = Color32::from_rgb(0x1a, 0x1a, 0x19);
pub const RAISED: Color32 = Color32::from_rgb(0x26, 0x26, 0x24);
pub const FIELD: Color32 = Color32::from_rgb(0x12, 0x12, 0x11);
pub const BORDER: Color32 = Color32::from_rgb(0x2f, 0x2f, 0x2d);
pub const INK: Color32 = Color32::from_rgb(0xf0, 0xef, 0xec);
pub const INK2: Color32 = Color32::from_rgb(0xc3, 0xc2, 0xb7);
pub const MUTED: Color32 = Color32::from_rgb(0x96, 0x94, 0x8d);
pub const GRID: Color32 = Color32::from_rgb(0x2c, 0x2c, 0x2a);
pub const AXIS: Color32 = Color32::from_rgb(0x38, 0x38, 0x35);

/// Reçu et envoyé : les deux mêmes teintes dans toute l'application.
pub const RX: Color32 = Color32::from_rgb(0x39, 0x87, 0xe5);
pub const TX: Color32 = Color32::from_rgb(0xd9, 0x59, 0x26);
pub const SERIES3: Color32 = Color32::from_rgb(0x19, 0x9e, 0x70);

pub const PRIMARY: Color32 = Color32::from_rgb(0x25, 0x6a, 0xbf);
pub const PRIMARY_HOVER: Color32 = Color32::from_rgb(0x2a, 0x78, 0xd6);

pub const GOOD: Color32 = Color32::from_rgb(0x0c, 0xa3, 0x0c);
pub const WARNING: Color32 = Color32::from_rgb(0xfa, 0xb2, 0x19);
pub const SERIOUS: Color32 = Color32::from_rgb(0xec, 0x83, 0x5a);
pub const CRITICAL: Color32 = Color32::from_rgb(0xd0, 0x3b, 0x3b);
pub const CRITICAL_TEXT: Color32 = Color32::from_rgb(0xf0, 0x7a, 0x7a);

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
        ],
        None,
    );
    add(
        "code",
        &[
            "/usr/share/fonts/truetype/noto/NotoSansMono-Regular.ttf",
            "/usr/share/fonts/noto/NotoSansMono-Regular.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        ],
        Some(FontFamily::Monospace),
    );
    // Dernier recours pour les symboles absents des autres polices.
    add("fallback", &["/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/dejavu/DejaVuSans.ttf"], None);
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

pub fn apply_style(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    ctx.global_style_mut(|s| {
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

        let v = &mut s.visuals;
        v.dark_mode = true;
        v.panel_fill = PAGE;
        v.window_fill = SURFACE;
        v.window_stroke = Stroke::new(1.0, AXIS);
        v.window_corner_radius = CornerRadius::same(10);
        v.menu_corner_radius = CornerRadius::same(8);
        v.extreme_bg_color = FIELD;
        v.faint_bg_color = Color32::from_rgb(0x1f, 0x1f, 0x1e);
        v.code_bg_color = FIELD;
        v.hyperlink_color = RX;
        v.selection.bg_fill = PRIMARY;
        v.selection.stroke = Stroke::new(1.0, INK);
        v.override_text_color = None;

        let radius = CornerRadius::same(6);
        let w = &mut v.widgets;
        w.noninteractive.bg_fill = SURFACE;
        w.noninteractive.weak_bg_fill = SURFACE;
        w.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
        w.noninteractive.fg_stroke = Stroke::new(1.0, INK2);
        w.noninteractive.corner_radius = radius;
        w.inactive.bg_fill = RAISED;
        w.inactive.weak_bg_fill = RAISED;
        w.inactive.bg_stroke = Stroke::new(1.0, BORDER);
        w.inactive.fg_stroke = Stroke::new(1.0, INK);
        w.inactive.corner_radius = radius;
        w.hovered.bg_fill = Color32::from_rgb(0x33, 0x33, 0x30);
        w.hovered.weak_bg_fill = Color32::from_rgb(0x33, 0x33, 0x30);
        w.hovered.bg_stroke = Stroke::new(1.0, Color32::from_rgb(0x4a, 0x4a, 0x46));
        w.hovered.fg_stroke = Stroke::new(1.0, INK);
        w.hovered.corner_radius = radius;
        w.hovered.expansion = 0.0;
        w.active.bg_fill = Color32::from_rgb(0x3d, 0x3d, 0x39);
        w.active.weak_bg_fill = Color32::from_rgb(0x3d, 0x3d, 0x39);
        w.active.bg_stroke = Stroke::new(1.0, Color32::from_rgb(0x5a, 0x5a, 0x55));
        w.active.fg_stroke = Stroke::new(1.0, INK);
        w.active.corner_radius = radius;
        w.active.expansion = 0.0;
        w.open.bg_fill = RAISED;
        w.open.weak_bg_fill = RAISED;
        w.open.bg_stroke = Stroke::new(1.0, AXIS);
        w.open.fg_stroke = Stroke::new(1.0, INK);
        w.open.corner_radius = radius;
    });
}
