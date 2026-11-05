//! Graphiques dessinés à la main : débit dans le temps, mini-courbes, barres classées, barres par jour.

use super::theme::*;
use crate::model::Sample;
use crate::util::{fmt_bytes, fmt_rate};
use eframe::egui::{self, epaint::PathShape, Align2, Color32, CornerRadius, Pos2, Rect, Sense, Shape, Stroke, Ui, Vec2};
use std::collections::VecDeque;

/// Graduation « ronde » : 1, 2 ou 5 × 10^n.
pub fn nice_step(max: f64, ticks: usize) -> f64 {
    let raw = (max / ticks.max(1) as f64).max(1e-9);
    let mag = 10f64.powf(raw.log10().floor());
    let n = raw / mag;
    let s = if n <= 1.0 {
        1.0
    } else if n <= 2.0 {
        2.0
    } else if n <= 5.0 {
        5.0
    } else {
        10.0
    };
    s * mag
}

fn with_alpha(c: Color32, a: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), a)
}

/// Aire sous la courbe : découpée en quadrilatères, car la zone n'est pas convexe.
fn area(painter: &egui::Painter, pts: &[Pos2], base: f32, color: Color32) {
    let mut mesh = egui::Mesh::default();
    for w in pts.windows(2) {
        let i = mesh.vertices.len() as u32;
        mesh.colored_vertex(w[0], color);
        mesh.colored_vertex(w[1], color);
        mesh.colored_vertex(Pos2::new(w[1].x, base), color);
        mesh.colored_vertex(Pos2::new(w[0].x, base), color);
        mesh.add_triangle(i, i + 1, i + 2);
        mesh.add_triangle(i, i + 2, i + 3);
    }
    painter.add(Shape::mesh(mesh));
}

/// Débit reçu et envoyé dans le temps, sur une seule échelle, avec lecture au survol.
pub fn throughput(ui: &mut Ui, samples: &VecDeque<Sample>, now: f64, window_secs: f64, height: f32) {
    let width = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, height), Sense::hover());
    let painter = ui.painter_at(rect);
    let plot = Rect::from_min_max(Pos2::new(rect.left() + 72.0, rect.top() + 6.0), Pos2::new(rect.right() - 8.0, rect.bottom() - 22.0));
    let t0 = now - window_secs;
    let visible: Vec<&Sample> = samples.iter().filter(|s| s.t >= t0).collect();
    let max = visible.iter().map(|s| s.rx.max(s.tx) as f64).fold(0.0, f64::max).max(1024.0);
    let step = nice_step(max * 1.1, 4);
    let top = (max * 1.1 / step).ceil() * step;
    let x_of = |t: f64| plot.left() + ((t - t0) / window_secs) as f32 * plot.width();
    let y_of = |v: f64| plot.bottom() - (v / top) as f32 * plot.height();

    // Échelle et grille, discrètes.
    let mut v = 0.0;
    while v <= top + step * 0.01 {
        let y = y_of(v);
        painter.hline(plot.x_range(), y, Stroke::new(1.0, if v == 0.0 { pal().axis } else { pal().grid }));
        painter.text(Pos2::new(plot.left() - 8.0, y), Align2::RIGHT_CENTER, fmt_rate(v), mono(11.0), pal().muted);
        v += step;
    }
    let tick_every = match window_secs as u64 {
        0..=60 => 15.0,
        61..=300 => 60.0,
        301..=900 => 180.0,
        _ => 600.0,
    };
    let mut ago = 0.0;
    while ago <= window_secs {
        let x = x_of(now - ago);
        painter.vline(x, plot.bottom()..=plot.bottom() + 4.0, Stroke::new(1.0, pal().axis));
        let label = if ago == 0.0 {
            "maintenant".to_string()
        } else if ago < 60.0 {
            format!("−{ago:.0} s")
        } else {
            format!("−{:.0} min", ago / 60.0)
        };
        let align = if ago == 0.0 { Align2::RIGHT_TOP } else { Align2::CENTER_TOP };
        painter.text(Pos2::new(x, plot.bottom() + 6.0), align, label, body(11.0), pal().muted);
        ago += tick_every;
    }

    // Une coupure dans les échantillons reste une coupure : pas de trait inventé.
    let series = |value: &dyn Fn(&Sample) -> f32, color: Color32| {
        let pts: Vec<Pos2> = visible.iter().map(|s| Pos2::new(x_of(s.t), y_of(value(s) as f64))).collect();
        if pts.len() >= 2 {
            area(&painter, &pts, plot.bottom(), with_alpha(color, 34));
            painter.add(PathShape::line(pts.clone(), Stroke::new(2.0, color)));
        }
        if let Some(last) = pts.last() {
            painter.circle_filled(*last, 3.5, color);
        }
    };
    series(&|s| s.tx, pal().tx);
    series(&|s| s.rx, pal().rx);

    if visible.len() < 2 {
        painter.text(plot.center(), Align2::CENTER_CENTER, "Collecte des premières mesures…", body(13.0), pal().muted);
    }

    // Lecture au survol : point le plus proche, valeurs exactes.
    if let Some(p) = resp.hover_pos() {
        if plot.expand(8.0).contains(p) && !visible.is_empty() {
            let t = t0 + ((p.x - plot.left()) / plot.width()) as f64 * window_secs;
            let near = visible.iter().min_by(|a, b| (a.t - t).abs().total_cmp(&(b.t - t).abs())).unwrap();
            let x = x_of(near.t);
            painter.vline(x, plot.y_range(), Stroke::new(1.0, pal().axis));
            painter.circle(Pos2::new(x, y_of(near.rx as f64)), 4.0, pal().rx, Stroke::new(2.0, pal().surface));
            painter.circle(Pos2::new(x, y_of(near.tx as f64)), 4.0, pal().tx, Stroke::new(2.0, pal().surface));
            let ago = now - near.t;
            let (rx, tx) = (near.rx, near.tx);
            egui::Tooltip::always_open(ui.ctx().clone(), ui.layer_id(), ui.scope_id().with("chart_tip"), egui::PopupAnchor::Pointer).show(|ui| {
                ui.label(egui::RichText::new(format!("il y a {ago:.0} s")).color(pal().muted).size(12.0));
                legend_value(ui, pal().rx, "Reçu", &fmt_rate(rx as f64));
                legend_value(ui, pal().tx, "Envoyé", &fmt_rate(tx as f64));
            });
        }
    }
}

pub fn legend_value(ui: &mut Ui, color: Color32, name: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        let (r, _) = ui.allocate_exact_size(Vec2::splat(10.0), Sense::hover());
        ui.painter().circle_filled(r.center(), 4.0, color);
        ui.label(egui::RichText::new(name).color(pal().ink2).size(12.5));
        ui.label(egui::RichText::new(value).color(pal().ink).size(12.5));
    });
}

/// Mini-courbe sans échelle, à côté d'une valeur écrite en toutes lettres.
pub fn spark_in(ui: &Ui, rect: Rect, hist: &VecDeque<(f32, f32)>) {
    if hist.len() < 2 {
        return;
    }
    let painter = ui.painter_at(rect);
    let r = rect.shrink2(Vec2::new(4.0, 5.0));
    let max = hist.iter().map(|h| h.0.max(h.1)).fold(1.0f32, f32::max);
    let n = hist.len().max(60);
    let x_of = |i: usize| r.right() - (hist.len() - 1 - i) as f32 / (n - 1) as f32 * r.width();
    let y_of = |v: f32| r.bottom() - (v / max) * r.height();
    painter.hline(r.x_range(), r.bottom(), Stroke::new(1.0, pal().grid));
    let tx: Vec<Pos2> = hist.iter().enumerate().map(|(i, h)| Pos2::new(x_of(i), y_of(h.1))).collect();
    let rx: Vec<Pos2> = hist.iter().enumerate().map(|(i, h)| Pos2::new(x_of(i), y_of(h.0))).collect();
    painter.add(PathShape::line(tx, Stroke::new(1.25, pal().tx)));
    painter.add(PathShape::line(rx, Stroke::new(1.25, pal().rx)));
}

pub fn spark_samples_in(ui: &Ui, rect: Rect, samples: &VecDeque<Sample>, last_n: usize) {
    let skip = samples.len().saturating_sub(last_n);
    let h: VecDeque<(f32, f32)> = samples.iter().skip(skip).map(|s| (s.rx, s.tx)).collect();
    spark_in(ui, rect, &h);
}

/// Barre fine en deux segments (reçu puis envoyé), séparés par un espace.
pub fn split_bar(ui: &Ui, rect: Rect, rx: f64, tx: f64, scale_max: f64) {
    let h = 6.0;
    let y = rect.center().y - h / 2.0;
    let track = Rect::from_min_size(Pos2::new(rect.left(), y), Vec2::new(rect.width(), h));
    ui.painter().rect_filled(track, CornerRadius::same(3), pal().raised);
    if scale_max <= 0.0 {
        return;
    }
    let rx_w = (rx / scale_max) as f32 * rect.width();
    let tx_w = (tx / scale_max) as f32 * rect.width();
    let min_vis = |w: f32| if w > 0.0 { w.max(2.0) } else { 0.0 };
    let (rx_w, tx_w) = (min_vis(rx_w), min_vis(tx_w));
    let gap = if rx_w > 0.0 && tx_w > 0.0 { 2.0 } else { 0.0 };
    if rx_w > 0.0 {
        ui.painter().rect_filled(Rect::from_min_size(track.min, Vec2::new(rx_w, h)), CornerRadius::same(3), pal().rx);
    }
    if tx_w > 0.0 {
        ui.painter().rect_filled(Rect::from_min_size(Pos2::new(track.left() + rx_w + gap, y), Vec2::new(tx_w, h)), CornerRadius::same(3), pal().tx);
    }
}

pub struct DayBar {
    pub label: String,
    pub full_date: String,
    pub rx: u64,
    pub tx: u64,
}

/// Consommation par jour : reçu et envoyé empilés, une seule échelle, détail au survol.
pub fn day_bars(ui: &mut Ui, bars: &[DayBar], height: f32) {
    let width = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, height), Sense::hover());
    let painter = ui.painter_at(rect);
    let plot = Rect::from_min_max(Pos2::new(rect.left() + 60.0, rect.top() + 6.0), Pos2::new(rect.right() - 4.0, rect.bottom() - 22.0));
    let max = bars.iter().map(|b| b.rx + b.tx).max().unwrap_or(0).max(1_000_000) as f64;
    let step = nice_step(max * 1.05, 4);
    let top = (max * 1.05 / step).ceil() * step;
    let y_of = |v: f64| plot.bottom() - (v / top) as f32 * plot.height();
    let mut v = 0.0;
    while v <= top + step * 0.01 {
        let y = y_of(v);
        painter.hline(plot.x_range(), y, Stroke::new(1.0, if v == 0.0 { pal().axis } else { pal().grid }));
        painter.text(Pos2::new(plot.left() - 8.0, y), Align2::RIGHT_CENTER, fmt_bytes(v as u64), mono(11.0), pal().muted);
        v += step;
    }
    let n = bars.len().max(1) as f32;
    let slot = plot.width() / n;
    let bar_w = (slot - 4.0).clamp(4.0, 28.0);
    let hover_idx = resp.hover_pos().filter(|p| plot.expand(4.0).contains(*p)).map(|p| (((p.x - plot.left()) / slot) as usize).min(bars.len().saturating_sub(1)));
    for (i, b) in bars.iter().enumerate() {
        let cx = plot.left() + slot * (i as f32 + 0.5);
        if hover_idx == Some(i) {
            painter.rect_filled(Rect::from_center_size(Pos2::new(cx, plot.center().y), Vec2::new(slot, plot.height())), CornerRadius::same(3), pal().raised);
        }
        let (rx_top, total_top) = (y_of(b.rx as f64), y_of((b.rx + b.tx) as f64));
        if b.rx > 0 {
            painter.rect_filled(Rect::from_min_max(Pos2::new(cx - bar_w / 2.0, rx_top), Pos2::new(cx + bar_w / 2.0, plot.bottom())), CornerRadius { nw: 2, ne: 2, sw: 0, se: 0 }, pal().rx);
        }
        if b.tx > 0 {
            let bottom = rx_top - if b.rx > 0 { 2.0 } else { 0.0 };
            let top_y = total_top.min(bottom - 1.0);
            painter.rect_filled(Rect::from_min_max(Pos2::new(cx - bar_w / 2.0, top_y), Pos2::new(cx + bar_w / 2.0, bottom)), CornerRadius { nw: 2, ne: 2, sw: 0, se: 0 }, pal().tx);
        }
        if bars.len() <= 14 || i % 5 == 0 || i + 1 == bars.len() {
            painter.text(Pos2::new(cx, plot.bottom() + 6.0), Align2::CENTER_TOP, &b.label, body(11.0), pal().muted);
        }
    }
    if let Some(i) = hover_idx {
        if let Some(b) = bars.get(i) {
            egui::Tooltip::always_open(ui.ctx().clone(), ui.layer_id(), ui.scope_id().with("day_tip"), egui::PopupAnchor::Pointer).show(|ui| {
                ui.label(egui::RichText::new(&b.full_date).color(pal().muted).size(12.0));
                legend_value(ui, pal().rx, "Reçu", &fmt_bytes(b.rx));
                legend_value(ui, pal().tx, "Envoyé", &fmt_bytes(b.tx));
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_are_round() {
        assert_eq!(nice_step(100.0, 4), 50.0);
        assert_eq!(nice_step(1000.0, 4), 500.0);
        assert_eq!(nice_step(70.0, 4), 20.0);
        assert_eq!(nice_step(9.0, 4), 5.0);
    }
}
