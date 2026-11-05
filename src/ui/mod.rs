//! La fenêtre de NetBuster.

pub mod chart;
pub mod page_analyse;
pub mod page_capture;
pub mod page_manage;
pub mod page_monitor;
pub mod page_settings;
pub mod theme;
pub mod widgets;

use crate::admin::AdminState;
use crate::collect::{Ctl, Shared, PANEL_CONFIG, PANEL_FIREWALL, PANEL_NONE, PANEL_SSH};
use crate::manage::Action;
use crate::model::{FlowKey, StreamKey};
use crate::trace::TraceMode;
use crate::util::{fmt_rate, RATE_IN_BITS};
use eframe::egui::{self, Align, Color32, CornerRadius, Frame, Layout, Margin, Pos2, Rect, RichText, Sense, Stroke, Ui, Vec2, WidgetInfo};
use egui_phosphor::regular as icon;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use theme::*;
use widgets::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Page {
    Overview,
    Apps,
    Conns,
    Ports,
    Packets,
    Trace,
    Ip,
    Usage,
    Firewall,
    Config,
    Ssh,
    Settings,
}

impl Page {
    pub const ALL: [Page; 12] =
        [Page::Overview, Page::Apps, Page::Conns, Page::Ports, Page::Packets, Page::Trace, Page::Ip, Page::Usage, Page::Firewall, Page::Config, Page::Ssh, Page::Settings];

    /// Les écrans qui reposent sur la capture de paquets ou les outils de Linux n'existent pas ailleurs.
    pub fn available(self) -> bool {
        crate::platform::full_features() || !matches!(self, Page::Packets | Page::Firewall | Page::Config | Page::Ssh)
    }

    pub fn slug(self) -> &'static str {
        match self {
            Page::Overview => "overview",
            Page::Apps => "apps",
            Page::Conns => "connections",
            Page::Ports => "ports",
            Page::Packets => "packets",
            Page::Trace => "traceroute",
            Page::Ip => "ip",
            Page::Usage => "usage",
            Page::Firewall => "firewall",
            Page::Config => "config",
            Page::Ssh => "ssh",
            Page::Settings => "settings",
        }
    }

    pub fn from_slug(s: &str) -> Option<Page> {
        Page::ALL.iter().copied().find(|p| p.slug() == s)
    }

    pub fn title(self) -> &'static str {
        match self {
            Page::Overview => "Vue d'ensemble",
            Page::Apps => "Applications",
            Page::Conns => "Connexions",
            Page::Ports => "Ports ouverts",
            Page::Packets => "Paquets",
            Page::Trace => "Traceroute",
            Page::Ip => "IP et fournisseurs",
            Page::Usage => "Consommation",
            Page::Firewall => "Pare-feu",
            Page::Config => "Configuration réseau",
            Page::Ssh => "SSH",
            Page::Settings => "Réglages",
        }
    }

    pub fn subtitle(self) -> &'static str {
        match self {
            Page::Overview => "Ce qui entre et sort de ce PC, maintenant",
            Page::Apps => "Le trafic de chaque programme et de chacun de ses appels",
            Page::Conns => "Toutes les connexions entrantes et sortantes",
            Page::Ports => "Les portes ouvertes de ce PC, et qui les écoute",
            Page::Packets => "Chaque paquet qui passe, chiffré ou non",
            Page::Trace => "Le chemin suivi par le trafic, étape par étape",
            Page::Ip => "À qui appartient chaque adresse contactée",
            Page::Usage => "Le volume de données utilisé, jour après jour",
            Page::Firewall => "Politiques, règles UFW, IP Tables et nftables",
            Page::Config => "Interfaces, adresses, routes, DNS et connexions",
            Page::Ssh => "Serveur, sessions, clés et tentatives de connexion",
            Page::Settings if !crate::platform::full_features() => "Apparence et démarrage de NetBuster",
            Page::Settings => "Démarrage de NetBuster et capture en arrière-plan",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Page::Overview => icon::GAUGE,
            Page::Apps => icon::APP_WINDOW,
            Page::Conns => icon::ARROWS_LEFT_RIGHT,
            Page::Ports => icon::DOOR_OPEN,
            Page::Packets => icon::PACKAGE,
            Page::Trace => icon::PATH,
            Page::Ip => icon::GLOBE,
            Page::Usage => icon::CHART_BAR,
            Page::Firewall => icon::SHIELD_CHECK,
            Page::Config => icon::SLIDERS,
            Page::Ssh => icon::TERMINAL_WINDOW,
            Page::Settings => icon::GEAR_SIX,
        }
    }
}

pub struct AppsUi {
    pub expanded: std::collections::HashSet<String>,
    pub collapsed_pids: std::collections::HashSet<(String, Option<u32>)>,
    pub show_local: bool,
    pub search: String,
    pub selected: Option<FlowKey>,
    pub freeze: Freeze,
}

#[derive(Clone, Copy, PartialEq)]
pub enum ConnFilter {
    All,
    In,
    Out,
    Listen,
}

pub struct ConnsUi {
    pub filter: ConnFilter,
    pub search: String,
    pub sort: Sort,
    pub show_local: bool,
    pub show_closed: bool,
    pub selected: Option<FlowKey>,
    pub freeze: Freeze,
}

pub struct PortsUi {
    pub search: String,
    pub sort: Sort,
    pub new_port: String,
    pub new_proto: String,
    pub new_scope: Option<String>,
    pub error: Option<String>,
    pub freeze: Freeze,
}

#[derive(Clone, Copy, PartialEq)]
pub enum DirFilter {
    All,
    In,
    Out,
}

#[derive(Clone, Copy, PartialEq)]
pub enum CryptoFilter {
    All,
    Encrypted,
    Clear,
}

#[derive(Clone, Copy, PartialEq)]
pub enum DetailTab {
    Packet,
    Conversation,
}

pub struct PacketsUi {
    pub dir: DirFilter,
    pub crypto: CryptoFilter,
    pub proto: String,
    pub search: String,
    pub follow_live: bool,
    pub selected: Option<u64>,
    pub flow_filter: Option<StreamKey>,
    pub detail_tab: DetailTab,
    pub cached: Vec<Arc<crate::model::PacketRow>>,
    pub cache_key: (u64, String),
    pub message: Option<String>,
    /// Ouvre le premier paquet de ce protocole dès qu'il arrive (vérification de l'écran).
    pub select_first: Option<String>,
    /// Liste figée : les paquets montrés. La capture continue et les nouveaux attendent derrière.
    pub frozen: Option<Vec<Arc<crate::model::PacketRow>>>,
    pub frozen_at: String,
    pub frozen_seen: u64,
}

pub struct TraceUi {
    pub target: String,
    pub mode: TraceModeChoice,
    pub tcp_port: String,
    pub selected_hop: Option<usize>,
}

#[derive(Clone, Copy, PartialEq)]
pub enum TraceModeChoice {
    Icmp,
    Udp,
    Tcp,
}

pub struct IpUi {
    pub query: String,
    pub selected: Option<IpAddr>,
    pub error: Option<String>,
    pub sort: Sort,
    pub search: String,
    pub freeze: Freeze,
}

#[derive(Clone, Copy, PartialEq)]
pub enum FwTab {
    Ufw,
    Iptables,
    Nft,
}

pub struct FwUi {
    pub tab: FwTab,
    pub family: u8,
    pub table: String,
    pub form: crate::manage::NewRule,
    pub error: Option<String>,
    pub ufw_port: String,
    pub ufw_proto: String,
    pub ufw_allow: bool,
}

pub struct CfgUi {
    pub selected_iface: Option<String>,
    pub addr: String,
    pub mtu: String,
    pub route_dst: String,
    pub route_via: String,
    pub route_dev: String,
    pub dns_conn: Option<String>,
    pub dns_servers: String,
    pub error: Option<String>,
}

#[derive(Clone, Copy, PartialEq)]
pub enum SshTab {
    Sessions,
    Keys,
    Hosts,
    Logins,
}

pub struct SshUi {
    pub tab: SshTab,
    pub port: String,
    pub root_login: String,
    pub password: String,
    pub pubkey: String,
    pub x11: String,
    pub tries: String,
    pub loaded_from: Option<String>,
    pub new_key: String,
    pub error: Option<String>,
}

pub struct ScreenshotJob {
    pub path: PathBuf,
    pub requested: bool,
}

pub struct Toast {
    pub ok: bool,
    pub title: String,
    pub detail: String,
    pub at: std::time::Instant,
}

pub struct App {
    pub shared: Arc<Shared>,
    pub page: Page,
    pub iface: Option<String>,
    pub range_secs: f64,
    pub apps: AppsUi,
    pub conns: ConnsUi,
    pub ports: PortsUi,
    pub packets: PacketsUi,
    pub trace: TraceUi,
    pub ip: IpUi,
    pub fw: FwUi,
    pub cfg: CfgUi,
    pub ssh: SshUi,
    pub confirm: Option<Action>,
    pub after_admin: Option<Action>,
    pub toast: Option<Toast>,
    pub seen_results: usize,
    pub bits: bool,
    pub frame: u64,
    pub started: std::time::Instant,
    pub screenshot: Option<ScreenshotJob>,
    pub style_ready: bool,
    pub about_open: bool,
    pub settings: page_settings::SettingsUi,
    /// Les listes de la vue d'ensemble.
    pub overview_freeze: Freeze,
    /// La personne a demandé à quitter : la fermeture de la fenêtre arrête tout.
    pub quit_requested: bool,
    /// La fenêtre doit se rouvrir aussitôt fermée.
    pub reopen_requested: bool,
    /// Se réduire dans la barre des tâches dès la première image.
    pub minimize_on_open: bool,
}

/// Page GitHub du développeur. Le nom, la version et le projet viennent de la fiche du projet.
pub const AUTHOR_GITHUB: &str = "https://github.com/ergen35";

/// Ouvre une adresse ou un dossier avec le programme par défaut du système.
fn open_external(url: &str) -> std::io::Result<()> {
    let mut child = std::process::Command::new("xdg-open")
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    // Récupère le processus quand il se termine, pour ne pas laisser de zombie.
    std::thread::spawn(move || child.wait());
    Ok(())
}

impl App {
    pub fn new(shared: Arc<Shared>) -> Self {
        App {
            shared,
            page: Page::Overview,
            iface: None,
            range_secs: 60.0,
            apps: AppsUi { expanded: Default::default(), collapsed_pids: Default::default(), show_local: false, search: String::new(), selected: None, freeze: Freeze::default() },
            conns: ConnsUi { filter: ConnFilter::All, search: String::new(), sort: Sort { col: 7, desc: true }, show_local: false, show_closed: true, selected: None, freeze: Freeze::default() },
            ports: PortsUi { search: String::new(), sort: Sort { col: 0, desc: false }, new_port: String::new(), new_proto: "tcp".into(), new_scope: None, error: None, freeze: Freeze::default() },
            packets: PacketsUi {
                dir: DirFilter::All,
                crypto: CryptoFilter::All,
                proto: String::new(),
                search: String::new(),
                follow_live: true,
                selected: None,
                flow_filter: None,
                detail_tab: DetailTab::Packet,
                cached: vec![],
                cache_key: (0, String::new()),
                message: None,
                select_first: None,
                frozen: None,
                frozen_at: String::new(),
                frozen_seen: 0,
            },
            trace: TraceUi { target: String::new(), mode: TraceModeChoice::Icmp, tcp_port: "443".into(), selected_hop: None },
            ip: IpUi { query: String::new(), selected: None, error: None, sort: Sort { col: 5, desc: true }, search: String::new(), freeze: Freeze::default() },
            fw: FwUi {
                tab: FwTab::Ufw,
                family: 4,
                table: "filter".into(),
                form: crate::manage::NewRule { chain: "INPUT".into(), action: "ACCEPT".into(), proto: "tcp".into(), ..Default::default() },
                error: None,
                ufw_port: String::new(),
                ufw_proto: "tcp".into(),
                ufw_allow: true,
            },
            cfg: CfgUi {
                selected_iface: None,
                addr: String::new(),
                mtu: String::new(),
                route_dst: String::new(),
                route_via: String::new(),
                route_dev: String::new(),
                dns_conn: None,
                dns_servers: String::new(),
                error: None,
            },
            ssh: SshUi {
                tab: SshTab::Sessions,
                port: String::new(),
                root_login: String::new(),
                password: String::new(),
                pubkey: String::new(),
                x11: String::new(),
                tries: String::new(),
                loaded_from: None,
                new_key: String::new(),
                error: None,
            },
            confirm: None,
            after_admin: None,
            toast: None,
            seen_results: 0,
            bits: false,
            frame: 0,
            started: std::time::Instant::now(),
            screenshot: None,
            style_ready: false,
            about_open: false,
            settings: page_settings::SettingsUi::new(),
            overview_freeze: Freeze::default(),
            quit_requested: false,
            reopen_requested: false,
            minimize_on_open: false,
        }
    }

    /// Ouvre le traceroute vers une adresse et le lance tout de suite.
    pub fn go_trace(&mut self, ip: IpAddr, iface: Option<String>, tcp_port: Option<u16>) {
        self.trace.target = ip.to_string();
        if let Some(p) = tcp_port {
            self.trace.mode = TraceModeChoice::Tcp;
            self.trace.tcp_port = p.to_string();
        }
        self.trace.selected_hop = None;
        let mode = self.trace_mode();
        self.shared.tracer.start(&ip.to_string(), iface, mode);
        self.page = Page::Trace;
    }

    pub fn trace_mode(&self) -> TraceMode {
        match self.trace.mode {
            TraceModeChoice::Icmp => TraceMode::Icmp,
            TraceModeChoice::Udp => TraceMode::Udp,
            TraceModeChoice::Tcp => TraceMode::Tcp(self.trace.tcp_port.trim().parse().unwrap_or(443)),
        }
    }

    pub fn go_lookup(&mut self, ip: IpAddr) {
        self.ip.query = ip.to_string();
        self.ip.selected = Some(ip);
        self.ip.error = None;
        self.shared.enrich.request(ip);
        self.shared.enrich.request_rdap(ip);
        self.page = Page::Ip;
    }

    pub fn ask(&mut self, action: Action) {
        self.confirm = Some(action);
    }

    /// Change de thème tout de suite et retient le choix.
    pub fn set_theme(&mut self, ctx: &egui::Context, choice: crate::desktop::ThemeChoice) {
        self.settings.settings.theme = choice;
        apply_style(ctx, choice);
        if let Err(e) = self.settings.settings.save() {
            self.notify(false, "Thème", e.to_string());
        }
    }

    pub fn notify(&mut self, ok: bool, title: impl Into<String>, detail: impl Into<String>) {
        self.toast = Some(Toast { ok, title: title.into(), detail: detail.into(), at: std::time::Instant::now() });
    }

    /// Exécute les ordres venus de l'icône de la barre d'état ou d'un second lancement.
    pub fn handle_control(&mut self, ctx: &egui::Context) {
        while let Some(c) = self.shared.control.try_pop() {
            match c {
                Ctl::Show => {
                    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
                        // Sous Wayland, une application ne peut pas sortir sa fenêtre de la barre des
                        // tâches : la rouvrir est le seul moyen sûr de la ramener devant.
                        self.reopen_requested = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    } else {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    }
                }
                Ctl::Hide => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                Ctl::Quit => {
                    self.quit_requested = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
    }

    /// Une nouvelle fenêtre a un nouveau contexte de dessin.
    pub fn window_opening(&mut self) {
        self.style_ready = false;
        self.reopen_requested = false;
    }

    /// Fermeture de la fenêtre seule : la mesure et la capture continuent sans dessin.
    pub fn window_closed(&self) {
        *self.shared.repaint.lock().unwrap() = None;
        self.shared.visible_panel.store(PANEL_NONE, Ordering::Relaxed);
    }

    /// Fin réelle de NetBuster.
    pub fn shutdown(&self) {
        self.shared.tracer.stop();
        self.shared.admin.shutdown();
        self.shared.enrich.save();
        let usage = self.shared.model.lock().unwrap().usage.clone();
        usage.save();
    }

    /// Le dessin d'une image complète.
    pub fn draw(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        if !self.style_ready {
            self.style_ready = true;
            install_fonts(&ctx);
            apply_style(&ctx, self.settings.settings.theme);
            *self.shared.repaint.lock().unwrap() = Some(ctx.clone());
        }
        self.frame += 1;
        if !self.page.available() {
            self.page = Page::Overview;
        }
        if std::mem::take(&mut self.minimize_on_open) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
        }
        self.handle_control(&ctx);
        RATE_IN_BITS.store(self.bits, Ordering::Relaxed);
        let panel = match self.page {
            Page::Firewall => PANEL_FIREWALL,
            Page::Config => PANEL_CONFIG,
            Page::Ssh => PANEL_SSH,
            _ => PANEL_NONE,
        };
        if self.shared.visible_panel.swap(panel, Ordering::Relaxed) != panel {
            self.shared.refresh_panels.store(true, Ordering::Relaxed);
        }

        // Action qui attendait le mode administrateur.
        if self.after_admin.is_some() {
            match self.shared.admin.state() {
                AdminState::On { .. } => {
                    let a = self.after_admin.take().unwrap();
                    self.shared.run_action(a);
                }
                AdminState::Failed(_) | AdminState::Off => self.after_admin = None,
                AdminState::Asking => {}
            }
        }
        self.collect_results();

        egui::Panel::left("nav")
            .exact_size(224.0)
            .resizable(false)
            .show_separator_line(false)
            .frame(Frame::new().fill(pal().surface).inner_margin(Margin::symmetric(10, 12)))
            .show(ui, |ui| self.sidebar(ui));

        egui::CentralPanel::no_frame().frame(Frame::new().fill(pal().page).inner_margin(Margin::symmetric(20, 14))).show(ui, |ui| {
            self.top_bar(ui);
            ui.add_space(8.0);
            match self.page {
                Page::Overview => page_monitor::overview(self, ui),
                Page::Apps => page_monitor::apps(self, ui),
                Page::Conns => page_monitor::connections(self, ui),
                Page::Ports => page_monitor::ports(self, ui),
                Page::Packets => page_capture::packets(self, ui),
                Page::Trace => page_analyse::traceroute(self, ui),
                Page::Ip => page_analyse::ip_page(self, ui),
                Page::Usage => page_analyse::usage(self, ui),
                Page::Firewall => page_manage::firewall(self, ui),
                Page::Config => page_manage::config(self, ui),
                Page::Ssh => page_manage::ssh(self, ui),
                Page::Settings => page_settings::settings(self, ui),
            }
        });

        self.confirm_modal(&ctx);
        self.about_modal(&ctx);
        self.toast_ui(&ctx);
        self.screenshot_step(&ctx);
        ctx.request_repaint_after(std::time::Duration::from_millis(1000));
    }

    /// Le bouton « À propos » du menu.
    fn about_row(&mut self, ui: &mut Ui) {
        let (rect, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 32.0), Sense::click());
        resp.widget_info(|| WidgetInfo::labeled(egui::Role::Button, true, "À propos"));
        if resp.hovered() {
            ui.painter().rect_filled(rect, CornerRadius::same(6), pal().row_hover);
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        ui.painter().text(Pos2::new(rect.left() + 22.0, rect.center().y), egui::Align2::CENTER_CENTER, icon::INFO, body(16.0), pal().ink2);
        ui.painter().text(Pos2::new(rect.left() + 38.0, rect.center().y), egui::Align2::LEFT_CENTER, "À propos", body(13.5), pal().ink2);
        if resp.clicked() {
            self.about_open = true;
        }
    }

    fn about_modal(&mut self, ctx: &egui::Context) {
        if !self.about_open {
            return;
        }
        let mut close = false;
        let mut link = None;
        let resp = egui::Modal::new(egui::Id::unique("netbuster_about"))
            .frame(Frame::new().fill(pal().surface).stroke(Stroke::new(1.0, pal().axis)).corner_radius(12).inner_margin(Margin::same(20)))
            .backdrop_color(Color32::from_black_alpha(pal().backdrop))
            .show(ctx, |ui| {
                ui.set_width(460.0);
                ui.horizontal(|ui| {
                    let (r, _) = ui.allocate_exact_size(Vec2::splat(44.0), Sense::hover());
                    brand_mark(ui, r);
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 1.0;
                        ui.label(RichText::new("NetBuster").font(bold(19.0)).color(pal().ink));
                        ui.label(RichText::new(format!("Version {}", env!("CARGO_PKG_VERSION"))).color(pal().ink2).size(12.5));
                    });
                });
                ui.add_space(8.0);
                ui.add(egui::Label::new(RichText::new("Surveillance et gestion du réseau de ce PC, en temps réel.").color(pal().ink2)).wrap());
                ui.add_space(12.0);
                ui.label(RichText::new("Crédits").font(bold(13.5)).color(pal().ink));
                ui.add_space(2.0);
                ui.spacing_mut().item_spacing.y = 4.0;
                kv(ui, "Développeur", env!("CARGO_PKG_AUTHORS"));
                if kv_link(ui, "GitHub", AUTHOR_GITHUB) {
                    link = Some(AUTHOR_GITHUB);
                }
                if kv_link(ui, "Projet sur GitHub", env!("CARGO_PKG_REPOSITORY")) {
                    link = Some(env!("CARGO_PKG_REPOSITORY"));
                }
                ui.add_space(14.0);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    close = ui.button("Fermer").clicked();
                });
            });
        if close || resp.should_close() {
            self.about_open = false;
        }
        if let Some(url) = link {
            if let Err(e) = open_external(url) {
                self.notify(false, format!("Ouvrir {url}"), e.to_string());
            }
        }
    }

    fn collect_results(&mut self) {
        let log = self.shared.action_log.lock().unwrap();
        if log.len() > self.seen_results {
            let last = log.last().unwrap();
            self.toast = Some(Toast { ok: last.ok, title: last.title.clone(), detail: last.detail.clone(), at: std::time::Instant::now() });
            self.seen_results = log.len();
        }
    }

    fn sidebar(&mut self, ui: &mut Ui) {
        egui::Panel::bottom("admin_panel").resizable(false).show_separator_line(false).frame(Frame::new()).show(ui, |ui| {
            self.nav_item(ui, Page::Settings);
            self.about_row(ui);
            ui.add_space(6.0);
            if crate::platform::full_features() {
                self.admin_card(ui);
            }
        });
        // Marque : un écran de contrôle barré d'un signal.
        ui.horizontal(|ui| {
            let (r, _) = ui.allocate_exact_size(Vec2::splat(30.0), Sense::hover());
            brand_mark(ui, r);
            ui.label(RichText::new("NetBuster").font(bold(18.0)).color(pal().ink));
        });
        ui.add_space(10.0);

        let (rx, tx) = {
            let m = self.shared.model.lock().unwrap();
            m.current_rates(self.iface.as_deref())
        };
        ui.horizontal(|ui| {
            ui.add_space(6.0);
            ui.spacing_mut().item_spacing.x = 4.0;
            ui.label(RichText::new(icon::ARROW_DOWN).color(pal().rx).size(13.0));
            ui.label(RichText::new(fmt_rate(rx)).color(pal().ink2).size(12.0));
            ui.add_space(6.0);
            ui.label(RichText::new(icon::ARROW_UP).color(pal().tx).size(13.0));
            ui.label(RichText::new(fmt_rate(tx)).color(pal().ink2).size(12.0));
        });
        ui.add_space(8.0);

        let group = |ui: &mut Ui, text: &str| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                ui.label(RichText::new(text).color(pal().muted).size(11.5));
            });
            ui.add_space(1.0);
        };
        // Sur une petite fenêtre, le menu défile au lieu de passer sous le bas du panneau.
        egui::ScrollArea::vertical().id_salt("nav_scroll").auto_shrink([false, false]).scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded).show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            group(ui, "SURVEILLER");
            for p in [Page::Overview, Page::Apps, Page::Conns, Page::Ports] {
                self.nav_item(ui, p);
            }
            group(ui, "ANALYSER");
            for p in [Page::Packets, Page::Trace, Page::Ip, Page::Usage] {
                if p.available() {
                    self.nav_item(ui, p);
                }
            }
            if Page::Firewall.available() {
                group(ui, "GÉRER");
                for p in [Page::Firewall, Page::Config, Page::Ssh] {
                    self.nav_item(ui, p);
                }
            }
        });
    }

    fn nav_item(&mut self, ui: &mut Ui, p: Page) {
        let selected = self.page == p;
        let (rect, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 32.0), Sense::click());
        let title = p.title();
        resp.widget_info(move || WidgetInfo::selected(egui::Role::Button, true, selected, title));
        if selected {
            ui.painter().rect_filled(rect, CornerRadius::same(6), pal().raised);
            let bar = Rect::from_min_size(Pos2::new(rect.left(), rect.top() + 7.0), Vec2::new(3.0, rect.height() - 14.0));
            ui.painter().rect_filled(bar, CornerRadius::same(2), pal().rx);
        } else if resp.hovered() {
            ui.painter().rect_filled(rect, CornerRadius::same(6), pal().row_hover);
        }
        let color = if selected { pal().ink } else { pal().ink2 };
        ui.painter().text(Pos2::new(rect.left() + 22.0, rect.center().y), egui::Align2::CENTER_CENTER, p.icon(), body(16.0), color);
        ui.painter().text(Pos2::new(rect.left() + 38.0, rect.center().y), egui::Align2::LEFT_CENTER, title, if selected { bold(13.5) } else { body(13.5) }, color);
        if resp.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        if resp.clicked() {
            self.page = p;
        }
    }

    fn admin_card(&mut self, ui: &mut Ui) {
        let state = self.shared.admin.state();
        let capturing = self.shared.model.lock().unwrap().capture.running;
        {
            Frame::new().fill(pal().field).stroke(Stroke::new(1.0, pal().border)).corner_radius(8).inner_margin(Margin::same(10)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                match &state {
                    AdminState::On { .. } => {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(icon::SHIELD_CHECK).color(pal().good).size(16.0));
                            ui.label(RichText::new("Administrateur actif").font(bold(12.5)).color(pal().ink));
                        });
                        hint(ui, if capturing { "Capture des paquets en cours, trafic mesuré au paquet près." } else { "Capture à l'arrêt." });
                        if ui.button("Quitter ce mode").clicked() {
                            self.shared.stop_capture();
                            self.shared.admin.shutdown();
                        }
                    }
                    AdminState::Asking => {
                        ui.horizontal(|ui| {
                            ui.add(egui::Spinner::new().size(14.0));
                            ui.label(RichText::new("En attente…").font(bold(12.5)).color(pal().ink));
                        });
                        hint(ui, "Validez la demande de mot de passe du système.");
                    }
                    other => {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(icon::LOCK).color(pal().warning).size(16.0));
                            ui.label(RichText::new("Mode normal").font(bold(12.5)).color(pal().ink));
                        });
                        if let AdminState::Failed(msg) = other {
                            ui.add(egui::Label::new(RichText::new(msg).color(pal().critical_text).size(12.0)).wrap());
                        } else if self.shared.service_up.load(Ordering::Relaxed) {
                            hint(ui, "Paquets capturés par le service. Pare-feu et processus système demandent les droits.");
                        } else {
                            hint(ui, "Paquets, pare-feu et processus système demandent les droits.");
                        }
                        if primary_button(ui, "Passer administrateur").clicked() {
                            self.shared.enable_admin();
                        }
                    }
                }
            });
        }
    }

    fn top_bar(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 1.0;
                ui.label(RichText::new(self.page.title()).font(bold(21.0)).color(pal().ink));
                ui.label(RichText::new(self.page.subtitle()).color(pal().muted).size(12.5));
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                chips(ui, &mut self.bits, &[(false, "Mo/s"), (true, "Mbit/s")]);
                ui.add_space(4.0);
                let light = self.settings.settings.theme == crate::desktop::ThemeChoice::Light;
                let (sym, tip, next) = if light {
                    (icon::MOON, "Passer au thème sombre", crate::desktop::ThemeChoice::Dark)
                } else {
                    (icon::SUN, "Passer au thème clair", crate::desktop::ThemeChoice::Light)
                };
                let toggle = ui.add(egui::Button::new(RichText::new(sym).size(15.0)).min_size(Vec2::splat(28.0))).on_hover_text(tip);
                toggle.widget_info(|| WidgetInfo::labeled(egui::Role::Button, true, tip));
                if toggle.clicked() {
                    let ctx = ui.ctx().clone();
                    self.set_theme(&ctx, next);
                }
                ui.add_space(4.0);
                self.iface_combo(ui);
            });
        });
    }

    fn iface_combo(&mut self, ui: &mut Ui) {
        let shared = self.shared.clone();
        let m = shared.model.lock().unwrap();
        let label = self.iface.clone().unwrap_or_else(|| "Toutes les interfaces".to_string());
        let mut ifaces: Vec<_> = m.ifaces.values().collect();
        ifaces.sort_by_key(|i| (!i.counted(), i.bridge_port, i.kind == crate::model::IfKind::Loopback, i.name.clone()));
        let r = egui::ComboBox::from_id_salt("iface_combo").selected_text(format!("{}  {label}", icon::SHARE_NETWORK)).width(230.0).show_ui(ui, |ui| {
            ui.set_min_width(380.0);
            if ui.selectable_label(self.iface.is_none(), "Toutes les interfaces").clicked() {
                self.iface = None;
            }
            for i in ifaces {
                let text = format!("{}  ·  {}  ·  {} {}  {} {}", i.name, i.kind.label(), icon::ARROW_DOWN, fmt_rate(i.rx_rate), icon::ARROW_UP, fmt_rate(i.tx_rate));
                if ui.selectable_label(self.iface.as_deref() == Some(i.name.as_str()), text).clicked() {
                    self.iface = Some(i.name.clone());
                }
            }
        });
        named(&r.response, "Interface réseau");
    }

    fn confirm_modal(&mut self, ctx: &egui::Context) {
        let Some(action) = self.confirm.clone() else { return };
        let mut decision = None;
        egui::Modal::new(egui::Id::unique("netbuster_confirm"))
            .frame(Frame::new().fill(pal().surface).stroke(Stroke::new(1.0, pal().axis)).corner_radius(12).inner_margin(Margin::same(20)))
            .backdrop_color(Color32::from_black_alpha(pal().backdrop))
            .show(ctx, |ui| {
                ui.set_width(500.0);
                ui.label(RichText::new(&action.title).font(bold(16.0)).color(pal().ink));
                ui.add_space(4.0);
                ui.add(egui::Label::new(RichText::new(&action.explain).color(pal().ink2)).wrap());
                if let Some(w) = &action.warning {
                    ui.add_space(8.0);
                    ui.horizontal_top(|ui| {
                        ui.label(RichText::new(icon::WARNING).color(pal().warning).size(16.0));
                        ui.add(egui::Label::new(RichText::new(w).color(pal().ink)).wrap());
                    });
                }
                ui.add_space(10.0);
                ui.label(RichText::new("Ce qui sera exécuté").color(pal().muted).size(12.0));
                Frame::new().fill(pal().field).corner_radius(6).inner_margin(Margin::same(8)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    for s in &action.steps {
                        ui.add(egui::Label::new(RichText::new(s.preview()).font(mono(12.0)).color(pal().ink2)).wrap());
                    }
                });
                if action.needs_root() && !self.shared.admin.is_on() {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(icon::LOCK).color(pal().warning));
                        ui.label(RichText::new("Le système vous demandera votre mot de passe.").color(pal().ink2).size(12.5));
                    });
                }
                ui.add_space(14.0);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if primary_button(ui, "Confirmer").clicked() {
                        decision = Some(true);
                    }
                    if ui.button("Annuler").clicked() {
                        decision = Some(false);
                    }
                });
            });
        match decision {
            Some(true) => {
                self.confirm = None;
                if action.needs_root() && !self.shared.admin.is_on() {
                    self.after_admin = Some(action);
                    self.shared.enable_admin();
                } else {
                    self.shared.run_action(action);
                }
            }
            Some(false) => self.confirm = None,
            None => {}
        }
    }

    fn toast_ui(&mut self, ctx: &egui::Context) {
        let Some(t) = &self.toast else { return };
        if t.ok && t.at.elapsed().as_secs_f32() > 6.0 {
            self.toast = None;
            return;
        }
        let mut close = false;
        egui::Area::new(egui::Id::unique("netbuster_toast")).anchor(egui::Align2::RIGHT_BOTTOM, Vec2::new(-20.0, -20.0)).order(egui::Order::Foreground).show(ctx, |ui| {
            Frame::new().fill(pal().raised).stroke(Stroke::new(1.0, pal().axis)).corner_radius(8).inner_margin(Margin::same(12)).show(ui, |ui| {
                ui.set_max_width(420.0);
                ui.horizontal(|ui| {
                    let (sym, c) = if t.ok { (icon::CHECK_CIRCLE, pal().good) } else { (icon::X_CIRCLE, pal().critical_text) };
                    ui.label(RichText::new(sym).color(c).size(18.0));
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        let verb = if t.ok { "Fait" } else { "Échec" };
                        ui.add(egui::Label::new(RichText::new(format!("{verb} : {}", t.title)).font(bold(13.0)).color(pal().ink)).wrap());
                        if !t.detail.is_empty() {
                            ui.add(egui::Label::new(RichText::new(&t.detail).color(pal().ink2).size(12.0)).wrap());
                        }
                        if !t.ok && small_button(ui, "Fermer").clicked() {
                            close = true;
                        }
                    });
                });
            });
        });
        if close {
            self.toast = None;
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(500));
    }

    fn screenshot_step(&mut self, ctx: &egui::Context) {
        let Some(job) = &mut self.screenshot else { return };
        ctx.request_repaint();
        // Environ 120 images, et assez de temps pour que les premières mesures arrivent.
        // Sur une machine très chargée, le dessin peut être lent : la capture part quand même après 45 s.
        let elapsed = self.started.elapsed().as_secs_f32();
        if !job.requested && ((self.frame >= 120 && elapsed >= 2.0) || (self.frame >= 2 && elapsed >= 45.0)) {
            job.requested = true;
            let path = job.path.clone();
            ctx.request_screenshot(move |img| {
                let code = match save_png(&path, &img) {
                    Ok(()) => 0,
                    Err(e) => {
                        eprintln!("capture d'écran impossible : {e}");
                        1
                    }
                };
                std::process::exit(code);
            });
        }
    }
}

fn save_png(path: &std::path::Path, img: &egui::ColorImage) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
    }
    let mut rgba = Vec::with_capacity(img.pixels.len() * 4);
    for p in &img.pixels {
        rgba.extend_from_slice(&[p.r(), p.g(), p.b(), 255]);
    }
    image::save_buffer(path, &rgba, img.width() as u32, img.height() as u32, image::ColorType::Rgba8).map_err(|e| e.to_string())
}

/// La marque NetBuster : la même icône que dans la barre des tâches.
pub fn brand_mark(ui: &Ui, r: Rect) {
    let id = egui::Id::unique("netbuster_brand_texture");
    let ctx = ui.ctx();
    let tex = ctx.data(|d| d.get_temp::<egui::TextureHandle>(id)).or_else(|| {
        let (w, h, px) = crate::desktop::icon_rgba(128)?;
        let image = egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &px);
        let tex = ctx.load_texture("netbuster_brand", image, egui::TextureOptions::LINEAR);
        ctx.data_mut(|d| d.insert_temp(id, tex.clone()));
        Some(tex)
    });
    if let Some(tex) = tex {
        let uv = Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0));
        ui.painter().image(tex.id(), r, uv, Color32::WHITE);
    }
}

/// La fenêtre en cours. `App` lui survit : son contenu reste quand elle se ferme et se rouvre.
pub struct Window<'a>(pub &'a mut App);

impl eframe::App for Window<'_> {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Ici et pas seulement au dessin : une fenêtre réduite ne se dessine pas, mais obéit.
        self.0.handle_control(ctx);
    }

    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        self.0.draw(ui);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.0.window_closed();
    }
}
