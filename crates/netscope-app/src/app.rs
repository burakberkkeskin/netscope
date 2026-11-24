use crate::theme::{AppPalette, section_label, status_pill};
use crate::tray::{TrayAction, TrayController};
use crate::views;
use crate::views::dns::{DnsJumpAction, DnsState};
use crate::views::dns_propagation::DnsPropagationState;
use crate::views::internet_check::InternetCheckState;
use crate::views::iperf3::Iperf3State;
use crate::views::ipv6_check::Ipv6CheckState;
use crate::views::lan_scanner::{LanJumpAction, LanScannerState};
use crate::views::mtr::MtrState;
use crate::views::path_troubleshoot::PathTroubleshootState;
use crate::views::ping::PingState;
use crate::views::port_scan::PortScanState;
use crate::views::speedtest::SpeedTestState;
use crate::views::subnet_calc::SubnetCalcState;
use crate::views::tls::TlsState;
use crate::views::traceroute::TracerouteState;
use crate::views::visual_traceroute::VisualTracerouteState;
use egui::{Align, CornerRadius, Frame, Layout, Margin, Stroke, Vec2, ViewportCommand};
use netscope_core::history::PersistedState;
use netscope_core::net_info::{DnsLeakStatus, PublicNetworkStatus, fetch_public_network_status};
use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tracing::{error, info};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolTab {
    InternetCheck,
    Ipv6Diagnostics,
    PathTroubleshoot,
    Ping,
    Traceroute,
    VisualTraceroute,
    Mtr,
    SpeedTest,
    Iperf3,
    LanScanner,
    PortScan,
    SubnetCalculator,
    DnsLookup,
    DnsPropagation,
    SslCertificate,
}

impl ToolTab {
    pub fn title(self) -> &'static str {
        match self {
            Self::InternetCheck => "Internet Check",
            Self::Ipv6Diagnostics => "IPv6 Check",
            Self::PathTroubleshoot => "Path Troubleshoot",
            Self::Ping => "Ping",
            Self::Traceroute => "Traceroute",
            Self::VisualTraceroute => "Visual Traceroute",
            Self::Mtr => "MTR",
            Self::SpeedTest => "Speed Test",
            Self::Iperf3 => "iperf3",
            Self::LanScanner => "LAN Scanner",
            Self::PortScan => "Port Scan",
            Self::SubnetCalculator => "Subnet Calculator",
            Self::DnsLookup => "DNS Lookup",
            Self::DnsPropagation => "DNS Propagation",
            Self::SslCertificate => "SSL Certificate",
        }
    }
}

pub struct NetScopeApp {
    rt: Runtime,
    tray: Option<TrayController>,
    active_tool: ToolTab,
    dark_mode: bool,
    window_visible: bool,
    should_quit: bool,

    history: PersistedState,

    public_status: Option<PublicNetworkStatus>,
    public_rx: mpsc::UnboundedReceiver<PublicNetworkStatus>,
    public_tx: mpsc::UnboundedSender<PublicNetworkStatus>,
    last_status_refresh: Instant,
    status_refreshing: bool,

    internet_check: InternetCheckState,
    ipv6_check: Ipv6CheckState,
    path_troubleshoot: PathTroubleshootState,
    ping: PingState,
    traceroute: TracerouteState,
    visual_traceroute: VisualTracerouteState,
    mtr: MtrState,
    speedtest: SpeedTestState,
    iperf3: Iperf3State,
    lan_scanner: LanScannerState,
    port_scan: PortScanState,
    subnet_calc: SubnetCalcState,
    dns: DnsState,
    dns_propagation: DnsPropagationState,
    tls: TlsState,

    screenshot_driver: Option<ScreenshotDriver>,
    headless_test: bool,
}

enum ShotPhase {
    StartStep,
    WaitData,
    SettleFrames(u8),
    WaitCapture(Arc<AtomicBool>),
}

struct ScreenshotDriver {
    dir: PathBuf,
    step: usize,
    phase: ShotPhase,
    started_at: Instant,
}

impl ScreenshotDriver {
    fn new(dir: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(&dir);
        Self {
            dir,
            step: 0,
            phase: ShotPhase::StartStep,
            started_at: Instant::now(),
        }
    }
}

impl NetScopeApp {
    pub fn new(cc: &eframe::CreationContext<'_>, screenshot_dir: Option<PathBuf>) -> Self {
        let rt = Runtime::new().expect("Tokio runtime initialization failed");
        let history = PersistedState::load();
        let tray = if screenshot_dir.is_some() || !history.menu_bar_enabled {
            None
        } else {
            TrayController::try_new()
        };
        let screenshot_driver = screenshot_dir.map(ScreenshotDriver::new);

        let (public_tx, public_rx) = mpsc::unbounded_channel();
        cc.egui_ctx.style_mut_of(egui::Theme::Dark, |s| {
            s.visuals.widgets.noninteractive.fg_stroke.color =
                AppPalette::for_mode(true).text_primary;
        });

        let mut app = Self {
            rt,
            tray,
            active_tool: ToolTab::InternetCheck,
            dark_mode: false,
            window_visible: true,
            should_quit: false,
            history,
            public_status: None,
            public_rx,
            public_tx,
            last_status_refresh: Instant::now(),
            status_refreshing: false,
            internet_check: InternetCheckState::default(),
            ipv6_check: Ipv6CheckState::default(),
            path_troubleshoot: PathTroubleshootState::default(),
            ping: PingState::default(),
            traceroute: TracerouteState::default(),
            visual_traceroute: VisualTracerouteState::default(),
            mtr: MtrState::default(),
            speedtest: SpeedTestState::default(),
            iperf3: Iperf3State::default(),
            lan_scanner: LanScannerState::default(),
            port_scan: PortScanState::default(),
            subnet_calc: SubnetCalcState::default(),
            dns: DnsState::default(),
            dns_propagation: DnsPropagationState::default(),
            tls: TlsState::default(),
            screenshot_driver,
            headless_test: false,
        };

        app.trigger_status_refresh(&cc.egui_ctx);
        app
    }

    #[cfg(test)]
    pub(crate) fn new_headless_for_test() -> Self {
        let rt = Runtime::new().expect("Tokio runtime initialization failed");
        let (public_tx, public_rx) = mpsc::unbounded_channel();
        Self {
            rt,
            tray: None,
            active_tool: ToolTab::InternetCheck,
            dark_mode: false,
            window_visible: true,
            should_quit: false,
            history: PersistedState::default(),
            public_status: None,
            public_rx,
            public_tx,
            last_status_refresh: Instant::now(),
            status_refreshing: false,
            internet_check: InternetCheckState::default(),
            ipv6_check: Ipv6CheckState::default(),
            path_troubleshoot: PathTroubleshootState::default(),
            ping: PingState::default(),
            traceroute: TracerouteState::default(),
            visual_traceroute: VisualTracerouteState::default(),
            mtr: MtrState::default(),
            speedtest: SpeedTestState::default(),
            iperf3: Iperf3State::default(),
            lan_scanner: LanScannerState::default(),
            port_scan: PortScanState::default(),
            subnet_calc: SubnetCalcState::default(),
            dns: DnsState::default(),
            dns_propagation: DnsPropagationState::default(),
            tls: TlsState::default(),
            screenshot_driver: None,
            headless_test: true,
        }
    }

    pub(crate) fn set_menu_bar_enabled(&mut self, enabled: bool) {
        self.history.menu_bar_enabled = enabled;
        if !self.headless_test {
            let _ = self.history.save();
        }
        if enabled {
            if self.tray.is_none() && self.screenshot_driver.is_none() && !self.headless_test {
                self.tray = TrayController::try_new();
            }
            if let (Some(tray), Some(st)) = (&self.tray, &self.public_status) {
                tray.update_status(st);
            }
        } else {
            self.tray = None;
        }
    }

    fn trigger_status_refresh(&mut self, ctx: &egui::Context) {
        if self.status_refreshing {
            return;
        }
        self.status_refreshing = true;
        self.last_status_refresh = Instant::now();
        let tx = self.public_tx.clone();
        let ctx_clone = ctx.clone();
        self.rt.spawn(async move {
            let status = fetch_public_network_status().await;
            let _ = tx.send(status);
            ctx_clone.request_repaint();
        });
    }
}

impl eframe::App for NetScopeApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if ctx.input(|i| i.viewport().close_requested()) && !self.should_quit && self.tray.is_some()
        {
            ctx.send_viewport_cmd(ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(ViewportCommand::Visible(false));
            self.window_visible = false;
        }

        if let Some(ref tray) = self.tray {
            for action in tray.poll_actions() {
                match action {
                    TrayAction::ToggleWindow => {
                        self.window_visible = !self.window_visible;
                        ctx.send_viewport_cmd(ViewportCommand::Visible(self.window_visible));
                        if self.window_visible {
                            ctx.send_viewport_cmd(ViewportCommand::Focus);
                        }
                    }
                    TrayAction::RunInternetCheck => {
                        self.active_tool = ToolTab::InternetCheck;
                        self.window_visible = true;
                        ctx.send_viewport_cmd(ViewportCommand::Visible(true));
                        ctx.send_viewport_cmd(ViewportCommand::Focus);
                        self.internet_check.start(&self.rt, ctx);
                    }
                    TrayAction::RefreshStatus => {
                        self.trigger_status_refresh(ctx);
                    }
                    TrayAction::Quit => {
                        self.should_quit = true;
                        self.internet_check.stop();
                        self.ipv6_check.stop();
                        self.path_troubleshoot.stop();
                        self.ping.stop();
                        self.traceroute.stop();
                        self.visual_traceroute.stop();
                        self.mtr.stop();
                        self.speedtest.stop();
                        self.iperf3.stop();
                        self.lan_scanner.stop();
                        self.port_scan.stop();
                        self.dns_propagation.stop();
                        ctx.send_viewport_cmd(ViewportCommand::Close);
                    }
                }
            }
        }

        if self.last_status_refresh.elapsed() >= Duration::from_secs(60) {
            self.trigger_status_refresh(ctx);
        }

        while let Ok(st) = self.public_rx.try_recv() {
            if let Some(ref tray) = self.tray {
                tray.update_status(&st);
            }
            self.public_status = Some(st);
            self.status_refreshing = false;
        }

        self.internet_check.poll();
        self.ipv6_check.poll();
        self.path_troubleshoot.poll();
        self.ping.poll();
        self.traceroute.poll();
        self.visual_traceroute.poll();
        self.mtr.poll();
        self.speedtest.poll(&mut self.history);
        self.iperf3.poll(&mut self.history);
        self.lan_scanner.poll(&mut self.history, &self.rt, ctx);
        self.port_scan.poll();
        self.dns.poll();
        self.dns_propagation.poll();
        self.tls.poll();

        self.drive_screenshots(ctx);

        ctx.set_theme(if self.dark_mode {
            egui::ThemePreference::Dark
        } else {
            egui::ThemePreference::Light
        });

        if !self.window_visible || self.screenshot_driver.is_some() {
            ctx.request_repaint_after(Duration::from_millis(80));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.render_ui(ui);
    }
}

impl NetScopeApp {
    pub(crate) fn render_ui(&mut self, ui: &mut egui::Ui) {
        let palette = AppPalette::for_mode(self.dark_mode);

        egui::Panel::left("netscope_sidebar")
            .resizable(false)
            .exact_size(214.0)
            .frame(
                Frame::new()
                    .fill(palette.sidebar_bg)
                    .stroke(Stroke::new(1.0, palette.card_border))
                    .inner_margin(Margin::symmetric(12, 14)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading(
                        egui::RichText::new("NetScope")
                            .strong()
                            .color(palette.text_primary),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let theme_lbl = if self.dark_mode { "Light" } else { "Dark" };
                        if ui.small_button(theme_lbl).clicked() {
                            self.dark_mode = !self.dark_mode;
                        }
                    });
                });

                ui.add_space(10.0);
                let nav_max_h = (ui.available_height() - 138.0).max(160.0);
                egui::ScrollArea::vertical()
                    .id_salt("netscope_nav_scroll")
                    .auto_shrink([false, true])
                    .max_height(nav_max_h)
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;

                        Self::nav_group_header(ui, &palette, "HEALTH CHECKS", true);
                        self.nav_button(
                            ui,
                            &palette,
                            ToolTab::InternetCheck,
                            self.internet_check.running,
                        );
                        self.nav_button(
                            ui,
                            &palette,
                            ToolTab::Ipv6Diagnostics,
                            self.ipv6_check.running,
                        );
                        self.nav_button(
                            ui,
                            &palette,
                            ToolTab::PathTroubleshoot,
                            self.path_troubleshoot.running,
                        );

                        Self::nav_group_header(ui, &palette, "PATH & PROBES", false);
                        self.nav_button(ui, &palette, ToolTab::Ping, self.ping.running);
                        self.nav_button(
                            ui,
                            &palette,
                            ToolTab::Traceroute,
                            self.traceroute.running,
                        );
                        self.nav_button(
                            ui,
                            &palette,
                            ToolTab::VisualTraceroute,
                            self.visual_traceroute.running,
                        );
                        self.nav_button(ui, &palette, ToolTab::Mtr, self.mtr.running);

                        Self::nav_group_header(ui, &palette, "BANDWIDTH", false);
                        self.nav_button(ui, &palette, ToolTab::SpeedTest, self.speedtest.running);
                        self.nav_button(ui, &palette, ToolTab::Iperf3, self.iperf3.running);

                        Self::nav_group_header(ui, &palette, "NETWORK TOOLS", false);
                        self.nav_button(
                            ui,
                            &palette,
                            ToolTab::LanScanner,
                            self.lan_scanner.running,
                        );
                        self.nav_button(ui, &palette, ToolTab::PortScan, self.port_scan.running);
                        self.nav_button(ui, &palette, ToolTab::SubnetCalculator, false);

                        Self::nav_group_header(ui, &palette, "DNS & DOMAINS", false);
                        self.nav_button(ui, &palette, ToolTab::DnsLookup, self.dns.running);
                        self.nav_button(
                            ui,
                            &palette,
                            ToolTab::DnsPropagation,
                            self.dns_propagation.running,
                        );
                        self.nav_button(ui, &palette, ToolTab::SslCertificate, self.tls.running);
                    });

                // Push Menu Bar Monitor card to the bottom without bottom_up stretching
                let monitor_card_h = 128.0;
                let push_down = (ui.available_height() - monitor_card_h).max(12.0);
                ui.add_space(push_down);

                palette
                    .card_frame()
                    .inner_margin(Margin::same(10))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            section_label(ui, &palette, "MENU BAR");
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui
                                    .add_enabled(
                                        !self.status_refreshing,
                                        egui::Button::new("↻").small(),
                                    )
                                    .on_hover_text("Refresh public IP & DNS status")
                                    .clicked()
                                {
                                    self.trigger_status_refresh(ui.ctx());
                                }
                                let tray_lbl = if self.history.menu_bar_enabled {
                                    "Tray: On"
                                } else {
                                    "Tray: Off"
                                };
                                if ui
                                    .add(
                                        egui::Button::new(
                                            egui::RichText::new(tray_lbl).size(10.5),
                                        )
                                        .small(),
                                    )
                                    .on_hover_text(
                                        "Toggle OS Menu Bar / System Tray icon. When Off, closing the window quits NetScope.",
                                    )
                                    .clicked()
                                {
                                    self.set_menu_bar_enabled(!self.history.menu_bar_enabled);
                                }
                            });
                        });
                        ui.add_space(4.0);
                        if let Some(ref st) = self.public_status {
                            let ip_txt = st
                                .public_ip
                                .map(|i| i.to_string())
                                .unwrap_or_else(|| "Offline".into());
                            ui.label(
                                egui::RichText::new(ip_txt)
                                    .monospace()
                                    .strong()
                                    .size(13.0),
                            );
                            if let Some(ref isp) = st.isp_or_org {
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(isp)
                                            .size(11.0)
                                            .color(palette.text_muted),
                                    )
                                    .truncate(),
                                );
                            }
                            ui.add_space(6.0);
                            ui.horizontal_wrapped(|ui| {
                                let (vpn_fg, vpn_bg, vpn_lbl) = if st.vpn_active {
                                    (palette.ok, palette.ok_bg, "VPN On")
                                } else {
                                    (palette.text_muted, palette.card_subtle_bg, "VPN Off")
                                };
                                status_pill(ui, vpn_lbl, vpn_fg, vpn_bg);

                                let (leak_fg, leak_bg, leak_lbl) = match st.dns_leak_status {
                                    DnsLeakStatus::NoLeak => {
                                        (palette.ok, palette.ok_bg, "DNS Matches")
                                    }
                                    DnsLeakStatus::ExternalResolver => {
                                        (palette.accent, palette.card_subtle_bg, "Upstream DNS")
                                    }
                                    DnsLeakStatus::PossibleLeak => {
                                        (palette.err, palette.err_bg, "DNS Leak!")
                                    }
                                    DnsLeakStatus::Unknown => {
                                        (palette.text_muted, palette.card_subtle_bg, "DNS ?")
                                    }
                                };
                                status_pill(ui, leak_lbl, leak_fg, leak_bg);
                            });
                        } else {
                            ui.label(
                                egui::RichText::new("Checking public IP...")
                                    .size(11.5)
                                    .color(palette.text_muted),
                            );
                        }
                        if !self.history.menu_bar_enabled {
                            ui.add_space(3.0);
                            ui.label(
                                egui::RichText::new("Tray icon off · Close quits app")
                                    .size(10.5)
                                    .color(palette.text_muted),
                            );
                        }
                    });
            });

        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(palette.canvas_bg)
                    .inner_margin(Margin::same(18)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading(
                        egui::RichText::new(self.active_tool.title())
                            .size(20.0)
                            .strong()
                            .color(palette.text_primary),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.small_button("Clear").clicked() {
                            match self.active_tool {
                                ToolTab::InternetCheck => self.internet_check.clear(),
                                ToolTab::Ipv6Diagnostics => self.ipv6_check.clear(),
                                ToolTab::PathTroubleshoot => self.path_troubleshoot.clear(),
                                ToolTab::Ping => self.ping.clear(),
                                ToolTab::Traceroute => self.traceroute.clear(),
                                ToolTab::VisualTraceroute => self.visual_traceroute.clear(),
                                ToolTab::Mtr => self.mtr.clear(),
                                ToolTab::SpeedTest => self.speedtest.clear(),
                                ToolTab::Iperf3 => self.iperf3.clear(),
                                ToolTab::LanScanner => self.lan_scanner.clear(),
                                ToolTab::PortScan => self.port_scan.clear(),
                                ToolTab::SubnetCalculator => {
                                    self.subnet_calc = SubnetCalcState::default()
                                }
                                ToolTab::DnsLookup => self.dns.clear(),
                                ToolTab::DnsPropagation => self.dns_propagation.clear(),
                                ToolTab::SslCertificate => self.tls.clear(),
                            }
                        }
                        if matches!(
                            self.active_tool,
                            ToolTab::LanScanner
                                | ToolTab::PortScan
                                | ToolTab::DnsPropagation
                                | ToolTab::Ipv6Diagnostics
                        ) && ui.small_button("Copy Output").clicked()
                        {
                            let txt = match self.active_tool {
                                ToolTab::LanScanner => self.lan_scanner.copy_text(),
                                ToolTab::PortScan => self.port_scan.copy_text(),
                                ToolTab::DnsPropagation => self.dns_propagation.copy_text(),
                                ToolTab::Ipv6Diagnostics => self.ipv6_check.copy_text(),
                                _ => String::new(),
                            };
                            ui.ctx().copy_text(txt);
                        }
                    });
                });

                ui.add_space(10.0);

                match self.active_tool {
                    ToolTab::InternetCheck => {
                        let jump = views::internet_check::render(
                            ui,
                            &palette,
                            &mut self.internet_check,
                            self.public_status.as_ref(),
                            &self.rt,
                        );
                        if jump {
                            self.active_tool = ToolTab::PathTroubleshoot;
                            self.path_troubleshoot.start(&self.rt, ui.ctx());
                        }
                    }
                    ToolTab::Ipv6Diagnostics => views::ipv6_check::render(
                        ui,
                        &palette,
                        &mut self.ipv6_check,
                        &self.rt,
                    ),
                    ToolTab::PathTroubleshoot => views::path_troubleshoot::render(
                        ui,
                        &palette,
                        &mut self.path_troubleshoot,
                        &mut self.history,
                        &self.rt,
                    ),
                    ToolTab::Ping => views::ping::render(
                        ui,
                        &palette,
                        &mut self.ping,
                        &mut self.history,
                        &self.rt,
                    ),
                    ToolTab::Traceroute => views::traceroute::render(
                        ui,
                        &palette,
                        &mut self.traceroute,
                        &mut self.history,
                        &self.rt,
                    ),
                    ToolTab::VisualTraceroute => views::visual_traceroute::render(
                        ui,
                        &palette,
                        &mut self.visual_traceroute,
                        &mut self.history,
                        &self.rt,
                    ),
                    ToolTab::Mtr => views::mtr::render(
                        ui,
                        &palette,
                        &mut self.mtr,
                        &mut self.history,
                        &self.rt,
                    ),
                    ToolTab::SpeedTest => views::speedtest::render(
                        ui,
                        &palette,
                        &mut self.speedtest,
                        &self.history,
                        &self.rt,
                    ),
                    ToolTab::Iperf3 => views::iperf3::render(
                        ui,
                        &palette,
                        &mut self.iperf3,
                        &mut self.history,
                        &self.rt,
                    ),
                    ToolTab::LanScanner => {
                        if let Some(action) = views::lan_scanner::render(
                            ui,
                            &palette,
                            &mut self.lan_scanner,
                            &mut self.history,
                            &self.rt,
                        ) {
                            match action {
                                LanJumpAction::PingHost(host) => {
                                    self.ping.host = host;
                                    self.active_tool = ToolTab::Ping;
                                    self.ping.start(&self.rt, ui.ctx());
                                }
                                LanJumpAction::PortScanHost(host) => {
                                    self.port_scan.host = host;
                                    self.active_tool = ToolTab::PortScan;
                                    self.port_scan.start(&self.rt, ui.ctx());
                                }
                            }
                        }
                    }
                    ToolTab::PortScan => views::port_scan::render(
                        ui,
                        &palette,
                        &mut self.port_scan,
                        &mut self.history,
                        &self.rt,
                    ),
                    ToolTab::SubnetCalculator => {
                        views::subnet_calc::render(ui, &palette, &mut self.subnet_calc)
                    }
                    ToolTab::DnsLookup => {
                        if let Some(DnsJumpAction::CheckPropagation { query, record_type }) =
                            views::dns::render(
                                ui,
                                &palette,
                                &mut self.dns,
                                &mut self.history,
                                &self.rt,
                            )
                        {
                            self.dns_propagation.query = query;
                            self.dns_propagation.record_type = record_type;
                            self.active_tool = ToolTab::DnsPropagation;
                            self.dns_propagation.start(&self.rt, ui.ctx());
                        }
                    }
                    ToolTab::DnsPropagation => views::dns_propagation::render(
                        ui,
                        &palette,
                        &mut self.dns_propagation,
                        &mut self.history,
                        &self.rt,
                    ),
                    ToolTab::SslCertificate => views::tls::render(
                        ui,
                        &palette,
                        &mut self.tls,
                        &mut self.history,
                        &self.rt,
                    ),
                }
            });
    }

    fn nav_group_header(ui: &mut egui::Ui, palette: &AppPalette, title: &str, is_first: bool) {
        if !is_first {
            ui.add_space(6.0);
        }
        let (rect, _) =
            ui.allocate_exact_size(Vec2::new(ui.available_width(), 20.0), egui::Sense::hover());
        let pill_bg = if palette.dark {
            egui::Color32::from_rgb(42, 45, 55)
        } else {
            egui::Color32::from_rgb(225, 229, 238)
        };
        let title_col = if palette.dark {
            egui::Color32::from_rgb(218, 224, 236)
        } else {
            egui::Color32::from_rgb(38, 48, 64)
        };
        ui.painter()
            .rect_filled(rect, CornerRadius::same(5), pill_bg);
        let bar_rect = egui::Rect::from_min_size(
            egui::pos2(rect.left() + 5.0, rect.center().y - 5.0),
            Vec2::new(3.0, 10.0),
        );
        ui.painter()
            .rect_filled(bar_rect, CornerRadius::same(2), palette.accent);
        let job = egui::text::LayoutJob::single_section(
            title.to_string(),
            egui::TextFormat {
                font_id: egui::FontId::proportional(10.5),
                color: title_col,
                extra_letter_spacing: 0.7,
                ..Default::default()
            },
        );
        let galley = ui.painter().layout_job(job);
        let text_pos = egui::pos2(rect.left() + 13.0, rect.center().y - galley.size().y * 0.5);
        ui.painter().galley(text_pos, galley, title_col);
        ui.add_space(2.0);
    }

    fn nav_button(
        &mut self,
        ui: &mut egui::Ui,
        palette: &AppPalette,
        tab: ToolTab,
        active_task: bool,
    ) {
        let (rect, resp) =
            ui.allocate_exact_size(Vec2::new(ui.available_width(), 24.0), egui::Sense::click());
        let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
        let selected = self.active_tool == tab;
        let fill = if selected {
            palette.selected_bg
        } else if resp.hovered() {
            if palette.dark {
                egui::Color32::from_rgba_unmultiplied(255, 255, 255, 16)
            } else {
                egui::Color32::from_rgba_unmultiplied(15, 23, 42, 14)
            }
        } else {
            egui::Color32::TRANSPARENT
        };
        if fill != egui::Color32::TRANSPARENT {
            ui.painter().rect_filled(rect, CornerRadius::same(6), fill);
        }

        let fg = if selected {
            egui::Color32::WHITE
        } else {
            palette.text_primary
        };
        let galley = ui.painter().layout_no_wrap(
            tab.title().to_string(),
            egui::FontId::proportional(13.0),
            fg,
        );
        let text_pos = egui::pos2(rect.left() + 14.0, rect.center().y - galley.size().y * 0.5);
        ui.painter().galley(text_pos, galley, fg);

        if active_task {
            let dot_col = if selected {
                egui::Color32::WHITE
            } else {
                palette.ok
            };
            ui.painter()
                .circle_filled(egui::pos2(rect.right() - 10.0, rect.center().y), 3.5, dot_col);
        }

        if resp.clicked() {
            self.active_tool = tab;
        }
    }

    fn drive_screenshots(&mut self, ctx: &egui::Context) {
        let Some(mut driver) = self.screenshot_driver.take() else {
            return;
        };

        const STEPS: [(ToolTab, &str, bool); 17] = [
            (ToolTab::InternetCheck, "01-internet-check-light.png", false),
            (ToolTab::PathTroubleshoot, "02-path-troubleshoot.png", false),
            (ToolTab::VisualTraceroute, "03-visual-traceroute.png", false),
            (ToolTab::Ping, "04-ping.png", false),
            (ToolTab::Mtr, "05-mtr.png", false),
            (ToolTab::SpeedTest, "06-speedtest.png", false),
            (ToolTab::Iperf3, "07-iperf3.png", false),
            (ToolTab::DnsLookup, "08-dns-lookup.png", false),
            (ToolTab::SslCertificate, "09-ssl-certificate.png", false),
            (ToolTab::VisualTraceroute, "10-visual-traceroute-dark.png", true),
            (
                ToolTab::VisualTraceroute,
                "11-visual-traceroute-turkiye-zoom.png",
                false,
            ),
            (ToolTab::LanScanner, "12-lan-scanner.png", false),
            (ToolTab::PortScan, "13-port-scan.png", false),
            (ToolTab::SubnetCalculator, "14-subnet-calculator.png", false),
            (ToolTab::DnsPropagation, "15-dns-propagation.png", false),
            (ToolTab::Ipv6Diagnostics, "16-ipv6-diagnostics.png", false),
            (ToolTab::Ipv6Diagnostics, "17-ipv6-diagnostics-dark.png", true),
        ];

        if driver.step >= STEPS.len() {
            info!(
                "Screenshot QA finished ({} screens saved to {})",
                STEPS.len(),
                driver.dir.display()
            );
            self.should_quit = true;
            ctx.send_viewport_cmd(ViewportCommand::Close);
            return;
        }

        let (tab, filename, dark) = STEPS[driver.step];

        match driver.phase {
            ShotPhase::StartStep => {
                self.active_tool = tab;
                self.dark_mode = dark;
                driver.started_at = Instant::now();
                match driver.step {
                    0 => self.internet_check.start(&self.rt, ctx),
                    1 => self.path_troubleshoot.start(&self.rt, ctx),
                    2 => self.visual_traceroute.start(&self.rt, ctx),
                    3 => self.ping.start(&self.rt, ctx),
                    4 => self.mtr.start(&self.rt, ctx),
                    5 => self.speedtest.start(&self.rt, ctx),
                    7 => self.dns.start(&self.rt, ctx),
                    8 => self.tls.start(&self.rt, ctx),
                    9 => self.visual_traceroute.fit_route(),
                    10 => self.visual_traceroute.focus_turkiye(),
                    11 => self.lan_scanner.start(&self.rt, ctx),
                    12 => {
                        let gw = netscope_core::net_info::get_local_network_info()
                            .ok()
                            .and_then(|i| i.gateway_ip)
                            .map(|ip| ip.to_string())
                            .unwrap_or_else(|| "127.0.0.1".into());
                        self.port_scan.host = gw;
                        self.port_scan.start(&self.rt, ctx);
                    }
                    14 => self.dns_propagation.start(&self.rt, ctx),
                    15 => self.ipv6_check.start(&self.rt, ctx),
                    _ => {}
                }
                driver.phase = ShotPhase::WaitData;
            }
            ShotPhase::WaitData => {
                let elapsed = driver.started_at.elapsed();
                let ready = match driver.step {
                    0 => {
                        (!self.internet_check.running && self.public_status.is_some())
                            || elapsed >= Duration::from_secs(9)
                    }
                    1 => !self.path_troubleshoot.running || elapsed >= Duration::from_secs(9),
                    2 => {
                        (!self.visual_traceroute.running && elapsed >= Duration::from_millis(800))
                            || elapsed >= Duration::from_secs(10)
                    }
                    3 => elapsed >= Duration::from_secs(3),
                    4 => elapsed >= Duration::from_secs(3),
                    5 => !self.speedtest.running || elapsed >= Duration::from_secs(24),
                    7 => !self.dns.running || elapsed >= Duration::from_secs(4),
                    8 => !self.tls.running || elapsed >= Duration::from_secs(5),
                    11 => !self.lan_scanner.running || elapsed >= Duration::from_secs(12),
                    12 => !self.port_scan.running || elapsed >= Duration::from_secs(6),
                    14 => !self.dns_propagation.running || elapsed >= Duration::from_secs(7),
                    15 => !self.ipv6_check.running || elapsed >= Duration::from_secs(10),
                    _ => elapsed >= Duration::from_millis(250),
                };
                if ready {
                    match driver.step {
                        2 => self.visual_traceroute.fit_route(),
                        3 => self.ping.stop(),
                        4 => self.mtr.stop(),
                        5 => self.speedtest.stop(),
                        11 => self.lan_scanner.stop(),
                        12 => self.port_scan.stop(),
                        14 => self.dns_propagation.stop(),
                        15 => self.ipv6_check.stop(),
                        _ => {}
                    }
                    driver.phase = ShotPhase::SettleFrames(3);
                }
            }
            ShotPhase::SettleFrames(rem) => {
                if rem > 0 {
                    driver.phase = ShotPhase::SettleFrames(rem - 1);
                    ctx.request_repaint();
                } else {
                    let done = Arc::new(AtomicBool::new(false));
                    let done_cb = done.clone();
                    let out_path = driver.dir.join(filename);
                    let ctx_cb = ctx.clone();
                    ctx.send_viewport_cmd(ViewportCommand::Screenshot(
                        egui::ScreenshotCallback::new(move |img| {
                            if let Err(e) = save_color_image_png(&out_path, &img) {
                                error!("Failed writing screenshot {}: {e}", out_path.display());
                            } else {
                                info!("Saved screenshot: {}", out_path.display());
                            }
                            done_cb.store(true, Ordering::SeqCst);
                            ctx_cb.request_repaint();
                        }),
                    ));
                    driver.started_at = Instant::now();
                    driver.phase = ShotPhase::WaitCapture(done);
                }
            }
            ShotPhase::WaitCapture(ref done) => {
                if done.load(Ordering::SeqCst) || driver.started_at.elapsed() >= Duration::from_secs(4)
                {
                    driver.step += 1;
                    driver.phase = ShotPhase::StartStep;
                }
            }
        }

        self.screenshot_driver = Some(driver);
    }
}

fn save_color_image_png(path: &Path, img: &egui::ColorImage) -> std::io::Result<()> {
    let file = File::create(path)?;
    let w = BufWriter::new(file);
    let mut encoder = png::Encoder::new(w, img.width() as u32, img.height() as u32);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder
        .write_header()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    writer
        .write_image_data(img.as_raw())
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod ui_e2e_tests {
    use super::*;
    use crate::views::dns::DnsViewMode;
    use crate::views::visual_traceroute::VisualHop;
    use chrono::Utc;
    use netscope_core::dns::{DnsLookupResult, DnsRecordRow, DnsRecordType};
    use netscope_core::geoip::GeoLocation;
    use netscope_core::history::SpeedTestRecord;
    use netscope_core::icmp::TracerouteHop;
    use netscope_core::internet_check::{StageHealth, VerdictSeverity};
    use netscope_core::ipv6_check::{
        CheckStatus, DualStackComparison, EndpointProbe, Ipv6AddressEntry, Ipv6AddressScope,
        Ipv6CheckReport, Ipv6ChecklistItem, Ipv6Stage, Ipv6StageKind, Ipv6Verdict,
        LocalIpv6Inventory, MtuReport, RaRouterInfo,
    };
    use netscope_core::net_info::LinkType;
    use netscope_core::speedtest::{BufferbloatGrade, SpeedTestResult};
    use netscope_core::stats::compute_latency_stats;
    use std::net::{IpAddr, Ipv4Addr};

    fn run_frame(ctx: &egui::Context, app: &mut NetScopeApp, events: Vec<egui::Event>) -> egui::FullOutput {
        ctx.set_theme(if app.dark_mode {
            egui::ThemePreference::Dark
        } else {
            egui::ThemePreference::Light
        });
        let raw = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1180.0, 760.0),
            )),
            events,
            ..Default::default()
        };
        let mut out = ctx.run_ui(raw, |ui| {
            app.render_ui(ui);
        });
        out.textures_delta.clear();
        out
    }

    fn collect_text_shapes(shape: &egui::epaint::Shape, out: &mut Vec<(String, egui::Pos2)>) {
        match shape {
            egui::epaint::Shape::Text(ts) => {
                let center = ts.pos + ts.galley.size() * 0.5;
                out.push((ts.galley.text().to_string(), center));
            }
            egui::epaint::Shape::Vec(children) => {
                for ch in children {
                    collect_text_shapes(ch, out);
                }
            }
            _ => {}
        }
    }

    fn all_rendered_texts(output: &egui::FullOutput) -> Vec<(String, egui::Pos2)> {
        let mut texts = Vec::new();
        for cs in &output.shapes {
            collect_text_shapes(&cs.shape, &mut texts);
        }
        texts
    }

    fn find_text_center(output: &egui::FullOutput, needle: &str) -> Option<egui::Pos2> {
        all_rendered_texts(output)
            .into_iter()
            .find(|(txt, _)| txt == needle)
            .map(|(_, pos)| pos)
    }

    fn has_rendered_text(output: &egui::FullOutput, needle_substr: &str) -> bool {
        all_rendered_texts(output)
            .into_iter()
            .any(|(txt, _)| txt.contains(needle_substr))
    }

    fn click_at(ctx: &egui::Context, app: &mut NetScopeApp, pos: egui::Pos2) -> egui::FullOutput {
        let _ = run_frame(ctx, app, vec![egui::Event::PointerMoved(pos)]);
        let _ = run_frame(
            ctx,
            app,
            vec![egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::NONE,
            }],
        );
        let _ = run_frame(
            ctx,
            app,
            vec![egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }],
        );
        // Immediate-mode widgets mutate state during the release frame; render 1 settle frame to observe updated UI.
        run_frame(ctx, app, Vec::new())
    }

    fn assert_no_nan_shapes(shape: &egui::epaint::Shape) {
        match shape {
            egui::epaint::Shape::Text(ts) => {
                assert!(ts.pos.x.is_finite() && ts.pos.y.is_finite());
            }
            egui::epaint::Shape::Rect(rs) => {
                assert!(rs.rect.min.x.is_finite() && rs.rect.max.y.is_finite());
            }
            egui::epaint::Shape::Circle(cs) => {
                assert!(cs.center.x.is_finite() && cs.radius.is_finite());
            }
            egui::epaint::Shape::Vec(children) => {
                for ch in children {
                    assert_no_nan_shapes(ch);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn e2e_all_15_tabs_render_cleanly_light_and_dark() {
        let tabs = [
            ToolTab::InternetCheck,
            ToolTab::Ipv6Diagnostics,
            ToolTab::PathTroubleshoot,
            ToolTab::Ping,
            ToolTab::Traceroute,
            ToolTab::VisualTraceroute,
            ToolTab::Mtr,
            ToolTab::SpeedTest,
            ToolTab::Iperf3,
            ToolTab::LanScanner,
            ToolTab::PortScan,
            ToolTab::SubnetCalculator,
            ToolTab::DnsLookup,
            ToolTab::DnsPropagation,
            ToolTab::SslCertificate,
        ];
        let ctx = egui::Context::default();
        let mut app = NetScopeApp::new_headless_for_test();

        for dark in [false, true] {
            app.dark_mode = dark;
            for tab in tabs {
                app.active_tool = tab;
                let out = run_frame(&ctx, &mut app, Vec::new());
                assert!(
                    out.shapes.len() > 5,
                    "tab {:?} (dark={dark}) rendered unexpectedly few shapes",
                    tab
                );
                for cs in &out.shapes {
                    assert_no_nan_shapes(&cs.shape);
                }
                assert!(
                    has_rendered_text(&out, tab.title()),
                    "tab heading '{}' missing",
                    tab.title()
                );
            }
        }
    }

    #[test]
    fn e2e_sidebar_click_navigation_and_theme_toggle() {
        let ctx = egui::Context::default();
        let mut app = NetScopeApp::new_headless_for_test();
        let out = run_frame(&ctx, &mut app, Vec::new());

        assert!(has_rendered_text(&out, "HEALTH CHECKS"));
        assert!(has_rendered_text(&out, "PATH & PROBES"));
        assert!(has_rendered_text(&out, "BANDWIDTH"));
        assert!(has_rendered_text(&out, "NETWORK TOOLS"));
        assert!(has_rendered_text(&out, "DNS & DOMAINS"));

        let dark_pos = find_text_center(&out, "Dark").expect("Dark button must be visible");
        let out = click_at(&ctx, &mut app, dark_pos);
        assert!(app.dark_mode, "clicking Dark button must enable dark_mode");
        assert!(has_rendered_text(&out, "Light"));

        let dns_pos =
            find_text_center(&out, "DNS Lookup").expect("DNS Lookup nav item must be visible");
        let out = click_at(&ctx, &mut app, dns_pos);
        assert_eq!(app.active_tool, ToolTab::DnsLookup);

        let v6_pos = find_text_center(&out, "IPv6 Check")
            .expect("IPv6 Check nav item must be visible");
        let _ = click_at(&ctx, &mut app, v6_pos);
        assert_eq!(app.active_tool, ToolTab::Ipv6Diagnostics);
    }

    #[test]
    fn e2e_menu_bar_tray_toggle_and_close_behavior() {
        let ctx = egui::Context::default();
        let mut app = NetScopeApp::new_headless_for_test();
        assert!(app.history.menu_bar_enabled);

        let out = run_frame(&ctx, &mut app, Vec::new());
        let tray_on = find_text_center(&out, "Tray: On").expect("Tray: On button must be visible");
        let out = click_at(&ctx, &mut app, tray_on);
        assert!(!app.history.menu_bar_enabled);
        assert!(app.tray.is_none());
        assert!(has_rendered_text(&out, "Tray: Off"));
        assert!(has_rendered_text(&out, "Tray icon off"));

        let tray_off =
            find_text_center(&out, "Tray: Off").expect("Tray: Off button must be visible");
        let out = click_at(&ctx, &mut app, tray_off);
        assert!(app.history.menu_bar_enabled);
        assert!(has_rendered_text(&out, "Tray: On"));
    }

    #[test]
    fn e2e_dns_lookup_table_raw_dig_and_propagation_jump() {
        let ctx = egui::Context::default();
        let mut app = NetScopeApp::new_headless_for_test();
        app.active_tool = ToolTab::DnsLookup;
        app.dns.query = "example.com".into();
        app.dns.record_type = DnsRecordType::A;
        app.dns.result = Some(DnsLookupResult {
            query: "example.com".into(),
            record_type: DnsRecordType::A,
            server_label: "System Default".into(),
            query_time_ms: 12.4,
            records: vec![DnsRecordRow {
                name: "example.com.".into(),
                ttl: 300,
                record_type: "A".into(),
                value: "192.0.2.10".into(),
            }],
            raw_dig_text: "; <<>> NetScope DNS <<>> example.com. A\n;; ANSWER SECTION:\nexample.com. 300 IN A 192.0.2.10".into(),
        });

        let out = run_frame(&ctx, &mut app, Vec::new());
        assert!(has_rendered_text(&out, "300s (5m)"));
        assert!(has_rendered_text(&out, "192.0.2.10"));

        let raw_btn = find_text_center(&out, "Raw dig").expect("Raw dig toggle must be visible");
        let out = click_at(&ctx, &mut app, raw_btn);
        assert_eq!(app.dns.view_mode, DnsViewMode::RawDig);
        assert!(has_rendered_text(&out, "ANSWER SECTION"));

        let jump_btn = find_text_center(&out, "Check Propagation ->")
            .expect("Check Propagation -> button must be visible");
        let _ = click_at(&ctx, &mut app, jump_btn);
        assert_eq!(app.active_tool, ToolTab::DnsPropagation);
        assert_eq!(app.dns_propagation.query, "example.com");
        assert_eq!(app.dns_propagation.record_type, DnsRecordType::A);
        app.dns_propagation.stop();
    }

    #[test]
    fn e2e_speedtest_and_bufferbloat_panel_renders_all_grades() {
        let ctx = egui::Context::default();
        let mut app = NetScopeApp::new_headless_for_test();
        app.active_tool = ToolTab::SpeedTest;
        app.speedtest.dl_samples = vec![[1.0, 92.0], [2.0, 96.0], [3.0, 95.0]];
        app.speedtest.ul_samples = vec![[1.0, 45.0], [2.0, 48.0], [3.0, 47.0]];
        app.speedtest.dl_rtt_samples = vec![[1.0, 18.0], [2.0, 20.0]];
        app.speedtest.ul_rtt_samples = vec![[1.0, 19.0], [2.0, 22.0]];
        app.speedtest.dl_peak_mbps = Some(96.0);
        app.speedtest.ul_peak_mbps = Some(48.0);
        app.history.record_speedtest(SpeedTestRecord {
            timestamp: Utc::now(),
            download_mbps: 94.5,
            upload_mbps: 46.8,
            idle_median_ms: 15.0,
            loaded_dl_median_ms: Some(19.0),
            loaded_ul_median_ms: Some(21.0),
            bufferbloat_grade: BufferbloatGrade::APlus,
        });

        for (grade, dl_med, ul_med) in [
            (BufferbloatGrade::APlus, 18.0, 19.0),
            (BufferbloatGrade::C, 42.0, 65.0),
            (BufferbloatGrade::F, 180.0, 240.0),
        ] {
            app.speedtest.result = Some(SpeedTestResult {
                timestamp: Utc::now(),
                download_mbps: 94.5,
                upload_mbps: 46.8,
                unloaded_stats: compute_latency_stats(&[Some(15.0), Some(16.0)]),
                loaded_dl_stats: compute_latency_stats(&[Some(dl_med)]),
                loaded_ul_stats: compute_latency_stats(&[Some(ul_med)]),
                bufferbloat_grade: grade,
            });
            let out = run_frame(&ctx, &mut app, Vec::new());
            assert!(has_rendered_text(&out, "BUFFERBLOAT ANALYSIS"));
            assert!(has_rendered_text(&out, grade.label()));
            assert!(has_rendered_text(&out, "Video Calls:"));
        }
    }

    #[test]
    fn e2e_ipv6_diagnostics_renders_healthy_and_blackhole_reports() {
        let ctx = egui::Context::default();
        let mut app = NetScopeApp::new_headless_for_test();
        app.active_tool = ToolTab::Ipv6Diagnostics;

        let inv = LocalIpv6Inventory {
            interface_name: "en0".into(),
            interface_index: 1,
            link_type: LinkType::WiFi,
            link_mtu: Some(1500),
            nd6_options: Some("201<PERFORMNUD,DAD>".into()),
            addresses: vec![
                Ipv6AddressEntry {
                    addr: "2001:db8:40::10".parse().unwrap(),
                    prefix_len: 64,
                    scope: Ipv6AddressScope::GlobalUnicast,
                    is_slaac: true,
                    is_temporary: true,
                    is_secured: false,
                    is_deprecated: false,
                    is_tentative: false,
                    is_duplicated: false,
                    is_permanent: false,
                },
                Ipv6AddressEntry {
                    addr: "fd00:db8:40::10".parse().unwrap(),
                    prefix_len: 64,
                    scope: Ipv6AddressScope::UniqueLocal,
                    is_slaac: true,
                    is_temporary: false,
                    is_secured: true,
                    is_deprecated: false,
                    is_tentative: false,
                    is_duplicated: false,
                    is_permanent: false,
                },
            ],
            ra_router: RaRouterInfo {
                gateway: Some("fe80::1".parse().unwrap()),
                gateway_display: Some("fe80::1%en0".into()),
                managed_m: false,
                other_o: true,
                preference: Some("medium".into()),
                expire: Some("25m".into()),
                provisioning_summary: "SLAAC (A=1) + Stateless DHCPv6 (O=1, M=0)".into(),
            },
            ra_prefixes: Vec::new(),
            ipv6_dns_servers: vec!["fd00:db8:20::53".parse().unwrap()],
            has_link_local: true,
            has_gua: true,
            has_ula: true,
            has_privacy_temp: true,
            has_dad_issue: false,
        };

        let stages = vec![
            Ipv6Stage {
                kind: Ipv6StageKind::LocalStack,
                title: "Local Stack".into(),
                short_badge: "GUA /64".into(),
                health: StageHealth::Ok,
                detail: "en0".into(),
                latency_ms: None,
            },
            Ipv6Stage {
                kind: Ipv6StageKind::Router,
                title: "Router (NDP)".into(),
                short_badge: "3.2 ms".into(),
                health: StageHealth::Ok,
                detail: "fe80::1%en0".into(),
                latency_ms: Some(3.2),
            },
            Ipv6Stage {
                kind: Ipv6StageKind::IcmpV6,
                title: "ICMPv6".into(),
                short_badge: "68 ms".into(),
                health: StageHealth::Ok,
                detail: "0% loss".into(),
                latency_ms: Some(68.0),
            },
            Ipv6Stage {
                kind: Ipv6StageKind::DnsV6,
                title: "DNS v6".into(),
                short_badge: "AAAA + v6".into(),
                health: StageHealth::Ok,
                detail: "OK".into(),
                latency_ms: Some(15.0),
            },
            Ipv6Stage {
                kind: Ipv6StageKind::HttpsV6,
                title: "HTTPS v6".into(),
                short_badge: "AMS · 72ms".into(),
                health: StageHealth::Ok,
                detail: "OK".into(),
                latency_ms: Some(72.0),
            },
            Ipv6Stage {
                kind: Ipv6StageKind::Pmtud,
                title: "PMTUD".into(),
                short_badge: "1484 B (PMTUD)".into(),
                health: StageHealth::Ok,
                detail: "32 KB OK".into(),
                latency_ms: Some(180.0),
            },
        ];

        app.ipv6_check.current = Some(Ipv6CheckReport {
            checked_at: Utc::now(),
            inventory: inv.clone(),
            stages: stages.clone(),
            dual_stack: DualStackComparison {
                ipv6: EndpointProbe {
                    ip: Some(IpAddr::V6("2001:db8:40::10".parse().unwrap())),
                    colo: Some("AMS".into()),
                    http_version: Some("HTTP/2.0".into()),
                    latency_ms: Some(72.0),
                    ok: true,
                    error: None,
                },
                ipv4: EndpointProbe {
                    ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
                    colo: Some("IST".into()),
                    http_version: Some("HTTP/2.0".into()),
                    latency_ms: Some(31.0),
                    ok: true,
                    error: None,
                },
                delta_ms: Some(41.0),
                happy_eyeballs_winner: "IPv6 Preferred (RFC 8305)".into(),
                peering_note: "PoP mismatch: IPv6 via AMS vs IPv4 via IST (+41 ms)".into(),
            },
            mtu: MtuReport {
                link_mtu: Some(1500),
                path_mtu: Some(1484),
                large_frame_ok: true,
                large_frame_bytes: 32768,
                large_frame_ms: Some(180.0),
                blackhole_suspected: false,
                status_summary: "Path MTU 1484 B (link 1500 B)".into(),
            },
            checklist: vec![Ipv6ChecklistItem {
                name: "Global Unicast Address (GUA 2000::/3)".into(),
                status: CheckStatus::Pass,
                evidence: "2001:db8:40::10/64".into(),
            }],
            verdict: Ipv6Verdict {
                severity: VerdictSeverity::Ok,
                score: 9,
                max_score: 10,
                headline: "IPv6 Operational (Minor Advisories)".into(),
                explanation: "Core checks passed".into(),
            },
            nat66_detected: Some(false),
            dns_aaaa_ok: true,
            dns_v6_transport_ok: true,
        });

        let out = run_frame(&ctx, &mut app, Vec::new());
        assert!(has_rendered_text(&out, "IPv6 Operational"));
        assert!(has_rendered_text(&out, "Path: 1484 B"));

        // Now flip to PMTUD Blackhole scenario
        if let Some(ref mut rep) = app.ipv6_check.current {
            rep.mtu.blackhole_suspected = true;
            rep.mtu.large_frame_ok = false;
            rep.verdict.severity = VerdictSeverity::Error;
            rep.verdict.headline = "IPv6 PMTUD Blackhole Detected".into();
        }
        let out = run_frame(&ctx, &mut app, Vec::new());
        assert!(has_rendered_text(&out, "PMTUD Blackhole!"));
    }

    #[test]
    fn e2e_subnet_calculator_ipv4_split_and_ipv6() {
        let ctx = egui::Context::default();
        let mut app = NetScopeApp::new_headless_for_test();
        app.active_tool = ToolTab::SubnetCalculator;
        app.subnet_calc.input = "192.0.2.0/24".into();
        app.subnet_calc.split_target_prefix = 26;
        app.subnet_calc.recompute();

        let out = run_frame(&ctx, &mut app, Vec::new());
        assert!(has_rendered_text(&out, "192.0.2.255"));
        assert!(has_rendered_text(&out, "192.0.2.64/26"));

        app.subnet_calc.input = "2001:db8::/48".into();
        app.subnet_calc.recompute();
        let out = run_frame(&ctx, &mut app, Vec::new());
        assert!(has_rendered_text(&out, "2001:db8::"));
    }

    #[test]
    fn e2e_visual_traceroute_hop0_and_turkiye_zoom() {
        let ctx = egui::Context::default();
        let mut app = NetScopeApp::new_headless_for_test();
        app.active_tool = ToolTab::VisualTraceroute;
        app.visual_traceroute.origin_geo = Some(GeoLocation {
            ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
            is_private: false,
            is_anycast: false,
            anycast_pop: None,
            registry_place: None,
            label: "Public IP".into(),
            city: Some("Ereğli, Zonguldak".into()),
            country: Some("Türkiye".into()),
            country_code: Some("TR".into()),
            isp: Some("Example ISP".into()),
            asn: Some(64512),
            lat: Some(41.28261),
            lon: Some(31.41806),
        });
        app.visual_traceroute.hops = vec![
            VisualHop {
                trace: TracerouteHop {
                    hop: 1,
                    ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
                    hostname: None,
                    probe_rtts_ms: vec![Some(3.2)],
                    avg_ms: Some(3.2),
                    reached_target: false,
                },
                geo: Some(GeoLocation {
                    ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                    is_private: false,
                    is_anycast: false,
                    anycast_pop: None,
                    registry_place: None,
                    label: "Public IP".into(),
                    city: Some("Ankara".into()),
                    country: Some("Türkiye".into()),
                    country_code: Some("TR".into()),
                    isp: Some("Example ISP".into()),
                    asn: Some(64512),
                    lat: Some(39.9334),
                    lon: Some(32.8597),
                }),
            },
            VisualHop {
                trace: TracerouteHop {
                    hop: 2,
                    ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 50))),
                    hostname: Some("one.one.one.one".into()),
                    probe_rtts_ms: vec![Some(28.0)],
                    avg_ms: Some(28.0),
                    reached_target: true,
                },
                geo: Some(GeoLocation {
                    ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 50)),
                    is_private: false,
                    is_anycast: true,
                    anycast_pop: Some("IST".into()),
                    registry_place: None,
                    label: "Public IP".into(),
                    city: Some("Istanbul".into()),
                    country: Some("Türkiye".into()),
                    country_code: Some("TR".into()),
                    isp: Some("Cloudflare, Inc.".into()),
                    asn: Some(13335),
                    lat: Some(41.0082),
                    lon: Some(28.9784),
                }),
            },
        ];

        app.visual_traceroute.fit_route();
        let out = run_frame(&ctx, &mut app, Vec::new());
        assert!(has_rendered_text(&out, "Ereğli"));

        app.visual_traceroute.focus_turkiye();
        app.dark_mode = true;
        let out = run_frame(&ctx, &mut app, Vec::new());
        assert!(out.shapes.len() > 20);
    }
}
