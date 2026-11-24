use crate::theme::{AppPalette, section_label, status_pill};
use crate::tray::{TrayAction, TrayController};
use crate::views;
use crate::views::dns::DnsState;
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
            Self::Ipv6Diagnostics => "IPv6 Diagnostics",
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
        let tray = if screenshot_dir.is_some() {
            None
        } else {
            TrayController::try_new()
        };
        let history = PersistedState::load();
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
        };

        app.trigger_status_refresh(&cc.egui_ctx);
        app
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
                let nav_max_h = (ui.available_height() - 126.0).max(160.0);
                egui::ScrollArea::vertical()
                    .id_salt("netscope_nav_scroll")
                    .auto_shrink([false, true])
                    .max_height(nav_max_h)
                    .show(ui, |ui| {
                        section_label(ui, &palette, "DIAGNOSTICS");
                        ui.add_space(4.0);
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
                        self.nav_button(ui, &palette, ToolTab::SpeedTest, self.speedtest.running);
                        self.nav_button(ui, &palette, ToolTab::Iperf3, self.iperf3.running);

                        ui.add_space(10.0);
                        section_label(ui, &palette, "NETWORK TOOLS");
                        ui.add_space(4.0);
                        self.nav_button(
                            ui,
                            &palette,
                            ToolTab::LanScanner,
                            self.lan_scanner.running,
                        );
                        self.nav_button(ui, &palette, ToolTab::PortScan, self.port_scan.running);
                        self.nav_button(ui, &palette, ToolTab::SubnetCalculator, false);

                        ui.add_space(10.0);
                        section_label(ui, &palette, "DNS & DOMAINS");
                        ui.add_space(4.0);
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
                let monitor_card_h = 116.0;
                let push_down = (ui.available_height() - monitor_card_h).max(12.0);
                ui.add_space(push_down);

                palette
                    .card_frame()
                    .inner_margin(Margin::same(10))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            section_label(ui, &palette, "MENU BAR MONITOR");
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
                    ToolTab::DnsLookup => views::dns::render(
                        ui,
                        &palette,
                        &mut self.dns,
                        &mut self.history,
                        &self.rt,
                    ),
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
}

impl NetScopeApp {
    fn nav_button(
        &mut self,
        ui: &mut egui::Ui,
        palette: &AppPalette,
        tab: ToolTab,
        active_task: bool,
    ) {
        let selected = self.active_tool == tab;
        let fill = if selected {
            palette.selected_bg
        } else {
            egui::Color32::TRANSPARENT
        };
        let fg = if selected {
            egui::Color32::WHITE
        } else {
            palette.text_primary
        };

        let label = if active_task {
            format!("{}  •", tab.title())
        } else {
            tab.title().to_string()
        };

        let btn = egui::Button::new(egui::RichText::new(label).size(13.0).color(fg))
            .fill(fill)
            .frame(selected)
            .corner_radius(CornerRadius::same(7))
            .min_size(Vec2::new(ui.available_width(), 27.0));

        if ui.add(btn).clicked() {
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
