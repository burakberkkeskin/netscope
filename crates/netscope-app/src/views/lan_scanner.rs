use crate::theme::{AppPalette, section_label, status_pill};
use egui::{Align, Layout, Sense, Stroke, Ui, vec2};
use egui_extras::{Column, TableBuilder};
use netscope_core::CancelToken;
use netscope_core::history::PersistedState;
use netscope_core::lan_scanner::{LanDevice, LanScanEvent, default_lan_cidr, run_lan_scan};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

pub enum LanJumpAction {
    PingHost(String),
    PortScanHost(String),
}

pub struct LanScannerState {
    pub cidr: String,
    pub filter: String,
    pub running: bool,
    pub completed: usize,
    pub total: usize,
    pub devices: Vec<LanDevice>,
    pub selected_ip: Option<Ipv4Addr>,
    pub guard_enabled: bool,
    pub rescan_interval_mins: u16, // 0 = Off, 5, 15, 30
    pub last_scan_time: Option<Instant>,
    pub last_scan_clock: Option<String>,
    pub newly_joined_keys: HashSet<String>,
    pub is_initial_baseline: bool,
    pub error: Option<String>,
    cancel: Option<CancelToken>,
    rx: Option<mpsc::UnboundedReceiver<LanScanEvent>>,
}

impl Default for LanScannerState {
    fn default() -> Self {
        Self {
            cidr: default_lan_cidr(),
            filter: String::new(),
            running: false,
            completed: 0,
            total: 0,
            devices: Vec::new(),
            selected_ip: None,
            guard_enabled: true,
            rescan_interval_mins: 15,
            last_scan_time: None,
            last_scan_clock: None,
            newly_joined_keys: HashSet::new(),
            is_initial_baseline: false,
            error: None,
            cancel: None,
            rx: None,
        }
    }
}

impl LanScannerState {
    pub fn start(&mut self, rt: &Runtime, ctx: &egui::Context) {
        self.stop();
        self.devices.clear();
        self.newly_joined_keys.clear();
        self.is_initial_baseline = false;
        self.completed = 0;
        self.total = 0;
        self.error = None;

        let cidr = self.cidr.clone();
        let (tx, rx) = mpsc::unbounded_channel();
        let cancel = CancelToken::new();
        self.cancel = Some(cancel.clone());
        self.rx = Some(rx);
        self.running = true;

        let ctx_clone = ctx.clone();
        rt.spawn(async move {
            let (fwd_tx, mut fwd_rx) = mpsc::unbounded_channel();
            let ctx_fwd = ctx_clone.clone();
            let fwd = tokio::spawn(async move {
                while let Some(ev) = fwd_rx.recv().await {
                    let _ = tx.send(ev);
                    ctx_fwd.request_repaint();
                }
            });
            run_lan_scan(cidr, fwd_tx, cancel).await;
            let _ = fwd.await;
            ctx_clone.request_repaint();
        });
    }

    pub fn stop(&mut self) {
        if let Some(c) = self.cancel.take() {
            c.cancel();
        }
        self.running = false;
    }

    pub fn clear(&mut self) {
        self.stop();
        self.devices.clear();
        self.newly_joined_keys.clear();
        self.selected_ip = None;
        self.completed = 0;
        self.total = 0;
        self.error = None;
    }

    pub fn poll(&mut self, history: &mut PersistedState, rt: &Runtime, ctx: &egui::Context) {
        // Periodic Network Guard auto-rescan
        if self.guard_enabled
            && !self.running
            && self.rescan_interval_mins > 0
            && let Some(last) = self.last_scan_time
            && last.elapsed() >= Duration::from_secs(u64::from(self.rescan_interval_mins) * 60)
        {
            self.start(rt, ctx);
        }

        let mut done = false;

        if let Some(rx) = &mut self.rx {
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    LanScanEvent::Started { cidr, total_hosts } => {
                        self.cidr = cidr;
                        self.total = total_hosts;
                        self.is_initial_baseline = history.known_lan_devices.is_empty();
                    }
                    LanScanEvent::Progress { completed, total } => {
                        self.completed = completed;
                        self.total = total;
                    }
                    LanScanEvent::DeviceFound(dev) => {
                        let key = dev.guard_key();
                        if !self.is_initial_baseline && !history.is_known_lan_device(&key) {
                            self.newly_joined_keys.insert(key.clone());
                        } else if self.is_initial_baseline || !self.guard_enabled {
                            history.trust_lan_device(
                                &key,
                                &dev.ip.to_string(),
                                dev.hostname.clone(),
                                dev.vendor.clone(),
                            );
                        }
                        if self.selected_ip.is_none() {
                            self.selected_ip = Some(dev.ip);
                        }
                        self.devices.push(dev);
                        self.devices.sort_by_key(|d| u32::from(d.ip));
                    }
                    LanScanEvent::Finished => {
                        self.running = false;
                        self.last_scan_time = Some(Instant::now());
                        self.last_scan_clock =
                            Some(chrono::Local::now().format("%H:%M:%S").to_string());
                        let _ = history.save();
                        done = true;
                    }
                    LanScanEvent::Error(e) => {
                        self.error = Some(e);
                        self.running = false;
                        done = true;
                    }
                }
            }
        }
        if done {
            self.rx = None;
            self.cancel = None;
        }
    }

    pub fn trust_all_new(&mut self, history: &mut PersistedState) {
        for dev in &self.devices {
            let key = dev.guard_key();
            history.trust_lan_device(
                &key,
                &dev.ip.to_string(),
                dev.hostname.clone(),
                dev.vendor.clone(),
            );
        }
        self.newly_joined_keys.clear();
        let _ = history.save();
    }

    pub fn copy_text(&self) -> String {
        let mut out = format!(
            "NetScope LAN Scan ({}) — {} devices\n",
            self.cidr,
            self.devices.len()
        );
        for d in &self.devices {
            out.push_str(&format!(
                "{:15}  {:18}  {:22}  {:24}  ports: {}\n",
                d.ip,
                d.mac.as_deref().unwrap_or("—"),
                d.vendor.as_deref().unwrap_or("—"),
                d.display_name(),
                d.open_ports_summary()
            ));
        }
        out
    }
}

pub fn render(
    ui: &mut Ui,
    palette: &AppPalette,
    state: &mut LanScannerState,
    history: &mut PersistedState,
    rt: &Runtime,
) -> Option<LanJumpAction> {
    let mut jump_action: Option<LanJumpAction> = None;

    // Row 1: Subnet CIDR input, Local interface quick chip, Filter search, Scan button, Status pill
    ui.horizontal(|ui| {
        ui.label("Subnet:");
        let resp = ui.add(
            egui::TextEdit::singleline(&mut state.cidr)
                .desired_width(135.0)
                .hint_text("192.168.1.0/24"),
        );
        let enter_pressed = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

        let auto_cidr = default_lan_cidr();
        if ui
            .small_button(format!("Auto ({auto_cidr})"))
            .on_hover_text("Use active interface /24 subnet")
            .clicked()
        {
            state.cidr = auto_cidr;
        }

        ui.label("Filter:");
        ui.add(
            egui::TextEdit::singleline(&mut state.filter)
                .desired_width(185.0)
                .hint_text("IP, name, vendor, MAC, port"),
        );

        let btn = if state.running { "Stop" } else { "Scan LAN" };
        if ui.button(btn).clicked() || (!state.running && enter_pressed) {
            if state.running {
                state.stop();
            } else {
                state.start(rt, ui.ctx());
            }
        }

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if state.running {
                status_pill(
                    ui,
                    &format!(
                        "Sweep {}/{} • {} devices",
                        state.completed,
                        state.total,
                        state.devices.len()
                    ),
                    palette.accent,
                    palette.card_subtle_bg,
                );
            } else {
                status_pill(
                    ui,
                    &format!("{} devices found", state.devices.len()),
                    palette.ok,
                    palette.ok_bg,
                );
            }
        });
    });

    ui.add_space(6.0);

    // Row 2: Network Guard Bar (New device alert counter, Trust All button, Rescan interval, Guard toggle)
    palette
        .subtle_card_frame()
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Network Guard").strong().size(12.5));
                let new_cnt = state.newly_joined_keys.len();
                if new_cnt > 0 {
                    status_pill(
                        ui,
                        &format!("{new_cnt} new device(s) joined"),
                        palette.warn,
                        palette.warn_bg,
                    );
                    if ui.small_button("Trust All New").clicked() {
                        state.trust_all_new(history);
                    }
                } else {
                    status_pill(
                        ui,
                        &format!("{} trusted in baseline", history.known_lan_devices.len()),
                        palette.ok,
                        palette.ok_bg,
                    );
                }

                if let Some(ref clk) = state.last_scan_clock {
                    ui.label(
                        egui::RichText::new(format!("Last sweep: {clk}"))
                            .size(11.5)
                            .color(palette.text_muted),
                    );
                }

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.checkbox(&mut state.guard_enabled, "Guard this network");
                    ui.add_space(8.0);
                    for (mins, lbl) in [(30u16, "30m"), (15, "15m"), (5, "5m"), (0, "Off")] {
                        if ui
                            .selectable_label(state.rescan_interval_mins == mins, lbl)
                            .clicked()
                        {
                            state.rescan_interval_mins = mins;
                        }
                    }
                    ui.label(
                        egui::RichText::new("Rescan:")
                            .size(11.5)
                            .color(palette.text_muted),
                    );
                });
            });
        });

    if let Some(ref err) = state.error {
        ui.add_space(6.0);
        status_pill(ui, err, palette.err, palette.err_bg);
    }

    ui.add_space(8.0);

    let filter_low = state.filter.trim().to_ascii_lowercase();
    let filtered: Vec<LanDevice> = state
        .devices
        .iter()
        .filter(|d| {
            if filter_low.is_empty() {
                return true;
            }
            d.ip.to_string().contains(&filter_low)
                || d.display_name().to_ascii_lowercase().contains(&filter_low)
                || d.device_role.to_ascii_lowercase().contains(&filter_low)
                || d.vendor
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .contains(&filter_low)
                || d.mac
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .contains(&filter_low)
                || d.open_ports_summary().contains(&filter_low)
        })
        .cloned()
        .collect();

    let avail_h = ui.available_height().max(340.0);
    let total_w = ui.available_width();
    let inspector_w = 258.0;
    let table_w = (total_w - inspector_w - 10.0).max(360.0);

    ui.horizontal_top(|ui| {
        // Left: Discovered LAN Devices Table
        ui.allocate_ui_with_layout(vec2(table_w, avail_h), Layout::top_down(Align::Min), |ui| {
            palette.card_frame().show(ui, |ui| {
                ui.set_width(table_w - 28.0);
                ui.set_height(avail_h - 28.0);
                section_label(ui, palette, "DISCOVERED DEVICES");
                ui.add_space(6.0);

                if filtered.is_empty() {
                    let msg = if state.running {
                        "Scanning local subnet via ICMP, TCP & ARP cache..."
                    } else {
                        "Click Scan LAN to discover active devices, vendors, and running services."
                    };
                    ui.label(
                        egui::RichText::new(msg)
                            .size(12.5)
                            .color(palette.text_muted),
                    );
                } else {
                    TableBuilder::new(ui)
                        .id_salt("lan_scanner_table")
                        .striped(true)
                        .sense(Sense::click())
                        .max_scroll_height(avail_h - 68.0)
                        .column(Column::initial(155.0).at_least(135.0).clip(true))
                        .column(Column::exact(102.0))
                        .column(Column::exact(88.0).clip(true))
                        .column(Column::exact(112.0).clip(true))
                        .column(Column::remainder().at_least(80.0).clip(true))
                        .column(Column::exact(58.0))
                        .header(22.0, |mut h| {
                            h.col(|ui| {
                                ui.strong("Device");
                            });
                            h.col(|ui| {
                                ui.strong("IP Address");
                            });
                            h.col(|ui| {
                                ui.strong("Vendor");
                            });
                            h.col(|ui| {
                                ui.strong("MAC");
                            });
                            h.col(|ui| {
                                ui.strong("Open Ports");
                            });
                            h.col(|ui| {
                                ui.strong("Latency");
                            });
                        })
                        .body(|body| {
                            body.rows(28.0, filtered.len(), |mut row| {
                                let dev = &filtered[row.index()];
                                let is_sel = state.selected_ip == Some(dev.ip);
                                row.set_selected(is_sel);
                                let is_new = state.newly_joined_keys.contains(&dev.guard_key());

                                row.col(|ui| {
                                    ui.horizontal(|ui| {
                                        ui.style_mut().wrap_mode =
                                            Some(egui::TextWrapMode::Truncate);
                                        ui.label(
                                            egui::RichText::new(dev.display_name())
                                                .strong()
                                                .size(12.0),
                                        );
                                        if dev.is_gateway {
                                            status_pill(
                                                ui,
                                                "GW",
                                                palette.accent,
                                                palette.card_subtle_bg,
                                            );
                                        } else if dev.is_this_host {
                                            status_pill(
                                                ui,
                                                "This Host",
                                                palette.ok,
                                                palette.ok_bg,
                                            );
                                        }
                                        if is_new {
                                            status_pill(
                                                ui,
                                                "NEW",
                                                palette.warn,
                                                palette.warn_bg,
                                            );
                                        }
                                    });
                                });
                                row.col(|ui| {
                                    ui.monospace(dev.ip.to_string());
                                });
                                row.col(|ui| {
                                    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
                                    ui.label(dev.vendor.as_deref().unwrap_or("—"));
                                });
                                row.col(|ui| {
                                    ui.monospace(
                                        egui::RichText::new(dev.mac.as_deref().unwrap_or("—"))
                                            .size(11.0),
                                    );
                                });
                                row.col(|ui| {
                                    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
                                    ui.monospace(
                                        egui::RichText::new(dev.open_ports_summary()).size(11.0),
                                    );
                                });
                                row.col(|ui| {
                                    let rtt = dev
                                        .latency_ms
                                        .map(|m| format!("{m:.1} ms"))
                                        .unwrap_or_else(|| "ARP".into());
                                    ui.monospace(rtt);
                                });

                                if row.response().clicked() {
                                    state.selected_ip = Some(dev.ip);
                                }
                            });
                        });
                }
            });
        });

        ui.add_space(8.0);

        // Right: Selected Device Inspector Panel (Running Services + Network Information + Quick Actions)
        ui.allocate_ui_with_layout(
            vec2(inspector_w, avail_h),
            Layout::top_down(Align::Min),
            |ui| {
                palette.card_frame().show(ui, |ui| {
                    ui.set_width(inspector_w - 28.0);
                    ui.set_height(avail_h - 28.0);
                    section_label(ui, palette, "DEVICE INSPECTOR");
                    ui.add_space(6.0);

                    let selected_dev = state
                        .selected_ip
                        .and_then(|ip| state.devices.iter().find(|d| d.ip == ip));

                    let Some(dev) = selected_dev else {
                        ui.label(
                            egui::RichText::new("Select a device from the table to inspect open services and identity.")
                                .size(12.0)
                                .color(palette.text_muted),
                        );
                        return;
                    };

                    ui.label(
                        egui::RichText::new(dev.display_name())
                            .strong()
                            .size(15.0)
                            .color(palette.text_primary),
                    );
                    ui.label(
                        egui::RichText::new(format!("{}  •  {}", dev.ip, dev.device_role))
                            .size(11.5)
                            .color(palette.text_muted),
                    );

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Ping Host").clicked() {
                            jump_action = Some(LanJumpAction::PingHost(dev.ip.to_string()));
                        }
                        if ui.button("Full Port Scan").clicked() {
                            jump_action = Some(LanJumpAction::PortScanHost(dev.ip.to_string()));
                        }
                    });

                    ui.add_space(10.0);
                    section_label(ui, palette, "RUNNING SERVICES");
                    ui.add_space(4.0);

                    egui::ScrollArea::vertical()
                        .id_salt("lan_inspector_services")
                        .max_height(155.0)
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            if dev.open_ports.is_empty() {
                                ui.label(
                                    egui::RichText::new("No common TCP services open.")
                                        .size(11.5)
                                        .color(palette.text_muted),
                                );
                            } else {
                                for p in &dev.open_ports {
                                    palette
                                        .subtle_card_frame()
                                        .stroke(Stroke::new(1.0, palette.card_border))
                                        .inner_margin(egui::Margin::symmetric(8, 5))
                                        .show(ui, |ui| {
                                            ui.set_width(ui.available_width());
                                            ui.horizontal(|ui| {
                                                ui.monospace(
                                                    egui::RichText::new(format!("{:<5}", p.port))
                                                        .strong()
                                                        .color(palette.accent),
                                                );
                                                ui.vertical(|ui| {
                                                    ui.label(
                                                        egui::RichText::new(&p.service)
                                                            .strong()
                                                            .size(12.0),
                                                    );
                                                    if let Some(ref b) = p.version_banner {
                                                        ui.label(
                                                            egui::RichText::new(b)
                                                                .size(10.5)
                                                                .color(palette.text_muted),
                                                        );
                                                    }
                                                });
                                            });
                                        });
                                    ui.add_space(3.0);
                                }
                            }
                        });

                    ui.add_space(10.0);
                    section_label(ui, palette, "NETWORK INFORMATION");
                    ui.add_space(4.0);
                    egui::Grid::new("lan_dev_info_grid")
                        .num_columns(2)
                        .spacing([10.0, 5.0])
                        .show(ui, |ui| {
                            ui.label(
                                egui::RichText::new("IP Address")
                                    .size(11.5)
                                    .color(palette.text_muted),
                            );
                            ui.monospace(dev.ip.to_string());
                            ui.end_row();

                            ui.label(
                                egui::RichText::new("Hostname")
                                    .size(11.5)
                                    .color(palette.text_muted),
                            );
                            ui.monospace(dev.hostname.as_deref().unwrap_or("—"));
                            ui.end_row();

                            ui.label(
                                egui::RichText::new("MAC Address")
                                    .size(11.5)
                                    .color(palette.text_muted),
                            );
                            ui.monospace(dev.mac.as_deref().unwrap_or("—"));
                            ui.end_row();

                            ui.label(
                                egui::RichText::new("Vendor (OUI)")
                                    .size(11.5)
                                    .color(palette.text_muted),
                            );
                            ui.label(dev.vendor.as_deref().unwrap_or("—"));
                            ui.end_row();

                            ui.label(
                                egui::RichText::new("Status")
                                    .size(11.5)
                                    .color(palette.text_muted),
                            );
                            status_pill(ui, "Online", palette.ok, palette.ok_bg);
                            ui.end_row();
                        });
                });
            },
        );
    });

    jump_action
}
