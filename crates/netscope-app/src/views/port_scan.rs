use crate::theme::{AppPalette, section_label, status_pill};
use crate::widgets::{HistoryPickAction, host_history_picker};
use egui::{Align, Layout, Ui};
use egui_extras::{Column, TableBuilder};
use netscope_core::CancelToken;
use netscope_core::history::PersistedState;
use netscope_core::port_scan::{
    PortPreset, PortScanConfig, PortScanEntry, PortScanEvent, run_port_scan,
};
use std::net::IpAddr;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

pub struct PortScanState {
    pub host: String,
    pub preset: PortPreset,
    pub port_spec: String,
    pub include_udp: bool,
    pub grab_banners: bool,
    pub timeout_ms: u64,
    pub running: bool,
    pub resolved_ip: Option<IpAddr>,
    pub completed: usize,
    pub total: usize,
    pub open_ports: Vec<PortScanEntry>,
    pub error: Option<String>,
    cancel: Option<CancelToken>,
    rx: Option<mpsc::UnboundedReceiver<PortScanEvent>>,
}

impl Default for PortScanState {
    fn default() -> Self {
        let preset = PortPreset::WebAndInfra;
        Self {
            host: "127.0.0.1".into(),
            preset,
            port_spec: preset.spec_string().into(),
            include_udp: false,
            grab_banners: true,
            timeout_ms: 700,
            running: false,
            resolved_ip: None,
            completed: 0,
            total: 0,
            open_ports: Vec::new(),
            error: None,
            cancel: None,
            rx: None,
        }
    }
}

impl PortScanState {
    pub fn start(&mut self, rt: &Runtime, ctx: &egui::Context) {
        self.stop();
        self.open_ports.clear();
        self.resolved_ip = None;
        self.completed = 0;
        self.total = 0;
        self.error = None;

        let cfg = PortScanConfig {
            host: self.host.clone(),
            port_spec: self.port_spec.clone(),
            include_udp: self.include_udp,
            concurrency: 64,
            timeout_ms: self.timeout_ms,
            grab_banners: self.grab_banners,
        };

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
            run_port_scan(cfg, fwd_tx, cancel).await;
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
        self.open_ports.clear();
        self.resolved_ip = None;
        self.completed = 0;
        self.total = 0;
        self.error = None;
    }

    pub fn poll(&mut self) {
        let mut done = false;
        if let Some(rx) = &mut self.rx {
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    PortScanEvent::Resolved {
                        ip, total_ports, ..
                    } => {
                        self.resolved_ip = Some(ip);
                        self.total = total_ports;
                    }
                    PortScanEvent::Progress { completed, total } => {
                        self.completed = completed;
                        self.total = total;
                    }
                    PortScanEvent::PortFound(entry) => {
                        self.open_ports.push(entry);
                        self.open_ports
                            .sort_by_key(|e| (e.port, e.protocol.clone()));
                    }
                    PortScanEvent::Finished => {
                        self.running = false;
                        done = true;
                    }
                    PortScanEvent::Error(e) => {
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

    pub fn copy_text(&self) -> String {
        let mut out = format!("NetScope Port Scan: {}\n", self.host);
        for p in &self.open_ports {
            out.push_str(&format!(
                "{:>5}/{}  {:18}  {}\n",
                p.port,
                p.protocol,
                p.service,
                p.version_banner.as_deref().unwrap_or("")
            ));
        }
        out
    }
}

pub fn render(
    ui: &mut Ui,
    palette: &AppPalette,
    state: &mut PortScanState,
    history: &mut PersistedState,
    rt: &Runtime,
) {
    // Row 1: Target Host, Preset selector, Scan button, Status Pill
    ui.horizontal(|ui| {
        ui.label("Host:");
        let resp = ui.add(
            egui::TextEdit::singleline(&mut state.host)
                .desired_width(185.0)
                .hint_text("192.168.1.1 or domain"),
        );
        let enter_pressed = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

        if let Some(act) =
            host_history_picker(ui, "pscan_hist", &mut state.host, &history.recent_hosts)
        {
            match act {
                HistoryPickAction::Selected(h) => state.host = h,
                HistoryPickAction::Removed(h) => {
                    history.remove_host(&h);
                    let _ = history.save();
                }
            }
        }

        ui.label("Preset:");
        for preset in [
            PortPreset::Common30,
            PortPreset::WebAndInfra,
            PortPreset::Top100,
            PortPreset::Custom,
        ] {
            if ui
                .selectable_label(state.preset == preset, preset.label())
                .clicked()
            {
                state.preset = preset;
                if preset != PortPreset::Custom {
                    state.port_spec = preset.spec_string().into();
                }
            }
        }

        let btn = if state.running { "Stop" } else { "Scan Ports" };
        if ui.button(btn).clicked() || (!state.running && enter_pressed) {
            if state.running {
                state.stop();
            } else {
                history.record_host(&state.host);
                let _ = history.save();
                state.start(rt, ui.ctx());
            }
        }
    });

    ui.add_space(4.0);

    // Row 2: Custom port specification + UDP + Banner detection + Timeout
    ui.horizontal(|ui| {
        ui.label("Ports:");
        if ui
            .add(
                egui::TextEdit::singleline(&mut state.port_spec)
                    .desired_width(340.0)
                    .hint_text("22,80,443,5000-5005,8006,8080"),
            )
            .changed()
        {
            state.preset = PortPreset::Custom;
        }

        ui.checkbox(&mut state.grab_banners, "Version & Banner Detection");
        ui.checkbox(&mut state.include_udp, "UDP Probe (DNS/NTP/mDNS)");
        ui.label("Timeout (ms):");
        ui.add(egui::DragValue::new(&mut state.timeout_ms).range(150..=3000));
    });

    if let Some(ref err) = state.error {
        ui.add_space(6.0);
        status_pill(ui, err, palette.err, palette.err_bg);
    }

    ui.add_space(10.0);

    palette.card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.horizontal(|ui| {
            section_label(ui, palette, "OPEN PORTS & DETECTED SERVICES");
            if let Some(ip) = state.resolved_ip {
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new(format!("Target IP: {ip}"))
                        .size(11.5)
                        .monospace()
                        .color(palette.text_muted),
                );
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if state.running && state.total > 0 {
                    status_pill(
                        ui,
                        &format!(
                            "Scanning {}/{} ({} open)",
                            state.completed,
                            state.total,
                            state.open_ports.len()
                        ),
                        palette.accent,
                        palette.card_subtle_bg,
                    );
                } else if state.total > 0 {
                    status_pill(
                        ui,
                        &format!("{} open / {} scanned", state.open_ports.len(), state.total),
                        palette.ok,
                        palette.ok_bg,
                    );
                }
            });
        });
        ui.add_space(6.0);

        if state.open_ports.is_empty() {
            let msg = if state.running {
                "Probing target ports..."
            } else if state.total > 0 {
                "No open ports responded on the target within the timeout."
            } else {
                "Select a preset or enter a port range and click Scan Ports."
            };
            ui.label(
                egui::RichText::new(msg)
                    .size(12.5)
                    .color(palette.text_muted),
            );
        } else {
            let table_h = ui.available_height().max(260.0);
            TableBuilder::new(ui)
                .id_salt("port_scan_table")
                .striped(true)
                .max_scroll_height(table_h)
                .column(Column::exact(75.0))
                .column(Column::exact(65.0))
                .column(Column::exact(75.0))
                .column(Column::exact(155.0))
                .column(Column::remainder())
                .column(Column::exact(85.0))
                .header(22.0, |mut h| {
                    h.col(|ui| {
                        ui.strong("Port");
                    });
                    h.col(|ui| {
                        ui.strong("Proto");
                    });
                    h.col(|ui| {
                        ui.strong("State");
                    });
                    h.col(|ui| {
                        ui.strong("Service");
                    });
                    h.col(|ui| {
                        ui.strong("Detected Version / Banner");
                    });
                    h.col(|ui| {
                        ui.strong("Connect RTT");
                    });
                })
                .body(|body| {
                    body.rows(24.0, state.open_ports.len(), |mut row| {
                        let entry = &state.open_ports[row.index()];
                        row.col(|ui| {
                            ui.monospace(format!("{:>5}", entry.port));
                        });
                        row.col(|ui| {
                            ui.monospace(&entry.protocol);
                        });
                        row.col(|ui| {
                            status_pill(ui, entry.state.label(), palette.ok, palette.ok_bg);
                        });
                        row.col(|ui| {
                            ui.label(egui::RichText::new(&entry.service).strong());
                        });
                        row.col(|ui| {
                            ui.monospace(entry.version_banner.as_deref().unwrap_or("—"));
                        });
                        row.col(|ui| {
                            let rtt = entry
                                .rtt_ms
                                .map(|m| format!("{m:.1} ms"))
                                .unwrap_or_else(|| "—".into());
                            ui.monospace(rtt);
                        });
                    });
                });
        }
    });
}
