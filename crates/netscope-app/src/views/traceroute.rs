use crate::theme::{AppPalette, status_pill};
use crate::widgets::{
    HistoryPickAction, format_resolved_ip_pill, host_history_picker, ip_family_selector,
};
use egui::{Ui, vec2};
use egui_extras::{Column, TableBuilder};
use netscope_core::history::PersistedState;
use netscope_core::icmp::{TracerouteEvent, TracerouteHop, run_traceroute};
use netscope_core::{CancelToken, IpFamily};
use std::net::IpAddr;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

pub struct TracerouteState {
    pub host: String,
    pub ip_family: IpFamily,
    pub max_hops: u8,
    pub running: bool,
    pub resolved_ip: Option<IpAddr>,
    pub hops: Vec<TracerouteHop>,
    pub error: Option<String>,
    cancel: Option<CancelToken>,
    rx: Option<mpsc::UnboundedReceiver<TracerouteEvent>>,
}

impl Default for TracerouteState {
    fn default() -> Self {
        Self {
            host: "cloudflare.com".into(),
            ip_family: IpFamily::Auto,
            max_hops: 30,
            running: false,
            resolved_ip: None,
            hops: Vec::new(),
            error: None,
            cancel: None,
            rx: None,
        }
    }
}

impl TracerouteState {
    pub fn start(&mut self, rt: &Runtime, ctx: &egui::Context) {
        self.stop();
        self.hops.clear();
        self.resolved_ip = None;
        self.error = None;

        let host = self.host.clone();
        let max_hops = self.max_hops;
        let ip_family = self.ip_family;
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
            run_traceroute(host, max_hops, 3, ip_family, fwd_tx, cancel).await;
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
        self.hops.clear();
        self.resolved_ip = None;
        self.error = None;
    }

    pub fn poll(&mut self) {
        let mut finished = false;
        if let Some(rx) = &mut self.rx {
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    TracerouteEvent::Resolved { ip, .. } => {
                        self.resolved_ip = Some(ip);
                    }
                    TracerouteEvent::HopUpdate(hop) => {
                        self.hops.push(hop);
                    }
                    TracerouteEvent::Finished => {
                        self.running = false;
                        finished = true;
                    }
                    TracerouteEvent::Error(err) => {
                        self.error = Some(err);
                        self.running = false;
                        finished = true;
                    }
                }
            }
        }
        if finished {
            self.rx = None;
            self.cancel = None;
        }
    }
}

pub fn render(
    ui: &mut Ui,
    palette: &AppPalette,
    state: &mut TracerouteState,
    history: &mut PersistedState,
    rt: &Runtime,
) {
    ui.horizontal(|ui| {
        ui.label("Host:");
        let resp = ui.add(
            egui::TextEdit::singleline(&mut state.host)
                .desired_width(220.0)
                .hint_text("cloudflare.com or IP"),
        );
        let enter_pressed = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

        if let Some(act) = host_history_picker(ui, "trace_hist", &mut state.host, &history.recent_hosts) {
            match act {
                HistoryPickAction::Selected(h) => state.host = h,
                HistoryPickAction::Removed(h) => {
                    history.remove_host(&h);
                    let _ = history.save();
                }
            }
        }

        ip_family_selector(ui, palette, &mut state.ip_family);

        ui.label("Max Hops:");
        ui.add(egui::DragValue::new(&mut state.max_hops).range(1..=64));

        let btn_text = if state.running { "Stop" } else { "Trace Route" };
        if ui.button(btn_text).clicked() || (!state.running && enter_pressed) {
            if state.running {
                state.stop();
            } else {
                history.record_host(&state.host);
                let _ = history.save();
                state.start(rt, ui.ctx());
            }
        }

        if ui.button("Clear").clicked() {
            state.clear();
        }

        if let Some(ip) = state.resolved_ip {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                status_pill(
                    ui,
                    &format!("{} ({} hops)", format_resolved_ip_pill(ip), state.hops.len()),
                    palette.accent,
                    palette.card_subtle_bg,
                );
            });
        }
    });

    if let Some(ref err) = state.error {
        ui.add_space(6.0);
        status_pill(ui, err, palette.err, palette.err_bg);
    }

    ui.add_space(10.0);

    palette.card_frame().show(ui, |ui| {
        let row_count = state.hops.len();
        let max_h = ui.available_height().max(260.0);
        TableBuilder::new(ui)
            .id_salt("traceroute_table")
            .striped(true)
            .resizable(true)
            .max_scroll_height(max_h)
            .column(Column::exact(48.0))
            .column(Column::initial(230.0).at_least(150.0))
            .column(Column::initial(135.0).at_least(110.0))
            .column(Column::exact(80.0))
            .column(Column::exact(80.0))
            .column(Column::exact(80.0))
            .column(Column::remainder())
            .header(24.0, |mut header| {
                header.col(|ui| {
                    ui.strong("Hop");
                });
                header.col(|ui| {
                    ui.strong("Hostname");
                });
                header.col(|ui| {
                    ui.strong("IP Address");
                });
                header.col(|ui| {
                    ui.strong("Probe 1");
                });
                header.col(|ui| {
                    ui.strong("Probe 2");
                });
                header.col(|ui| {
                    ui.strong("Probe 3");
                });
                header.col(|ui| {
                    ui.strong("Avg");
                });
            })
            .body(|body| {
                body.rows(22.0, row_count, |mut row| {
                    let h = &state.hops[row.index()];
                    row.col(|ui| {
                        ui.horizontal(|ui| {
                            let col = if h.reached_target {
                                palette.accent
                            } else if h.ip.is_some() {
                                palette.ok
                            } else {
                                palette.text_muted
                            };
                            let (dot, _) =
                                ui.allocate_exact_size(vec2(10.0, 10.0), egui::Sense::hover());
                            ui.painter().circle_filled(dot.center(), 4.0, col);
                            ui.monospace(h.hop.to_string());
                        });
                    });
                    row.col(|ui| {
                        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
                        let text = h
                            .hostname
                            .as_deref()
                            .unwrap_or(if h.ip.is_some() { "—" } else { "* * *" });
                        ui.label(text).on_hover_text(text);
                    });
                    row.col(|ui| {
                        ui.monospace(
                            h.ip.map(|i| i.to_string())
                                .unwrap_or_else(|| "*".into()),
                        );
                    });
                    for probe_idx in 0..3 {
                        row.col(|ui| {
                            let val = h
                                .probe_rtts_ms
                                .get(probe_idx)
                                .copied()
                                .flatten()
                                .map(|ms| format!("{ms:.1} ms"))
                                .unwrap_or_else(|| "*".into());
                            ui.monospace(val);
                        });
                    }
                    row.col(|ui| {
                        let avg = h
                            .avg_ms
                            .map(|ms| format!("{ms:.1} ms"))
                            .unwrap_or_else(|| "—".into());
                        ui.monospace(avg);
                    });
                });
            });
    });
}
