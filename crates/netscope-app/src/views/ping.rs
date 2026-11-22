use crate::theme::{AppPalette, section_label, status_pill};
use crate::widgets::{HistoryPickAction, host_history_picker};
use egui::Ui;
use egui_extras::{Column, TableBuilder};
use egui_plot::{Line, MarkerShape, Plot, PlotPoints, Points};
use netscope_core::CancelToken;
use netscope_core::history::PersistedState;
use netscope_core::icmp::{PingConfig, PingEvent, PingSample, run_ping};
use netscope_core::stats::{LatencyStats, compute_latency_stats};
use std::net::IpAddr;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

pub struct PingState {
    pub host: String,
    pub interval_ms: u64,
    pub running: bool,
    pub resolved_ip: Option<IpAddr>,
    pub samples: Vec<PingSample>,
    pub stats: LatencyStats,
    pub error: Option<String>,
    cancel: Option<CancelToken>,
    rx: Option<mpsc::UnboundedReceiver<PingEvent>>,
}

impl Default for PingState {
    fn default() -> Self {
        Self {
            host: "1.1.1.1".into(),
            interval_ms: 1000,
            running: false,
            resolved_ip: None,
            samples: Vec::new(),
            stats: LatencyStats::default(),
            error: None,
            cancel: None,
            rx: None,
        }
    }
}

impl PingState {
    pub fn start(&mut self, rt: &Runtime, ctx: &egui::Context) {
        self.stop();
        self.samples.clear();
        self.stats = LatencyStats::default();
        self.resolved_ip = None;
        self.error = None;

        let host = self.host.clone();
        let cfg = PingConfig {
            interval: Duration::from_millis(self.interval_ms),
            timeout: Duration::from_secs(2),
            count: None,
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
            run_ping(host, cfg, fwd_tx, cancel).await;
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
        self.samples.clear();
        self.stats = LatencyStats::default();
        self.resolved_ip = None;
        self.error = None;
    }

    pub fn poll(&mut self) {
        let mut finished = false;
        if let Some(rx) = &mut self.rx {
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    PingEvent::Resolved { ip, .. } => {
                        self.resolved_ip = Some(ip);
                    }
                    PingEvent::Sample(sample) => {
                        self.samples.push(sample);
                        let raw: Vec<Option<f64>> =
                            self.samples.iter().map(|s| s.rtt_ms).collect();
                        self.stats = compute_latency_stats(&raw);
                    }
                    PingEvent::Finished(stats) => {
                        self.stats = stats;
                        self.running = false;
                        finished = true;
                    }
                    PingEvent::Error(err) => {
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
    state: &mut PingState,
    history: &mut PersistedState,
    rt: &Runtime,
) {
    ui.horizontal(|ui| {
        ui.label("Host:");
        let resp = ui.add(
            egui::TextEdit::singleline(&mut state.host)
                .desired_width(210.0)
                .hint_text("1.1.1.1 or domain"),
        );
        let enter_pressed = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

        if let Some(act) = host_history_picker(ui, "ping_hist", &mut state.host, &history.recent_hosts) {
            match act {
                HistoryPickAction::Selected(h) => {
                    state.host = h;
                }
                HistoryPickAction::Removed(h) => {
                    history.remove_host(&h);
                    let _ = history.save();
                }
            }
        }

        ui.label("Interval:");
        egui::ComboBox::from_id_salt("ping_interval")
            .selected_text(format!("{:.1}s", state.interval_ms as f64 / 1000.0))
            .width(72.0)
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut state.interval_ms, 500, "0.5s");
                ui.selectable_value(&mut state.interval_ms, 1000, "1.0s");
                ui.selectable_value(&mut state.interval_ms, 2000, "2.0s");
            });

        let btn_text = if state.running { "Stop" } else { "Start Ping" };
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
                status_pill(ui, &ip.to_string(), palette.accent, palette.card_subtle_bg);
            });
        }
    });

    if let Some(ref err) = state.error {
        ui.add_space(6.0);
        status_pill(ui, err, palette.err, palette.err_bg);
    }

    ui.add_space(10.0);

    // 6 metric cards
    ui.columns(6, |cols| {
        metric_card(
            &mut cols[0],
            palette,
            "Sent / Loss",
            &format!("{} / {:.0}%", state.stats.sent, state.stats.loss_pct),
            if state.stats.loss_pct > 0.0 {
                Some(palette.err)
            } else {
                None
            },
        );
        metric_card(
            &mut cols[1],
            palette,
            "Min",
            &fmt_ms(state.stats.min_ms),
            None,
        );
        metric_card(
            &mut cols[2],
            palette,
            "Median",
            &fmt_ms(state.stats.median_ms),
            None,
        );
        metric_card(
            &mut cols[3],
            palette,
            "Avg",
            &fmt_ms(state.stats.avg_ms),
            None,
        );
        metric_card(
            &mut cols[4],
            palette,
            "Max",
            &fmt_ms(state.stats.max_ms),
            None,
        );
        metric_card(
            &mut cols[5],
            palette,
            "Jitter",
            &fmt_ms(state.stats.jitter_ms),
            None,
        );
    });

    ui.add_space(10.0);

    // Real-time RTT plot
    palette.card_frame().show(ui, |ui| {
        section_label(ui, palette, "ROUND-TRIP LATENCY (MS)");
        ui.add_space(4.0);
        let ok_pts: Vec<[f64; 2]> = state
            .samples
            .iter()
            .filter_map(|s| s.rtt_ms.map(|ms| [s.seq as f64, ms]))
            .collect();
        let lost_pts: Vec<[f64; 2]> = state
            .samples
            .iter()
            .filter(|s| s.rtt_ms.is_none())
            .map(|s| [s.seq as f64, 0.0])
            .collect();

        Plot::new("ping_rtt_plot")
            .height(200.0)
            .x_axis_formatter(|mark, _range| format!("#{}", mark.value.round() as i64))
            .y_axis_formatter(|mark, _range| format!("{:.1} ms", mark.value))
            .show(ui, |plot_ui| {
                if !ok_pts.is_empty() {
                    plot_ui.line(
                        Line::new("RTT (ms)", PlotPoints::from(ok_pts.clone()))
                            .color(palette.accent)
                            .width(2.0),
                    );
                    plot_ui.points(
                        Points::new("Samples", PlotPoints::from(ok_pts))
                            .color(palette.accent)
                            .radius(3.0),
                    );
                }
                if !lost_pts.is_empty() {
                    plot_ui.points(
                        Points::new("Lost", PlotPoints::from(lost_pts))
                            .color(palette.err)
                            .shape(MarkerShape::Cross)
                            .radius(5.0),
                    );
                }
            });
    });

    ui.add_space(10.0);

    // Samples table (newest first)
    palette.card_frame().show(ui, |ui| {
        section_label(ui, palette, "REPLIES");
        ui.add_space(4.0);
        let row_count = state.samples.len();
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .max_scroll_height(210.0)
            .column(Column::exact(60.0))
            .column(Column::initial(150.0).at_least(110.0))
            .column(Column::exact(60.0))
            .column(Column::exact(95.0))
            .column(Column::remainder())
            .header(22.0, |mut header| {
                header.col(|ui| {
                    ui.strong("Seq");
                });
                header.col(|ui| {
                    ui.strong("From");
                });
                header.col(|ui| {
                    ui.strong("TTL");
                });
                header.col(|ui| {
                    ui.strong("RTT");
                });
                header.col(|ui| {
                    ui.strong("Status");
                });
            })
            .body(|body| {
                body.rows(20.0, row_count, |mut row| {
                    let rev_idx = row_count - 1 - row.index();
                    let s = &state.samples[rev_idx];
                    row.col(|ui| {
                        ui.monospace(s.seq.to_string());
                    });
                    row.col(|ui| {
                        ui.monospace(
                            s.from
                                .map(|i| i.to_string())
                                .unwrap_or_else(|| "—".into()),
                        );
                    });
                    row.col(|ui| {
                        ui.monospace(
                            s.ttl
                                .map(|t| t.to_string())
                                .unwrap_or_else(|| "—".into()),
                        );
                    });
                    row.col(|ui| {
                        let txt = s
                            .rtt_ms
                            .map(|ms| format!("{ms:.2} ms"))
                            .unwrap_or_else(|| "—".into());
                        ui.monospace(txt);
                    });
                    row.col(|ui| {
                        let col = if s.rtt_ms.is_some() {
                            palette.ok
                        } else {
                            palette.err
                        };
                        ui.label(egui::RichText::new(&s.status).color(col));
                    });
                });
            });
    });
}

fn metric_card(
    ui: &mut Ui,
    palette: &AppPalette,
    label: &str,
    value: &str,
    color_override: Option<egui::Color32>,
) {
    palette.subtle_card_frame().show(ui, |ui| {
        ui.label(
            egui::RichText::new(label)
                .size(11.0)
                .color(palette.text_muted),
        );
        ui.label(
            egui::RichText::new(value)
                .size(15.0)
                .strong()
                .monospace()
                .color(color_override.unwrap_or(palette.text_primary)),
        );
    });
}

fn fmt_ms(v: Option<f64>) -> String {
    v.map(|ms| format!("{ms:.1} ms"))
        .unwrap_or_else(|| "—".into())
}
