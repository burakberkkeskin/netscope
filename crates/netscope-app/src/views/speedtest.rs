use crate::theme::{AppPalette, section_label, status_pill};
use egui::{Color32, Ui};
use egui_extras::{Column, TableBuilder};
use egui_plot::{Line, Plot, PlotPoints};
use netscope_core::CancelToken;
use netscope_core::history::{PersistedState, SpeedTestRecord};
use netscope_core::speedtest::{
    BufferbloatGrade, SpeedTestEvent, SpeedTestPhase, SpeedTestResult, run_speedtest,
};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

#[derive(Default)]
pub struct SpeedTestState {
    pub running: bool,
    pub phase: Option<SpeedTestPhase>,
    pub dl_samples: Vec<[f64; 2]>,
    pub ul_samples: Vec<[f64; 2]>,
    pub live_dl_mbps: Option<f64>,
    pub live_ul_mbps: Option<f64>,
    pub live_loaded_rtt: Option<f64>,
    pub result: Option<SpeedTestResult>,
    pub error: Option<String>,
    cancel: Option<CancelToken>,
    rx: Option<mpsc::UnboundedReceiver<SpeedTestEvent>>,
}

impl SpeedTestState {
    pub fn start(&mut self, rt: &Runtime, ctx: &egui::Context) {
        self.stop();
        self.dl_samples.clear();
        self.ul_samples.clear();
        self.live_dl_mbps = None;
        self.live_ul_mbps = None;
        self.live_loaded_rtt = None;
        self.result = None;
        self.error = None;
        self.phase = Some(SpeedTestPhase::IdleLatency);

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
            run_speedtest(fwd_tx, cancel).await;
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
        self.dl_samples.clear();
        self.ul_samples.clear();
        self.live_dl_mbps = None;
        self.live_ul_mbps = None;
        self.live_loaded_rtt = None;
        self.result = None;
        self.error = None;
        self.phase = None;
    }

    pub fn poll(&mut self, history: &mut PersistedState) {
        let mut done = false;
        if let Some(rx) = &mut self.rx {
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    SpeedTestEvent::PhaseChanged(p) => {
                        self.phase = Some(p);
                    }
                    SpeedTestEvent::DownloadSample(s) => {
                        self.live_dl_mbps = Some(s.mbps);
                        self.live_loaded_rtt = s.loaded_rtt_ms;
                        self.dl_samples.push([s.elapsed_sec, s.mbps]);
                    }
                    SpeedTestEvent::UploadSample(s) => {
                        self.live_ul_mbps = Some(s.mbps);
                        self.live_loaded_rtt = s.loaded_rtt_ms;
                        self.ul_samples.push([s.elapsed_sec, s.mbps]);
                    }
                    SpeedTestEvent::Completed(res) => {
                        let r = *res;
                        history.record_speedtest(SpeedTestRecord {
                            timestamp: r.timestamp,
                            download_mbps: r.download_mbps,
                            upload_mbps: r.upload_mbps,
                            idle_median_ms: r.unloaded_stats.median_ms.unwrap_or(0.0),
                            loaded_dl_median_ms: r.loaded_dl_stats.median_ms,
                            loaded_ul_median_ms: r.loaded_ul_stats.median_ms,
                            bufferbloat_grade: r.bufferbloat_grade,
                        });
                        let _ = history.save();
                        self.result = Some(r);
                        self.running = false;
                        done = true;
                    }
                    SpeedTestEvent::Error(e) => {
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
}

pub fn render(
    ui: &mut Ui,
    palette: &AppPalette,
    state: &mut SpeedTestState,
    history: &PersistedState,
    rt: &Runtime,
) {
    ui.horizontal(|ui| {
        let btn = if state.running {
            "Stop Speed Test"
        } else {
            "Start Speed Test (4 Streams)"
        };
        if ui.button(btn).clicked() {
            if state.running {
                state.stop();
            } else {
                state.start(rt, ui.ctx());
            }
        }

        if let Some(p) = state.phase {
            let (fg, bg) = if p == SpeedTestPhase::Completed {
                (palette.ok, palette.ok_bg)
            } else {
                (palette.accent, palette.card_subtle_bg)
            };
            status_pill(ui, p.label(), fg, bg);
        }

        if let Some(rtt) = state.live_loaded_rtt
            && state.running
        {
            ui.label(
                egui::RichText::new(format!("Loaded RTT: {rtt:.1} ms"))
                    .monospace()
                    .color(palette.text_muted),
            );
        }
    });

    if let Some(ref err) = state.error {
        ui.add_space(6.0);
        status_pill(ui, err, palette.err, palette.err_bg);
    }

    ui.add_space(10.0);

    // KPI Cards
    let dl_val = state
        .result
        .as_ref()
        .map(|r| r.download_mbps)
        .or(state.live_dl_mbps);
    let ul_val = state
        .result
        .as_ref()
        .map(|r| r.upload_mbps)
        .or(state.live_ul_mbps);
    let idle_ms = state
        .result
        .as_ref()
        .and_then(|r| r.unloaded_stats.median_ms);

    ui.columns(4, |cols| {
        kpi_card(
            &mut cols[0],
            palette,
            "Download",
            &dl_val
                .map(|m| format!("{m:.1} Mbps"))
                .unwrap_or_else(|| "—".into()),
            Some(palette.accent),
        );
        kpi_card(
            &mut cols[1],
            palette,
            "Upload",
            &ul_val
                .map(|m| format!("{m:.1} Mbps"))
                .unwrap_or_else(|| "—".into()),
            Some(palette.ok),
        );
        kpi_card(
            &mut cols[2],
            palette,
            "Idle Latency",
            &idle_ms
                .map(|m| format!("{m:.1} ms"))
                .unwrap_or_else(|| "—".into()),
            None,
        );
        cols[3].vertical(|ui| {
            palette.subtle_card_frame().show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.set_min_height(41.0);
                ui.label(
                    egui::RichText::new("Bufferbloat Grade")
                        .size(11.0)
                        .color(palette.text_muted),
                );
                if let Some(ref res) = state.result {
                    let (fg, _bg) = bloat_colors(palette, res.bufferbloat_grade);
                    let dl_l = res
                        .loaded_dl_stats
                        .median_ms
                        .map(|m| format!("{m:.0}"))
                        .unwrap_or_else(|| "—".into());
                    let ul_l = res
                        .loaded_ul_stats
                        .median_ms
                        .map(|m| format!("{m:.0}"))
                        .unwrap_or_else(|| "—".into());
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(res.bufferbloat_grade.label())
                                .size(17.0)
                                .strong()
                                .color(fg),
                        );
                        ui.label(
                            egui::RichText::new(format!("(DL {dl_l} / UL {ul_l} ms)"))
                                .size(11.0)
                                .color(palette.text_muted),
                        );
                    });
                } else {
                    ui.label(
                        egui::RichText::new("—")
                            .size(17.0)
                            .strong()
                            .monospace()
                            .color(palette.text_muted),
                    );
                }
            });
        });
    });

    ui.add_space(10.0);

    // Live Throughput Plot
    palette.card_frame().show(ui, |ui| {
        section_label(ui, palette, "LIVE THROUGHPUT — MBPS (CLOUDFLARE 4-STREAM)");
        ui.add_space(4.0);
        Plot::new("speedtest_plot")
            .height(190.0)
            .x_axis_formatter(|mark, _range| format!("{:.1}s", mark.value))
            .y_axis_formatter(|mark, _range| format!("{:.0}", mark.value))
            .show(ui, |plot_ui| {
                if !state.dl_samples.is_empty() {
                    plot_ui.line(
                        Line::new("Download", PlotPoints::from(state.dl_samples.clone()))
                            .color(palette.accent)
                            .width(2.2),
                    );
                }
                if !state.ul_samples.is_empty() {
                    plot_ui.line(
                        Line::new("Upload", PlotPoints::from(state.ul_samples.clone()))
                            .color(palette.ok)
                            .width(2.2),
                    );
                }
            });
    });

    ui.add_space(10.0);

    // Persistent Run History
    palette.card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        section_label(ui, palette, "SPEED TEST HISTORY");
        ui.add_space(4.0);
        if history.speedtest_history.is_empty() {
            ui.label(
                egui::RichText::new("No past speed tests recorded yet.")
                    .size(12.0)
                    .color(palette.text_muted),
            );
        } else {
            TableBuilder::new(ui)
                .striped(true)
                .max_scroll_height(160.0)
                .column(Column::exact(140.0))
                .column(Column::exact(110.0))
                .column(Column::exact(110.0))
                .column(Column::exact(95.0))
                .column(Column::remainder())
                .header(22.0, |mut h| {
                    h.col(|ui| {
                        ui.strong("When");
                    });
                    h.col(|ui| {
                        ui.strong("Download");
                    });
                    h.col(|ui| {
                        ui.strong("Upload");
                    });
                    h.col(|ui| {
                        ui.strong("Idle RTT");
                    });
                    h.col(|ui| {
                        ui.strong("Bufferbloat");
                    });
                })
                .body(|body| {
                    body.rows(22.0, history.speedtest_history.len(), |mut row| {
                        let r = &history.speedtest_history[row.index()];
                        row.col(|ui| {
                            ui.monospace(
                                r.timestamp
                                    .with_timezone(&chrono::Local)
                                    .format("%Y-%m-%d %H:%M")
                                    .to_string(),
                            );
                        });
                        row.col(|ui| {
                            ui.monospace(format!("{:.1} Mbps", r.download_mbps));
                        });
                        row.col(|ui| {
                            ui.monospace(format!("{:.1} Mbps", r.upload_mbps));
                        });
                        row.col(|ui| {
                            ui.monospace(format!("{:.1} ms", r.idle_median_ms));
                        });
                        row.col(|ui| {
                            let (fg, bg) = bloat_colors(palette, r.bufferbloat_grade);
                            status_pill(ui, r.bufferbloat_grade.label(), fg, bg);
                        });
                    });
                });
        }
    });
}

fn kpi_card(
    ui: &mut Ui,
    palette: &AppPalette,
    title: &str,
    value: &str,
    col: Option<Color32>,
) {
    palette.subtle_card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.set_min_height(41.0);
        ui.label(
            egui::RichText::new(title)
                .size(11.0)
                .color(palette.text_muted),
        );
        ui.label(
            egui::RichText::new(value)
                .size(17.0)
                .strong()
                .monospace()
                .color(col.unwrap_or(palette.text_primary)),
        );
    });
}

fn bloat_colors(palette: &AppPalette, grade: BufferbloatGrade) -> (Color32, Color32) {
    match grade {
        BufferbloatGrade::APlus | BufferbloatGrade::A => (palette.ok, palette.ok_bg),
        BufferbloatGrade::B | BufferbloatGrade::C => (palette.warn, palette.warn_bg),
        BufferbloatGrade::D | BufferbloatGrade::F => (palette.err, palette.err_bg),
    }
}
