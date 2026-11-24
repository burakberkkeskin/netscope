use crate::theme::{AppPalette, section_label, status_pill};
use crate::widgets::nice_y_grid_spacer;
use egui::{Align, Align2, Color32, FontId, Layout, Rect, Sense, Stroke, Ui, pos2, vec2};
use egui_extras::{Column, TableBuilder};
use egui_plot::{AxisHints, HLine, Legend, Line, LineStyle, Plot, PlotPoints, uniform_grid_spacer};
use netscope_core::CancelToken;
use netscope_core::history::{PersistedState, SpeedTestRecord};
use netscope_core::speedtest::{
    BufferbloatGrade, SpeedTestEvent, SpeedTestPhase, SpeedTestResult, WorkloadQuality,
    evaluate_bufferbloat_workloads, run_speedtest,
};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

#[derive(Default)]
pub struct SpeedTestState {
    pub running: bool,
    pub phase: Option<SpeedTestPhase>,
    pub idle_rtts: Vec<f64>,
    pub dl_samples: Vec<[f64; 2]>,
    pub ul_samples: Vec<[f64; 2]>,
    pub dl_rtt_samples: Vec<[f64; 2]>,
    pub ul_rtt_samples: Vec<[f64; 2]>,
    pub live_dl_mbps: Option<f64>,
    pub live_ul_mbps: Option<f64>,
    pub dl_peak_mbps: Option<f64>,
    pub ul_peak_mbps: Option<f64>,
    pub live_loaded_rtt: Option<f64>,
    pub result: Option<SpeedTestResult>,
    pub error: Option<String>,
    cancel: Option<CancelToken>,
    rx: Option<mpsc::UnboundedReceiver<SpeedTestEvent>>,
}

impl SpeedTestState {
    pub fn start(&mut self, rt: &Runtime, ctx: &egui::Context) {
        self.stop();
        self.idle_rtts.clear();
        self.dl_samples.clear();
        self.ul_samples.clear();
        self.dl_rtt_samples.clear();
        self.ul_rtt_samples.clear();
        self.live_dl_mbps = None;
        self.live_ul_mbps = None;
        self.dl_peak_mbps = None;
        self.ul_peak_mbps = None;
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
        self.idle_rtts.clear();
        self.dl_samples.clear();
        self.ul_samples.clear();
        self.dl_rtt_samples.clear();
        self.ul_rtt_samples.clear();
        self.live_dl_mbps = None;
        self.live_ul_mbps = None;
        self.dl_peak_mbps = None;
        self.ul_peak_mbps = None;
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
                    SpeedTestEvent::IdleSample(rtt) => {
                        self.idle_rtts.push(rtt);
                        self.live_loaded_rtt = Some(rtt);
                    }
                    SpeedTestEvent::DownloadSample(s) => {
                        self.live_dl_mbps = Some(s.mbps);
                        self.dl_peak_mbps =
                            Some(self.dl_peak_mbps.map_or(s.mbps, |p| p.max(s.mbps)));
                        self.live_loaded_rtt = s.loaded_rtt_ms;
                        self.dl_samples.push([s.elapsed_sec, s.mbps]);
                        if let Some(rtt) = s.loaded_rtt_ms {
                            self.dl_rtt_samples.push([s.elapsed_sec, rtt]);
                        }
                    }
                    SpeedTestEvent::UploadSample(s) => {
                        self.live_ul_mbps = Some(s.mbps);
                        self.ul_peak_mbps =
                            Some(self.ul_peak_mbps.map_or(s.mbps, |p| p.max(s.mbps)));
                        self.live_loaded_rtt = s.loaded_rtt_ms;
                        self.ul_samples.push([s.elapsed_sec, s.mbps]);
                        if let Some(rtt) = s.loaded_rtt_ms {
                            self.ul_rtt_samples.push([s.elapsed_sec, rtt]);
                        }
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

        render_phase_stepper(ui, palette, state.phase, state.running);

        if let Some(rtt) = state.live_loaded_rtt
            && state.running
        {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                status_pill(
                    ui,
                    &format!("Live RTT {rtt:.1} ms"),
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

    egui::ScrollArea::vertical()
        .id_salt("speedtest_scroll")
        .show(ui, |ui| {
            // 1. Upgraded KPI Cards
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
                .and_then(|r| r.unloaded_stats.median_ms)
                .or_else(|| {
                    (!state.idle_rtts.is_empty()).then(|| {
                        let mut sorted = state.idle_rtts.clone();
                        sorted.sort_by(|a, b| a.total_cmp(b));
                        sorted[sorted.len() / 2]
                    })
                });
            let idle_jitter = state
                .result
                .as_ref()
                .and_then(|r| r.unloaded_stats.jitter_ms);

            ui.columns(4, |cols| {
                kpi_card(
                    &mut cols[0],
                    palette,
                    "Download",
                    &dl_val
                        .map(|m| format!("{m:.1} Mbps"))
                        .unwrap_or_else(|| "—".into()),
                    &state
                        .dl_peak_mbps
                        .map(|p| format!("Peak {p:.1} Mbps"))
                        .unwrap_or_else(|| "4 parallel TCP streams".into()),
                    Some(palette.accent),
                );
                kpi_card(
                    &mut cols[1],
                    palette,
                    "Upload",
                    &ul_val
                        .map(|m| format!("{m:.1} Mbps"))
                        .unwrap_or_else(|| "—".into()),
                    &state
                        .ul_peak_mbps
                        .map(|p| format!("Peak {p:.1} Mbps"))
                        .unwrap_or_else(|| "4 parallel TCP streams".into()),
                    Some(palette.ok),
                );
                kpi_card(
                    &mut cols[2],
                    palette,
                    "Idle Latency",
                    &idle_ms
                        .map(|m| format!("{m:.1} ms"))
                        .unwrap_or_else(|| "—".into()),
                    &idle_jitter
                        .map(|j| format!("Jitter {j:.1} ms"))
                        .unwrap_or_else(|| "Unloaded baseline".into()),
                    None,
                );
                cols[3].vertical(|ui| {
                    palette.subtle_card_frame().show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.set_min_height(56.0);
                        ui.label(
                            egui::RichText::new("Bufferbloat Grade")
                                .size(11.0)
                                .color(palette.text_muted),
                        );
                        if let Some(ref res) = state.result {
                            let (fg, _bg) = bloat_colors(palette, res.bufferbloat_grade);
                            let idle = res.unloaded_stats.median_ms.unwrap_or(0.0);
                            let worst = res
                                .loaded_dl_stats
                                .median_ms
                                .unwrap_or(idle)
                                .max(res.loaded_ul_stats.median_ms.unwrap_or(idle));
                            let bloat = (worst - idle).max(0.0);
                            ui.label(
                                egui::RichText::new(res.bufferbloat_grade.label())
                                    .size(18.0)
                                    .strong()
                                    .color(fg),
                            );
                            ui.label(
                                egui::RichText::new(format!("Worst +{bloat:.0} ms under load"))
                                    .size(11.0)
                                    .color(palette.text_muted),
                            );
                        } else {
                            ui.label(
                                egui::RichText::new("—")
                                    .size(18.0)
                                    .strong()
                                    .monospace()
                                    .color(palette.text_muted),
                            );
                            ui.label(
                                egui::RichText::new("Measured under full load")
                                    .size(11.0)
                                    .color(palette.text_muted),
                            );
                        }
                    });
                });
            });

            ui.add_space(10.0);

            // 2. Live Throughput Area Chart
            palette.card_frame().show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                section_label(ui, palette, "LIVE THROUGHPUT — MBPS (CLOUDFLARE 4-STREAM)");
                ui.add_space(4.0);
                let y_axis = AxisHints::new_y().min_thickness(54.0).formatter(|mark, _range| {
                    let v = if mark.value.abs() < 0.5 { 0.0 } else { mark.value };
                    format!("{v:.0} Mbps")
                });
                let mut plot = Plot::new("speedtest_plot")
                    .height(180.0)
                    .show_background(false)
                    .legend(Legend::default())
                    .include_y(0.0)
                    .custom_y_axes(vec![y_axis])
                    .y_grid_spacer(uniform_grid_spacer(nice_y_grid_spacer))
                    .x_axis_formatter(|mark, _range| {
                        let v = if mark.value.abs() < 0.05 { 0.0 } else { mark.value };
                        format!("{v:.1}s")
                    });
                if state.dl_samples.is_empty() && state.ul_samples.is_empty() {
                    plot = plot
                        .default_x_bounds(0.0, 8.0)
                        .default_y_bounds(0.0, 100.0);
                }
                plot.show(ui, |plot_ui| {
                        if !state.dl_samples.is_empty() {
                            plot_ui.line(
                                Line::new("Download", PlotPoints::from(state.dl_samples.clone()))
                                    .color(palette.accent)
                                    .width(2.2)
                                    .fill(0.0)
                                    .fill_alpha(0.14),
                            );
                        }
                        if !state.ul_samples.is_empty() {
                            plot_ui.line(
                                Line::new("Upload", PlotPoints::from(state.ul_samples.clone()))
                                    .color(palette.ok)
                                    .width(2.2)
                                    .fill(0.0)
                                    .fill_alpha(0.14),
                            );
                        }
                        if let Some(ref res) = state.result {
                            if res.download_mbps > 0.0 {
                                plot_ui.hline(
                                    HLine::new("Avg Download", res.download_mbps)
                                        .color(palette.accent)
                                        .width(1.2)
                                        .style(LineStyle::dashed_dense()),
                                );
                            }
                            if res.upload_mbps > 0.0 {
                                plot_ui.hline(
                                    HLine::new("Avg Upload", res.upload_mbps)
                                        .color(palette.ok)
                                        .width(1.2)
                                        .style(LineStyle::dashed_dense()),
                                );
                            }
                        }
                    });
            });

            ui.add_space(10.0);

            // 3. Detailed Bufferbloat Analysis & Loaded Latency Timeline
            render_bufferbloat_details(ui, palette, state, idle_ms);

            ui.add_space(10.0);

            // 4. Persistent Run History
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
                        .id_salt("speedtest_history_table")
                        .striped(true)
                        .max_scroll_height(160.0)
                        .column(Column::exact(132.0))
                        .column(Column::exact(105.0))
                        .column(Column::exact(105.0))
                        .column(Column::exact(90.0))
                        .column(Column::exact(140.0))
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
                                ui.strong("DL / UL Loaded");
                            });
                            h.col(|ui| {
                                ui.strong("Grade");
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
                                    let dl = r
                                        .loaded_dl_median_ms
                                        .map(|m| format!("{m:.0}"))
                                        .unwrap_or_else(|| "—".into());
                                    let ul = r
                                        .loaded_ul_median_ms
                                        .map(|m| format!("{m:.0}"))
                                        .unwrap_or_else(|| "—".into());
                                    ui.monospace(format!("{dl} / {ul} ms"));
                                });
                                row.col(|ui| {
                                    let (fg, bg) = bloat_colors(palette, r.bufferbloat_grade);
                                    status_pill(ui, r.bufferbloat_grade.label(), fg, bg);
                                });
                            });
                        });
                }
            });
        });
}

fn render_phase_stepper(
    ui: &mut Ui,
    palette: &AppPalette,
    phase: Option<SpeedTestPhase>,
    running: bool,
) {
    let steps = [
        ("1. Idle", SpeedTestPhase::IdleLatency),
        ("2. Download", SpeedTestPhase::Download),
        ("3. Upload", SpeedTestPhase::Upload),
        ("4. Grade", SpeedTestPhase::Completed),
    ];

    let active_idx = match phase {
        None => None,
        Some(SpeedTestPhase::IdleLatency) => Some(0),
        Some(SpeedTestPhase::Download) => Some(1),
        Some(SpeedTestPhase::Upload) => Some(2),
        Some(SpeedTestPhase::Completed) => Some(3),
    };

    for (idx, (lbl, _)) in steps.iter().enumerate() {
        let (fg, bg) = match active_idx {
            Some(cur) if idx < cur || (!running && cur == 3) => (palette.ok, palette.ok_bg),
            Some(cur) if idx == cur && running => (palette.accent, palette.card_subtle_bg),
            _ => (palette.text_muted, palette.card_subtle_bg),
        };
        status_pill(ui, lbl, fg, bg);
    }
}

fn render_bufferbloat_details(
    ui: &mut Ui,
    palette: &AppPalette,
    state: &SpeedTestState,
    idle_ms: Option<f64>,
) {
    palette.card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        section_label(
            ui,
            palette,
            "BUFFERBLOAT ANALYSIS — LATENCY UNDER LOAD (SQM / QUEUE HEALTH)",
        );
        ui.add_space(8.0);

        let total_w = ui.available_width();
        let gap = 20.0;
        let left_w = ((total_w - gap) * 0.49).max(260.0);
        let right_w = (total_w - gap - left_w).max(250.0);

        ui.horizontal_top(|ui| {
            // Left: Grade badge, 3 latency bars, workload impact pills, SQM advice
            ui.allocate_ui_with_layout(
                vec2(left_w, 10.0),
                Layout::top_down(Align::LEFT),
                |ui| {
                    ui.set_width(left_w);
                    ui.set_max_width(left_w);
                    if let Some(ref res) = state.result {
                        let (fg, bg) = bloat_colors(palette, res.bufferbloat_grade);
                        let summary = evaluate_bufferbloat_workloads(res);
                        let idle = res.unloaded_stats.median_ms.unwrap_or(0.0);
                        let dl_med = res.loaded_dl_stats.median_ms.unwrap_or(idle);
                        let ul_med = res.loaded_ul_stats.median_ms.unwrap_or(idle);
                        let bar_scale = idle.max(dl_med).max(ul_med).max(40.0);

                        ui.horizontal(|ui| {
                            let (rect, _) =
                                ui.allocate_exact_size(vec2(42.0, 42.0), Sense::hover());
                            ui.painter().circle_filled(rect.center(), 20.0, bg);
                            ui.painter().circle_stroke(
                                rect.center(),
                                20.0,
                                Stroke::new(1.5, fg),
                            );
                            ui.painter().text(
                                rect.center(),
                                Align2::CENTER_CENTER,
                                res.bufferbloat_grade.label(),
                                FontId::proportional(16.0),
                                fg,
                            );
                            ui.add_space(8.0);
                            let text_w = (left_w - 56.0).max(160.0);
                            ui.allocate_ui_with_layout(
                                vec2(text_w, 10.0),
                                Layout::top_down(Align::LEFT),
                                |ui| {
                                    ui.set_max_width(text_w);
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(res.bufferbloat_grade.description())
                                                .size(13.0)
                                                .strong()
                                                .color(palette.text_primary),
                                        )
                                        .wrap(),
                                    );
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(&summary.recommendation)
                                                .size(11.5)
                                                .color(palette.text_muted),
                                        )
                                        .wrap(),
                                    );
                                },
                            );
                        });

                        ui.add_space(10.0);
                        latency_bar_row(
                            ui,
                            palette,
                            "Unloaded Idle",
                            idle,
                            0.0,
                            bar_scale,
                            palette.ok,
                        );
                        ui.add_space(5.0);
                        latency_bar_row(
                            ui,
                            palette,
                            "Download Active",
                            dl_med,
                            summary.dl_bloat_ms,
                            bar_scale,
                            palette.accent,
                        );
                        ui.add_space(5.0);
                        latency_bar_row(
                            ui,
                            palette,
                            "Upload Active",
                            ul_med,
                            summary.ul_bloat_ms,
                            bar_scale,
                            palette.warn,
                        );

                        ui.add_space(10.0);
                        ui.horizontal_wrapped(|ui| {
                            workload_pill(ui, palette, "Video Calls", summary.video_calls);
                            workload_pill(ui, palette, "Gaming", summary.gaming);
                            workload_pill(ui, palette, "VoIP", summary.voip);
                            workload_pill(ui, palette, "Web", summary.web_browsing);
                        });
                    } else {
                        ui.label(
                            egui::RichText::new(if state.running {
                                "Measuring unloaded baseline and active-load RTT inflation..."
                            } else {
                                "Run Speed Test to inspect Download/Upload queue latency inflation and real-time app impact."
                            })
                            .size(12.0)
                            .color(palette.text_muted),
                        );
                    }
                },
            );

            ui.add_space(gap);

            // Right: Loaded RTT Timeline Plot
            ui.allocate_ui_with_layout(
                vec2(right_w, 10.0),
                Layout::top_down(Align::LEFT),
                |ui| {
                    ui.set_width(right_w);
                    let bloat_y_axis = AxisHints::new_y().min_thickness(44.0).formatter(|mark, _range| {
                        let v = if mark.value.abs() < 0.5 { 0.0 } else { mark.value };
                        format!("{v:.0} ms")
                    });
                    let mut bplot = Plot::new("speedtest_bloat_plot")
                        .height(185.0)
                        .show_background(false)
                        .legend(Legend::default())
                        .custom_y_axes(vec![bloat_y_axis])
                        .y_grid_spacer(uniform_grid_spacer(nice_y_grid_spacer))
                        .x_axis_formatter(|mark, _range| {
                            let v = if mark.value.abs() < 0.05 { 0.0 } else { mark.value };
                            format!("{v:.1}s")
                        });
                    if state.dl_rtt_samples.is_empty() && state.ul_rtt_samples.is_empty() {
                        bplot = bplot
                            .default_x_bounds(0.0, 8.0)
                            .default_y_bounds(0.0, 50.0);
                    }
                    bplot.show(ui, |plot_ui| {
                            if let Some(idle) = idle_ms {
                                plot_ui.hline(
                                    HLine::new("Idle Baseline", idle)
                                        .color(palette.ok)
                                        .width(1.3)
                                        .style(LineStyle::dashed_dense()),
                                );
                            }
                            if !state.dl_rtt_samples.is_empty() {
                                plot_ui.line(
                                    Line::new(
                                        "DL Loaded RTT",
                                        PlotPoints::from(state.dl_rtt_samples.clone()),
                                    )
                                    .color(palette.accent)
                                    .width(2.0),
                                );
                            }
                            if !state.ul_rtt_samples.is_empty() {
                                plot_ui.line(
                                    Line::new(
                                        "UL Loaded RTT",
                                        PlotPoints::from(state.ul_rtt_samples.clone()),
                                    )
                                    .color(palette.warn)
                                    .width(2.0),
                                );
                            }
                        });
                },
            );
        });
    });
}

fn latency_bar_row(
    ui: &mut Ui,
    palette: &AppPalette,
    label: &str,
    median_ms: f64,
    bloat_ms: f64,
    scale_max_ms: f64,
    bar_col: Color32,
) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(label)
                .size(11.5)
                .color(palette.text_muted),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let txt = if bloat_ms > 0.4 {
                format!("{median_ms:.1} ms (+{bloat_ms:.0} ms)")
            } else {
                format!("{median_ms:.1} ms")
            };
            ui.label(egui::RichText::new(txt).size(11.5).monospace().strong());
        });
    });
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 9.0), Sense::hover());
    ui.painter()
        .rect_filled(rect, 4.5, palette.card_subtle_bg);
    let frac = (median_ms / scale_max_ms.max(1.0)).clamp(0.03, 1.0) as f32;
    let fill_rect = Rect::from_min_max(
        rect.min,
        pos2(rect.left() + rect.width() * frac, rect.bottom()),
    );
    ui.painter().rect_filled(fill_rect, 4.5, bar_col);
}

fn workload_pill(ui: &mut Ui, palette: &AppPalette, app: &str, q: WorkloadQuality) {
    let (fg, bg) = match q {
        WorkloadQuality::Smooth => (palette.ok, palette.ok_bg),
        WorkloadQuality::LagSpikes => (palette.warn, palette.warn_bg),
        WorkloadQuality::Poor => (palette.err, palette.err_bg),
    };
    status_pill(ui, &format!("{app}: {}", q.label()), fg, bg);
}

fn kpi_card(
    ui: &mut Ui,
    palette: &AppPalette,
    title: &str,
    value: &str,
    subtitle: &str,
    col: Option<Color32>,
) {
    palette.subtle_card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.set_min_height(56.0);
        ui.label(
            egui::RichText::new(title)
                .size(11.0)
                .color(palette.text_muted),
        );
        ui.label(
            egui::RichText::new(value)
                .size(18.0)
                .strong()
                .monospace()
                .color(col.unwrap_or(palette.text_primary)),
        );
        ui.label(
            egui::RichText::new(subtitle)
                .size(11.0)
                .color(palette.text_muted),
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
