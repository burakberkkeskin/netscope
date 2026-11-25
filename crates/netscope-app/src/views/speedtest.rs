use crate::theme::{AppPalette, section_label, status_pill};
use crate::widgets::{ip_family_selector, nice_y_grid_spacer};
use egui::{
    Align, Align2, Color32, CornerRadius, FontId, Frame, Layout, Margin, Rect, Sense, Stroke, Ui,
    pos2, vec2,
};
use egui_extras::{Column, TableBuilder};
use egui_plot::{
    AxisHints, Corner, HLine, Legend, Line, LineStyle, Plot, PlotPoints, uniform_grid_spacer,
};
use netscope_core::history::{PersistedState, SpeedTestRecord};
use netscope_core::speedtest::{
    BufferbloatGrade, SpeedTestEvent, SpeedTestPhase, SpeedTestResult, SpeedTestServerInfo,
    WorkloadQuality, evaluate_bufferbloat_workloads, run_speedtest,
};
use netscope_core::{CancelToken, IpFamily};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpeedTestSubTab {
    #[default]
    SpeedTest,
    Bufferbloat,
    History,
}

#[derive(Default)]
pub struct SpeedTestState {
    pub running: bool,
    pub ip_family: IpFamily,
    pub sub_tab: SpeedTestSubTab,
    pub server_info: Option<SpeedTestServerInfo>,
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
        self.server_info = None;
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

        let family = self.ip_family;
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
            run_speedtest(family, fwd_tx, cancel).await;
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
        self.server_info = None;
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
                    SpeedTestEvent::ServerInfo(info) => {
                        self.server_info = Some(info);
                    }
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
    // Row 1: Compact primary controls (left) + Edge PoP / Live RTT (right) — never overflows at 920px
    ui.horizontal(|ui| {
        let btn = if state.running {
            "Stop Test"
        } else {
            "Start Test"
        };
        if ui.button(btn).clicked() {
            if state.running {
                state.stop();
            } else {
                state.start(rt, ui.ctx());
            }
        }

        ui.add_enabled_ui(!state.running, |ui| {
            ip_family_selector(ui, palette, &mut state.ip_family);
        });

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if let Some(ref info) = state.server_info {
                status_pill(
                    ui,
                    &info.badge_label(),
                    palette.text_primary,
                    palette.card_subtle_bg,
                );
            } else if let Some(ref res) = state.result
                && let Some(ref colo) = res.server_colo
            {
                let stack = if res.is_ipv6 { "IPv6" } else { "IPv4" };
                status_pill(
                    ui,
                    &format!("Cloudflare {colo} ({stack})"),
                    palette.text_primary,
                    palette.card_subtle_bg,
                );
            }
            if let Some(rtt) = state.live_loaded_rtt
                && state.running
            {
                status_pill(
                    ui,
                    &format!("RTT {rtt:.0} ms"),
                    palette.accent,
                    palette.card_subtle_bg,
                );
            }
        });
    });

    if let Some(ref err) = state.error {
        ui.add_space(6.0);
        palette.card_frame().show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.add(
                egui::Label::new(egui::RichText::new(err).size(12.5).color(palette.err)).wrap(),
            );
        });
    }

    ui.add_space(6.0);

    // Row 2: Dedicated Sub-Tabs (left) + Phase Stepper or Compact Result Summary (right)
    ui.horizontal(|ui| {
        render_sub_tabs(ui, palette, state, history.speedtest_history.len());

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if state.running {
                render_phase_stepper_rtl(ui, palette, state.phase, true);
            } else if let Some(ref res) = state.result {
                let (fg, bg) = bloat_colors(palette, res.bufferbloat_grade);
                status_pill(
                    ui,
                    &format!("Bloat {}", res.bufferbloat_grade.label()),
                    fg,
                    bg,
                );
                status_pill(
                    ui,
                    &format!("↓ {:.0} / ↑ {:.0} Mbps", res.download_mbps, res.upload_mbps),
                    palette.accent,
                    palette.card_subtle_bg,
                );
            }
        });
    });

    ui.add_space(8.0);

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

    egui::ScrollArea::vertical()
        .id_salt("speedtest_scroll")
        .show(ui, |ui| match state.sub_tab {
            SpeedTestSubTab::SpeedTest => render_throughput_tab(ui, palette, state, idle_ms),
            SpeedTestSubTab::Bufferbloat => render_bufferbloat_tab(ui, palette, state, idle_ms),
            SpeedTestSubTab::History => render_history_tab(ui, palette, history),
        });
}

fn render_sub_tabs(
    ui: &mut Ui,
    palette: &AppPalette,
    state: &mut SpeedTestState,
    history_count: usize,
) {
    let bloat_lbl = match &state.result {
        Some(r) => format!("Bufferbloat ({})", r.bufferbloat_grade.label()),
        None => "Bufferbloat".into(),
    };
    let hist_lbl = if history_count > 0 {
        format!("History ({history_count})")
    } else {
        "History".into()
    };

    let tabs = [
        (SpeedTestSubTab::SpeedTest, "Speed Test".to_string()),
        (SpeedTestSubTab::Bufferbloat, bloat_lbl),
        (SpeedTestSubTab::History, hist_lbl),
    ];

    Frame::new()
        .fill(palette.card_subtle_bg)
        .stroke(Stroke::new(1.0, palette.card_border))
        .corner_radius(CornerRadius::same(7))
        .inner_margin(Margin::same(2))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                for (tab, label) in tabs {
                    let selected = state.sub_tab == tab;
                    let fill = if selected {
                        palette.selected_bg
                    } else {
                        Color32::TRANSPARENT
                    };
                    let fg = if selected {
                        Color32::WHITE
                    } else {
                        palette.text_primary
                    };
                    let btn = egui::Button::new(
                        egui::RichText::new(label)
                            .size(12.0)
                            .strong()
                            .color(fg),
                    )
                    .fill(fill)
                    .frame(selected)
                    .corner_radius(CornerRadius::same(5))
                    .min_size(vec2(84.0, 22.0));
                    if ui.add(btn).clicked() {
                        state.sub_tab = tab;
                    }
                }
            });
        });
}

fn render_throughput_tab(
    ui: &mut Ui,
    palette: &AppPalette,
    state: &mut SpeedTestState,
    idle_ms: Option<f64>,
) {
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
    let idle_jitter = state
        .result
        .as_ref()
        .and_then(|r| r.unloaded_stats.jitter_ms);

    let edge_val = state
        .server_info
        .as_ref()
        .map(|i| {
            let s = if i.is_ipv6 { "IPv6" } else { "IPv4" };
            match &i.colo {
                Some(c) => format!("{c} · {s}"),
                None => s.into(),
            }
        })
        .or_else(|| {
            state.result.as_ref().map(|r| {
                let s = if r.is_ipv6 { "IPv6" } else { "IPv4" };
                match &r.server_colo {
                    Some(c) => format!("{c} · {s}"),
                    None => s.into(),
                }
            })
        })
        .unwrap_or_else(|| "—".into());

    let edge_sub = state
        .server_info
        .as_ref()
        .map(|i| i.ip.to_string())
        .or_else(|| {
            state
                .result
                .as_ref()
                .and_then(|r| r.server_ip.map(|ip| ip.to_string()))
        })
        .unwrap_or_else(|| "Cloudflare Speed Edge".into());

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
                .unwrap_or_else(|| "4 continuous TLS streams".into()),
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
        kpi_card(&mut cols[3], palette, "Edge PoP", &edge_val, &edge_sub, None);
    });

    ui.add_space(10.0);

    // Two dedicated side-by-side throughput charts so asymmetric links (e.g. 780 DL / 45 UL)
    // each auto-scale to their own full Y range without squashing Upload into the floor.
    let plot_h = (ui.available_height() - 56.0).clamp(200.0, 310.0);
    let total_w = ui.available_width();
    let gap = 10.0;
    let half_w = ((total_w - gap) * 0.5).max(200.0);

    ui.horizontal_top(|ui| {
        ui.allocate_ui_with_layout(vec2(half_w, 10.0), Layout::top_down(Align::LEFT), |ui| {
            ui.set_width(half_w);
            render_single_throughput_chart(
                ui,
                palette,
                "speedtest_dl_plot",
                "DOWNLOAD THROUGHPUT (MBPS)",
                "Download",
                "Avg Download",
                &state.dl_samples,
                state.result.as_ref().map(|r| r.download_mbps),
                palette.accent,
                plot_h,
            );
        });

        ui.add_space(gap);

        ui.allocate_ui_with_layout(vec2(half_w, 10.0), Layout::top_down(Align::LEFT), |ui| {
            ui.set_width(half_w);
            render_single_throughput_chart(
                ui,
                palette,
                "speedtest_ul_plot",
                "UPLOAD THROUGHPUT (MBPS)",
                "Upload",
                "Avg Upload",
                &state.ul_samples,
                state.result.as_ref().map(|r| r.upload_mbps),
                palette.ok,
                plot_h,
            );
        });
    });
}

#[allow(clippy::too_many_arguments)]
fn render_single_throughput_chart(
    ui: &mut Ui,
    palette: &AppPalette,
    plot_id: &str,
    title: &str,
    series_name: &str,
    avg_name: &str,
    samples: &[[f64; 2]],
    avg_mbps: Option<f64>,
    color: Color32,
    height: f32,
) {
    palette.card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.horizontal(|ui| {
            section_label(ui, palette, title);
            if let Some(avg) = avg_mbps
                && avg > 0.0
            {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(format!("Avg {avg:.1} Mbps"))
                            .size(11.5)
                            .monospace()
                            .strong()
                            .color(color),
                    );
                });
            }
        });
        ui.add_space(4.0);

        let y_axis = AxisHints::new_y()
            .min_thickness(46.0)
            .formatter(|mark, _range| {
                let v = if mark.value.abs() < 0.5 {
                    0.0
                } else {
                    mark.value
                };
                format!("{v:.0}")
            });

        let peak_y = samples
            .iter()
            .map(|p| p[1])
            .fold(0.0_f64, f64::max)
            .max(avg_mbps.unwrap_or(0.0));
        let headroom_y = if peak_y > 0.0 {
            (peak_y * 1.18).max(10.0)
        } else {
            100.0
        };
        let max_x = samples
            .iter()
            .map(|p| p[0])
            .fold(0.0_f64, f64::max)
            .max(8.0);

        Plot::new(plot_id)
            .height(height)
            .show_background(false)
            .allow_drag(false)
            .allow_zoom(false)
            .allow_scroll(false)
            .auto_bounds([true, true])
            .include_x(0.0)
            .include_x(max_x)
            .include_y(0.0)
            .include_y(headroom_y)
            .custom_y_axes(vec![y_axis])
            .y_grid_spacer(uniform_grid_spacer(nice_y_grid_spacer))
            .x_grid_spacer(uniform_grid_spacer(|_| [2.0, 1.0, 0.5]))
            .x_axis_formatter(|mark, _range| {
                let v = if mark.value.abs() < 0.05 {
                    0.0
                } else {
                    mark.value
                };
                format!("{v:.0}s")
            })
            .show(ui, |plot_ui| {
                plot_ui.set_auto_bounds([true, true]);
                if !samples.is_empty() {
                    plot_ui.line(
                        Line::new(series_name, PlotPoints::from(samples.to_vec()))
                            .color(color)
                            .width(2.3)
                            .fill(0.0)
                            .fill_alpha(0.16),
                    );
                }
                if let Some(avg) = avg_mbps
                    && avg > 0.0
                {
                    plot_ui.hline(
                        HLine::new(avg_name, avg)
                            .color(color)
                            .width(1.2)
                            .style(LineStyle::dashed_dense()),
                    );
                }
            });
    });
}

fn render_bufferbloat_tab(
    ui: &mut Ui,
    palette: &AppPalette,
    state: &SpeedTestState,
    idle_ms: Option<f64>,
) {
    let dl_loaded = state
        .result
        .as_ref()
        .and_then(|r| r.loaded_dl_stats.median_ms);
    let ul_loaded = state
        .result
        .as_ref()
        .and_then(|r| r.loaded_ul_stats.median_ms);
    let idle_base = idle_ms.unwrap_or(0.0);

    ui.columns(4, |cols| {
        cols[0].vertical(|ui| {
            palette.subtle_card_frame().show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.set_min_height(52.0);
                ui.label(
                    egui::RichText::new("Bufferbloat Grade")
                        .size(11.0)
                        .color(palette.text_muted),
                );
                if let Some(ref res) = state.result {
                    let (fg, _bg) = bloat_colors(palette, res.bufferbloat_grade);
                    let worst = res
                        .loaded_dl_stats
                        .median_ms
                        .unwrap_or(idle_base)
                        .max(res.loaded_ul_stats.median_ms.unwrap_or(idle_base));
                    let bloat = (worst - idle_base).max(0.0);
                    ui.label(
                        egui::RichText::new(res.bufferbloat_grade.label())
                            .size(18.0)
                            .strong()
                            .color(fg),
                    );
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(format!("Worst +{bloat:.0} ms under load"))
                                .size(11.0)
                                .color(palette.text_muted),
                        )
                        .truncate(),
                    );
                } else {
                    ui.label(
                        egui::RichText::new("—")
                            .size(18.0)
                            .strong()
                            .monospace()
                            .color(palette.text_muted),
                    );
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new("Run test to grade")
                                .size(11.0)
                                .color(palette.text_muted),
                        )
                        .truncate(),
                    );
                }
            });
        });

        kpi_card(
            &mut cols[1],
            palette,
            "Unloaded Idle",
            &idle_ms
                .map(|m| format!("{m:.1} ms"))
                .unwrap_or_else(|| "—".into()),
            &state
                .result
                .as_ref()
                .and_then(|r| r.unloaded_stats.jitter_ms)
                .map(|j| format!("Jitter {j:.1} ms"))
                .unwrap_or_else(|| "Baseline RTT".into()),
            Some(palette.ok),
        );

        let dl_delta = dl_loaded.map(|m| (m - idle_base).max(0.0));
        kpi_card(
            &mut cols[2],
            palette,
            "Download Loaded",
            &dl_loaded
                .map(|m| format!("{m:.1} ms"))
                .unwrap_or_else(|| "—".into()),
            &dl_delta
                .map(|d| format!("+{d:.1} ms vs idle"))
                .unwrap_or_else(|| "Active download RTT".into()),
            Some(palette.accent),
        );

        let ul_delta = ul_loaded.map(|m| (m - idle_base).max(0.0));
        kpi_card(
            &mut cols[3],
            palette,
            "Upload Loaded",
            &ul_loaded
                .map(|m| format!("{m:.1} ms"))
                .unwrap_or_else(|| "—".into()),
            &ul_delta
                .map(|d| format!("+{d:.1} ms vs idle"))
                .unwrap_or_else(|| "Active upload RTT".into()),
            Some(palette.warn),
        );
    });

    ui.add_space(10.0);

    palette.card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        section_label(
            ui,
            palette,
            "BUFFERBLOAT ANALYSIS — LATENCY UNDER LOAD (SQM / QUEUE HEALTH)",
        );
        ui.add_space(8.0);

        let total_w = ui.available_width();
        let gap = 16.0;
        let left_w = ((total_w - gap) * 0.46).max(180.0);
        let right_w = (total_w - gap - left_w).max(180.0);

        ui.horizontal_top(|ui| {
            // Left: Grade ring, 3 latency bars, workload pills, SQM advice
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
                                ui.allocate_exact_size(vec2(44.0, 44.0), Sense::hover());
                            ui.painter().circle_filled(rect.center(), 21.0, bg);
                            ui.painter().circle_stroke(
                                rect.center(),
                                21.0,
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
                            let text_w = (left_w - 56.0).max(120.0);
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
                        ui.add_space(6.0);
                        latency_bar_row(
                            ui,
                            palette,
                            "Download Active",
                            dl_med,
                            summary.dl_bloat_ms,
                            bar_scale,
                            palette.accent,
                        );
                        ui.add_space(6.0);
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
                        section_label(ui, palette, "REAL-TIME WORKLOAD IMPACT");
                        ui.add_space(4.0);
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
                                "Start a test to measure queue latency inflation under full Download & Upload saturation."
                            })
                            .size(12.5)
                            .color(palette.text_muted),
                        );
                    }
                },
            );

            ui.add_space(gap);

            // Right: Loaded RTT Timeline Plot (always auto-bounds with 28% headroom so Legend never overlaps)
            ui.allocate_ui_with_layout(
                vec2(right_w, 10.0),
                Layout::top_down(Align::LEFT),
                |ui| {
                    ui.set_width(right_w);
                    let bloat_y_axis =
                        AxisHints::new_y()
                            .min_thickness(46.0)
                            .formatter(|mark, _range| {
                                let v = if mark.value.abs() < 0.5 {
                                    0.0
                                } else {
                                    mark.value
                                };
                                format!("{v:.0} ms")
                            });

                    let max_rtt = state
                        .dl_rtt_samples
                        .iter()
                        .chain(state.ul_rtt_samples.iter())
                        .map(|p| p[1])
                        .fold(idle_ms.unwrap_or(0.0), f64::max);
                    let headroom_rtt = if max_rtt > 0.0 {
                        (max_rtt * 1.30).max(25.0)
                    } else {
                        60.0
                    };
                    let max_x = state
                        .dl_rtt_samples
                        .iter()
                        .chain(state.ul_rtt_samples.iter())
                        .map(|p| p[0])
                        .fold(0.0_f64, f64::max)
                        .max(8.0);

                    Plot::new("speedtest_bloat_plot")
                        .height(225.0)
                        .show_background(false)
                        .allow_drag(false)
                        .allow_zoom(false)
                        .allow_scroll(false)
                        .auto_bounds([true, true])
                        .include_x(0.0)
                        .include_x(max_x)
                        .include_y(0.0)
                        .include_y(headroom_rtt)
                        .legend(Legend::default().position(Corner::LeftTop))
                        .custom_y_axes(vec![bloat_y_axis])
                        .y_grid_spacer(uniform_grid_spacer(nice_y_grid_spacer))
                        .x_grid_spacer(uniform_grid_spacer(|_| [2.0, 1.0, 0.5]))
                        .x_axis_formatter(|mark, _range| {
                            let v = if mark.value.abs() < 0.05 {
                                0.0
                            } else {
                                mark.value
                            };
                            format!("{v:.0}s")
                        })
                        .show(ui, |plot_ui| {
                            plot_ui.set_auto_bounds([true, true]);
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
                                    .width(2.1),
                                );
                            }
                            if !state.ul_rtt_samples.is_empty() {
                                plot_ui.line(
                                    Line::new(
                                        "UL Loaded RTT",
                                        PlotPoints::from(state.ul_rtt_samples.clone()),
                                    )
                                    .color(palette.warn)
                                    .width(2.1),
                                );
                            }
                        });
                },
            );
        });
    });
}

fn render_history_tab(ui: &mut Ui, palette: &AppPalette, history: &PersistedState) {
    palette.card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        section_label(ui, palette, "SPEED TEST & BUFFERBLOAT HISTORY");
        ui.add_space(6.0);
        if history.speedtest_history.is_empty() {
            ui.label(
                egui::RichText::new("No past speed tests recorded yet.")
                    .size(12.5)
                    .color(palette.text_muted),
            );
        } else {
            TableBuilder::new(ui)
                .id_salt("speedtest_history_table")
                .striped(true)
                .max_scroll_height(320.0)
                .column(Column::exact(132.0))
                .column(Column::exact(105.0))
                .column(Column::exact(105.0))
                .column(Column::exact(86.0))
                .column(Column::exact(135.0))
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
                    body.rows(24.0, history.speedtest_history.len(), |mut row| {
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
}

fn render_phase_stepper_rtl(
    ui: &mut Ui,
    palette: &AppPalette,
    phase: Option<SpeedTestPhase>,
    running: bool,
) {
    // Reversed because parent layout is right_to_left.
    let steps = [
        (3usize, "4. Grade"),
        (2usize, "3. Upload"),
        (1usize, "2. Download"),
        (0usize, "1. Idle"),
    ];

    let active_idx = match phase {
        None => None,
        Some(SpeedTestPhase::IdleLatency) => Some(0),
        Some(SpeedTestPhase::Download) => Some(1),
        Some(SpeedTestPhase::Upload) => Some(2),
        Some(SpeedTestPhase::Completed) => Some(3),
    };

    for (idx, lbl) in steps {
        let (fg, bg) = match active_idx {
            Some(cur) if idx < cur || (!running && cur == 3) => (palette.ok, palette.ok_bg),
            Some(cur) if idx == cur && running => (palette.accent, palette.card_subtle_bg),
            _ => (palette.text_muted, palette.card_subtle_bg),
        };
        status_pill(ui, lbl, fg, bg);
    }
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
    color: Option<Color32>,
) {
    palette.subtle_card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.set_min_height(52.0);
        ui.label(
            egui::RichText::new(title)
                .size(11.0)
                .color(palette.text_muted),
        );
        ui.add(
            egui::Label::new(
                egui::RichText::new(value)
                    .size(17.5)
                    .strong()
                    .monospace()
                    .color(color.unwrap_or(palette.text_primary)),
            )
            .truncate(),
        )
        .on_hover_text(value);
        ui.add(
            egui::Label::new(
                egui::RichText::new(subtitle)
                    .size(11.0)
                    .color(palette.text_muted),
            )
            .truncate(),
        )
        .on_hover_text(subtitle);
    });
}

fn bloat_colors(palette: &AppPalette, grade: BufferbloatGrade) -> (Color32, Color32) {
    match grade {
        BufferbloatGrade::APlus | BufferbloatGrade::A => (palette.ok, palette.ok_bg),
        BufferbloatGrade::B | BufferbloatGrade::C => (palette.warn, palette.warn_bg),
        BufferbloatGrade::D | BufferbloatGrade::F => (palette.err, palette.err_bg),
    }
}
