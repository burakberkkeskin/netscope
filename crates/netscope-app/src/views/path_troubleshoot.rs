use crate::theme::{AppPalette, section_label, status_pill};
use crate::widgets::{HistoryPickAction, host_history_picker};
use egui::{Align2, Color32, FontId, Rect, Sense, Ui, pos2, vec2};
use egui_extras::{Column, TableBuilder};
use netscope_core::CancelToken;
use netscope_core::history::PersistedState;
use netscope_core::internet_check::VerdictSeverity;
use netscope_core::path_troubleshoot::{
    HopAnomaly, HopSegment, PathTroubleshootEvent, PathTroubleshootReport, run_path_troubleshoot,
};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

pub struct PathTroubleshootState {
    pub host: String,
    pub probes_per_hop: usize,
    pub running: bool,
    pub report: Option<PathTroubleshootReport>,
    pub error: Option<String>,
    cancel: Option<CancelToken>,
    rx: Option<mpsc::UnboundedReceiver<PathTroubleshootEvent>>,
}

impl Default for PathTroubleshootState {
    fn default() -> Self {
        Self {
            host: "1.1.1.1".into(),
            probes_per_hop: 5,
            running: false,
            report: None,
            error: None,
            cancel: None,
            rx: None,
        }
    }
}

impl PathTroubleshootState {
    pub fn start(&mut self, rt: &Runtime, ctx: &egui::Context) {
        self.stop();
        self.error = None;
        let host = self.host.clone();
        let probes = self.probes_per_hop;

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
            run_path_troubleshoot(host, 30, probes, fwd_tx, cancel).await;
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
        self.report = None;
        self.error = None;
    }

    pub fn poll(&mut self) {
        let mut done = false;
        if let Some(rx) = &mut self.rx {
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    PathTroubleshootEvent::Progress(r) => {
                        self.report = Some(*r);
                    }
                    PathTroubleshootEvent::Completed(r) => {
                        self.report = Some(*r);
                        self.running = false;
                        done = true;
                    }
                    PathTroubleshootEvent::Error(err) => {
                        self.error = Some(err);
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
    state: &mut PathTroubleshootState,
    history: &mut PersistedState,
    rt: &Runtime,
) {
    ui.horizontal(|ui| {
        ui.label("Target:");
        let resp = ui.add(
            egui::TextEdit::singleline(&mut state.host)
                .desired_width(210.0)
                .hint_text("1.1.1.1 or domain"),
        );
        let enter_pressed = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

        if let Some(act) =
            host_history_picker(ui, "pt_hist", &mut state.host, &history.recent_hosts)
        {
            match act {
                HistoryPickAction::Selected(h) => state.host = h,
                HistoryPickAction::Removed(h) => {
                    history.remove_host(&h);
                    let _ = history.save();
                }
            }
        }

        ui.label("Probes/hop:");
        egui::ComboBox::from_id_salt("pt_probes")
            .selected_text(state.probes_per_hop.to_string())
            .width(58.0)
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut state.probes_per_hop, 3, "3");
                ui.selectable_value(&mut state.probes_per_hop, 5, "5");
                ui.selectable_value(&mut state.probes_per_hop, 10, "10");
            });

        let btn = if state.running { "Stop" } else { "Analyze Path" };
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

    if let Some(ref err) = state.error {
        ui.add_space(6.0);
        status_pill(ui, err, palette.err, palette.err_bg);
    }

    ui.add_space(10.0);

    let Some(ref report) = state.report else {
        palette.card_frame().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(22.0);
                ui.heading("Hop-by-Hop Latency & Loss Troubleshooter");
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(
                        "Probes each hop across LAN, CGNAT, ISP, and Transit to pinpoint where latency jumps or packet loss truly starts — filtering out harmless control-plane ICMP rate limits.",
                    )
                    .color(palette.text_muted),
                );
                ui.add_space(14.0);
                if ui.button("Run Path Analysis").clicked() {
                    history.record_host(&state.host);
                    let _ = history.save();
                    state.start(rt, ui.ctx());
                }
                ui.add_space(18.0);
            });
        });
        return;
    };

    // Bottleneck Verdict Banner
    palette.card_frame().show(ui, |ui| {
        let (fg, bg, glyph) = if state.running {
            (
                palette.accent,
                Color32::from_rgba_unmultiplied(10, 132, 255, 28),
                "...",
            )
        } else {
            match report.severity {
                VerdictSeverity::Ok => (palette.ok, palette.ok_bg, "OK"),
                VerdictSeverity::Warning => (palette.warn, palette.warn_bg, "!"),
                VerdictSeverity::Error => (palette.err, palette.err_bg, "X"),
            }
        };

        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(vec2(34.0, 34.0), Sense::hover());
            ui.painter().circle_filled(rect.center(), 16.0, bg);
            ui.painter().text(
                rect.center(),
                Align2::CENTER_CENTER,
                glyph,
                FontId::proportional(12.0),
                fg,
            );
            ui.add_space(8.0);
            ui.vertical(|ui| {
                ui.label(
                    egui::RichText::new(format!(
                        "Path Analysis: {} ({})",
                        report.target_host, report.target_ip
                    ))
                    .strong()
                    .size(14.5),
                );
                ui.label(
                    egui::RichText::new(&report.bottleneck_summary)
                        .size(12.5)
                        .color(palette.text_muted),
                );
            });
        });
    });

    ui.add_space(10.0);

    // Waterfall Latency Table
    let max_med = report
        .hops
        .iter()
        .filter_map(|h| h.stats.median_ms)
        .fold(15.0_f64, f64::max);

    palette.card_frame().show(ui, |ui| {
        section_label(ui, palette, "HOP WATERFALL & ANOMALY DIAGNOSIS");
        ui.add_space(6.0);
        let max_h = ui.available_height().max(260.0);
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .max_scroll_height(max_h)
            .column(Column::exact(36.0))
            .column(Column::exact(68.0))
            .column(Column::initial(210.0).at_least(150.0))
            .column(Column::initial(170.0).at_least(120.0))
            .column(Column::exact(68.0))
            .column(Column::exact(62.0))
            .column(Column::exact(52.0))
            .column(Column::remainder())
            .header(22.0, |mut h| {
                h.col(|ui| {
                    ui.strong("#");
                });
                h.col(|ui| {
                    ui.strong("Segment");
                });
                h.col(|ui| {
                    ui.strong("Hop / Location");
                });
                h.col(|ui| {
                    ui.strong("RTT Waterfall");
                });
                h.col(|ui| {
                    ui.strong("Median");
                });
                h.col(|ui| {
                    ui.strong("Jitter");
                });
                h.col(|ui| {
                    ui.strong("Loss");
                });
                h.col(|ui| {
                    ui.strong("Diagnosis");
                });
            })
            .body(|body| {
                body.rows(36.0, report.hops.len(), |mut row| {
                    let h = &report.hops[row.index()];
                    row.col(|ui| {
                        ui.monospace(h.hop.to_string());
                    });
                    row.col(|ui| {
                        let (fg, bg) = segment_colors(palette, h.segment);
                        status_pill(ui, h.segment.label(), fg, bg);
                    });
                    row.col(|ui| {
                        let host_lbl = h
                            .hostname
                            .as_deref()
                            .or_else(|| {
                                h.geo.as_ref().and_then(|g| g.isp.as_deref())
                            })
                            .unwrap_or(if h.ip.is_some() { "" } else { "* * *" });
                        let ip_lbl = h
                            .ip
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "timeout".into());
                        let place = h
                            .geo
                            .as_ref()
                            .filter(|g| !g.is_private)
                            .map(|g| g.short_place())
                            .unwrap_or_default();
                        let line1 = if host_lbl.is_empty() {
                            ip_lbl.clone()
                        } else {
                            format!("{ip_lbl} ({host_lbl})")
                        };
                        ui.vertical(|ui| {
                            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
                            ui.label(egui::RichText::new(&line1).size(11.5))
                                .on_hover_text(&line1);
                            if !place.is_empty() {
                                ui.label(
                                    egui::RichText::new(&place)
                                        .size(10.0)
                                        .color(palette.text_muted),
                                );
                            }
                        });
                    });
                    row.col(|ui| {
                        let (rect, _) = ui.allocate_exact_size(
                            vec2(ui.available_width().max(110.0), 16.0),
                            Sense::hover(),
                        );
                        paint_waterfall_bar(ui.painter(), rect, palette, h.stats.median_ms, h.delta_ms, max_med, h.anomaly);
                    });
                    row.col(|ui| {
                        let txt = h
                            .stats
                            .median_ms
                            .map(|m| format!("{m:.1} ms"))
                            .unwrap_or_else(|| "—".into());
                        ui.monospace(txt);
                    });
                    row.col(|ui| {
                        let txt = h
                            .stats
                            .jitter_ms
                            .map(|j| format!("{j:.1}"))
                            .unwrap_or_else(|| "—".into());
                        ui.monospace(txt);
                    });
                    row.col(|ui| {
                        let lc = if h.stats.loss_pct >= 5.0
                            && !matches!(h.anomaly, HopAnomaly::IcmpRateLimited)
                        {
                            palette.err
                        } else {
                            palette.text_primary
                        };
                        ui.label(
                            egui::RichText::new(format!("{:.0}%", h.stats.loss_pct))
                                .monospace()
                                .color(lc),
                        );
                    });
                    row.col(|ui| {
                        let (lbl, fg, bg) = match h.anomaly {
                            HopAnomaly::Healthy => ("Normal".to_string(), palette.ok, palette.ok_bg),
                            HopAnomaly::IcmpRateLimited => (
                                "ICMP Rate-Limit".to_string(),
                                palette.text_muted,
                                palette.card_subtle_bg,
                            ),
                            HopAnomaly::LatencyJump { delta_ms } => (
                                format!("+{delta_ms:.1} ms step"),
                                if delta_ms >= 45.0 {
                                    palette.err
                                } else {
                                    palette.warn
                                },
                                if delta_ms >= 45.0 {
                                    palette.err_bg
                                } else {
                                    palette.warn_bg
                                },
                            ),
                            HopAnomaly::PacketLossOrigin { loss_pct } => (
                                format!("{loss_pct:.0}% loss origin"),
                                palette.err,
                                palette.err_bg,
                            ),
                            HopAnomaly::HighJitter { jitter_ms } => (
                                format!("Jitter {jitter_ms:.0} ms"),
                                palette.warn,
                                palette.warn_bg,
                            ),
                        };
                        ui.horizontal(|ui| {
                            status_pill(ui, &lbl, fg, bg);
                        })
                        .response
                        .on_hover_text(&h.note);
                    });
                });
            });
    });
}

fn segment_colors(palette: &AppPalette, seg: HopSegment) -> (Color32, Color32) {
    match seg {
        HopSegment::LocalLan => (palette.ok, palette.ok_bg),
        HopSegment::Cgnat => (palette.warn, palette.warn_bg),
        HopSegment::IspAccess => (palette.accent, Color32::from_rgba_unmultiplied(10, 132, 255, 24)),
        HopSegment::Transit => (palette.text_primary, palette.card_subtle_bg),
        HopSegment::Destination => (palette.accent, palette.ok_bg),
        HopSegment::Unresponsive => (palette.text_muted, palette.card_subtle_bg),
    }
}

fn paint_waterfall_bar(
    painter: &egui::Painter,
    rect: Rect,
    palette: &AppPalette,
    median_ms: Option<f64>,
    delta_ms: Option<f64>,
    max_med: f64,
    anomaly: HopAnomaly,
) {
    painter.rect_filled(rect, 3.0, palette.card_subtle_bg);
    let Some(med) = median_ms else {
        return;
    };
    let total_frac = (med / max_med.max(1.0)).clamp(0.03, 1.0) as f32;
    let delta = delta_ms.unwrap_or(0.0).min(med);
    let base_frac = ((med - delta) / max_med.max(1.0)).clamp(0.0, total_frac as f64) as f32;

    let base_end = rect.left() + rect.width() * base_frac;
    let total_end = rect.left() + rect.width() * total_frac;

    if base_end > rect.left() {
        painter.rect_filled(
            Rect::from_min_max(rect.min, pos2(base_end, rect.bottom())),
            2.0,
            Color32::from_rgba_unmultiplied(10, 132, 255, 95),
        );
    }

    let step_col = match anomaly {
        HopAnomaly::LatencyJump { delta_ms } if delta_ms >= 45.0 => palette.err,
        HopAnomaly::LatencyJump { .. } => palette.warn,
        HopAnomaly::IcmpRateLimited => palette.text_muted,
        HopAnomaly::PacketLossOrigin { .. } => palette.err,
        _ => palette.accent,
    };
    if total_end > base_end {
        painter.rect_filled(
            Rect::from_min_max(pos2(base_end, rect.top()), pos2(total_end, rect.bottom())),
            2.0,
            step_col,
        );
    }
}
