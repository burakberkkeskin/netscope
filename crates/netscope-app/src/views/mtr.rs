use crate::theme::{AppPalette, section_label, status_pill};
use crate::widgets::{HistoryPickAction, host_history_picker};
use egui::{Color32, Rect, Sense, Ui, pos2, vec2};
use egui_extras::{Column, TableBuilder};
use netscope_core::CancelToken;
use netscope_core::history::PersistedState;
use netscope_core::icmp::{HopProbeMark, MtrEvent, MtrHopStats, MtrOutageEvent, run_mtr};
use std::net::IpAddr;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

pub struct MtrState {
    pub host: String,
    pub max_hops: u8,
    pub running: bool,
    pub resolved_ip: Option<IpAddr>,
    pub rounds: usize,
    pub hops: Vec<MtrHopStats>,
    pub outages: Vec<MtrOutageEvent>,
    pub error: Option<String>,
    cancel: Option<CancelToken>,
    rx: Option<mpsc::UnboundedReceiver<MtrEvent>>,
}

impl Default for MtrState {
    fn default() -> Self {
        Self {
            host: "1.1.1.1".into(),
            max_hops: 25,
            running: false,
            resolved_ip: None,
            rounds: 0,
            hops: Vec::new(),
            outages: Vec::new(),
            error: None,
            cancel: None,
            rx: None,
        }
    }
}

impl MtrState {
    pub fn start(&mut self, rt: &Runtime, ctx: &egui::Context) {
        self.stop();
        self.hops.clear();
        self.outages.clear();
        self.rounds = 0;
        self.resolved_ip = None;
        self.error = None;

        let host = self.host.clone();
        let max_hops = self.max_hops;
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
            run_mtr(host, max_hops, Duration::from_secs(1), fwd_tx, cancel).await;
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
        self.outages.clear();
        self.rounds = 0;
        self.resolved_ip = None;
        self.error = None;
    }

    pub fn poll(&mut self) {
        let mut finished = false;
        if let Some(rx) = &mut self.rx {
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    MtrEvent::Resolved { ip, .. } => self.resolved_ip = Some(ip),
                    MtrEvent::Snapshot { hops, rounds } => {
                        self.hops = hops;
                        self.rounds = rounds;
                    }
                    MtrEvent::Outage(o) => {
                        self.outages.insert(0, o);
                        if self.outages.len() > 100 {
                            self.outages.truncate(100);
                        }
                    }
                    MtrEvent::Finished => {
                        self.running = false;
                        finished = true;
                    }
                    MtrEvent::Error(err) => {
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
    state: &mut MtrState,
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

        if let Some(act) = host_history_picker(ui, "mtr_hist", &mut state.host, &history.recent_hosts) {
            match act {
                HistoryPickAction::Selected(h) => state.host = h,
                HistoryPickAction::Removed(h) => {
                    history.remove_host(&h);
                    let _ = history.save();
                }
            }
        }

        ui.label("Max Hops:");
        ui.add(egui::DragValue::new(&mut state.max_hops).range(1..=40));

        let btn = if state.running { "Stop" } else { "Start MTR" };
        if ui.button(btn).clicked() || (!state.running && enter_pressed) {
            if state.running {
                state.stop();
            } else {
                history.record_host(&state.host);
                let _ = history.save();
                state.start(rt, ui.ctx());
            }
        }

        if ui.button("Reset").clicked() {
            state.clear();
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if let Some(ip) = state.resolved_ip {
                status_pill(
                    ui,
                    &format!("{ip}  •  Rounds: {}", state.rounds),
                    palette.accent,
                    palette.card_subtle_bg,
                );
            }
        });
    });

    if let Some(ref err) = state.error {
        ui.add_space(6.0);
        status_pill(ui, err, palette.err, palette.err_bg);
    }

    ui.add_space(10.0);

    palette.card_frame().show(ui, |ui| {
        section_label(ui, palette, "CONTINUOUS PATH & LOSS HEATMAP (LAST 40 ROUNDS)");
        ui.add_space(6.0);
        let row_count = state.hops.len();
        TableBuilder::new(ui)
            .id_salt("mtr_heatmap_table")
            .striped(true)
            .resizable(true)
            .max_scroll_height(310.0)
            .column(Column::exact(38.0))
            .column(Column::initial(200.0).at_least(130.0))
            .column(Column::exact(58.0))
            .column(Column::exact(46.0))
            .column(Column::exact(62.0))
            .column(Column::exact(62.0))
            .column(Column::exact(62.0))
            .column(Column::exact(62.0))
            .column(Column::exact(60.0))
            .column(Column::remainder().at_least(180.0))
            .header(22.0, |mut h| {
                h.col(|ui| {
                    ui.strong("#");
                });
                h.col(|ui| {
                    ui.strong("Host / IP");
                });
                h.col(|ui| {
                    ui.strong("Loss%");
                });
                h.col(|ui| {
                    ui.strong("Snt");
                });
                h.col(|ui| {
                    ui.strong("Last");
                });
                h.col(|ui| {
                    ui.strong("Avg");
                });
                h.col(|ui| {
                    ui.strong("Best");
                });
                h.col(|ui| {
                    ui.strong("Wrst");
                });
                h.col(|ui| {
                    ui.strong("StDev");
                });
                h.col(|ui| {
                    ui.strong("Loss Heatmap");
                });
            })
            .body(|body| {
                body.rows(22.0, row_count, |mut row| {
                    let h = &state.hops[row.index()];
                    row.col(|ui| {
                        ui.monospace(h.hop.to_string());
                    });
                    row.col(|ui| {
                        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
                        let txt = match (&h.hostname, h.ip) {
                            (Some(name), Some(ip)) => format!("{name} ({ip})"),
                            (None, Some(ip)) => ip.to_string(),
                            _ => "* * *".into(),
                        };
                        ui.label(&txt).on_hover_text(&txt);
                    });
                    row.col(|ui| {
                        let col = if h.loss_pct >= 10.0 {
                            palette.err
                        } else if h.loss_pct > 0.0 {
                            palette.warn
                        } else {
                            palette.ok
                        };
                        ui.label(
                            egui::RichText::new(format!("{:.1}%", h.loss_pct))
                                .monospace()
                                .color(col),
                        );
                    });
                    row.col(|ui| {
                        ui.monospace(h.sent.to_string());
                    });
                    row.col(|ui| {
                        ui.monospace(fmt_opt(h.last_ms));
                    });
                    row.col(|ui| {
                        ui.monospace(fmt_opt(h.avg_ms));
                    });
                    row.col(|ui| {
                        ui.monospace(fmt_opt(h.best_ms));
                    });
                    row.col(|ui| {
                        ui.monospace(fmt_opt(h.worst_ms));
                    });
                    row.col(|ui| {
                        ui.monospace(fmt_opt(h.stdev_ms));
                    });
                    row.col(|ui| {
                        let (rect, _) = ui.allocate_exact_size(
                            vec2(ui.available_width().max(160.0), 16.0),
                            Sense::hover(),
                        );
                        paint_heatmap(ui.painter(), rect, palette, &h.recent_history);
                    });
                });
            });
    });

    ui.add_space(10.0);

    palette.card_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            section_label(ui, palette, "OUTAGE LOG (2+ CONSECUTIVE DROPS)");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    egui::RichText::new(format!("{} events", state.outages.len()))
                        .size(11.0)
                        .color(palette.text_muted),
                );
            });
        });
        ui.add_space(4.0);
        if state.outages.is_empty() {
            ui.label(
                egui::RichText::new("No outage bursts detected yet.")
                    .size(12.0)
                    .color(palette.text_muted),
            );
        } else {
            egui::ScrollArea::vertical().max_height(130.0).show(ui, |ui| {
                for ev in &state.outages {
                    ui.horizontal(|ui| {
                        ui.monospace(
                            ev.timestamp
                                .with_timezone(&chrono::Local)
                                .format("%H:%M:%S")
                                .to_string(),
                        );
                        ui.label(egui::RichText::new(&ev.description).color(palette.err));
                    });
                }
            });
        }
    });
}

fn fmt_opt(v: Option<f64>) -> String {
    v.map(|x| format!("{x:.1}")).unwrap_or_else(|| "—".into())
}

fn paint_heatmap(
    painter: &egui::Painter,
    rect: Rect,
    palette: &AppPalette,
    history: &std::collections::VecDeque<HopProbeMark>,
) {
    if history.is_empty() {
        return;
    }
    let slots = 40usize;
    let cell_w = (rect.width() / slots as f32).max(3.0);
    let draw_w = (cell_w - 1.5).max(2.0);
    let start_slot = slots.saturating_sub(history.len());

    for (idx, mark) in history.iter().enumerate() {
        let slot = start_slot + idx;
        let x0 = rect.left() + slot as f32 * cell_w;
        let cell = Rect::from_min_max(
            pos2(x0, rect.top() + 2.0),
            pos2(x0 + draw_w, rect.bottom() - 2.0),
        );
        let col = match mark {
            HopProbeMark::Lost => palette.err,
            HopProbeMark::Ok(ms) if *ms > 120.0 => palette.warn,
            HopProbeMark::Ok(ms) if *ms > 50.0 => Color32::from_rgb(76, 175, 80),
            HopProbeMark::Ok(_) => palette.ok,
        };
        painter.rect_filled(cell, 1.5, col);
    }
}
