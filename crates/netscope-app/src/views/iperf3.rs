use crate::theme::{AppPalette, section_label, status_pill};
use crate::widgets::{
    HistoryPickAction, host_history_picker, ip_family_selector, nice_y_grid_spacer,
};
use egui::{Align, Layout, Ui};
use egui_extras::{Column, TableBuilder};
use egui_plot::{AxisHints, HLine, Legend, Line, LineStyle, Plot, PlotPoints, uniform_grid_spacer};
use netscope_core::history::{Iperf3Record, Iperf3ServerProfile, PersistedState};
use netscope_core::iperf3::{
    Iperf3Config, Iperf3Event, Iperf3Interval, Iperf3Summary, run_iperf3,
};
use netscope_core::{CancelToken, IpFamily};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

pub struct Iperf3State {
    pub profile_name: String,
    pub host: String,
    pub ip_family: IpFamily,
    pub port: u16,
    pub duration_secs: u16,
    pub parallel_streams: u8,
    pub reverse: bool,
    pub bidir: bool,
    pub use_udp: bool,
    pub udp_bandwidth_mbps: u32,
    pub omit_secs: u8,
    pub buffer_len_kb: u16,
    pub no_delay: bool,
    pub running: bool,
    pub intervals: Vec<Iperf3Interval>,
    pub summary: Option<Iperf3Summary>,
    pub error: Option<String>,
    cancel: Option<CancelToken>,
    rx: Option<mpsc::UnboundedReceiver<Iperf3Event>>,
}

impl Default for Iperf3State {
    fn default() -> Self {
        Self {
            profile_name: "Homelab LAN".into(),
            host: "127.0.0.1".into(),
            ip_family: IpFamily::Auto,
            port: 5201,
            duration_secs: 10,
            parallel_streams: 4,
            reverse: false,
            bidir: false,
            use_udp: false,
            udp_bandwidth_mbps: 100,
            omit_secs: 0,
            buffer_len_kb: 128,
            no_delay: false,
            running: false,
            intervals: Vec::new(),
            summary: None,
            error: None,
            cancel: None,
            rx: None,
        }
    }
}

impl Iperf3State {
    pub fn start(&mut self, rt: &Runtime, ctx: &egui::Context) {
        self.stop();
        self.intervals.clear();
        self.summary = None;
        self.error = None;

        let buffer_len_bytes = if self.use_udp {
            1448
        } else {
            u32::from(self.buffer_len_kb.max(4)) * 1024
        };

        let cfg = Iperf3Config {
            host: self.host.clone(),
            port: self.port,
            duration_secs: self.duration_secs,
            parallel_streams: self.parallel_streams,
            reverse: self.reverse,
            bidir: self.bidir,
            use_udp: self.use_udp,
            udp_bandwidth_mbps: self.udp_bandwidth_mbps,
            omit_secs: self.omit_secs,
            buffer_len_bytes,
            no_delay: self.no_delay,
            ip_family: self.ip_family,
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
            run_iperf3(cfg, fwd_tx, cancel).await;
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
        self.intervals.clear();
        self.summary = None;
        self.error = None;
    }

    pub fn load_profile(&mut self, p: &Iperf3ServerProfile) {
        self.profile_name = p.name.clone();
        self.host = p.host.clone();
        self.port = p.port;
        self.parallel_streams = p.parallel_streams;
        self.duration_secs = p.duration_secs;
        self.reverse = p.reverse;
        self.bidir = p.bidir;
        self.use_udp = p.use_udp;
        self.udp_bandwidth_mbps = p.udp_bandwidth_mbps;
        self.omit_secs = p.omit_secs;
        if p.buffer_len_kb > 0 {
            self.buffer_len_kb = p.buffer_len_kb;
        }
        self.no_delay = p.no_delay;
    }

    pub fn poll(&mut self, history: &mut PersistedState) {
        let mut done = false;
        if let Some(rx) = &mut self.rx {
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    Iperf3Event::Interval(iv) => {
                        self.intervals.push(iv);
                    }
                    Iperf3Event::Completed(sum) => {
                        let s = *sum;
                        history.record_iperf3(Iperf3Record {
                            timestamp: s.timestamp,
                            host: s.host.clone(),
                            port: s.port,
                            protocol: s.protocol.clone(),
                            direction: s.direction.clone(),
                            streams: s.streams,
                            duration_secs: s.duration_secs,
                            avg_mbps: s.avg_mbps,
                            retransmits: s.retransmits,
                            jitter_ms: s.jitter_ms,
                            lost_pct: s.lost_pct,
                        });
                        let _ = history.save();
                        self.summary = Some(s);
                        self.running = false;
                        done = true;
                    }
                    Iperf3Event::Error(e) => {
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
    state: &mut Iperf3State,
    history: &mut PersistedState,
    rt: &Runtime,
) {
    // Target & Options Bar (Row 1: -c Host, -p Port, -P Streams, -t Secs, Run button, Engine badge)
    ui.horizontal(|ui| {
        ui.label("Server (-c):");
        ui.add(
            egui::TextEdit::singleline(&mut state.host)
                .desired_width(175.0)
                .hint_text("192.168.1.10 or LAN host"),
        );

        if let Some(act) =
            host_history_picker(ui, "iperf_hist", &mut state.host, &history.recent_hosts)
        {
            match act {
                HistoryPickAction::Selected(h) => state.host = h,
                HistoryPickAction::Removed(h) => {
                    history.remove_host(&h);
                    let _ = history.save();
                }
            }
        }

        ui.label("Port (-p):");
        ui.add(egui::DragValue::new(&mut state.port).range(1..=65535));

        ui.label("Streams (-P):");
        ui.add(egui::DragValue::new(&mut state.parallel_streams).range(1..=32));

        ui.label("Secs (-t):");
        ui.add(egui::DragValue::new(&mut state.duration_secs).range(1..=120));

        let btn = if state.running { "Stop" } else { "Run iperf3" };
        if ui.button(btn).clicked() {
            if state.running {
                state.stop();
            } else {
                history.record_host(&state.host);
                let _ = history.save();
                state.start(rt, ui.ctx());
            }
        }

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            status_pill(
                ui,
                "Engine: Native Rust Wire v3.17",
                palette.ok,
                palette.ok_bg,
            );
        });
    });

    ui.add_space(4.0);

    // Row 2: Standard iperf3 protocol & tuning flags (-R, --bidir, -u, -b, -O, -l, -N)
    ui.horizontal(|ui| {
        if ui
            .checkbox(&mut state.reverse, "Reverse (-R Download)")
            .changed()
            && state.reverse
        {
            state.bidir = false;
        }
        if ui
            .checkbox(&mut state.bidir, "Bidir (--bidir)")
            .on_hover_text("Simultaneous upload + download streams")
            .changed()
            && state.bidir
        {
            state.reverse = false;
        }
        ui.checkbox(&mut state.use_udp, "UDP (-u)");
        if state.use_udp {
            ui.label("Bitrate (-b Mbps):");
            ui.add(egui::DragValue::new(&mut state.udp_bandwidth_mbps).range(1..=10_000));
        } else {
            ui.label("Buf (-l KB):");
            ui.add(egui::DragValue::new(&mut state.buffer_len_kb).range(4..=1024));
            ui.checkbox(&mut state.no_delay, "NoDelay (-N)");
        }
        ui.label("Omit (-O s):");
        ui.add(egui::DragValue::new(&mut state.omit_secs).range(0..=10));
        ip_family_selector(ui, palette, &mut state.ip_family);
    });

    if let Some(ref err) = state.error {
        ui.add_space(6.0);
        status_pill(ui, err, palette.err, palette.err_bg);
    }

    ui.add_space(10.0);

    let avail_h = ui.available_height().max(360.0);
    let total_w = ui.available_width();
    let left_w = 248.0;
    let right_w = (total_w - left_w - 10.0).max(320.0);

    ui.horizontal_top(|ui| {
        // Left: Saved Servers Profiles (explicit top-down width-bounded column)
        ui.allocate_ui_with_layout(egui::vec2(left_w, avail_h), Layout::top_down(Align::Min), |ui| {
            palette.card_frame().show(ui, |ui| {
                ui.set_width(left_w - 28.0);
                section_label(ui, palette, "SAVED SERVERS");
                ui.add_space(6.0);

                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut state.profile_name)
                            .desired_width(136.0)
                            .hint_text("Profile name"),
                    );
                    if ui.button("Save").clicked() && !state.host.trim().is_empty() {
                        let name = if state.profile_name.trim().is_empty() {
                            state.host.trim().to_string()
                        } else {
                            state.profile_name.trim().to_string()
                        };
                        history.upsert_iperf3_server(Iperf3ServerProfile {
                            name,
                            host: state.host.trim().to_string(),
                            port: state.port,
                            parallel_streams: state.parallel_streams,
                            duration_secs: state.duration_secs,
                            reverse: state.reverse,
                            bidir: state.bidir,
                            use_udp: state.use_udp,
                            udp_bandwidth_mbps: state.udp_bandwidth_mbps,
                            omit_secs: state.omit_secs,
                            buffer_len_kb: state.buffer_len_kb,
                            no_delay: state.no_delay,
                        });
                        let _ = history.save();
                    }
                });

                ui.add_space(8.0);
                egui::ScrollArea::vertical().max_height(310.0).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    if history.iperf3_servers.is_empty() {
                        ui.label(
                            egui::RichText::new("No saved servers yet. Enter a host above and click Save.")
                                .size(11.5)
                                .color(palette.text_muted),
                        );
                    }

                    let profiles = history.iperf3_servers.clone();
                    for prof in profiles {
                        palette
                            .subtle_card_frame()
                            .inner_margin(egui::Margin::symmetric(8, 6))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.vertical(|ui| {
                                    ui.label(egui::RichText::new(&prof.name).strong().size(12.5));
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "{}:{} • {}x {}",
                                            prof.host,
                                            prof.port,
                                            prof.parallel_streams,
                                            if prof.use_udp { "UDP" } else { "TCP" }
                                        ))
                                        .size(11.0)
                                        .color(palette.text_muted),
                                    );
                                });
                                ui.horizontal(|ui| {
                                    if ui.small_button("Load").clicked() {
                                        state.load_profile(&prof);
                                    }
                                    if ui
                                        .add_enabled(!state.running, egui::Button::new("Run").small())
                                        .clicked()
                                    {
                                        state.load_profile(&prof);
                                        state.start(rt, ui.ctx());
                                    }
                                    if ui.small_button("Delete").clicked() {
                                        history.remove_iperf3_server(&prof.name);
                                        let _ = history.save();
                                    }
                                });
                            });
                        ui.add_space(4.0);
                    }
                });

                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new("Zero OS binary required. Compatible with any `iperf3 -s` daemon.")
                        .size(10.5)
                        .color(palette.text_muted),
                );
            });
        });

        ui.add_space(8.0);

        // Right: Live Plot + Summary + Past Runs
        ui.allocate_ui_with_layout(egui::vec2(right_w, avail_h), Layout::top_down(Align::Min), |ui| {
            ui.set_width(right_w);

            // Live KPIs
            let latest_mbps = state
                .summary
                .as_ref()
                .map(|s| s.avg_mbps)
                .or_else(|| state.intervals.last().map(|i| i.mbps));
            let retrans_or_jitter = if let Some(ref s) = state.summary {
                if let Some(j) = s.jitter_ms {
                    format!("{j:.2} ms / {:.2}% loss", s.lost_pct.unwrap_or(0.0))
                } else {
                    format!("{} retransmits", s.retransmits.unwrap_or(0))
                }
            } else if let Some(last) = state.intervals.last() {
                if let Some(j) = last.jitter_ms {
                    format!("{j:.2} ms")
                } else {
                    format!("{} retransmits", last.retransmits.unwrap_or(0))
                }
            } else {
                "—".into()
            };

            ui.columns(3, |cols| {
                palette.subtle_card_frame().show(&mut cols[0], |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.label(
                        egui::RichText::new("Throughput")
                            .size(11.0)
                            .color(palette.text_muted),
                    );
                    ui.label(
                        egui::RichText::new(
                            latest_mbps
                                .map(|m| format!("{m:.1} Mbps"))
                                .unwrap_or_else(|| "—".into()),
                        )
                        .size(16.0)
                        .strong()
                        .monospace()
                        .color(palette.accent),
                    );
                });
                palette.subtle_card_frame().show(&mut cols[1], |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.label(
                        egui::RichText::new(if state.use_udp {
                            "Jitter / Loss"
                        } else {
                            "TCP Retransmits"
                        })
                        .size(11.0)
                        .color(palette.text_muted),
                    );
                    ui.label(
                        egui::RichText::new(retrans_or_jitter)
                            .size(14.5)
                            .strong()
                            .monospace(),
                    );
                });
                palette.subtle_card_frame().show(&mut cols[2], |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.label(
                        egui::RichText::new("Transferred")
                            .size(11.0)
                            .color(palette.text_muted),
                    );
                    let mb = state
                        .summary
                        .as_ref()
                        .map(|s| format!("{:.1} MB", s.total_bytes as f64 / 1_048_576.0))
                        .unwrap_or_else(|| "—".into());
                    ui.label(egui::RichText::new(mb).size(15.5).strong().monospace());
                });
            });

            ui.add_space(8.0);

            palette.card_frame().show(ui, |ui| {
                section_label(ui, palette, "LIVE LINK THROUGHPUT (MBPS)");
                ui.add_space(4.0);
                let pts: Vec<[f64; 2]> = state
                    .intervals
                    .iter()
                    .map(|iv| [iv.second, iv.mbps])
                    .collect();
                let y_axis = AxisHints::new_y().min_thickness(44.0).formatter(|mark, _range| {
                    let v = if mark.value.abs() < 0.5 { 0.0 } else { mark.value };
                    format!("{v:.0}")
                });
                let mut plot = Plot::new("iperf3_plot")
                    .height(175.0)
                    .show_background(false)
                    .legend(Legend::default())
                    .include_y(0.0)
                    .custom_y_axes(vec![y_axis])
                    .y_grid_spacer(uniform_grid_spacer(nice_y_grid_spacer))
                    .x_axis_formatter(|mark, _range| {
                        let v = if mark.value.abs() < 0.5 { 0.0 } else { mark.value };
                        format!("{v:.0}s")
                    });
                if pts.is_empty() {
                    plot = plot
                        .default_x_bounds(0.0, 10.0)
                        .default_y_bounds(0.0, 100.0);
                }
                plot.show(ui, |plot_ui| {
                        if !pts.is_empty() {
                            plot_ui.line(
                                Line::new("Throughput", PlotPoints::from(pts))
                                    .color(palette.accent)
                                    .width(2.2)
                                    .fill(0.0)
                                    .fill_alpha(0.14),
                            );
                        }
                        if let Some(ref s) = state.summary {
                            plot_ui.hline(
                                HLine::new("Average Mbps", s.avg_mbps)
                                    .color(palette.ok)
                                    .width(1.2)
                                    .style(LineStyle::dashed_dense()),
                            );
                        }
                    });
            });

            ui.add_space(8.0);

            palette.card_frame().show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                section_label(ui, palette, "RUN HISTORY");
                ui.add_space(4.0);
                if history.iperf3_history.is_empty() {
                    ui.label(
                        egui::RichText::new("No iperf3 runs recorded yet.")
                            .size(12.0)
                            .color(palette.text_muted),
                    );
                } else {
                    TableBuilder::new(ui)
                        .id_salt("iperf3_history_table")
                        .striped(true)
                        .max_scroll_height(135.0)
                        .column(Column::exact(105.0))
                        .column(Column::initial(165.0).at_least(145.0))
                        .column(Column::exact(90.0))
                        .column(Column::exact(90.0))
                        .column(Column::remainder())
                        .header(20.0, |mut h| {
                            h.col(|ui| {
                                ui.strong("When");
                            });
                            h.col(|ui| {
                                ui.strong("Server");
                            });
                            h.col(|ui| {
                                ui.strong("Mode");
                            });
                            h.col(|ui| {
                                ui.strong("Avg Mbps");
                            });
                            h.col(|ui| {
                                ui.strong("Quality");
                            });
                        })
                        .body(|body| {
                            body.rows(20.0, history.iperf3_history.len(), |mut row| {
                                let r = &history.iperf3_history[row.index()];
                                row.col(|ui| {
                                    ui.monospace(
                                        r.timestamp
                                            .with_timezone(&chrono::Local)
                                            .format("%m-%d %H:%M")
                                            .to_string(),
                                    );
                                });
                                row.col(|ui| {
                                    ui.monospace(format!("{}:{}", r.host, r.port));
                                });
                                row.col(|ui| {
                                    ui.label(format!("{} {}x", r.protocol, r.streams));
                                });
                                row.col(|ui| {
                                    ui.monospace(format!("{:.1}", r.avg_mbps));
                                });
                                row.col(|ui| {
                                    let q = if let Some(j) = r.jitter_ms {
                                        format!("{j:.2} ms / {:.1}%", r.lost_pct.unwrap_or(0.0))
                                    } else {
                                        format!("{} retr", r.retransmits.unwrap_or(0))
                                    };
                                    ui.monospace(q);
                                });
                            });
                        });
                }
            });
        });
    });
}
