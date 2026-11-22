use crate::theme::{AppPalette, kv_row, section_label, status_pill};
use egui::{Align, Align2, Color32, FontId, Layout, Pos2, Rect, Sense, Stroke, TextWrapMode, Ui, Vec2, pos2, vec2};
use netscope_core::CancelToken;
use netscope_core::internet_check::{
    InternetCheckEvent, InternetCheckReport, StageHealth, VerdictSeverity, format_report_text,
    run_internet_check,
};
use netscope_core::net_info::PublicNetworkStatus;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

#[derive(Default)]
pub struct InternetCheckState {
    pub running: bool,
    pub current: Option<InternetCheckReport>,
    pub history: Vec<InternetCheckReport>,
    cancel: Option<CancelToken>,
    rx: Option<mpsc::UnboundedReceiver<InternetCheckEvent>>,
}

impl InternetCheckState {
    pub fn start(&mut self, rt: &Runtime, ctx: &egui::Context) {
        self.stop();
        let (tx, rx) = mpsc::unbounded_channel();
        let cancel = CancelToken::new();
        self.cancel = Some(cancel.clone());
        self.rx = Some(rx);
        self.running = true;

        let ctx_clone = ctx.clone();
        rt.spawn(async move {
            let (fwd_tx, mut fwd_rx) = mpsc::unbounded_channel();
            let check_fut = run_internet_check(fwd_tx, cancel);
            let ctx_fwd = ctx_clone.clone();
            let fwd_handle = tokio::spawn(async move {
                while let Some(ev) = fwd_rx.recv().await {
                    let _ = tx.send(ev);
                    ctx_fwd.request_repaint();
                }
            });
            let _ = check_fut.await;
            let _ = fwd_handle.await;
            ctx_clone.request_repaint();
        });
    }

    pub fn stop(&mut self) {
        if let Some(c) = self.cancel.take() {
            c.cancel();
        }
        self.running = false;
    }

    pub fn poll(&mut self) {
        let mut completed = false;
        if let Some(rx) = &mut self.rx {
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    InternetCheckEvent::Progress(r) => {
                        self.current = Some(*r);
                    }
                    InternetCheckEvent::Completed(r) => {
                        let rep = *r;
                        self.history.insert(0, rep.clone());
                        if self.history.len() > 12 {
                            self.history.truncate(12);
                        }
                        self.current = Some(rep);
                        self.running = false;
                        completed = true;
                    }
                }
            }
        }
        if completed {
            self.rx = None;
            self.cancel = None;
        }
    }

    pub fn clear(&mut self) {
        self.stop();
        self.current = None;
        self.history.clear();
    }
}

/// Renders Internet Check and returns `true` if user clicked "Troubleshoot Hops".
pub fn render(
    ui: &mut Ui,
    palette: &AppPalette,
    state: &mut InternetCheckState,
    public_status: Option<&PublicNetworkStatus>,
    rt: &Runtime,
) -> bool {
    let mut jump_to_troubleshoot = false;

    ui.horizontal(|ui| {
        let btn_label = if state.running {
            "Stop Check"
        } else if state.current.is_some() {
            "Run Again"
        } else {
            "Run Internet Check"
        };
        if ui.button(btn_label).clicked() {
            if state.running {
                state.stop();
            } else {
                state.start(rt, ui.ctx());
            }
        }

        if let Some(ref r) = state.current {
            if ui.button("Copy Report").clicked() {
                ui.ctx().copy_text(format_report_text(r));
            }
            if ui
                .button("Troubleshoot Hops ->")
                .on_hover_text("Run hop-by-hop latency & loss root-cause analysis")
                .clicked()
            {
                jump_to_troubleshoot = true;
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let (fg, bg) = match r.verdict.severity {
                    VerdictSeverity::Ok => (palette.ok, palette.ok_bg),
                    VerdictSeverity::Warning => (palette.warn, palette.warn_bg),
                    VerdictSeverity::Error => (palette.err, palette.err_bg),
                };
                status_pill(ui, &r.verdict.headline, fg, bg);
            });
        }
    });

    ui.add_space(10.0);

    let Some(report) = state.current.clone() else {
        palette.card_frame().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(28.0);
                ui.heading("Diagnose Your Connection");
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(
                        "One click tests your local interface, router, upstream internet, DNS, and HTTPS web reachability.",
                    )
                    .color(palette.text_muted),
                );
                ui.add_space(14.0);
                if ui.button("Start Diagnostic Check").clicked() {
                    state.start(rt, ui.ctx());
                }
                ui.add_space(24.0);
            });
        });
        return jump_to_troubleshoot;
    };

    egui::ScrollArea::vertical().show(ui, |ui| {
        // Verdict + 5-node visual pipeline card
        palette.card_frame().show(ui, |ui| {
            let (accent_col, badge_bg) = if state.running {
                (palette.accent, Color32::from_rgba_unmultiplied(10, 132, 255, 28))
            } else {
                match report.verdict.severity {
                    VerdictSeverity::Ok => (palette.ok, palette.ok_bg),
                    VerdictSeverity::Warning => (palette.warn, palette.warn_bg),
                    VerdictSeverity::Error => (palette.err, palette.err_bg),
                }
            };

            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(vec2(38.0, 38.0), Sense::hover());
                let painter = ui.painter();
                painter.circle_filled(rect.center(), 18.0, badge_bg);
                let glyph = if state.running {
                    "..."
                } else {
                    match report.verdict.severity {
                        VerdictSeverity::Ok => "OK",
                        VerdictSeverity::Warning => "!",
                        VerdictSeverity::Error => "X",
                    }
                };
                painter.text(
                    rect.center(),
                    Align2::CENTER_CENTER,
                    glyph,
                    FontId::proportional(13.0),
                    accent_col,
                );
                ui.add_space(8.0);
                ui.vertical(|ui| {
                    ui.label(
                        egui::RichText::new(&report.verdict.headline)
                            .size(16.0)
                            .strong()
                            .color(palette.text_primary),
                    );
                    ui.label(
                        egui::RichText::new(&report.verdict.explanation)
                            .size(12.5)
                            .color(palette.text_muted),
                    );
                });
            });

            ui.add_space(16.0);
            paint_pipeline(ui, palette, &report);
        });

        ui.add_space(12.0);

        ui.columns(2, |cols| {
            cols[0].vertical(|ui| {
                section_label(ui, palette, "STAGE DETAILS");
                ui.add_space(6.0);
                palette.card_frame().show(ui, |ui| {
                    if let Some(ref rt_res) = report.router {
                        stage_sparkline_row(
                            ui,
                            palette,
                            "Router",
                            &rt_res.target_label,
                            &rt_res.samples_ms,
                            rt_res.stats.median_ms,
                            rt_res.stats.jitter_ms,
                            Some(rt_res.stats.loss_pct),
                            rt_res.health,
                        );
                        ui.separator();
                    }
                    if let Some(ref net_res) = report.internet {
                        stage_sparkline_row(
                            ui,
                            palette,
                            "Internet",
                            &net_res.target_label,
                            &net_res.samples_ms,
                            net_res.stats.median_ms,
                            net_res.stats.jitter_ms,
                            Some(net_res.stats.loss_pct),
                            net_res.health,
                        );
                        ui.separator();
                    }
                    if let Some(ref d_res) = report.dns {
                        stage_sparkline_row(
                            ui,
                            palette,
                            "DNS",
                            &format!(
                                "{} ({}/{})",
                                d_res.resolver_label, d_res.resolved_count, d_res.total_count
                            ),
                            &d_res.sample_ms,
                            d_res.median_ms,
                            None,
                            None,
                            d_res.health,
                        );
                        ui.separator();
                    }
                    if let Some(ref w_res) = report.web {
                        ui.horizontal(|ui| {
                            let col = health_color(palette, w_res.health);
                            let (dot, _) = ui.allocate_exact_size(vec2(10.0, 10.0), Sense::hover());
                            ui.painter().circle_filled(dot.center(), 4.5, col);
                            ui.vertical(|ui| {
                                ui.label(egui::RichText::new("Web (HTTPS)").strong());
                                ui.label(
                                    egui::RichText::new(&w_res.url)
                                        .size(11.5)
                                        .color(palette.text_muted),
                                );
                            });
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                let label = match w_res.ttfb_ms {
                                    Some(ms) => format!("{} ({ms:.0} ms)", w_res.detail),
                                    None => w_res.detail.clone(),
                                };
                                ui.label(egui::RichText::new(label).monospace().color(col));
                            });
                        });
                    }
                });
            });

            cols[1].vertical(|ui| {
                section_label(ui, palette, "CONNECTION");
                ui.add_space(6.0);
                palette.card_frame().show(ui, |ui| {
                    kv_row(
                        ui,
                        palette,
                        "Link",
                        &format!(
                            "{} ({})",
                            report.local.link_type.label(),
                            report.local.interface_name
                        ),
                    );
                    kv_row(
                        ui,
                        palette,
                        "Local IPv4",
                        &report
                            .local
                            .local_ipv4
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "—".into()),
                    );
                    kv_row(
                        ui,
                        palette,
                        "Router / GW",
                        &report
                            .local
                            .gateway_ip
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "—".into()),
                    );
                    let pub_ref = report.public.as_ref().or(public_status);
                    kv_row(
                        ui,
                        palette,
                        "Public IP",
                        &pub_ref
                            .and_then(|p| p.public_ip)
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "—".into()),
                    );
                    kv_row(
                        ui,
                        palette,
                        "VPN",
                        if report.local.vpn_active {
                            "Active"
                        } else {
                            "Off"
                        },
                    );
                    kv_row(
                        ui,
                        palette,
                        "DNS Egress",
                        &pub_ref
                            .and_then(|p| p.dns_resolver_ip)
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "—".into()),
                    );
                    kv_row(
                        ui,
                        palette,
                        "DNS Status",
                        pub_ref
                            .map(|p| p.dns_leak_status.label())
                            .unwrap_or("Checking..."),
                    );
                });

                if !state.history.is_empty() {
                    ui.add_space(10.0);
                    section_label(ui, palette, "EARLIER CHECKS");
                    ui.add_space(6.0);
                    palette.card_frame().show(ui, |ui| {
                        for item in state.history.iter().take(5) {
                            ui.horizontal(|ui| {
                                let col = match item.verdict.severity {
                                    VerdictSeverity::Ok => palette.ok,
                                    VerdictSeverity::Warning => palette.warn,
                                    VerdictSeverity::Error => palette.err,
                                };
                                let (dot, _) =
                                    ui.allocate_exact_size(vec2(10.0, 10.0), Sense::hover());
                                ui.painter().circle_filled(dot.center(), 4.0, col);
                                ui.vertical(|ui| {
                                    ui.label(
                                        egui::RichText::new(&item.verdict.headline).size(12.5),
                                    );
                                    let sub = format!(
                                        "Router {}  •  Internet {}",
                                        item.router
                                            .as_ref()
                                            .and_then(|r| r.stats.median_ms)
                                            .map(|v| format!("{v:.1} ms"))
                                            .unwrap_or_else(|| "—".into()),
                                        item.internet
                                            .as_ref()
                                            .and_then(|i| i.stats.median_ms)
                                            .map(|v| format!("{v:.1} ms"))
                                            .unwrap_or_else(|| "—".into()),
                                    );
                                    ui.label(
                                        egui::RichText::new(sub)
                                            .size(11.0)
                                            .color(palette.text_muted),
                                    );
                                });
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.label(
                                        egui::RichText::new(
                                            item.checked_at
                                                .with_timezone(&chrono::Local)
                                                .format("%H:%M:%S")
                                                .to_string(),
                                        )
                                        .size(11.0)
                                        .color(palette.text_muted),
                                    );
                                });
                            });
                            ui.add_space(4.0);
                        }
                    });
                }
            });
        });
    });

    jump_to_troubleshoot
}

fn health_color(palette: &AppPalette, health: StageHealth) -> Color32 {
    match health {
        StageHealth::Ok => palette.ok,
        StageHealth::Warning => palette.warn,
        StageHealth::Failed => palette.err,
        StageHealth::Running => palette.accent,
        StageHealth::Pending => palette.text_muted,
    }
}

fn health_bg(palette: &AppPalette, health: StageHealth) -> Color32 {
    match health {
        StageHealth::Ok => palette.ok_bg,
        StageHealth::Warning => palette.warn_bg,
        StageHealth::Failed => palette.err_bg,
        StageHealth::Running => Color32::from_rgba_unmultiplied(10, 132, 255, 28),
        StageHealth::Pending => Color32::from_rgba_unmultiplied(140, 145, 155, 26),
    }
}

fn paint_pipeline(ui: &mut Ui, palette: &AppPalette, r: &InternetCheckReport) {
    let desired_width = ui.available_width().max(420.0);
    let (rect, _) = ui.allocate_exact_size(vec2(desired_width, 94.0), Sense::hover());
    let painter = ui.painter();

    let stages = [
        (
            "This Host",
            r.local.link_type.label().to_string(),
            r.local_health,
            "PC",
        ),
        (
            "Router",
            r.router
                .as_ref()
                .and_then(|s| s.stats.median_ms)
                .map(|m| format!("{m:.1} ms"))
                .unwrap_or_else(|| "—".into()),
            r.router.as_ref().map_or(StageHealth::Pending, |s| s.health),
            "GW",
        ),
        (
            "Internet",
            r.internet
                .as_ref()
                .and_then(|s| s.stats.median_ms)
                .map(|m| format!("{m:.1} ms"))
                .unwrap_or_else(|| "—".into()),
            r.internet
                .as_ref()
                .map_or(StageHealth::Pending, |s| s.health),
            "NET",
        ),
        (
            "DNS",
            r.dns
                .as_ref()
                .and_then(|s| s.median_ms)
                .map(|m| format!("{m:.0} ms"))
                .unwrap_or_else(|| "—".into()),
            r.dns.as_ref().map_or(StageHealth::Pending, |s| s.health),
            "DNS",
        ),
        (
            "Web",
            r.web
                .as_ref()
                .and_then(|s| s.ttfb_ms)
                .map(|m| format!("{m:.0} ms"))
                .unwrap_or_else(|| {
                    r.web
                        .as_ref()
                        .map(|w| w.detail.clone())
                        .unwrap_or_else(|| "—".into())
                }),
            r.web.as_ref().map_or(StageHealth::Pending, |s| s.health),
            "WEB",
        ),
    ];

    let margin_x = 58.0;
    let usable_w = (rect.width() - margin_x * 2.0).max(200.0);
    let step = usable_w / 4.0;
    let center_y = rect.top() + 30.0;
    let radius = 21.0;

    let centers: Vec<Pos2> = (0..5)
        .map(|i| pos2(rect.left() + margin_x + step * i as f32, center_y))
        .collect();

    for i in 0..4 {
        let h_right = stages[i + 1].2;
        let line_col = health_color(palette, h_right);
        let p0 = pos2(centers[i].x + radius + 5.0, center_y);
        let p1 = pos2(centers[i + 1].x - radius - 5.0, center_y);
        if p1.x > p0.x {
            painter.line_segment([p0, p1], Stroke::new(2.2, line_col));
        }
    }

    for (i, (title, sub, health, short_tag)) in stages.iter().enumerate() {
        let c = centers[i];
        let fg = health_color(palette, *health);
        let bg = health_bg(palette, *health);
        painter.circle_filled(c, radius, bg);
        painter.circle_stroke(c, radius, Stroke::new(1.5, fg));
        painter.text(
            c,
            Align2::CENTER_CENTER,
            short_tag,
            FontId::proportional(11.0),
            fg,
        );

        let badge_pos = pos2(c.x + radius * 0.68, c.y + radius * 0.68);
        painter.circle_filled(badge_pos, 7.5, fg);
        let s = Stroke::new(1.6, Color32::WHITE);
        match health {
            StageHealth::Ok => {
                // Crisp geometric checkmark
                painter.line_segment(
                    [
                        pos2(badge_pos.x - 3.2, badge_pos.y + 0.2),
                        pos2(badge_pos.x - 0.8, badge_pos.y + 2.6),
                    ],
                    s,
                );
                painter.line_segment(
                    [
                        pos2(badge_pos.x - 0.8, badge_pos.y + 2.6),
                        pos2(badge_pos.x + 3.4, badge_pos.y - 2.4),
                    ],
                    s,
                );
            }
            StageHealth::Failed => {
                // Crisp geometric cross
                painter.line_segment(
                    [
                        pos2(badge_pos.x - 2.6, badge_pos.y - 2.6),
                        pos2(badge_pos.x + 2.6, badge_pos.y + 2.6),
                    ],
                    s,
                );
                painter.line_segment(
                    [
                        pos2(badge_pos.x + 2.6, badge_pos.y - 2.6),
                        pos2(badge_pos.x - 2.6, badge_pos.y + 2.6),
                    ],
                    s,
                );
            }
            StageHealth::Warning => {
                painter.text(
                    badge_pos,
                    Align2::CENTER_CENTER,
                    "!",
                    FontId::proportional(9.5),
                    Color32::WHITE,
                );
            }
            StageHealth::Running => {
                painter.circle_filled(badge_pos, 2.2, Color32::WHITE);
            }
            StageHealth::Pending => {
                painter.line_segment(
                    [
                        pos2(badge_pos.x - 2.8, badge_pos.y),
                        pos2(badge_pos.x + 2.8, badge_pos.y),
                    ],
                    s,
                );
            }
        }

        painter.text(
            pos2(c.x, c.y + radius + 14.0),
            Align2::CENTER_CENTER,
            title,
            FontId::proportional(12.5),
            palette.text_primary,
        );
        painter.text(
            pos2(c.x, c.y + radius + 30.0),
            Align2::CENTER_CENTER,
            sub,
            FontId::proportional(11.0),
            palette.text_muted,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn stage_sparkline_row(
    ui: &mut Ui,
    palette: &AppPalette,
    title: &str,
    subtitle: &str,
    samples: &[Option<f64>],
    median_ms: Option<f64>,
    jitter_ms: Option<f64>,
    loss_pct: Option<f64>,
    health: StageHealth,
) {
    ui.horizontal(|ui| {
        let col = health_color(palette, health);
        let (dot, _) = ui.allocate_exact_size(vec2(10.0, 10.0), Sense::hover());
        ui.painter().circle_filled(dot.center(), 4.5, col);

        // Fixed left column for stage name + target (exact width so all rows align vertically)
        let left_w = 138.0;
        ui.allocate_ui_with_layout(vec2(left_w, 34.0), Layout::top_down(Align::LEFT), |ui| {
            ui.set_width(left_w);
            ui.style_mut().wrap_mode = Some(TextWrapMode::Truncate);
            ui.label(egui::RichText::new(title).strong().size(13.0));
            ui.label(
                egui::RichText::new(subtitle)
                    .size(11.0)
                    .color(palette.text_muted),
            )
            .on_hover_text(subtitle);
        });

        // Sparkline bars
        let (spark_rect, _) = ui.allocate_exact_size(Vec2::new(86.0, 26.0), Sense::hover());
        paint_sparkline_bars(ui.painter(), spark_rect, palette, samples);
        ui.add_space(10.0);

        // Fixed-width horizontal metric columns (never wrapped inside right_to_left!)
        let med_str = median_ms
            .map(|m| format!("{m:.1} ms"))
            .unwrap_or_else(|| "—".into());
        metric_cell(ui, palette, "Median", &med_str, None, 68.0);

        if let Some(jit) = jitter_ms {
            metric_cell(ui, palette, "Jitter", &format!("{jit:.1} ms"), None, 68.0);
        } else {
            ui.allocate_exact_size(vec2(68.0, 32.0), Sense::hover());
        }

        if let Some(loss) = loss_pct {
            let lc = if loss > 0.0 {
                Some(palette.err)
            } else {
                None
            };
            metric_cell(ui, palette, "Loss", &format!("{loss:.0}%"), lc, 46.0);
        } else {
            ui.allocate_exact_size(vec2(46.0, 32.0), Sense::hover());
        }
    });
}

fn metric_cell(
    ui: &mut Ui,
    palette: &AppPalette,
    label: &str,
    value: &str,
    val_color: Option<Color32>,
    width: f32,
) {
    ui.allocate_ui_with_layout(vec2(width, 34.0), Layout::top_down(Align::LEFT), |ui| {
        ui.style_mut().wrap_mode = Some(TextWrapMode::Extend);
        ui.label(
            egui::RichText::new(label)
                .size(10.5)
                .color(palette.text_muted),
        );
        ui.label(
            egui::RichText::new(value)
                .size(12.0)
                .monospace()
                .color(val_color.unwrap_or(palette.text_primary)),
        );
    });
}

fn paint_sparkline_bars(
    painter: &egui::Painter,
    rect: Rect,
    palette: &AppPalette,
    samples: &[Option<f64>],
) {
    if samples.is_empty() {
        return;
    }
    let max_val = samples
        .iter()
        .flatten()
        .copied()
        .fold(10.0_f64, f64::max);
    let slot_w = rect.width() / samples.len().max(1) as f32;
    let bar_w = (slot_w - 2.0).max(3.0);

    for (i, sample) in samples.iter().enumerate() {
        let x0 = rect.left() + i as f32 * slot_w;
        match sample {
            Some(ms) => {
                let frac = (*ms / max_val).clamp(0.18, 1.0) as f32;
                let h = rect.height() * frac;
                let col = if *ms > max_val * 0.8 && *ms > 80.0 {
                    palette.err
                } else {
                    palette.accent
                };
                let bar = Rect::from_min_max(
                    pos2(x0, rect.bottom() - h),
                    pos2(x0 + bar_w, rect.bottom()),
                );
                painter.rect_filled(bar, 1.5, col);
            }
            None => {
                let bar = Rect::from_min_max(
                    pos2(x0, rect.bottom() - 4.0),
                    pos2(x0 + bar_w, rect.bottom()),
                );
                painter.rect_filled(bar, 1.5, palette.err);
            }
        }
    }
}
