use crate::theme::{AppPalette, section_label, status_pill};
use egui::{Align, Align2, Color32, FontId, Layout, Pos2, Rect, Sense, Stroke, Ui, pos2, vec2};
use egui_extras::{Column, TableBuilder};
use netscope_core::CancelToken;
use netscope_core::internet_check::{StageHealth, VerdictSeverity};
use netscope_core::ipv6_check::{
    CheckStatus, Ipv6AddressScope, Ipv6CheckEvent, Ipv6CheckReport, MtuReport,
    format_ipv6_report_text, run_ipv6_check,
};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

#[derive(Default)]
pub struct Ipv6CheckState {
    pub running: bool,
    pub current: Option<Ipv6CheckReport>,
    cancel: Option<CancelToken>,
    rx: Option<mpsc::UnboundedReceiver<Ipv6CheckEvent>>,
}

impl Ipv6CheckState {
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
            let check_fut = run_ipv6_check(fwd_tx, cancel);
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
                    Ipv6CheckEvent::Progress(r) => {
                        self.current = Some(*r);
                    }
                    Ipv6CheckEvent::Completed(r) => {
                        self.current = Some(*r);
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
    }

    pub fn copy_text(&self) -> String {
        self.current
            .as_ref()
            .map(format_ipv6_report_text)
            .unwrap_or_default()
    }
}

pub fn render(ui: &mut Ui, palette: &AppPalette, state: &mut Ipv6CheckState, rt: &Runtime) {
    ui.horizontal(|ui| {
        let btn_label = if state.running {
            "Stop Audit"
        } else if state.current.is_some() {
            "Run Again"
        } else {
            "Run IPv6 Audit"
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
                ui.ctx().copy_text(format_ipv6_report_text(r));
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let (fg, bg) = match r.verdict.severity {
                    VerdictSeverity::Ok => (palette.ok, palette.ok_bg),
                    VerdictSeverity::Warning => (palette.warn, palette.warn_bg),
                    VerdictSeverity::Error => (palette.err, palette.err_bg),
                };
                status_pill(
                    ui,
                    &format!(
                        "{} · {}/{}",
                        r.verdict.headline, r.verdict.score, r.verdict.max_score
                    ),
                    fg,
                    bg,
                );
            });
        }
    });

    ui.add_space(10.0);

    let Some(report) = state.current.clone() else {
        palette.card_frame().show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.vertical_centered(|ui| {
                ui.add_space(28.0);
                ui.heading("IPv6 Diagnostics & Readiness Audit");
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(
                        "Inspects GUA/SLAAC/ULA addressing, Router Advertisements (M/O/A/L), scoped NDP gateway, global ICMPv6, DNS AAAA/IPv6 transport, Dual-Stack Happy Eyeballs, NAT66, and PMTUD blackholes.",
                    )
                    .color(palette.text_muted),
                );
                ui.add_space(14.0);
                if ui.button("Start IPv6 Audit").clicked() {
                    state.start(rt, ui.ctx());
                }
                ui.add_space(24.0);
            });
        });
        return;
    };

    egui::ScrollArea::vertical()
        .id_salt("ipv6_diag_scroll")
        .show(ui, |ui| {
            // 1. Verdict + 6-Node Visual Pipeline Card
            palette.card_frame().show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                let (accent_col, badge_bg) = if state.running {
                    (palette.accent, palette.card_subtle_bg)
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

                ui.add_space(14.0);
                paint_ipv6_pipeline(ui, palette, &report);
            });

            ui.add_space(12.0);

            // 2. Two-Column Detail Grid (explicit ADR-006 top-down sizing)
            let total_w = ui.available_width();
            let gap = 12.0;
            let col_w = ((total_w - gap) * 0.5).max(260.0);

            ui.horizontal_top(|ui| {
                // Left column: Addressing & Provisioning
                ui.allocate_ui_with_layout(
                    vec2(col_w, 10.0),
                    Layout::top_down(Align::LEFT),
                    |ui| {
                        ui.set_width(col_w);
                        section_label(ui, palette, "ADDRESSING & PROVISIONING");
                        ui.add_space(6.0);
                        palette.card_frame().show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            detail_kv_row(
                                ui,
                                palette,
                                "Interface",
                                &format!(
                                    "{} ({})",
                                    report.inventory.interface_name,
                                    report.inventory.link_type.label()
                                ),
                            );
                            detail_kv_row(
                                ui,
                                palette,
                                "Provisioning",
                                &report.inventory.ra_router.provisioning_summary,
                            );
                            detail_kv_row(
                                ui,
                                palette,
                                "IPv6 Gateway",
                                report
                                    .inventory
                                    .ra_router
                                    .gateway_display
                                    .as_deref()
                                    .unwrap_or("—"),
                            );

                            let ra_pfx = report
                                .inventory
                                .ra_prefixes
                                .iter()
                                .find(|p| !p.prefix.starts_with("fd") && !p.prefix.starts_with("fc"))
                                .or_else(|| report.inventory.ra_prefixes.first());
                            let ra_val = ra_pfx
                                .map(|p| {
                                    format!(
                                        "{} (vl {}s · pl {}s)",
                                        p.prefix,
                                        p.valid_lft.as_deref().unwrap_or("?"),
                                        p.preferred_lft.as_deref().unwrap_or("?")
                                    )
                                })
                                .unwrap_or_else(|| "—".into());
                            detail_kv_row(ui, palette, "RA Prefix", &ra_val);

                            let dns_val = if report.inventory.ipv6_dns_servers.is_empty() {
                                "None (IPv4 DNS only)".into()
                            } else {
                                report
                                    .inventory
                                    .ipv6_dns_servers
                                    .iter()
                                    .map(|i| i.to_string())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            };
                            detail_kv_row(ui, palette, "IPv6 DNS", &dns_val);

                            ui.add_space(6.0);
                            ui.separator();
                            ui.add_space(6.0);
                            section_label(ui, palette, "INTERFACE ADDRESSES");
                            ui.add_space(4.0);

                            if report.inventory.addresses.is_empty() {
                                ui.label(
                                    egui::RichText::new("No IPv6 addresses assigned.")
                                        .size(12.0)
                                        .color(palette.text_muted),
                                );
                            } else {
                                for entry in &report.inventory.addresses {
                                    ui.horizontal(|ui| {
                                        let (s_fg, s_bg) = match entry.scope {
                                            Ipv6AddressScope::GlobalUnicast => {
                                                (palette.ok, palette.ok_bg)
                                            }
                                            Ipv6AddressScope::UniqueLocal => {
                                                (palette.accent, palette.card_subtle_bg)
                                            }
                                            _ => (palette.text_muted, palette.card_subtle_bg),
                                        };
                                        status_pill(ui, entry.scope.badge_label(), s_fg, s_bg);
                                        if entry.is_temporary {
                                            status_pill(
                                                ui,
                                                "TEMP",
                                                palette.accent,
                                                palette.card_subtle_bg,
                                            );
                                        } else if entry.is_slaac {
                                            status_pill(
                                                ui,
                                                "SLAAC",
                                                palette.text_muted,
                                                palette.card_subtle_bg,
                                            );
                                        }
                                        if entry.is_duplicated || entry.is_tentative {
                                            status_pill(ui, "DAD!", palette.err, palette.err_bg);
                                        } else if entry.is_deprecated {
                                            status_pill(ui, "DEPR", palette.warn, palette.warn_bg);
                                        }

                                        let full = format!("{}/{}", entry.addr, entry.prefix_len);
                                        let resp = ui.add(
                                            egui::Label::new(
                                                egui::RichText::new(&full)
                                                    .size(11.5)
                                                    .monospace()
                                                    .color(palette.text_primary),
                                            )
                                            .truncate()
                                            .sense(Sense::click()),
                                        );
                                        if resp
                                            .on_hover_text(format!("{full}\nClick to copy address"))
                                            .clicked()
                                        {
                                            ui.ctx().copy_text(entry.addr.to_string());
                                        }
                                    });
                                    ui.add_space(2.0);
                                }
                            }
                        });
                    },
                );

                ui.add_space(gap);

                // Right column: Dual-Stack Parity & Path MTU
                ui.allocate_ui_with_layout(
                    vec2(col_w, 10.0),
                    Layout::top_down(Align::LEFT),
                    |ui| {
                        ui.set_width(col_w);
                        section_label(ui, palette, "DUAL-STACK & PATH MTU");
                        ui.add_space(6.0);
                        palette.card_frame().show(ui, |ui| {
                            ui.set_width(ui.available_width());

                            dual_stack_row(
                                ui,
                                palette,
                                "IPv6",
                                &report.dual_stack.ipv6,
                            );
                            ui.add_space(4.0);
                            dual_stack_row(
                                ui,
                                palette,
                                "IPv4",
                                &report.dual_stack.ipv4,
                            );

                            ui.add_space(6.0);
                            ui.horizontal_wrapped(|ui| {
                                let he_fg = if report.dual_stack.ipv6.ok {
                                    palette.accent
                                } else {
                                    palette.warn
                                };
                                status_pill(
                                    ui,
                                    &report.dual_stack.happy_eyeballs_winner,
                                    he_fg,
                                    palette.card_subtle_bg,
                                );

                                let (nat_lbl, nat_fg, nat_bg) = match report.nat66_detected {
                                    Some(false) => ("Native (No NAT66)", palette.ok, palette.ok_bg),
                                    Some(true) => {
                                        ("NAT66 / Tunnel", palette.warn, palette.warn_bg)
                                    }
                                    None => ("NAT66 ?", palette.text_muted, palette.card_subtle_bg),
                                };
                                status_pill(ui, nat_lbl, nat_fg, nat_bg);
                            });

                            ui.add_space(4.0);
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(&report.dual_stack.peering_note)
                                        .size(11.5)
                                        .color(palette.text_muted),
                                )
                                .truncate(),
                            )
                            .on_hover_text(&report.dual_stack.peering_note);

                            ui.add_space(8.0);
                            ui.separator();
                            ui.add_space(6.0);
                            section_label(ui, palette, "PATH MTU & PMTUD");
                            ui.add_space(6.0);

                            paint_mtu_bar(ui, palette, &report.mtu);

                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                let (f_lbl, f_fg, f_bg) = if report.mtu.blackhole_suspected {
                                    ("PMTUD Blackhole!".into(), palette.err, palette.err_bg)
                                } else if report.mtu.large_frame_ok {
                                    let ms = report.mtu.large_frame_ms.unwrap_or(0.0);
                                    (
                                        format!("32 KB TLS Frame OK ({ms:.0} ms)"),
                                        palette.ok,
                                        palette.ok_bg,
                                    )
                                } else {
                                    (
                                        "32 KB TLS Frame Failed".into(),
                                        palette.text_muted,
                                        palette.card_subtle_bg,
                                    )
                                };
                                status_pill(ui, &f_lbl, f_fg, f_bg);
                            });
                            ui.add_space(3.0);
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(&report.mtu.status_summary)
                                        .size(11.5)
                                        .color(palette.text_muted),
                                )
                                .truncate(),
                            )
                            .on_hover_text(&report.mtu.status_summary);
                        });
                    },
                );
            });

            ui.add_space(12.0);

            // 3. Core IPv6 Readiness Checklist Table
            palette.card_frame().show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                section_label(ui, palette, "CORE IPv6 READINESS CHECKLIST");
                ui.add_space(6.0);

                TableBuilder::new(ui)
                    .id_salt("ipv6_checklist_table")
                    .striped(true)
                    .max_scroll_height(280.0)
                    .column(Column::exact(68.0))
                    .column(Column::exact(245.0))
                    .column(Column::remainder())
                    .header(22.0, |mut h| {
                        h.col(|ui| {
                            ui.strong("Status");
                        });
                        h.col(|ui| {
                            ui.strong("Core Check");
                        });
                        h.col(|ui| {
                            ui.strong("Evidence & Technical Details");
                        });
                    })
                    .body(|body| {
                        body.rows(24.0, report.checklist.len(), |mut row| {
                            let item = &report.checklist[row.index()];
                            row.col(|ui| {
                                let (fg, bg) = match item.status {
                                    CheckStatus::Pass => (palette.ok, palette.ok_bg),
                                    CheckStatus::Warn => (palette.warn, palette.warn_bg),
                                    CheckStatus::Fail => (palette.err, palette.err_bg),
                                    CheckStatus::Info => (palette.accent, palette.card_subtle_bg),
                                };
                                status_pill(ui, item.status.label(), fg, bg);
                            });
                            row.col(|ui| {
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(&item.name).strong().size(12.0),
                                    )
                                    .truncate(),
                                );
                            });
                            row.col(|ui| {
                                let resp = ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(&item.evidence)
                                            .size(12.0)
                                            .monospace()
                                            .color(palette.text_primary),
                                    )
                                    .truncate(),
                                );
                                resp.on_hover_text(&item.evidence);
                            });
                        });
                    });
            });
        });
}

fn detail_kv_row(ui: &mut Ui, palette: &AppPalette, key: &str, val: &str) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(key)
                .size(12.0)
                .color(palette.text_muted),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let resp = ui.add(
                egui::Label::new(
                    egui::RichText::new(val)
                        .size(12.0)
                        .monospace()
                        .color(palette.text_primary),
                )
                .truncate(),
            );
            resp.on_hover_text(val);
        });
    });
    ui.add_space(2.0);
}

fn dual_stack_row(
    ui: &mut Ui,
    palette: &AppPalette,
    label: &str,
    probe: &netscope_core::ipv6_check::EndpointProbe,
) {
    ui.horizontal(|ui| {
        let (fg, bg) = if probe.ok {
            (palette.ok, palette.ok_bg)
        } else {
            (palette.err, palette.err_bg)
        };
        status_pill(ui, label, fg, bg);

        let ip_str = probe
            .ip
            .map(|i| i.to_string())
            .unwrap_or_else(|| probe.error.clone().unwrap_or_else(|| "Unreachable".into()));
        let right_txt = if probe.ok {
            format!(
                "{} · {:.0} ms",
                probe.colo.as_deref().unwrap_or("—"),
                probe.latency_ms.unwrap_or(0.0)
            )
        } else {
            "Failed".into()
        };

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(
                egui::RichText::new(&right_txt)
                    .size(11.5)
                    .strong()
                    .color(if probe.ok {
                        palette.text_primary
                    } else {
                        palette.err
                    }),
            );
            ui.add_space(6.0);
            let resp = ui.add(
                egui::Label::new(
                    egui::RichText::new(&ip_str)
                        .size(11.5)
                        .monospace()
                        .color(palette.text_muted),
                )
                .truncate(),
            );
            resp.on_hover_text(&ip_str);
        });
    });
}

fn paint_mtu_bar(ui: &mut Ui, palette: &AppPalette, mtu: &MtuReport) {
    let link_val = mtu.link_mtu.unwrap_or(1500);
    let path_val = mtu.path_mtu;

    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(format!(
                "Path: {}",
                path_val
                    .map(|m| format!("{m} B"))
                    .unwrap_or_else(|| "—".into())
            ))
            .size(12.0)
            .strong()
            .monospace(),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(
                egui::RichText::new(format!("Link: {link_val} B · RFC 8200 Min: 1280 B"))
                    .size(11.0)
                    .color(palette.text_muted),
            );
        });
    });
    ui.add_space(4.0);

    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 14.0), Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, 6.0, palette.card_subtle_bg);
    painter.rect_stroke(
        rect,
        6.0,
        Stroke::new(1.0, palette.card_border),
        egui::StrokeKind::Inside,
    );

    let min_scale = 1200.0_f32;
    let max_scale = (link_val.max(1520)) as f32;
    let map_x = |val: f32| -> f32 {
        let t = ((val - min_scale) / (max_scale - min_scale)).clamp(0.0, 1.0);
        rect.left() + rect.width() * t
    };

    if let Some(p) = path_val {
        let fill_right = map_x(p as f32);
        let fill_rect = Rect::from_min_max(rect.min, pos2(fill_right, rect.bottom()));
        let fill_col = if mtu.blackhole_suspected || p < 1280 {
            palette.err
        } else if p < link_val {
            palette.accent
        } else {
            palette.ok
        };
        painter.rect_filled(fill_rect, 6.0, fill_col);
    }

    // RFC 8200 minimum tick (1280 B)
    let min_x = map_x(1280.0);
    painter.line_segment(
        [pos2(min_x, rect.top() - 1.0), pos2(min_x, rect.bottom() + 1.0)],
        Stroke::new(1.5, palette.warn),
    );
}

fn paint_ipv6_pipeline(ui: &mut Ui, palette: &AppPalette, r: &Ipv6CheckReport) {
    let desired_w = ui.available_width().max(520.0);
    let (rect, _) = ui.allocate_exact_size(vec2(desired_w, 98.0), Sense::hover());
    let painter = ui.painter();

    let count = r.stages.len().max(1);
    let margin_x = 52.0;
    let usable_w = (rect.width() - margin_x * 2.0).max(240.0);
    let step = if count > 1 {
        usable_w / (count - 1) as f32
    } else {
        0.0
    };
    let center_y = rect.top() + 28.0;
    let radius = 20.0;

    let centers: Vec<Pos2> = (0..count)
        .map(|i| pos2(rect.left() + margin_x + step * i as f32, center_y))
        .collect();

    for i in 0..count.saturating_sub(1) {
        let h_right = r.stages[i + 1].health;
        let line_col = health_color(palette, h_right);
        let p0 = pos2(centers[i].x + radius + 5.0, center_y);
        let p1 = pos2(centers[i + 1].x - radius - 5.0, center_y);
        if p1.x > p0.x {
            painter.line_segment([p0, p1], Stroke::new(2.2, line_col));
        }
    }

    for (i, st) in r.stages.iter().enumerate() {
        let c = centers[i];
        let fg = health_color(palette, st.health);
        let bg = health_bg(palette, st.health);
        painter.circle_filled(c, radius, bg);
        painter.circle_stroke(c, radius, Stroke::new(1.5, fg));
        painter.text(
            c,
            Align2::CENTER_CENTER,
            st.kind.node_code(),
            FontId::proportional(10.5),
            fg,
        );

        let badge_pos = pos2(c.x + radius * 0.68, c.y + radius * 0.68);
        painter.circle_filled(badge_pos, 7.0, fg);
        let s = Stroke::new(1.5, Color32::WHITE);
        match st.health {
            StageHealth::Ok => {
                painter.line_segment(
                    [
                        pos2(badge_pos.x - 3.0, badge_pos.y + 0.2),
                        pos2(badge_pos.x - 0.8, badge_pos.y + 2.4),
                    ],
                    s,
                );
                painter.line_segment(
                    [
                        pos2(badge_pos.x - 0.8, badge_pos.y + 2.4),
                        pos2(badge_pos.x + 3.2, badge_pos.y - 2.2),
                    ],
                    s,
                );
            }
            StageHealth::Failed => {
                painter.line_segment(
                    [
                        pos2(badge_pos.x - 2.4, badge_pos.y - 2.4),
                        pos2(badge_pos.x + 2.4, badge_pos.y + 2.4),
                    ],
                    s,
                );
                painter.line_segment(
                    [
                        pos2(badge_pos.x + 2.4, badge_pos.y - 2.4),
                        pos2(badge_pos.x - 2.4, badge_pos.y + 2.4),
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
                        pos2(badge_pos.x - 2.6, badge_pos.y),
                        pos2(badge_pos.x + 2.6, badge_pos.y),
                    ],
                    s,
                );
            }
        }

        painter.text(
            pos2(c.x, c.y + radius + 14.0),
            Align2::CENTER_CENTER,
            &st.title,
            FontId::proportional(12.0),
            palette.text_primary,
        );
        painter.text(
            pos2(c.x, c.y + radius + 29.0),
            Align2::CENTER_CENTER,
            &st.short_badge,
            FontId::proportional(10.8),
            palette.text_muted,
        );
    }
}

fn health_color(palette: &AppPalette, h: StageHealth) -> Color32 {
    match h {
        StageHealth::Ok => palette.ok,
        StageHealth::Warning => palette.warn,
        StageHealth::Failed => palette.err,
        StageHealth::Running => palette.accent,
        StageHealth::Pending => palette.text_muted,
    }
}

fn health_bg(palette: &AppPalette, h: StageHealth) -> Color32 {
    match h {
        StageHealth::Ok => palette.ok_bg,
        StageHealth::Warning => palette.warn_bg,
        StageHealth::Failed => palette.err_bg,
        StageHealth::Running => palette.card_subtle_bg,
        StageHealth::Pending => palette.card_subtle_bg,
    }
}
