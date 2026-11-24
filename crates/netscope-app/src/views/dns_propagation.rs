use crate::theme::{AppPalette, section_label, status_pill};
use crate::widgets::{HistoryPickAction, host_history_picker};
use egui::Ui;
use egui_extras::{Column, TableBuilder};
use netscope_core::CancelToken;
use netscope_core::dns::DnsRecordType;
use netscope_core::dns_propagation::{
    GLOBAL_RESOLVERS, PropagationEvent, PropagationOutcome, ResolverResult, ResolverVerdict,
    evaluate_propagation, format_propagation_report, run_propagation,
};
use netscope_core::history::PersistedState;
use std::collections::HashMap;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

pub struct DnsPropagationState {
    pub query: String,
    pub record_type: DnsRecordType,
    pub expected_value: String,
    pub running: bool,
    pub total: usize,
    pub results: Vec<ResolverResult>,
    pub error: Option<String>,
    cancel: Option<CancelToken>,
    rx: Option<mpsc::UnboundedReceiver<PropagationEvent>>,
}

impl Default for DnsPropagationState {
    fn default() -> Self {
        Self {
            query: "cloudflare.com".into(),
            record_type: DnsRecordType::A,
            expected_value: String::new(),
            running: false,
            total: GLOBAL_RESOLVERS.len(),
            results: Vec::new(),
            error: None,
            cancel: None,
            rx: None,
        }
    }
}

impl DnsPropagationState {
    pub fn start(&mut self, rt: &Runtime, ctx: &egui::Context) {
        self.stop();
        self.results.clear();
        self.error = None;
        self.total = GLOBAL_RESOLVERS.len();

        let query = self.query.clone();
        let rtype = self.record_type;
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
            run_propagation(query, rtype, fwd_tx, cancel).await;
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
        self.results.clear();
        self.error = None;
    }

    pub fn poll(&mut self) {
        let mut done = false;
        if let Some(rx) = &mut self.rx {
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    PropagationEvent::Started { total } => {
                        self.total = total;
                    }
                    PropagationEvent::ResolverDone(res) => {
                        self.results.push(res);
                        self.results.sort_by_key(|r| r.index);
                    }
                    PropagationEvent::Error(err) => {
                        self.error = Some(err);
                        self.running = false;
                        done = true;
                    }
                    PropagationEvent::Finished => {
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

    pub fn copy_text(&self) -> String {
        let summary = evaluate_propagation(&self.results, &self.expected_value);
        format_propagation_report(&self.query, self.record_type, &self.results, &summary)
    }
}

pub fn render(
    ui: &mut Ui,
    palette: &AppPalette,
    state: &mut DnsPropagationState,
    history: &mut PersistedState,
    rt: &Runtime,
) {
    ui.horizontal(|ui| {
        ui.label("Domain:");
        let resp = ui.add(
            egui::TextEdit::singleline(&mut state.query)
                .desired_width(205.0)
                .hint_text("example.com or 1.1.1.1"),
        );
        let enter_pressed = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

        if let Some(act) = host_history_picker(
            ui,
            "dns_prop_hist",
            &mut state.query,
            &history.recent_dns_queries,
        ) {
            match act {
                HistoryPickAction::Selected(q) => state.query = q,
                HistoryPickAction::Removed(q) => {
                    history
                        .recent_dns_queries
                        .retain(|x| !x.eq_ignore_ascii_case(&q));
                    let _ = history.save();
                }
            }
        }

        ui.label("Expected:");
        let exp_resp = ui.add(
            egui::TextEdit::singleline(&mut state.expected_value)
                .desired_width(160.0)
                .hint_text("Optional target value"),
        );
        let exp_enter = exp_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

        let btn_label = if state.running { "Stop" } else { "Check" };
        if ui.button(btn_label).clicked() || (!state.running && (enter_pressed || exp_enter)) {
            if state.running {
                state.stop();
            } else {
                history.record_dns(&state.query);
                let _ = history.save();
                state.start(rt, ui.ctx());
            }
        }
    });

    ui.add_space(6.0);

    ui.horizontal_wrapped(|ui| {
        for rtype in DnsRecordType::ALL {
            let selected = state.record_type == rtype;
            if ui.selectable_label(selected, rtype.label()).clicked() {
                state.record_type = rtype;
                if !state.query.trim().is_empty() && !state.running {
                    history.record_dns(&state.query);
                    let _ = history.save();
                    state.start(rt, ui.ctx());
                }
            }
        }
    });

    if let Some(ref err) = state.error {
        ui.add_space(6.0);
        status_pill(ui, err, palette.err, palette.err_bg);
    }

    ui.add_space(10.0);

    let summary = evaluate_propagation(&state.results, &state.expected_value);
    let verdict_map: HashMap<usize, ResolverVerdict> = summary.verdicts.iter().copied().collect();

    if state.running || !state.results.is_empty() {
        palette.card_frame().show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                if state.running {
                    status_pill(
                        ui,
                        &format!("Checking {}/{} resolvers...", summary.completed, state.total),
                        palette.accent,
                        palette.card_subtle_bg,
                    );
                } else if summary.completed > 0 && summary.matched == summary.completed {
                    status_pill(
                        ui,
                        &format!("{}/{} Propagated (100%)", summary.matched, summary.completed),
                        palette.ok,
                        palette.ok_bg,
                    );
                } else if summary.matched > 0 {
                    let pct = (summary.matched as f64 / summary.completed.max(1) as f64) * 100.0;
                    status_pill(
                        ui,
                        &format!(
                            "{}/{} Match ({:.0}%) · {} Divergent · {} Missing",
                            summary.matched,
                            summary.completed,
                            pct,
                            summary.divergent,
                            summary.missing + summary.errors
                        ),
                        palette.warn,
                        palette.warn_bg,
                    );
                } else {
                    status_pill(
                        ui,
                        &format!(
                            "0/{} Matched · {} Missing/Error",
                            summary.completed,
                            summary.missing + summary.errors
                        ),
                        palette.err,
                        palette.err_bg,
                    );
                }

                if let Some(avg) = summary.avg_latency_ms {
                    status_pill(
                        ui,
                        &format!("Avg {avg:.0} ms"),
                        palette.accent,
                        palette.card_subtle_bg,
                    );
                }

                if !summary.consensus_values.is_empty() {
                    let prefix = if state.expected_value.trim().is_empty() {
                        "Consensus:"
                    } else {
                        "Expected:"
                    };
                    ui.label(
                        egui::RichText::new(prefix)
                            .size(12.0)
                            .color(palette.text_muted),
                    );
                    let preview = summary.consensus_values.join(", ");
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(&preview)
                                .size(12.0)
                                .monospace()
                                .color(palette.text_primary),
                        )
                        .truncate(),
                    )
                    .on_hover_text(&preview);
                }
            });
        });

        ui.add_space(8.0);
    }

    palette.card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        section_label(ui, palette, "GLOBAL RESOLVER MATRIX");
        ui.add_space(6.0);

        if state.results.is_empty() {
            let msg = if state.running {
                "Querying System Default + 13 global RFC 8484 DoH resolvers..."
            } else {
                "Enter a domain or IP and click Check to verify DNS propagation across 14 global resolvers."
            };
            ui.label(
                egui::RichText::new(msg)
                    .size(12.5)
                    .color(palette.text_muted),
            );
            return;
        }

        let max_h = ui.available_height().max(260.0);
        TableBuilder::new(ui)
            .id_salt("dns_propagation_table")
            .striped(true)
            .max_scroll_height(max_h)
            .column(Column::exact(155.0))
            .column(Column::exact(140.0))
            .column(Column::exact(92.0))
            .column(Column::exact(76.0))
            .column(Column::exact(64.0))
            .column(Column::remainder())
            .header(22.0, |mut h| {
                h.col(|ui| {
                    ui.strong("Resolver");
                });
                h.col(|ui| {
                    ui.strong("Region");
                });
                h.col(|ui| {
                    ui.strong("Status");
                });
                h.col(|ui| {
                    ui.strong("Latency");
                });
                h.col(|ui| {
                    ui.strong("TTL");
                });
                h.col(|ui| {
                    ui.strong("Answers");
                });
            })
            .body(|body| {
                body.rows(24.0, state.results.len(), |mut row| {
                    let res = &state.results[row.index()];
                    let verdict = verdict_map
                        .get(&res.index)
                        .copied()
                        .unwrap_or(ResolverVerdict::Error);

                    row.col(|ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&res.resolver_name).strong(),
                            )
                            .truncate(),
                        )
                        .on_hover_text(format!("{} ({})", res.resolver_name, res.endpoint_hint));
                    });
                    row.col(|ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&res.region).color(palette.text_muted),
                            )
                            .truncate(),
                        );
                    });
                    row.col(|ui| {
                        let (lbl, fg, bg) = match (&res.outcome, verdict) {
                            (PropagationOutcome::Resolved, ResolverVerdict::Match) => {
                                ("Match", palette.ok, palette.ok_bg)
                            }
                            (PropagationOutcome::Resolved, _) => {
                                ("Divergent", palette.warn, palette.warn_bg)
                            }
                            (PropagationOutcome::NoData, _) => {
                                ("No Data", palette.text_muted, palette.card_subtle_bg)
                            }
                            (PropagationOutcome::NxDomain, _) => {
                                ("NXDOMAIN", palette.warn, palette.warn_bg)
                            }
                            (PropagationOutcome::Error(_), _) => {
                                ("Error", palette.err, palette.err_bg)
                            }
                        };
                        status_pill(ui, lbl, fg, bg);
                    });
                    row.col(|ui| {
                        ui.monospace(format!("{:.0} ms", res.latency_ms));
                    });
                    row.col(|ui| {
                        let ttl = res
                            .min_ttl
                            .map(|t| format!("{t}s"))
                            .unwrap_or_else(|| "—".into());
                        ui.monospace(ttl);
                    });
                    row.col(|ui| {
                        let ans_text = match &res.outcome {
                            PropagationOutcome::Resolved => res.answers.join(", "),
                            PropagationOutcome::NoData => "— (no records)".into(),
                            PropagationOutcome::NxDomain => "— (NXDOMAIN)".into(),
                            PropagationOutcome::Error(e) => e.clone(),
                        };
                        let color = if matches!(res.outcome, PropagationOutcome::Error(_)) {
                            palette.err
                        } else {
                            palette.text_primary
                        };
                        let label_resp = ui.add(
                            egui::Label::new(
                                egui::RichText::new(&ans_text).monospace().color(color),
                            )
                            .truncate(),
                        );
                        if !ans_text.is_empty() {
                            label_resp.on_hover_text(&ans_text);
                        }
                    });
                });
            });
    });
}
