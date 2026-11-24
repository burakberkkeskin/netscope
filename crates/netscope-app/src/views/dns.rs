use crate::theme::{AppPalette, section_label, status_pill};
use crate::widgets::{HistoryPickAction, host_history_picker};
use egui::{Align, Layout, Sense, Ui};
use egui_extras::{Column, TableBuilder};
use netscope_core::dns::{DnsLookupResult, DnsRecordType, DnsServerChoice, lookup};
use netscope_core::history::PersistedState;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerPreset {
    System,
    Cloudflare,
    Google,
    Quad9,
    Custom,
}

impl ServerPreset {
    const ALL: [Self; 5] = [
        Self::System,
        Self::Cloudflare,
        Self::Google,
        Self::Quad9,
        Self::Custom,
    ];

    fn short_label(self) -> &'static str {
        match self {
            Self::System => "System",
            Self::Cloudflare => "1.1.1.1",
            Self::Google => "8.8.8.8",
            Self::Quad9 => "9.9.9.9",
            Self::Custom => "Custom",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsViewMode {
    #[default]
    Structured,
    RawDig,
}

#[derive(Debug, Clone)]
pub enum DnsJumpAction {
    CheckPropagation {
        query: String,
        record_type: DnsRecordType,
    },
}

pub struct DnsState {
    pub query: String,
    pub record_type: DnsRecordType,
    pub server_preset: ServerPreset,
    pub custom_server_ip: String,
    pub view_mode: DnsViewMode,
    pub running: bool,
    pub result: Option<DnsLookupResult>,
    pub error: Option<String>,
    rx: Option<mpsc::UnboundedReceiver<Result<DnsLookupResult, String>>>,
}

impl Default for DnsState {
    fn default() -> Self {
        Self {
            query: "cloudflare.com".into(),
            record_type: DnsRecordType::A,
            server_preset: ServerPreset::System,
            custom_server_ip: "1.1.1.1".into(),
            view_mode: DnsViewMode::Structured,
            running: false,
            result: None,
            error: None,
            rx: None,
        }
    }
}

impl DnsState {
    pub fn start(&mut self, rt: &Runtime, ctx: &egui::Context) {
        self.error = None;
        let query = self.query.clone();
        let rtype = self.record_type;
        let server = match self.server_preset {
            ServerPreset::System => DnsServerChoice::System,
            ServerPreset::Cloudflare => DnsServerChoice::Cloudflare,
            ServerPreset::Google => DnsServerChoice::Google,
            ServerPreset::Quad9 => DnsServerChoice::Quad9,
            ServerPreset::Custom => DnsServerChoice::Custom(self.custom_server_ip.clone()),
        };

        let (tx, rx) = mpsc::unbounded_channel();
        self.rx = Some(rx);
        self.running = true;

        let ctx_clone = ctx.clone();
        rt.spawn(async move {
            let res = lookup(&query, rtype, &server).await.map_err(|e| e.to_string());
            let _ = tx.send(res);
            ctx_clone.request_repaint();
        });
    }

    pub fn poll(&mut self) {
        let mut done = false;
        if let Some(rx) = &mut self.rx
            && let Ok(res) = rx.try_recv()
        {
            match res {
                Ok(data) => {
                    self.result = Some(data);
                    self.error = None;
                }
                Err(e) => {
                    self.error = Some(e);
                }
            }
            self.running = false;
            done = true;
        }
        if done {
            self.rx = None;
        }
    }

    pub fn clear(&mut self) {
        self.result = None;
        self.error = None;
    }
}

pub fn render(
    ui: &mut Ui,
    palette: &AppPalette,
    state: &mut DnsState,
    history: &mut PersistedState,
    rt: &Runtime,
) -> Option<DnsJumpAction> {
    let mut jump = None;

    // Row 1: Domain input + History + Action buttons
    ui.horizontal(|ui| {
        ui.label("Domain / IP:");
        let resp = ui.add(
            egui::TextEdit::singleline(&mut state.query)
                .desired_width(230.0)
                .hint_text("example.com or 1.1.1.1"),
        );
        let enter_pressed = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

        if let Some(act) =
            host_history_picker(ui, "dns_hist", &mut state.query, &history.recent_dns_queries)
        {
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

        if ui
            .add_enabled(!state.running, egui::Button::new("Lookup"))
            .clicked()
            || (!state.running && enter_pressed)
        {
            history.record_dns(&state.query);
            let _ = history.save();
            state.start(rt, ui.ctx());
        }

        if ui
            .add_enabled(
                !state.query.trim().is_empty(),
                egui::Button::new("Check Propagation ->"),
            )
            .on_hover_text("Check this domain and record type across 14 global DNS resolvers")
            .clicked()
        {
            history.record_dns(&state.query);
            let _ = history.save();
            jump = Some(DnsJumpAction::CheckPropagation {
                query: state.query.clone(),
                record_type: state.record_type,
            });
        }

        if let Some(ref res) = state.result
            && ui.button("Copy dig Output").clicked()
        {
            ui.ctx().copy_text(res.raw_dig_text.clone());
        }
    });

    ui.add_space(6.0);

    // Row 2: Record type pills
    ui.horizontal_wrapped(|ui| {
        section_label(ui, palette, "RECORD:");
        for rtype in DnsRecordType::ALL {
            let selected = state.record_type == rtype;
            if ui.selectable_label(selected, rtype.label()).clicked() {
                state.record_type = rtype;
                if !state.query.trim().is_empty() && !state.running {
                    state.start(rt, ui.ctx());
                }
            }
        }
    });

    ui.add_space(4.0);

    // Row 3: 1-click Resolver pills + Custom IP
    ui.horizontal_wrapped(|ui| {
        section_label(ui, palette, "RESOLVER:");
        for preset in ServerPreset::ALL {
            let selected = state.server_preset == preset;
            if ui.selectable_label(selected, preset.short_label()).clicked() {
                state.server_preset = preset;
                if preset != ServerPreset::Custom
                    && !state.query.trim().is_empty()
                    && !state.running
                {
                    state.start(rt, ui.ctx());
                }
            }
        }
        if state.server_preset == ServerPreset::Custom {
            let ip_resp = ui.add(
                egui::TextEdit::singleline(&mut state.custom_server_ip)
                    .desired_width(130.0)
                    .hint_text("Resolver IP"),
            );
            if ip_resp.lost_focus()
                && ui.input(|i| i.key_pressed(egui::Key::Enter))
                && !state.running
            {
                state.start(rt, ui.ctx());
            }
        }
    });

    if let Some(ref err) = state.error {
        ui.add_space(6.0);
        status_pill(ui, err, palette.err, palette.err_bg);
    }

    ui.add_space(10.0);

    if let Some(ref res) = state.result {
        let min_ttl = res.records.iter().map(|r| r.ttl).min();

        // Summary KPI Strip
        ui.columns(4, |cols| {
            dns_kpi_card(
                &mut cols[0],
                palette,
                "Records",
                &res.records.len().to_string(),
                Some(palette.ok),
            );
            dns_kpi_card(
                &mut cols[1],
                palette,
                "Query Time",
                &format!("{:.1} ms", res.query_time_ms),
                Some(palette.accent),
            );
            dns_kpi_card(
                &mut cols[2],
                palette,
                "Min TTL",
                &min_ttl
                    .map(format_human_ttl)
                    .unwrap_or_else(|| "—".into()),
                None,
            );
            dns_kpi_card(&mut cols[3], palette, "Resolver", &res.server_label, None);
        });

        ui.add_space(10.0);

        palette.card_frame().show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                section_label(
                    ui,
                    palette,
                    match state.view_mode {
                        DnsViewMode::Structured => "ANSWER RECORDS",
                        DnsViewMode::RawDig => "RAW DIG OUTPUT",
                    },
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .selectable_label(state.view_mode == DnsViewMode::RawDig, "Raw dig")
                        .clicked()
                    {
                        state.view_mode = DnsViewMode::RawDig;
                    }
                    if ui
                        .selectable_label(
                            state.view_mode == DnsViewMode::Structured,
                            "Structured Table",
                        )
                        .clicked()
                    {
                        state.view_mode = DnsViewMode::Structured;
                    }
                });
            });
            ui.add_space(6.0);

            match state.view_mode {
                DnsViewMode::Structured => {
                    let max_h = ui.available_height().max(240.0);
                    TableBuilder::new(ui)
                        .id_salt("dns_lookup_table")
                        .striped(true)
                        .max_scroll_height(max_h)
                        .column(Column::exact(210.0))
                        .column(Column::exact(105.0))
                        .column(Column::exact(72.0))
                        .column(Column::remainder())
                        .header(22.0, |mut h| {
                            h.col(|ui| {
                                ui.strong("Name");
                            });
                            h.col(|ui| {
                                ui.strong("TTL");
                            });
                            h.col(|ui| {
                                ui.strong("Type");
                            });
                            h.col(|ui| {
                                ui.strong("Value (click to copy)");
                            });
                        })
                        .body(|body| {
                            body.rows(24.0, res.records.len(), |mut row| {
                                let rec = &res.records[row.index()];
                                row.col(|ui| {
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(&rec.name).monospace(),
                                        )
                                        .truncate(),
                                    )
                                    .on_hover_text(&rec.name);
                                });
                                row.col(|ui| {
                                    ui.monospace(format_human_ttl(rec.ttl));
                                });
                                row.col(|ui| {
                                    status_pill(
                                        ui,
                                        &rec.record_type,
                                        palette.accent,
                                        palette.card_subtle_bg,
                                    );
                                });
                                row.col(|ui| {
                                    let resp = ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(&rec.value).monospace(),
                                        )
                                        .truncate()
                                        .sense(Sense::click()),
                                    );
                                    if resp
                                        .on_hover_text(format!("{}\nClick to copy", rec.value))
                                        .clicked()
                                    {
                                        ui.ctx().copy_text(rec.value.clone());
                                    }
                                });
                            });
                        });
                }
                DnsViewMode::RawDig => {
                    let mut raw = res.raw_dig_text.clone();
                    egui::ScrollArea::vertical()
                        .id_salt("dns_raw_dig_scroll")
                        .max_height(ui.available_height().max(240.0))
                        .show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut raw)
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(f32::INFINITY)
                                    .desired_rows(12),
                            );
                        });
                }
            }
        });
    } else if !state.running {
        palette.card_frame().show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(
                egui::RichText::new("Enter a domain or IP, pick record type & resolver, and click Lookup.")
                    .color(palette.text_muted),
            );
        });
    }

    jump
}

fn dns_kpi_card(
    ui: &mut Ui,
    palette: &AppPalette,
    title: &str,
    value: &str,
    color: Option<egui::Color32>,
) {
    palette.subtle_card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.set_min_height(42.0);
        ui.label(
            egui::RichText::new(title)
                .size(11.0)
                .color(palette.text_muted),
        );
        ui.add(
            egui::Label::new(
                egui::RichText::new(value)
                    .size(14.5)
                    .strong()
                    .monospace()
                    .color(color.unwrap_or(palette.text_primary)),
            )
            .truncate(),
        )
        .on_hover_text(value);
    });
}

fn format_human_ttl(ttl: u32) -> String {
    if ttl >= 86_400 {
        format!("{ttl}s ({}d)", ttl / 86_400)
    } else if ttl >= 3_600 {
        format!("{ttl}s ({}h)", ttl / 3_600)
    } else if ttl >= 60 {
        format!("{ttl}s ({}m)", ttl / 60)
    } else {
        format!("{ttl}s")
    }
}
