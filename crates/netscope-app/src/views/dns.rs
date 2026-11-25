use crate::theme::{AppPalette, section_label, status_pill};
use crate::widgets::{HistoryPickAction, host_history_picker};
use egui::{Align, Layout, Sense, Ui};
use egui_extras::{Column, TableBuilder};
use netscope_core::dns::{
    DNS_LOOKUP_TIMEOUT, DnsLookupResult, DnsLookupStatus, DnsRecordType, DnsServerChoice,
    detect_system_dns_servers, format_system_dns_pill, lookup,
};
use netscope_core::history::PersistedState;
use std::collections::BTreeMap;
use std::net::IpAddr;
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

#[derive(Debug, Clone)]
pub struct DnsLookupError {
    pub query: String,
    pub record_type: DnsRecordType,
    pub server_label: String,
    pub message: String,
}

pub struct DnsState {
    pub query: String,
    pub record_type: DnsRecordType,
    pub server_preset: ServerPreset,
    pub custom_server_ip: String,
    pub system_dns_servers: Vec<IpAddr>,
    pub view_mode: DnsViewMode,
    pub type_filter: Option<String>,
    pub running: bool,
    pub active_summary: Option<String>,
    pub result: Option<DnsLookupResult>,
    pub error: Option<DnsLookupError>,
    request_id: u64,
    rx: Option<mpsc::UnboundedReceiver<(u64, Result<DnsLookupResult, DnsLookupError>)>>,
}

impl Default for DnsState {
    fn default() -> Self {
        Self {
            query: "cloudflare.com".into(),
            record_type: DnsRecordType::All,
            server_preset: ServerPreset::System,
            custom_server_ip: "1.1.1.1".into(),
            system_dns_servers: detect_system_dns_servers(),
            view_mode: DnsViewMode::Structured,
            type_filter: None,
            running: false,
            active_summary: None,
            result: None,
            error: None,
            request_id: 0,
            rx: None,
        }
    }
}

impl DnsState {
    pub fn cancel(&mut self) {
        self.request_id = self.request_id.wrapping_add(1);
        self.rx = None;
        self.running = false;
        self.active_summary = None;
    }

    pub fn start(&mut self, rt: &Runtime, ctx: &egui::Context) {
        self.request_id = self.request_id.wrapping_add(1);
        let req_id = self.request_id;
        // Clear previous results immediately so stale records never mislead across switches.
        self.result = None;
        self.error = None;
        self.type_filter = None;

        if self.server_preset == ServerPreset::System {
            self.system_dns_servers = detect_system_dns_servers();
        }

        let query = self.query.clone();
        let rtype = self.record_type;
        let server = match self.server_preset {
            ServerPreset::System => DnsServerChoice::System,
            ServerPreset::Cloudflare => DnsServerChoice::Cloudflare,
            ServerPreset::Google => DnsServerChoice::Google,
            ServerPreset::Quad9 => DnsServerChoice::Quad9,
            ServerPreset::Custom => DnsServerChoice::Custom(self.custom_server_ip.clone()),
        };
        let server_label = match self.server_preset {
            ServerPreset::System => format_system_dns_pill(&self.system_dns_servers),
            _ => server.label(),
        };

        self.active_summary = Some(format!(
            "Querying {} records for '{}' via {} ({:.0}s timeout)...",
            rtype.label(),
            query.trim(),
            server_label,
            DNS_LOOKUP_TIMEOUT.as_secs_f64()
        ));

        let (tx, rx) = mpsc::unbounded_channel();
        self.rx = Some(rx);
        self.running = true;

        let ctx_clone = ctx.clone();
        rt.spawn(async move {
            let res = lookup(&query, rtype, &server).await.map_err(|e| DnsLookupError {
                query: query.trim().to_string(),
                record_type: rtype,
                server_label,
                message: e.to_string(),
            });
            let _ = tx.send((req_id, res));
            ctx_clone.request_repaint();
        });
    }

    pub fn poll(&mut self) {
        let mut done = false;
        if let Some(rx) = &mut self.rx
            && let Ok((id, res)) = rx.try_recv()
            && id == self.request_id
        {
            match res {
                Ok(data) => {
                    if !data.resolved_servers.is_empty()
                        && self.server_preset == ServerPreset::System
                    {
                        self.system_dns_servers = data.resolved_servers.clone();
                    }
                    self.result = Some(data);
                    self.error = None;
                }
                Err(e) => {
                    self.result = None;
                    self.error = Some(e);
                }
            }
            self.running = false;
            self.active_summary = None;
            done = true;
        }
        if done {
            self.rx = None;
        }
    }

    pub fn clear(&mut self) {
        self.cancel();
        self.result = None;
        self.error = None;
        self.type_filter = None;
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
    ui.horizontal_wrapped(|ui| {
        ui.label("Domain / IP:");
        let resp = ui.add(
            egui::TextEdit::singleline(&mut state.query)
                .desired_width(225.0)
                .hint_text("example.com or 1.1.1.1"),
        );
        let enter_pressed = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

        if let Some(act) =
            host_history_picker(ui, "dns_hist", &mut state.query, &history.recent_dns_queries)
        {
            match act {
                HistoryPickAction::Selected(q) => {
                    state.query = q;
                    state.start(rt, ui.ctx());
                }
                HistoryPickAction::Removed(q) => {
                    history
                        .recent_dns_queries
                        .retain(|x| !x.eq_ignore_ascii_case(&q));
                    let _ = history.save();
                }
            }
        }

        if ui.button("Lookup").clicked() || enter_pressed {
            history.record_dns(&state.query);
            let _ = history.save();
            state.start(rt, ui.ctx());
        }

        if state.running && ui.button("Cancel").clicked() {
            state.cancel();
        }

        if ui
            .add_enabled(
                !state.query.trim().is_empty(),
                egui::Button::new("Check Propagation ->"),
            )
            .on_hover_text("Check this domain across 14 global DNS resolvers")
            .clicked()
        {
            history.record_dns(&state.query);
            let _ = history.save();
            let prop_type = if state.record_type == DnsRecordType::All {
                if state.query.trim().parse::<IpAddr>().is_ok() {
                    DnsRecordType::PTR
                } else {
                    DnsRecordType::A
                }
            } else {
                state.record_type
            };
            jump = Some(DnsJumpAction::CheckPropagation {
                query: state.query.clone(),
                record_type: prop_type,
            });
        }

        if let Some(ref res) = state.result
            && ui.button("Copy dig Output").clicked()
        {
            ui.ctx().copy_text(res.raw_dig_text.clone());
        }
    });

    ui.add_space(6.0);

    // Row 2: Record type pills (`ALL` first; switching supersedes any in-flight query immediately)
    ui.horizontal_wrapped(|ui| {
        section_label(ui, palette, "RECORD:");
        for rtype in DnsRecordType::LOOKUP_TYPES {
            let selected = state.record_type == rtype;
            let resp = ui.selectable_label(selected, rtype.label());
            let resp = if rtype == DnsRecordType::All {
                resp.on_hover_text("Query A, AAAA, CNAME, MX, TXT, NS, SOA, CAA in parallel (or PTR for IPs)")
            } else {
                resp
            };
            if resp.clicked() {
                state.record_type = rtype;
                if !state.query.trim().is_empty() {
                    state.start(rt, ui.ctx());
                }
            }
        }
    });

    ui.add_space(4.0);

    // Row 3: 1-click Resolver pills (showing live detected System DNS IP) + Custom IP + Timeout badge
    ui.horizontal_wrapped(|ui| {
        section_label(ui, palette, "RESOLVER:");
        let sys_pill = format_system_dns_pill(&state.system_dns_servers);
        let sys_hover = if state.system_dns_servers.is_empty() {
            "OS default DNS resolver".to_string()
        } else {
            let list = state
                .system_dns_servers
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join("\n");
            format!("Detected OS DNS servers:\n{list}")
        };

        for preset in ServerPreset::ALL {
            let selected = state.server_preset == preset;
            let label = match preset {
                ServerPreset::System => sys_pill.as_str(),
                ServerPreset::Cloudflare => "1.1.1.1",
                ServerPreset::Google => "8.8.8.8",
                ServerPreset::Quad9 => "9.9.9.9",
                ServerPreset::Custom => "Custom",
            };
            let resp = ui.selectable_label(selected, label);
            let resp = if preset == ServerPreset::System {
                resp.on_hover_text(&sys_hover)
            } else {
                resp
            };
            if resp.clicked() {
                state.server_preset = preset;
                if preset != ServerPreset::Custom && !state.query.trim().is_empty() {
                    state.start(rt, ui.ctx());
                }
            }
        }
        if state.server_preset == ServerPreset::Custom {
            let ip_resp = ui.add(
                egui::TextEdit::singleline(&mut state.custom_server_ip)
                    .desired_width(135.0)
                    .hint_text("e.g. 192.168.1.1"),
            );
            if ip_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                state.start(rt, ui.ctx());
            }
        }

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            status_pill(
                ui,
                &format!("Timeout {:.0}s", DNS_LOOKUP_TIMEOUT.as_secs_f64()),
                palette.text_muted,
                palette.card_subtle_bg,
            );
        });
    });

    ui.add_space(10.0);

    // Active loading state (replaces stale results cleanly)
    if state.running {
        palette.card_frame().show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.spinner();
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(
                        state
                            .active_summary
                            .as_deref()
                            .unwrap_or("Running DNS lookup..."),
                    )
                    .size(13.0)
                    .color(palette.text_primary),
                );
            });
        });
        return jump;
    }

    // Dedicated error card (timeout / firewall block / invalid input — no stale table underneath)
    if let Some(ref err) = state.error {
        palette.card_frame().show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                status_pill(ui, "LOOKUP FAILED", palette.err, palette.err_bg);
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(format!(
                        "{} · {} · {}",
                        err.query,
                        err.record_type.label(),
                        err.server_label
                    ))
                    .size(12.5)
                    .monospace()
                    .color(palette.text_muted),
                );
            });
            ui.add_space(8.0);
            ui.add(
                egui::Label::new(
                    egui::RichText::new(&err.message)
                        .size(13.0)
                        .color(palette.err),
                )
                .wrap(),
            );
        });
        return jump;
    }

    // Structured Result View (handles Found, NoRecords, and NxDomain cleanly)
    if let Some(ref res) = state.result {
        let min_ttl = res.records.iter().map(|r| r.ttl).min();
        let servers_tooltip = if res.resolved_servers.is_empty() {
            res.server_label.clone()
        } else {
            let ips = res
                .resolved_servers
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join("\n");
            format!("{}\n{ips}", res.server_label)
        };

        let status_color = match res.status {
            DnsLookupStatus::Found => palette.ok,
            DnsLookupStatus::NoRecords => palette.warn,
            DnsLookupStatus::NxDomain => palette.err,
        };

        // Summary KPI Strip
        ui.columns(4, |cols| {
            dns_kpi_card(
                &mut cols[0],
                palette,
                "Records",
                &match res.status {
                    DnsLookupStatus::Found => res.records.len().to_string(),
                    DnsLookupStatus::NoRecords => "0 (NODATA)".into(),
                    DnsLookupStatus::NxDomain => "NXDOMAIN".into(),
                },
                Some(status_color),
                None,
            );
            dns_kpi_card(
                &mut cols[1],
                palette,
                "Query Time",
                &format!("{:.1} ms", res.query_time_ms),
                Some(palette.accent),
                None,
            );
            dns_kpi_card(
                &mut cols[2],
                palette,
                "Min TTL",
                &min_ttl
                    .map(format_human_ttl)
                    .unwrap_or_else(|| "—".into()),
                None,
                None,
            );
            dns_kpi_card(
                &mut cols[3],
                palette,
                "Resolver",
                &res.server_label,
                None,
                Some(&servers_tooltip),
            );
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
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new(format!("{} ({})", res.query, res.record_type.label()))
                        .size(11.5)
                        .monospace()
                        .color(palette.text_muted),
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
                    if res.records.is_empty() {
                        let (badge, fg, bg, msg) = match res.status {
                            DnsLookupStatus::NxDomain => (
                                "NXDOMAIN",
                                palette.err,
                                palette.err_bg,
                                format!(
                                    "Domain '{}' does not exist according to {}.",
                                    res.query, res.server_label
                                ),
                            ),
                            _ => (
                                "NO RECORDS",
                                palette.warn,
                                palette.warn_bg,
                                format!(
                                    "No {} records were returned for '{}' via {}.",
                                    res.record_type.label(),
                                    res.query,
                                    res.server_label
                                ),
                            ),
                        };
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            status_pill(ui, badge, fg, bg);
                            ui.add_space(6.0);
                            ui.label(
                                egui::RichText::new(msg)
                                    .size(12.5)
                                    .color(palette.text_muted),
                            );
                        });
                        ui.add_space(8.0);
                    } else {
                        // When `ALL` returned multiple record types, show quick filter pills
                        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
                        for r in &res.records {
                            *counts.entry(r.record_type.as_str()).or_insert(0) += 1;
                        }
                        if counts.len() > 1 {
                            ui.horizontal_wrapped(|ui| {
                                let all_sel = state.type_filter.is_none();
                                if ui
                                    .selectable_label(all_sel, format!("All ({})", res.records.len()))
                                    .clicked()
                                {
                                    state.type_filter = None;
                                }
                                for (rtype, cnt) in &counts {
                                    let sel = state.type_filter.as_deref() == Some(*rtype);
                                    if ui
                                        .selectable_label(sel, format!("{rtype} ({cnt})"))
                                        .clicked()
                                    {
                                        state.type_filter = Some((*rtype).to_string());
                                    }
                                }
                            });
                            ui.add_space(6.0);
                        }

                        let filtered: Vec<_> = res
                            .records
                            .iter()
                            .filter(|r| {
                                state
                                    .type_filter
                                    .as_deref()
                                    .is_none_or(|f| r.record_type == f)
                            })
                            .collect();

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
                                body.rows(24.0, filtered.len(), |mut row| {
                                    let rec = filtered[row.index()];
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
    } else {
        palette.card_frame().show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(
                egui::RichText::new(
                    "Enter a domain or IP, pick ALL or a specific record type & resolver, and click Lookup.",
                )
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
    hover: Option<&str>,
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
                    .size(13.5)
                    .strong()
                    .monospace()
                    .color(color.unwrap_or(palette.text_primary)),
            )
            .truncate(),
        )
        .on_hover_text(hover.unwrap_or(value));
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
