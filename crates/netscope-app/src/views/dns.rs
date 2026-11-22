use crate::theme::{AppPalette, section_label, status_pill};
use crate::widgets::{HistoryPickAction, host_history_picker};
use egui::Ui;
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

pub struct DnsState {
    pub query: String,
    pub record_type: DnsRecordType,
    pub server_preset: ServerPreset,
    pub custom_server_ip: String,
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
) {
    ui.horizontal(|ui| {
        ui.label("Domain / IP:");
        let resp = ui.add(
            egui::TextEdit::singleline(&mut state.query)
                .desired_width(210.0)
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

        ui.label("Server:");
        egui::ComboBox::from_id_salt("dns_server")
            .selected_text(match state.server_preset {
                ServerPreset::System => "System",
                ServerPreset::Cloudflare => "1.1.1.1",
                ServerPreset::Google => "8.8.8.8",
                ServerPreset::Quad9 => "9.9.9.9",
                ServerPreset::Custom => "Custom",
            })
            .width(100.0)
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut state.server_preset, ServerPreset::System, "System");
                ui.selectable_value(
                    &mut state.server_preset,
                    ServerPreset::Cloudflare,
                    "Cloudflare (1.1.1.1)",
                );
                ui.selectable_value(
                    &mut state.server_preset,
                    ServerPreset::Google,
                    "Google (8.8.8.8)",
                );
                ui.selectable_value(
                    &mut state.server_preset,
                    ServerPreset::Quad9,
                    "Quad9 (9.9.9.9)",
                );
                ui.selectable_value(&mut state.server_preset, ServerPreset::Custom, "Custom IP");
            });

        if state.server_preset == ServerPreset::Custom {
            ui.add(
                egui::TextEdit::singleline(&mut state.custom_server_ip)
                    .desired_width(120.0)
                    .hint_text("Resolver IP"),
            );
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

        if let Some(ref res) = state.result
            && ui.button("Copy dig Output").clicked()
        {
            ui.ctx().copy_text(res.raw_dig_text.clone());
        }
    });

    ui.add_space(6.0);

    // Record type selector bar
    ui.horizontal_wrapped(|ui| {
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

    if let Some(ref err) = state.error {
        ui.add_space(6.0);
        status_pill(ui, err, palette.err, palette.err_bg);
    }

    ui.add_space(10.0);

    if let Some(ref res) = state.result {
        ui.horizontal(|ui| {
            status_pill(
                ui,
                &format!("{} records", res.records.len()),
                palette.ok,
                palette.ok_bg,
            );
            status_pill(
                ui,
                &format!("{:.1} ms", res.query_time_ms),
                palette.accent,
                palette.card_subtle_bg,
            );
            ui.label(
                egui::RichText::new(format!("Server: {}", res.server_label))
                    .size(12.0)
                    .color(palette.text_muted),
            );
        });

        ui.add_space(8.0);

        palette.card_frame().show(ui, |ui| {
            section_label(ui, palette, "ANSWER RECORDS");
            ui.add_space(4.0);
            let max_h = ui.available_height().max(240.0);
            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .max_scroll_height(max_h)
                .column(Column::initial(190.0).at_least(120.0))
                .column(Column::exact(68.0))
                .column(Column::exact(68.0))
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
                        ui.strong("Value");
                    });
                })
                .body(|body| {
                    body.rows(22.0, res.records.len(), |mut row| {
                        let rec = &res.records[row.index()];
                        row.col(|ui| {
                            ui.monospace(&rec.name);
                        });
                        row.col(|ui| {
                            ui.monospace(rec.ttl.to_string());
                        });
                        row.col(|ui| {
                            ui.monospace(&rec.record_type);
                        });
                        row.col(|ui| {
                            ui.monospace(&rec.value);
                        });
                    });
                });
        });
    } else if !state.running {
        palette.card_frame().show(ui, |ui| {
            ui.label(
                egui::RichText::new("Enter a domain or IP and click Lookup to query DNS records.")
                    .color(palette.text_muted),
            );
        });
    }
}
