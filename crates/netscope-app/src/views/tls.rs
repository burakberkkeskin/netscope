use crate::theme::{AppPalette, kv_row, section_label, status_pill};
use crate::widgets::{HistoryPickAction, host_history_picker};
use egui::{Ui, vec2};
use netscope_core::history::{PersistedState, TlsTargetEntry};
use netscope_core::tls::{TlsInspectionResult, inspect_tls};
use std::path::PathBuf;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

pub struct TlsState {
    pub host: String,
    pub port_text: String,
    pub sni_override: String,
    pub custom_ca_path: String,
    pub running: bool,
    pub selected_idx: usize,
    pub result: Option<TlsInspectionResult>,
    pub error: Option<String>,
    rx: Option<mpsc::UnboundedReceiver<Result<TlsInspectionResult, String>>>,
}

impl Default for TlsState {
    fn default() -> Self {
        Self {
            host: "cloudflare.com".into(),
            port_text: "443".into(),
            sni_override: String::new(),
            custom_ca_path: String::new(),
            running: false,
            selected_idx: 0,
            result: None,
            error: None,
            rx: None,
        }
    }
}

impl TlsState {
    pub fn start(&mut self, rt: &Runtime, ctx: &egui::Context) {
        self.error = None;
        let port = match self.port_text.trim().parse::<u16>() {
            Ok(p) if p > 0 => p,
            _ => {
                self.error = Some("Port must be a valid integer between 1 and 65535".into());
                return;
            }
        };

        let host = self.host.clone();
        let sni = if self.sni_override.trim().is_empty() {
            None
        } else {
            Some(self.sni_override.clone())
        };
        let ca_path = if self.custom_ca_path.trim().is_empty() {
            None
        } else {
            Some(PathBuf::from(self.custom_ca_path.trim()))
        };

        let (tx, rx) = mpsc::unbounded_channel();
        self.rx = Some(rx);
        self.running = true;

        let ctx_clone = ctx.clone();
        rt.spawn(async move {
            let res = inspect_tls(&host, port, sni.as_deref(), ca_path.as_deref())
                .await
                .map_err(|e| e.to_string());
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
                    self.selected_idx = 0;
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
        self.selected_idx = 0;
    }
}

pub fn render(
    ui: &mut Ui,
    palette: &AppPalette,
    state: &mut TlsState,
    history: &mut PersistedState,
    rt: &Runtime,
) {
    ui.horizontal(|ui| {
        ui.label("Host:");
        let resp = ui.add(
            egui::TextEdit::singleline(&mut state.host)
                .desired_width(190.0)
                .hint_text("example.com"),
        );
        let enter_pressed = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

        let tls_hosts: Vec<String> = history
            .recent_tls_targets
            .iter()
            .map(|t| format!("{}:{}", t.host, t.port))
            .collect();
        if let Some(act) = host_history_picker(ui, "tls_hist", &mut state.host, &tls_hosts) {
            match act {
                HistoryPickAction::Selected(sel) => {
                    if let Some(entry) = history
                        .recent_tls_targets
                        .iter()
                        .find(|t| format!("{}:{}", t.host, t.port) == sel)
                    {
                        state.host = entry.host.clone();
                        state.port_text = entry.port.to_string();
                        state.sni_override = entry.sni.clone();
                        state.custom_ca_path = entry.custom_ca_path.clone();
                    }
                }
                HistoryPickAction::Removed(sel) => {
                    history
                        .recent_tls_targets
                        .retain(|t| format!("{}:{}", t.host, t.port) != sel);
                    let _ = history.save();
                }
            }
        }

        ui.label("Port:");
        ui.add(egui::TextEdit::singleline(&mut state.port_text).desired_width(54.0));

        ui.label("SNI:");
        ui.add(
            egui::TextEdit::singleline(&mut state.sni_override)
                .desired_width(120.0)
                .hint_text("optional"),
        );

        if ui
            .add_enabled(!state.running, egui::Button::new("Inspect TLS"))
            .clicked()
            || (!state.running && enter_pressed)
        {
            if let Ok(port) = state.port_text.trim().parse::<u16>()
                && port > 0
            {
                history.record_tls(TlsTargetEntry {
                    host: state.host.trim().to_string(),
                    port,
                    sni: state.sni_override.trim().to_string(),
                    custom_ca_path: state.custom_ca_path.trim().to_string(),
                });
                let _ = history.save();
            }
            state.start(rt, ui.ctx());
        }
    });

    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label("Custom CA PEM:");
        ui.add(
            egui::TextEdit::singleline(&mut state.custom_ca_path)
                .desired_width(360.0)
                .hint_text("/path/to/private-ca.pem (optional for corporate/private PKI)"),
        );
    });

    if let Some(ref err) = state.error {
        ui.add_space(6.0);
        status_pill(ui, err, palette.err, palette.err_bg);
    }

    ui.add_space(10.0);

    let Some(res) = state.result.as_ref() else {
        palette.card_frame().show(ui, |ui| {
            ui.label(
                egui::RichText::new(
                    "Inspects the live TLS handshake, full certificate chain, OS trust store validation, and optional private CA trust.",
                )
                .color(palette.text_muted),
            );
        });
        return;
    };

    // Trust diagnosis banner + protocol pills
    palette.card_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            let (fg, bg) = if res.diagnosis.os_trusted {
                (palette.ok, palette.ok_bg)
            } else if res.diagnosis.custom_ca_trusted == Some(true) {
                (palette.warn, palette.warn_bg)
            } else {
                (palette.err, palette.err_bg)
            };
            status_pill(
                ui,
                if res.diagnosis.os_trusted {
                    "OS Trusted"
                } else {
                    "OS Untrusted"
                },
                fg,
                bg,
            );
            if let Some(custom_ok) = res.diagnosis.custom_ca_trusted {
                status_pill(
                    ui,
                    if custom_ok {
                        "Custom CA: Trusted"
                    } else {
                        "Custom CA: Failed"
                    },
                    if custom_ok { palette.ok } else { palette.err },
                    if custom_ok {
                        palette.ok_bg
                    } else {
                        palette.err_bg
                    },
                );
            }
            status_pill(
                ui,
                &res.protocol_version,
                palette.accent,
                palette.card_subtle_bg,
            );
            status_pill(
                ui,
                &res.cipher_suite,
                palette.text_primary,
                palette.card_subtle_bg,
            );
        });

        ui.add_space(6.0);
        ui.label(egui::RichText::new(&res.diagnosis.summary).strong());
        for reason in &res.diagnosis.reasons {
            ui.label(
                egui::RichText::new(format!("• {reason}"))
                    .size(12.0)
                    .color(palette.err),
            );
        }
    });

    ui.add_space(10.0);

    // Chain list (left) + Selected cert details (right)
    ui.columns(2, |cols| {
        cols[0].vertical(|ui| {
            section_label(
                ui,
                palette,
                &format!("CERTIFICATE CHAIN ({})", res.chain.len()),
            );
            ui.add_space(6.0);
            for (idx, cert) in res.chain.iter().enumerate() {
                let selected = state.selected_idx == idx;
                let frame = if selected {
                    palette
                        .card_frame()
                        .stroke(egui::Stroke::new(1.5, palette.accent))
                } else {
                    palette.subtle_card_frame()
                };
                frame.show(ui, |ui| {
                    let resp = ui
                        .horizontal(|ui| {
                            let badge_col = if cert.is_expired || cert.is_not_yet_valid {
                                palette.err
                            } else if cert.days_remaining < 14 {
                                palette.warn
                            } else {
                                palette.ok
                            };
                            let (dot, _) =
                                ui.allocate_exact_size(vec2(10.0, 10.0), egui::Sense::hover());
                            ui.painter().circle_filled(dot.center(), 4.5, badge_col);

                            ui.vertical(|ui| {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "[{}] {}",
                                        cert.position_label, cert.subject_cn
                                    ))
                                    .strong()
                                    .size(13.0),
                                );
                                ui.label(
                                    egui::RichText::new(format!(
                                        "Issuer: {}  •  {}d left",
                                        cert.issuer_cn, cert.days_remaining
                                    ))
                                    .size(11.5)
                                    .color(palette.text_muted),
                                );
                            });
                        })
                        .response
                        .interact(egui::Sense::click());
                    if resp.clicked() {
                        state.selected_idx = idx;
                    }
                });
                ui.add_space(6.0);
            }
        });

        cols[1].vertical(|ui| {
            section_label(ui, palette, "CERTIFICATE DETAILS");
            ui.add_space(6.0);
            if let Some(cert) = res.chain.get(state.selected_idx) {
                palette.card_frame().show(ui, |ui| {
                    egui::ScrollArea::vertical().max_height(370.0).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(&cert.subject_cn).strong().size(15.0));
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.button("Copy PEM").clicked() {
                                        ui.ctx().copy_text(cert.pem.clone());
                                    }
                                },
                            );
                        });
                        ui.separator();
                        kv_row(ui, palette, "Role", &cert.position_label);
                        kv_row(ui, palette, "Not Before", &cert.not_before);
                        kv_row(ui, palette, "Not After", &cert.not_after);
                        kv_row(
                            ui,
                            palette,
                            "Days Left",
                            &format!("{} days", cert.days_remaining),
                        );
                        kv_row(
                            ui,
                            palette,
                            "Public Key",
                            &format!("{} ({} bits)", cert.key_algorithm, cert.key_bits),
                        );
                        kv_row(ui, palette, "Serial", &cert.serial_hex);
                        ui.add_space(6.0);
                        ui.label(
                            egui::RichText::new("Subject")
                                .size(11.0)
                                .color(palette.text_muted),
                        );
                        ui.monospace(&cert.subject);
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new("Issuer")
                                .size(11.0)
                                .color(palette.text_muted),
                        );
                        ui.monospace(&cert.issuer);
                        if !cert.sans.is_empty() {
                            ui.add_space(6.0);
                            ui.label(
                                egui::RichText::new(format!("SANs ({})", cert.sans.len()))
                                    .size(11.0)
                                    .color(palette.text_muted),
                            );
                            ui.monospace(cert.sans.join(", "));
                        }
                        ui.add_space(6.0);
                        ui.label(
                            egui::RichText::new("SHA-256 Fingerprint")
                                .size(11.0)
                                .color(palette.text_muted),
                        );
                        ui.monospace(&cert.sha256_fingerprint);
                    });
                });
            }
        });
    });
}
