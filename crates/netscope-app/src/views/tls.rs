use crate::theme::{AppPalette, kv_row, section_label, status_pill};
use crate::widgets::{HistoryPickAction, host_history_picker};
use egui::{Align, CornerRadius, CursorIcon, Layout, Stroke, Ui, vec2};
use netscope_core::history::{PersistedState, TlsTargetEntry};
use netscope_core::tls::{TlsInspectionResult, inspect_tls};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

pub struct TlsState {
    pub host: String,
    pub port_text: String,
    pub sni_override: String,
    pub custom_ca_path: String,
    pub running: bool,
    pub selected_idx: usize,
    pub result: Option<TlsInspectionResult>,
    pub error: Option<String>,
    copied_at: Option<Instant>,
    abort_handle: Option<AbortHandle>,
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
            copied_at: None,
            abort_handle: None,
            rx: None,
        }
    }
}

impl TlsState {
    pub fn start(&mut self, rt: &Runtime, ctx: &egui::Context) {
        self.stop();
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
        let join_handle = rt.spawn(async move {
            let res = inspect_tls(&host, port, sni.as_deref(), ca_path.as_deref())
                .await
                .map_err(|e| e.to_string());
            let _ = tx.send(res);
            ctx_clone.request_repaint();
        });
        self.abort_handle = Some(join_handle.abort_handle());
    }

    pub fn stop(&mut self) {
        if let Some(handle) = self.abort_handle.take() {
            handle.abort();
        }
        self.rx = None;
        self.running = false;
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
            self.abort_handle = None;
        }
    }

    pub fn clear(&mut self) {
        self.stop();
        self.result = None;
        self.error = None;
        self.selected_idx = 0;
        self.copied_at = None;
    }
}

pub fn render(
    ui: &mut Ui,
    palette: &AppPalette,
    state: &mut TlsState,
    history: &mut PersistedState,
    rt: &Runtime,
) {
    let mut trigger_inspect = false;

    ui.horizontal(|ui| {
        ui.label("Host:");
        let host_resp = ui.add(
            egui::TextEdit::singleline(&mut state.host)
                .desired_width(190.0)
                .hint_text("example.com"),
        );
        if host_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            trigger_inspect = true;
        }

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
        let port_resp = ui.add(egui::TextEdit::singleline(&mut state.port_text).desired_width(54.0));
        if port_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            trigger_inspect = true;
        }

        ui.label("SNI:");
        let sni_resp = ui.add(
            egui::TextEdit::singleline(&mut state.sni_override)
                .desired_width(120.0)
                .hint_text("optional"),
        );
        if sni_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            trigger_inspect = true;
        }

        if state.running {
            if ui.button("Stop").clicked() {
                state.stop();
            }
            ui.spinner();
            ui.label(
                egui::RichText::new("Inspecting TLS...")
                    .size(12.0)
                    .color(palette.text_muted),
            );
        } else if ui.button("Inspect TLS").clicked() {
            trigger_inspect = true;
        }
    });

    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label("Custom CA PEM:");
        let ca_resp = ui.add(
            egui::TextEdit::singleline(&mut state.custom_ca_path)
                .desired_width(360.0)
                .hint_text("/path/to/private-ca.pem (optional for corporate/private PKI)"),
        );
        if ca_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            trigger_inspect = true;
        }
    });

    if trigger_inspect && !state.running {
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

    if let Some(ref err) = state.error {
        ui.add_space(6.0);
        status_pill(ui, err, palette.err, palette.err_bg);
    }

    ui.add_space(10.0);

    let Some(res) = state.result.as_ref() else {
        palette.card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                egui::RichText::new(
                    "Inspects the live TLS handshake, full certificate chain, OS trust store validation, and optional private CA trust.",
                )
                .color(palette.text_muted),
            );
        });
        return;
    };

    // Trust diagnosis banner + protocol pills (full width)
    palette.card_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal_wrapped(|ui| {
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

    // Explicit ADR-006 two-column layout: Chain list (left) + Selected cert details (right)
    let avail_h = ui.available_height().max(300.0);
    let total_w = ui.available_width();
    let left_w = (total_w * 0.38).clamp(260.0, 360.0);
    let right_w = (total_w - left_w - 10.0).max(320.0);

    ui.horizontal_top(|ui| {
        ui.allocate_ui_with_layout(vec2(left_w, avail_h), Layout::top_down(Align::Min), |ui| {
            section_label(
                ui,
                palette,
                &format!("CERTIFICATE CHAIN ({})", res.chain.len()),
            );
            ui.add_space(6.0);
            egui::ScrollArea::vertical()
                .id_salt("tls_chain_scroll")
                .max_height((avail_h - 24.0).max(200.0))
                .show(ui, |ui| {
                    for (idx, cert) in res.chain.iter().enumerate() {
                        let selected = state.selected_idx == idx;
                        let frame = if selected {
                            palette
                                .card_frame()
                                .stroke(Stroke::new(1.5, palette.accent))
                        } else {
                            palette.subtle_card_frame()
                        };
                        let card_resp = frame.show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            // Disable label text selection so clicks anywhere on the card trigger selection cleanly.
                            ui.style_mut().interaction.selectable_labels = false;
                            ui.horizontal(|ui| {
                                let badge_col = if cert.is_expired || cert.is_not_yet_valid {
                                    palette.err
                                } else if cert.days_remaining < 14 {
                                    palette.warn
                                } else {
                                    palette.ok
                                };
                                let (dot, _) =
                                    ui.allocate_exact_size(vec2(10.0, 10.0), egui::Sense::empty());
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
                            });
                        });
                        let card_id = ui.scope_id().with(("tls_cert_card", idx));
                        let click_resp = ui
                            .interact(card_resp.response.rect, card_id, egui::Sense::click())
                            .on_hover_cursor(CursorIcon::PointingHand);
                        if click_resp.hovered() && !selected {
                            ui.painter().rect_stroke(
                                card_resp.response.rect,
                                CornerRadius::same(10),
                                Stroke::new(1.5, palette.accent.linear_multiply(0.55)),
                                egui::StrokeKind::Inside,
                            );
                        }
                        if click_resp.clicked() {
                            state.selected_idx = idx;
                        }
                        ui.add_space(6.0);
                    }
                });
        });

        ui.add_space(10.0);

        ui.allocate_ui_with_layout(vec2(right_w, avail_h), Layout::top_down(Align::Min), |ui| {
            section_label(ui, palette, "CERTIFICATE DETAILS");
            ui.add_space(6.0);
            if let Some(cert) = res.chain.get(state.selected_idx) {
                palette.card_frame().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    egui::ScrollArea::vertical()
                        .id_salt("tls_details_scroll")
                        .max_height((avail_h - 52.0).max(200.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new(&cert.subject_cn).strong().size(15.0));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    let copied_recent = state
                                        .copied_at
                                        .is_some_and(|t| t.elapsed() < Duration::from_secs(2));
                                    if copied_recent {
                                        ui.ctx().request_repaint_after(Duration::from_millis(200));
                                    }
                                    let copy_label = if copied_recent {
                                        "Copied ✓"
                                    } else {
                                        "Copy PEM"
                                    };
                                    if ui.button(copy_label).clicked() {
                                        ui.ctx().copy_text(cert.pem.clone());
                                        state.copied_at = Some(Instant::now());
                                    }
                                });
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
