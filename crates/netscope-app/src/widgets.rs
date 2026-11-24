use crate::theme::AppPalette;
use egui::{Color32, CornerRadius, Frame, Margin, Popup, Stroke, Ui};
use egui_plot::GridInput;
use netscope_core::IpFamily;
use std::net::IpAddr;

pub enum HistoryPickAction {
    Selected(String),
    Removed(String),
}

/// Renders a compact `History` dropdown button next to a target host/domain field.
/// Selecting an entry updates `target` and returns `HistoryPickAction::Selected`.
pub fn host_history_picker(
    ui: &mut Ui,
    _id_salt: &str,
    target: &mut String,
    recent: &[String],
) -> Option<HistoryPickAction> {
    let btn = ui.add_enabled(!recent.is_empty(), egui::Button::new("History ▾"));
    let mut action = None;

    Popup::menu(&btn).show(|ui| {
        ui.set_min_width(210.0);
        ui.label(egui::RichText::new("Recent Targets").small().strong());
        ui.separator();
        for item in recent {
            ui.horizontal(|ui| {
                if ui.button(item).clicked() {
                    *target = item.clone();
                    action = Some(HistoryPickAction::Selected(item.clone()));
                    ui.close();
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .small_button("×")
                        .on_hover_text("Remove from history")
                        .clicked()
                    {
                        action = Some(HistoryPickAction::Removed(item.clone()));
                    }
                });
            });
        }
    });

    action
}

/// Computes 1-2-5 nice major/minor Y-axis grid spacings so `egui_plot` renders 4–5 readable tick labels.
pub fn nice_y_grid_spacer(input: GridInput) -> [f64; 3] {
    let span = (input.bounds.1 - input.bounds.0).abs().max(1e-3);
    let raw = (span / 4.0).max(input.base_step_size);
    let pow10 = 10_f64.powf(raw.log10().floor());
    let norm = raw / pow10;
    let step = if norm <= 1.0 {
        1.0
    } else if norm <= 2.0 {
        2.0
    } else if norm <= 5.0 {
        5.0
    } else {
        10.0
    } * pow10;
    [step, step * 0.5, step * 0.25]
}

/// Compact `[Auto | IPv4 | IPv6]` segmented protocol selector for probing tools.
pub fn ip_family_selector(ui: &mut Ui, palette: &AppPalette, value: &mut IpFamily) -> bool {
    let mut changed = false;
    Frame::new()
        .fill(palette.card_subtle_bg)
        .stroke(Stroke::new(1.0, palette.card_border))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::same(2))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                for fam in [IpFamily::Auto, IpFamily::Ipv4, IpFamily::Ipv6] {
                    let selected = *value == fam;
                    let fill = if selected {
                        palette.selected_bg
                    } else {
                        Color32::TRANSPARENT
                    };
                    let fg = if selected {
                        Color32::WHITE
                    } else {
                        palette.text_primary
                    };
                    let btn =
                        egui::Button::new(egui::RichText::new(fam.label()).size(11.5).color(fg))
                            .fill(fill)
                            .frame(selected)
                            .corner_radius(CornerRadius::same(4))
                            .min_size(egui::vec2(34.0, 20.0));
                    if ui.add(btn).clicked() && !selected {
                        *value = fam;
                        changed = true;
                    }
                }
            });
        });
    changed
}

pub fn format_resolved_ip_pill(ip: IpAddr) -> String {
    let tag = if ip.is_ipv6() { "IPv6" } else { "IPv4" };
    format!("{tag} · {ip}")
}
