use egui::{Popup, Ui};
use egui_plot::GridInput;

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
