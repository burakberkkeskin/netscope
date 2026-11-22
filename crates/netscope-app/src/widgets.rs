use egui::{Popup, Ui};

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
