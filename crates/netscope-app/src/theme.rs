use egui::{Color32, CornerRadius, Frame, Margin, Stroke, Ui};

#[derive(Debug, Clone, Copy)]
pub struct AppPalette {
    pub dark: bool,
    pub canvas_bg: Color32,
    pub sidebar_bg: Color32,
    pub card_bg: Color32,
    pub card_subtle_bg: Color32,
    pub card_border: Color32,
    pub text_primary: Color32,
    pub text_muted: Color32,
    pub accent: Color32,
    pub ok: Color32,
    pub ok_bg: Color32,
    pub warn: Color32,
    pub warn_bg: Color32,
    pub err: Color32,
    pub err_bg: Color32,
    pub selected_bg: Color32,
}

impl AppPalette {
    pub fn for_mode(dark: bool) -> Self {
        if dark {
            Self {
                dark: true,
                canvas_bg: Color32::from_rgb(24, 25, 29),
                sidebar_bg: Color32::from_rgb(31, 33, 38),
                card_bg: Color32::from_rgb(38, 40, 47),
                card_subtle_bg: Color32::from_rgb(32, 34, 40),
                card_border: Color32::from_rgb(58, 61, 70),
                text_primary: Color32::from_rgb(236, 238, 242),
                text_muted: Color32::from_rgb(154, 160, 172),
                accent: Color32::from_rgb(10, 132, 255),
                ok: Color32::from_rgb(48, 209, 88),
                ok_bg: Color32::from_rgba_unmultiplied(48, 209, 88, 34),
                warn: Color32::from_rgb(255, 159, 10),
                warn_bg: Color32::from_rgba_unmultiplied(255, 159, 10, 34),
                err: Color32::from_rgb(255, 69, 58),
                err_bg: Color32::from_rgba_unmultiplied(255, 69, 58, 34),
                selected_bg: Color32::from_rgb(10, 132, 255),
            }
        } else {
            Self {
                dark: false,
                canvas_bg: Color32::from_rgb(246, 247, 250),
                sidebar_bg: Color32::from_rgb(239, 241, 245),
                card_bg: Color32::WHITE,
                card_subtle_bg: Color32::from_rgb(250, 251, 253),
                card_border: Color32::from_rgb(218, 222, 229),
                text_primary: Color32::from_rgb(24, 27, 32),
                text_muted: Color32::from_rgb(82, 90, 102),
                accent: Color32::from_rgb(0, 122, 255),
                ok: Color32::from_rgb(40, 167, 69),
                ok_bg: Color32::from_rgba_unmultiplied(40, 167, 69, 28),
                warn: Color32::from_rgb(217, 119, 6),
                warn_bg: Color32::from_rgba_unmultiplied(217, 119, 6, 28),
                err: Color32::from_rgb(220, 38, 38),
                err_bg: Color32::from_rgba_unmultiplied(220, 38, 38, 28),
                selected_bg: Color32::from_rgb(0, 122, 255),
            }
        }
    }

    pub fn card_frame(&self) -> Frame {
        Frame::new()
            .fill(self.card_bg)
            .stroke(Stroke::new(1.0, self.card_border))
            .corner_radius(CornerRadius::same(10))
            .inner_margin(Margin::same(14))
    }

    pub fn subtle_card_frame(&self) -> Frame {
        Frame::new()
            .fill(self.card_subtle_bg)
            .stroke(Stroke::new(1.0, self.card_border))
            .corner_radius(CornerRadius::same(10))
            .inner_margin(Margin::same(12))
    }
}

pub fn status_pill(ui: &mut Ui, text: &str, fg: Color32, bg: Color32) {
    Frame::new()
        .fill(bg)
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(8, 3))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).size(11.5).strong().color(fg));
        });
}

pub fn section_label(ui: &mut Ui, palette: &AppPalette, text: &str) {
    let col = if palette.dark {
        Color32::from_rgb(176, 184, 198)
    } else {
        Color32::from_rgb(71, 82, 98)
    };
    ui.label(
        egui::RichText::new(text)
            .size(11.0)
            .strong()
            .extra_letter_spacing(0.6)
            .color(col),
    );
}

pub fn kv_row(ui: &mut Ui, palette: &AppPalette, key: &str, val: &str) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(key).size(12.5).color(palette.text_muted));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                egui::RichText::new(val)
                    .size(12.5)
                    .monospace()
                    .color(palette.text_primary),
            );
        });
    });
}
