use crate::theme::{AppPalette, section_label, status_pill};
use egui::{Align, Layout, Ui};
use egui_extras::{Column, TableBuilder};
use netscope_core::subnet::{SubnetCalculation, calculate_subnet, split_ipv4_subnet};

pub struct SubnetCalcState {
    pub input: String,
    pub prefix_slider: u8,
    pub split_target_prefix: u8,
    pub last_calc: Result<SubnetCalculation, String>,
}

impl Default for SubnetCalcState {
    fn default() -> Self {
        let input = "192.168.1.0/24".to_string();
        let last_calc = calculate_subnet(&input, 24);
        Self {
            input,
            prefix_slider: 24,
            split_target_prefix: 26,
            last_calc,
        }
    }
}

impl SubnetCalcState {
    pub fn recompute(&mut self) {
        self.last_calc = calculate_subnet(&self.input, self.prefix_slider);
        if let Ok(SubnetCalculation::V4(ref v4)) = self.last_calc {
            self.prefix_slider = v4.prefix_len;
            if self.split_target_prefix <= v4.prefix_len {
                self.split_target_prefix = (v4.prefix_len + 2).min(32);
            }
        }
    }

    pub fn set_prefix(&mut self, prefix: u8) {
        self.prefix_slider = prefix;
        let ip_part = self
            .input
            .split_once('/')
            .map(|(ip, _)| ip.trim())
            .unwrap_or(self.input.trim());
        self.input = format!("{ip_part}/{prefix}");
        self.recompute();
    }
}

pub fn render(ui: &mut Ui, palette: &AppPalette, state: &mut SubnetCalcState) {
    ui.horizontal(|ui| {
        ui.label("IP / CIDR:");
        let resp = ui.add(
            egui::TextEdit::singleline(&mut state.input)
                .desired_width(240.0)
                .hint_text("192.168.1.0/24 or fd00::/48"),
        );
        if resp.changed() {
            state.recompute();
        }

        ui.label("Prefix:");
        let mut p = state.prefix_slider;
        if ui
            .add(egui::Slider::new(&mut p, 1..=32).prefix("/"))
            .changed()
        {
            state.set_prefix(p);
        }

        for quick in [8u8, 16, 22, 24, 26, 28, 30, 32] {
            let label = format!("/{quick}");
            if ui.small_button(label).clicked() {
                state.set_prefix(quick);
            }
        }
    });

    ui.add_space(10.0);

    match &state.last_calc {
        Err(err) => {
            status_pill(ui, err, palette.err, palette.err_bg);
        }
        Ok(SubnetCalculation::V4(v4)) => {
            // Top summary KPI cards
            ui.columns(4, |cols| {
                kpi_card(&mut cols[0], palette, "Network CIDR", &v4.cidr, true);
                kpi_card(
                    &mut cols[1],
                    palette,
                    "Netmask / Wildcard",
                    &format!("{}  ({ })", v4.netmask, v4.wildcard),
                    false,
                );
                kpi_card(
                    &mut cols[2],
                    palette,
                    "Usable Host Range",
                    &format!("{} - {}", v4.first_usable, v4.last_usable),
                    false,
                );
                kpi_card(
                    &mut cols[3],
                    palette,
                    "Usable Hosts",
                    &format!("{}  (Total: {})", v4.usable_hosts, v4.total_addresses),
                    true,
                );
            });

            ui.add_space(10.0);

            // Middle: Address Details & Binary Bitmask Visualizer
            ui.columns(2, |cols| {
                palette.card_frame().show(&mut cols[0], |ui| {
                    ui.set_min_width(ui.available_width());
                    section_label(ui, palette, "SUBNET PARAMETERS");
                    ui.add_space(6.0);
                    egui::Grid::new("subnet_params_grid")
                        .num_columns(2)
                        .spacing([18.0, 6.0])
                        .show(ui, |ui| {
                            kv_row(ui, palette, "Address Scope", &v4.scope);
                            kv_row(ui, palette, "Network Address", &v4.network.to_string());
                            kv_row(ui, palette, "Broadcast Address", &v4.broadcast.to_string());
                            kv_row(ui, palette, "First Usable IP", &v4.first_usable.to_string());
                            kv_row(ui, palette, "Last Usable IP", &v4.last_usable.to_string());
                            kv_row(ui, palette, "Subnet Mask", &v4.netmask.to_string());
                            kv_row(ui, palette, "Wildcard Mask", &v4.wildcard.to_string());
                        });
                });

                palette.card_frame().show(&mut cols[1], |ui| {
                    ui.set_min_width(ui.available_width());
                    section_label(ui, palette, "BINARY BITMASK BREAKDOWN");
                    ui.add_space(6.0);
                    egui::Grid::new("subnet_bin_grid")
                        .num_columns(2)
                        .spacing([14.0, 8.0])
                        .show(ui, |ui| {
                            ui.label(
                                egui::RichText::new("Input IP")
                                    .size(12.0)
                                    .color(palette.text_muted),
                            );
                            ui.monospace(&v4.binary_ip);
                            ui.end_row();

                            ui.label(
                                egui::RichText::new("Subnet Mask")
                                    .size(12.0)
                                    .color(palette.text_muted),
                            );
                            ui.monospace(&v4.binary_netmask);
                            ui.end_row();

                            ui.label(
                                egui::RichText::new("Network ID")
                                    .size(12.0)
                                    .color(palette.text_muted),
                            );
                            ui.label(
                                egui::RichText::new(&v4.binary_network)
                                    .monospace()
                                    .color(palette.accent),
                            );
                            ui.end_row();
                        });
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new(format!(
                            "Network bits: {}   •   Host bits: {}",
                            v4.prefix_len,
                            32 - v4.prefix_len
                        ))
                        .size(11.5)
                        .color(palette.text_muted),
                    );
                });
            });

            ui.add_space(10.0);

            // Bottom: Interactive Subnet Splitter
            palette.card_frame().show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    section_label(ui, palette, "SUBNET SPLITTER");
                    ui.add_space(12.0);
                    ui.label("Split into:");
                    let min_split = (v4.prefix_len + 1).min(32);
                    for cand in min_split..=(v4.prefix_len + 6).min(32) {
                        let selected = state.split_target_prefix == cand;
                        if ui
                            .selectable_label(selected, format!("/{cand}"))
                            .clicked()
                        {
                            state.split_target_prefix = cand;
                        }
                    }
                });

                ui.add_space(6.0);
                let children =
                    split_ipv4_subnet(v4.network, v4.prefix_len, state.split_target_prefix);

                TableBuilder::new(ui)
                    .striped(true)
                    .max_scroll_height(220.0)
                    .column(Column::exact(45.0))
                    .column(Column::exact(145.0))
                    .column(Column::exact(135.0))
                    .column(Column::exact(135.0))
                    .column(Column::exact(135.0))
                    .column(Column::remainder())
                    .header(22.0, |mut h| {
                        h.col(|ui| {
                            ui.strong("#");
                        });
                        h.col(|ui| {
                            ui.strong("Subnet CIDR");
                        });
                        h.col(|ui| {
                            ui.strong("First Usable");
                        });
                        h.col(|ui| {
                            ui.strong("Last Usable");
                        });
                        h.col(|ui| {
                            ui.strong("Broadcast");
                        });
                        h.col(|ui| {
                            ui.strong("Usable Hosts");
                        });
                    })
                    .body(|body| {
                        body.rows(21.0, children.len(), |mut row| {
                            let c = &children[row.index()];
                            row.col(|ui| {
                                ui.monospace(c.index.to_string());
                            });
                            row.col(|ui| {
                                ui.monospace(&c.cidr);
                            });
                            row.col(|ui| {
                                ui.monospace(c.first_usable.to_string());
                            });
                            row.col(|ui| {
                                ui.monospace(c.last_usable.to_string());
                            });
                            row.col(|ui| {
                                ui.monospace(c.broadcast.to_string());
                            });
                            row.col(|ui| {
                                ui.monospace(c.usable_hosts.to_string());
                            });
                        });
                    });
            });
        }
        Ok(SubnetCalculation::V6(v6)) => {
            palette.card_frame().show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                section_label(ui, palette, "IPV6 PREFIX DETAILS");
                ui.add_space(6.0);
                egui::Grid::new("ipv6_subnet_grid")
                    .num_columns(2)
                    .spacing([18.0, 8.0])
                    .show(ui, |ui| {
                        kv_row(ui, palette, "Canonical CIDR", &v6.cidr);
                        kv_row(ui, palette, "Address Scope", &v6.scope);
                        kv_row(ui, palette, "Network Prefix", &v6.network.to_string());
                        kv_row(ui, palette, "First Address", &v6.first_address.to_string());
                        kv_row(ui, palette, "Last Address", &v6.last_address.to_string());
                        kv_row(ui, palette, "/64 Allocation Capacity", &v6.total_64_blocks);
                    });
            });
        }
    }
}

fn kpi_card(ui: &mut Ui, palette: &AppPalette, title: &str, value: &str, accent: bool) {
    palette.subtle_card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.with_layout(Layout::top_down(Align::Min), |ui| {
            ui.label(
                egui::RichText::new(title)
                    .size(11.0)
                    .color(palette.text_muted),
            );
            ui.label(
                egui::RichText::new(value)
                    .size(14.5)
                    .strong()
                    .monospace()
                    .color(if accent {
                        palette.accent
                    } else {
                        palette.text_primary
                    }),
            );
        });
    });
}

fn kv_row(ui: &mut Ui, palette: &AppPalette, k: &str, v: &str) {
    ui.label(egui::RichText::new(k).size(12.0).color(palette.text_muted));
    ui.monospace(v);
    ui.end_row();
}
