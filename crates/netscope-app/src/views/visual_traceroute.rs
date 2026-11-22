use crate::theme::{AppPalette, section_label, status_pill};
use crate::widgets::{HistoryPickAction, host_history_picker};
use egui::epaint::{PathShape, PathStroke, Vertex, WHITE_UV};
use egui::{
    Align, Align2, Color32, FontId, Layout, Mesh, Pos2, Sense, Shape, Stroke, Ui, pos2, vec2,
};
use netscope_core::CancelToken;
use netscope_core::geoip::{GeoLocation, lookup_ip, reconcile_hop_with_speed_of_light};
use netscope_core::history::PersistedState;
use netscope_core::icmp::{TracerouteEvent, TracerouteHop, run_traceroute};
use netscope_core::net_info::fetch_public_network_status;
use std::net::IpAddr;
use std::sync::OnceLock;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

const WORLD_LAND_JSON: &str = include_str!("../../assets/world_land.json");

struct WorldMapData {
    rings: Vec<Vec<[f32; 2]>>,
    meshes_norm: Vec<(Vec<[f32; 2]>, Vec<u32>)>,
}

static WORLD_MAP: OnceLock<WorldMapData> = OnceLock::new();

fn lon_lat_to_norm(lon: f64, lat: f64) -> [f32; 2] {
    let x = ((lon + 180.0) / 360.0).clamp(0.0, 1.0) as f32;
    let y = ((90.0 - lat.clamp(-85.0, 85.0)) / 180.0).clamp(0.0, 1.0) as f32;
    [x, y]
}

fn world_map() -> &'static WorldMapData {
    WORLD_MAP.get_or_init(|| {
        let raw_polys: Vec<Vec<[f32; 2]>> =
            serde_json::from_str(WORLD_LAND_JSON).unwrap_or_default();
        let mut rings = Vec::with_capacity(raw_polys.len());
        let mut meshes_norm: Vec<(Vec<[f32; 2]>, Vec<u32>)> = Vec::new();
        let mut cur_verts: Vec<[f32; 2]> = Vec::new();
        let mut cur_indices: Vec<u32> = Vec::new();

        for poly in raw_polys {
            if poly.len() < 3 {
                continue;
            }
            let mut ring_norm = Vec::with_capacity(poly.len());
            let mut flat: Vec<f64> = Vec::with_capacity(poly.len() * 2);
            for &[lon, lat] in &poly {
                let n = lon_lat_to_norm(f64::from(lon), f64::from(lat));
                ring_norm.push(n);
            }
            let earcut_slice = if ring_norm.len() > 3 && ring_norm.first() == ring_norm.last() {
                &ring_norm[..ring_norm.len() - 1]
            } else {
                &ring_norm[..]
            };
            for &[nx, ny] in earcut_slice {
                flat.push(f64::from(nx));
                flat.push(f64::from(ny));
            }
            if let Ok(tris) = earcutr::earcut(&flat, &[], 2) {
                if cur_verts.len() + earcut_slice.len() > 16_000 && !cur_verts.is_empty() {
                    meshes_norm.push((
                        std::mem::take(&mut cur_verts),
                        std::mem::take(&mut cur_indices),
                    ));
                }
                let base = cur_verts.len() as u32;
                cur_verts.extend_from_slice(earcut_slice);
                for idx in tris {
                    cur_indices.push(base + idx as u32);
                }
            }
            rings.push(ring_norm);
        }
        if !cur_verts.is_empty() {
            meshes_norm.push((cur_verts, cur_indices));
        }

        WorldMapData {
            rings,
            meshes_norm,
        }
    })
}

#[derive(Debug, Clone)]
pub struct VisualHop {
    pub trace: TracerouteHop,
    pub geo: Option<GeoLocation>,
}

pub enum VisualTraceMsg {
    OriginGeo(GeoLocation),
    Resolved(IpAddr),
    HopRaw(TracerouteHop),
    HopGeo { hop: u8, geo: GeoLocation },
    Finished,
    Error(String),
}

pub struct VisualTracerouteState {
    pub host: String,
    pub max_hops: u8,
    pub running: bool,
    pub resolved_ip: Option<IpAddr>,
    /// Hop 0: The user's own public egress IP & city (e.g. 198.51.100.10)
    pub origin_geo: Option<GeoLocation>,
    pub hops: Vec<VisualHop>,
    pub selected_hop: Option<u8>,
    pub error: Option<String>,
    pub zoom: f32,
    pub pan: egui::Vec2,
    cancel: Option<CancelToken>,
    rx: Option<mpsc::UnboundedReceiver<VisualTraceMsg>>,
}

impl Default for VisualTracerouteState {
    fn default() -> Self {
        Self {
            host: "cloudflare.com".into(),
            max_hops: 30,
            running: false,
            resolved_ip: None,
            origin_geo: None,
            hops: Vec::new(),
            selected_hop: None,
            error: None,
            zoom: 1.0,
            pan: egui::Vec2::ZERO,
            cancel: None,
            rx: None,
        }
    }
}

impl VisualTracerouteState {
    pub fn start(&mut self, rt: &Runtime, ctx: &egui::Context) {
        self.stop();
        self.hops.clear();
        self.resolved_ip = None;
        self.selected_hop = None;
        self.error = None;

        let host = self.host.clone();
        let max_hops = self.max_hops;
        let (tx, rx) = mpsc::unbounded_channel();
        let cancel = CancelToken::new();
        self.cancel = Some(cancel.clone());
        self.rx = Some(rx);
        self.running = true;

        let ctx_clone = ctx.clone();
        rt.spawn(async move {
            let (tr_tx, mut tr_rx) = mpsc::unbounded_channel();
            let trace_fut = run_traceroute(host, max_hops, 3, tr_tx, cancel);
            let trace_handle = tokio::spawn(trace_fut);

            let mut geo_tasks = tokio::task::JoinSet::new();

            // Resolve Hop 0 (This Mac's public egress IP & city) in parallel
            {
                let tx_orig = tx.clone();
                let ctx_orig = ctx_clone.clone();
                geo_tasks.spawn(async move {
                    let st = fetch_public_network_status().await;
                    if let Some(pub_ip) = st.public_ip {
                        let geo = lookup_ip(pub_ip).await;
                        let _ = tx_orig.send(VisualTraceMsg::OriginGeo(geo));
                        ctx_orig.request_repaint();
                    }
                });
            }

            while let Some(ev) = tr_rx.recv().await {
                match ev {
                    TracerouteEvent::Resolved { ip, .. } => {
                        let _ = tx.send(VisualTraceMsg::Resolved(ip));
                    }
                    TracerouteEvent::HopUpdate(hop) => {
                        let hop_num = hop.hop;
                        let ip_opt = hop.ip;
                        let _ = tx.send(VisualTraceMsg::HopRaw(hop));
                        if let Some(ip) = ip_opt {
                            let tx_g = tx.clone();
                            let ctx_g = ctx_clone.clone();
                            geo_tasks.spawn(async move {
                                let geo = lookup_ip(ip).await;
                                let _ = tx_g.send(VisualTraceMsg::HopGeo { hop: hop_num, geo });
                                ctx_g.request_repaint();
                            });
                        }
                    }
                    TracerouteEvent::Finished => {
                        while geo_tasks.join_next().await.is_some() {}
                        let _ = tx.send(VisualTraceMsg::Finished);
                    }
                    TracerouteEvent::Error(err) => {
                        let _ = tx.send(VisualTraceMsg::Error(err));
                    }
                }
                ctx_clone.request_repaint();
            }
            let _ = trace_handle.await;
            while geo_tasks.join_next().await.is_some() {}
            let _ = tx.send(VisualTraceMsg::Finished);
            ctx_clone.request_repaint();
        });
    }

    pub fn stop(&mut self) {
        if let Some(c) = self.cancel.take() {
            c.cancel();
        }
        self.running = false;
    }

    pub fn clear(&mut self) {
        self.stop();
        self.hops.clear();
        self.resolved_ip = None;
        self.selected_hop = None;
        self.error = None;
        self.reset_view();
    }

    pub fn reset_view(&mut self) {
        self.zoom = 1.0;
        self.pan = egui::Vec2::ZERO;
    }

    pub fn focus_lat_lon(&mut self, lat: f64, lon: f64, zoom: f32) {
        let z = zoom.clamp(1.0, 32.0);
        let [nx, ny] = lon_lat_to_norm(lon, lat);
        self.zoom = z;
        self.pan = vec2((0.5 - nx) * z, (0.5 - ny) * z);
    }

    pub fn focus_turkiye(&mut self) {
        // Center on Anatolia (lat 39.0° N, lon 35.2° E) at 11.5x zoom
        self.focus_lat_lon(39.0, 35.2, 11.5);
    }

    pub fn zoom_by(&mut self, factor: f32, anchor_norm: Option<[f32; 2]>) {
        let old_z = self.zoom;
        let new_z = (old_z * factor).clamp(1.0, 32.0);
        if (new_z - old_z).abs() <= 1e-4 {
            return;
        }
        if let Some([ax, ay]) = anchor_norm {
            // Keep screen point (ax, ay) in [0..1] fixed while zooming
            let nx = (ax - 0.5 - self.pan.x) / old_z + 0.5;
            let ny = (ay - 0.5 - self.pan.y) / old_z + 0.5;
            self.pan.x = ax - 0.5 - (nx - 0.5) * new_z;
            self.pan.y = ay - 0.5 - (ny - 0.5) * new_z;
        } else {
            let ratio = new_z / old_z;
            self.pan *= ratio;
        }
        self.zoom = new_z;
    }

    pub fn fit_route(&mut self) {
        let mut pts: Vec<[f32; 2]> = Vec::new();
        if let Some(ref orig) = self.origin_geo
            && let (Some(lat), Some(lon)) = (orig.lat, orig.lon)
        {
            pts.push(lon_lat_to_norm(lon, lat));
        }
        pts.extend(self.hops.iter().filter_map(|h| {
            h.geo
                .as_ref()
                .and_then(|g| Some(lon_lat_to_norm(g.lon?, g.lat?)))
        }));
        if pts.is_empty() {
            self.reset_view();
            return;
        }
        let mut min_x = 1.0_f32;
        let mut max_x = 0.0_f32;
        let mut min_y = 1.0_f32;
        let mut max_y = 0.0_f32;
        for [x, y] in &pts {
            min_x = min_x.min(*x);
            max_x = max_x.max(*x);
            min_y = min_y.min(*y);
            max_y = max_y.max(*y);
        }
        let span_x = (max_x - min_x).max(0.015);
        let span_y = (max_y - min_y).max(0.015);
        let z = (0.68 / span_x.max(span_y * 1.35)).clamp(1.2, 18.0);
        let cx = (min_x + max_x) * 0.5;
        let cy = (min_y + max_y) * 0.5;
        self.zoom = z;
        // Center norm (cx, cy) around viewport center (0.5, 0.5)
        self.pan = vec2((0.5 - cx) * z, (0.5 - cy) * z);
    }

    pub fn poll(&mut self) {
        let mut done = false;
        let mut geo_updated = false;
        if let Some(rx) = &mut self.rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    VisualTraceMsg::OriginGeo(geo) => {
                        self.origin_geo = Some(geo);
                        geo_updated = true;
                    }
                    VisualTraceMsg::Resolved(ip) => self.resolved_ip = Some(ip),
                    VisualTraceMsg::HopRaw(trace) => {
                        self.hops.push(VisualHop { trace, geo: None });
                    }
                    VisualTraceMsg::HopGeo { hop, geo } => {
                        if let Some(item) = self.hops.iter_mut().find(|h| h.trace.hop == hop) {
                            item.geo = Some(geo);
                            geo_updated = true;
                        }
                    }
                    VisualTraceMsg::Finished => {
                        self.running = false;
                        done = true;
                        geo_updated = true;
                    }
                    VisualTraceMsg::Error(e) => {
                        self.error = Some(e);
                        self.running = false;
                        done = true;
                    }
                }
            }
        }
        if geo_updated {
            self.reconcile_anycast_hops();
        }
        if done {
            self.rx = None;
            self.cancel = None;
        }
    }

    /// Walks hops in TTL order and applies speed-of-light physical RTT validation so Anycast IPs
    /// without HTTP PoP headers cannot falsely jump to a US registry HQ when RTT proves they are local/regional.
    fn reconcile_anycast_hops(&mut self) {
        let mut last_verified: Option<GeoLocation> = self.origin_geo.clone();
        for hop in &mut self.hops {
            let rtt = hop.trace.avg_ms;
            if let Some(ref mut g) = hop.geo
                && !g.is_private
                && g.lat.is_some()
                && g.lon.is_some()
            {
                reconcile_hop_with_speed_of_light(g, rtt, last_verified.as_ref());
                last_verified = Some(g.clone());
            }
        }
    }
}

pub fn render(
    ui: &mut Ui,
    palette: &AppPalette,
    state: &mut VisualTracerouteState,
    history: &mut PersistedState,
    rt: &Runtime,
) {
    ui.horizontal(|ui| {
        ui.label("Host:");
        let resp = ui.add(
            egui::TextEdit::singleline(&mut state.host)
                .desired_width(210.0)
                .hint_text("example.com or IP"),
        );
        let enter_pressed = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

        if let Some(act) =
            host_history_picker(ui, "vtrace_hist", &mut state.host, &history.recent_hosts)
        {
            match act {
                HistoryPickAction::Selected(h) => state.host = h,
                HistoryPickAction::Removed(h) => {
                    history.remove_host(&h);
                    let _ = history.save();
                }
            }
        }

        ui.label("Hops:");
        ui.add(egui::DragValue::new(&mut state.max_hops).range(1..=40));

        let btn = if state.running { "Stop" } else { "Trace" };
        if ui.button(btn).clicked() || (!state.running && enter_pressed) {
            if state.running {
                state.stop();
            } else {
                history.record_host(&state.host);
                let _ = history.save();
                state.start(rt, ui.ctx());
            }
        }

        if ui.button("Fit Route").clicked() {
            state.fit_route();
        }
        if ui.button("Türkiye").on_hover_text("Focus map on Türkiye (11.5x)").clicked() {
            state.focus_turkiye();
        }
        if ui.button("Reset View").clicked() {
            state.reset_view();
        }
        if ui.small_button("−").on_hover_text("Zoom Out").clicked() {
            state.zoom_by(1.0 / 1.35, None);
        }
        ui.monospace(format!("{:.1}x", state.zoom));
        if ui.small_button("+").on_hover_text("Zoom In").clicked() {
            state.zoom_by(1.35, None);
        }

        if let Some(ip) = state.resolved_ip {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                status_pill(
                    ui,
                    &format!("{ip}  •  {} hops", state.hops.len()),
                    palette.accent,
                    palette.card_subtle_bg,
                );
            });
        }
    });

    if let Some(ref err) = state.error {
        ui.add_space(6.0);
        status_pill(ui, err, palette.err, palette.err_bg);
    }

    ui.add_space(10.0);

    let avail_h = ui.available_height().max(360.0);
    let total_w = ui.available_width();
    let route_w = (total_w * 0.31).clamp(245.0, 315.0);
    let map_w = (total_w - route_w - 10.0).max(320.0);

    ui.horizontal_top(|ui| {
        // Left: Interactive Offline Vector World Map (explicit top-down container)
        ui.allocate_ui_with_layout(vec2(map_w, avail_h), Layout::top_down(Align::Min), |ui| {
            palette
                .card_frame()
                .inner_margin(egui::Margin::same(6))
                .show(ui, |ui| {
                    ui.set_width(map_w - 14.0);
                    ui.set_height(avail_h - 14.0);
                    paint_world_map(ui, palette, state);
                });
        });

        ui.add_space(8.0);

        // Right: Route Hop List (explicit top-down container so hops stack vertically)
        ui.allocate_ui_with_layout(vec2(route_w, avail_h), Layout::top_down(Align::Min), |ui| {
            palette.card_frame().show(ui, |ui| {
                ui.set_width(route_w - 30.0);
                ui.set_height(avail_h - 30.0);
                section_label(ui, palette, "ROUTE");
                ui.add_space(6.0);

                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    if state.hops.is_empty() {
                        ui.label(
                            egui::RichText::new("Run a trace to plot hops across the globe.")
                                .size(12.0)
                                .color(palette.text_muted),
                        );
                    }

                    let mut pending_focus_geo = None;

                    // Hop 0: Origin (User's own public egress IP & city)
                    if let Some(ref orig) = state.origin_geo {
                        let is_sel = state.selected_hop == Some(0);
                        let row_frame = if is_sel {
                            palette
                                .subtle_card_frame()
                                .stroke(Stroke::new(1.5, palette.accent))
                        } else {
                            palette.subtle_card_frame()
                        };
                        let mut clicked_orig = false;
                        row_frame
                            .inner_margin(egui::Margin::symmetric(8, 6))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                let resp = ui
                                    .horizontal(|ui| {
                                        let (dot, _) =
                                            ui.allocate_exact_size(vec2(10.0, 10.0), Sense::hover());
                                        ui.painter().circle_filled(dot.center(), 4.5, palette.accent);

                                        ui.monospace(" 0");
                                        ui.vertical(|ui| {
                                            ui.style_mut().wrap_mode =
                                                Some(egui::TextWrapMode::Truncate);
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "{} (This Mac)",
                                                    orig.short_place()
                                                ))
                                                .strong()
                                                .size(12.5),
                                            );
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "{}  •  0.0 ms",
                                                    orig.ip
                                                ))
                                                .size(11.0)
                                                .color(palette.text_muted),
                                            );
                                            if let Some(isp) = orig.isp.as_deref() {
                                                ui.label(
                                                    egui::RichText::new(isp)
                                                        .size(10.5)
                                                        .color(palette.text_muted),
                                                );
                                            }
                                        });
                                    })
                                    .response
                                    .interact(Sense::click());
                                if resp.clicked() {
                                    clicked_orig = true;
                                }
                            });
                        if clicked_orig {
                            state.selected_hop = Some(0);
                            if let (Some(lat), Some(lon)) = (orig.lat, orig.lon) {
                                pending_focus_geo = Some((lat, lon));
                            }
                        }
                        ui.add_space(4.0);
                    }

                    for hop in &state.hops {
                        let is_sel = state.selected_hop == Some(hop.trace.hop);
                        let row_frame = if is_sel {
                            palette
                                .subtle_card_frame()
                                .stroke(Stroke::new(1.5, palette.accent))
                        } else {
                            palette.subtle_card_frame()
                        };

                        let mut clicked_hop = None;
                        row_frame
                            .inner_margin(egui::Margin::symmetric(8, 6))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                let resp = ui
                                    .horizontal(|ui| {
                                        let dot_col = hop_rtt_color(
                                            palette,
                                            hop.trace.avg_ms,
                                            hop.trace.ip.is_none(),
                                        );
                                        let (dot, _) =
                                            ui.allocate_exact_size(vec2(10.0, 10.0), Sense::hover());
                                        ui.painter().circle_filled(dot.center(), 4.5, dot_col);

                                        ui.monospace(format!("{:>2}", hop.trace.hop));
                                        ui.vertical(|ui| {
                                            ui.style_mut().wrap_mode =
                                                Some(egui::TextWrapMode::Truncate);
                                            let title = match &hop.geo {
                                                Some(g) => g.short_place(),
                                                None => hop
                                                    .trace
                                                    .hostname
                                                    .clone()
                                                    .unwrap_or_else(|| {
                                                        hop.trace
                                                            .ip
                                                            .map(|i| i.to_string())
                                                            .unwrap_or_else(|| "* * *".into())
                                                    }),
                                            };
                                            ui.label(
                                                egui::RichText::new(title).strong().size(12.5),
                                            );
                                            let sub_ip = hop
                                                .trace
                                                .ip
                                                .map(|i| i.to_string())
                                                .unwrap_or_else(|| "No reply".into());
                                            let rtt_str = hop
                                                .trace
                                                .avg_ms
                                                .map(|m| format!("{m:.1} ms"))
                                                .unwrap_or_else(|| "*".into());
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "{sub_ip}  •  {rtt_str}"
                                                ))
                                                .size(11.0)
                                                .color(palette.text_muted),
                                            );
                                            if let Some(isp) =
                                                hop.geo.as_ref().and_then(|g| g.isp.as_deref())
                                            {
                                                ui.label(
                                                    egui::RichText::new(isp)
                                                        .size(10.5)
                                                        .color(palette.text_muted),
                                                );
                                            }
                                            if let Some(reg) = hop
                                                .geo
                                                .as_ref()
                                                .and_then(|g| g.registry_place.as_deref())
                                            {
                                                ui.label(
                                                    egui::RichText::new(format!(
                                                        "Anycast Edge • Registry HQ: {reg}"
                                                    ))
                                                    .size(10.0)
                                                    .color(palette.accent),
                                                );
                                            }
                                        });
                                    })
                                    .response
                                    .interact(Sense::click());
                                if resp.clicked() {
                                    clicked_hop = Some(hop.trace.hop);
                                    if let Some(ref g) = hop.geo
                                        && let (Some(lat), Some(lon)) = (g.lat, g.lon)
                                    {
                                        pending_focus_geo = Some((lat, lon));
                                    }
                                }
                            });
                        if let Some(hnum) = clicked_hop {
                            state.selected_hop = Some(hnum);
                        }
                        ui.add_space(4.0);
                    }
                    if let Some((lat, lon)) = pending_focus_geo {
                        state.focus_lat_lon(lat, lon, state.zoom.max(8.5));
                    }
                });
            });
        });
    });
}

fn paint_world_map(ui: &mut Ui, palette: &AppPalette, state: &mut VisualTracerouteState) {
    let rect = ui.available_rect_before_wrap();
    let resp = ui.allocate_rect(rect, Sense::click_and_drag());

    // Handle pan, trackpad pinch zoom, cursor-anchored scroll zoom, and double-click zoom
    if resp.dragged() {
        let delta = resp.drag_delta();
        state.pan += vec2(
            delta.x / rect.width().max(1.0),
            delta.y / rect.height().max(1.0),
        );
    }
    if resp.hovered() {
        let pointer = ui.input(|i| i.pointer.hover_pos());
        let anchor_norm = pointer.map(|p| {
            [
                ((p.x - rect.left()) / rect.width().max(1.0)).clamp(0.0, 1.0),
                ((p.y - rect.top()) / rect.height().max(1.0)).clamp(0.0, 1.0),
            ]
        });

        let pinch = ui.input(|i| i.zoom_delta());
        if (pinch - 1.0).abs() > 1e-3 {
            state.zoom_by(pinch.clamp(0.75, 1.35), anchor_norm);
        } else {
            let scroll = ui.input(|i| i.smooth_scroll_delta.y);
            if scroll.abs() > 0.1 {
                let factor = (1.0 + scroll * 0.0025).clamp(0.78, 1.28);
                state.zoom_by(factor, anchor_norm);
            }
        }

        if resp.double_clicked() {
            state.zoom_by(1.85, anchor_norm);
        }
    }
    // Clamp pan so map stays in viewport
    let max_pan = (state.zoom - 1.0) * 0.52 + 0.08;
    state.pan.x = state.pan.x.clamp(-max_pan, max_pan);
    state.pan.y = state.pan.y.clamp(-max_pan, max_pan);

    let painter = ui.painter_at(rect).with_clip_rect(rect);

    let (ocean_col, grid_col, land_fill, land_stroke) = if palette.dark {
        (
            Color32::from_rgb(18, 29, 44),
            Color32::from_rgba_unmultiplied(120, 150, 190, 24),
            Color32::from_rgb(47, 63, 79),
            Color32::from_rgb(71, 92, 114),
        )
    } else {
        (
            Color32::from_rgb(206, 229, 248),
            Color32::from_rgba_unmultiplied(120, 155, 190, 48),
            Color32::from_rgb(219, 232, 206),
            Color32::from_rgb(168, 189, 152),
        )
    };

    painter.rect_filled(rect, 6.0, ocean_col);

    let map = world_map();
    let zoom = state.zoom;
    let pan = state.pan;
    let project_norm = |nx: f32, ny: f32| -> Pos2 {
        let sx = (nx - 0.5) * zoom + 0.5 + pan.x;
        let sy = (ny - 0.5) * zoom + 0.5 + pan.y;
        pos2(rect.left() + sx * rect.width(), rect.top() + sy * rect.height())
    };

    // Subtle lat/lon graticule
    for lon_deg in [-120.0, -60.0, 0.0, 60.0, 120.0] {
        let [nx, _] = lon_lat_to_norm(lon_deg, 0.0);
        let p0 = project_norm(nx, 0.0);
        let p1 = project_norm(nx, 1.0);
        painter.line_segment([p0, p1], Stroke::new(0.8, grid_col));
    }
    for lat_deg in [-60.0, -30.0, 0.0, 30.0, 60.0] {
        let [_, ny] = lon_lat_to_norm(0.0, lat_deg);
        let p0 = project_norm(0.0, ny);
        let p1 = project_norm(1.0, ny);
        painter.line_segment([p0, p1], Stroke::new(0.8, grid_col));
    }

    // Filled landmasses via pre-triangulated offline Natural Earth polygons
    // Keep each Mesh under ~3000 vertices so epaint's batch combiner never exceeds u16::MAX (65,535) vertices per batch
    for chunk in &map.meshes_norm {
        let mesh = Mesh {
            vertices: chunk
                .0
                .iter()
                .map(|[nx, ny]| Vertex {
                    pos: project_norm(*nx, *ny),
                    uv: WHITE_UV,
                    color: land_fill,
                })
                .collect(),
            indices: chunk.1.clone(),
            ..Default::default()
        };
        painter.add(Shape::mesh(mesh));
    }

    for ring in &map.rings {
        let slice = if ring.len() > 3 && ring.first() == ring.last() {
            &ring[..ring.len() - 1]
        } else {
            &ring[..]
        };
        if slice.len() >= 3 {
            // Draw country borders via direct 2-vertex line_segments (~2 verts/edge vs ~8 in PathShape)
            let mut prev = project_norm(slice[slice.len() - 1][0], slice[slice.len() - 1][1]);
            for &[nx, ny] in slice {
                let cur = project_norm(nx, ny);
                if (rect.contains(prev) || rect.contains(cur))
                    && (cur.x - prev.x).abs() < rect.width() * 0.45
                {
                    painter.line_segment([prev, cur], Stroke::new(0.85, land_stroke));
                }
                prev = cur;
            }
        }
    }

    // Build unified list of geo-located hops starting with Hop 0 (This Mac's public egress IP & city)
    let origin_hop: Option<VisualHop> = state.origin_geo.as_ref().and_then(|g| {
        if g.lat.is_some() && g.lon.is_some() {
            Some(VisualHop {
                trace: TracerouteHop {
                    hop: 0,
                    ip: Some(g.ip),
                    hostname: None,
                    probe_rtts_ms: vec![Some(0.0)],
                    avg_ms: Some(0.0),
                    reached_target: false,
                },
                geo: Some(g.clone()),
            })
        } else {
            None
        }
    });

    let mut geo_hops: Vec<&VisualHop> = Vec::new();
    if let Some(ref oh) = origin_hop {
        geo_hops.push(oh);
    }
    geo_hops.extend(state.hops.iter().filter(|h| {
        h.geo
            .as_ref()
            .is_some_and(|g| g.lat.is_some() && g.lon.is_some())
    }));

    // Draw geodesic arcs between consecutive located hops
    for pair in geo_hops.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        let (Some(ga), Some(gb)) = (&a.geo, &b.geo) else {
            continue;
        };
        let (Some(lat1), Some(lon1), Some(lat2), Some(lon2)) = (ga.lat, ga.lon, gb.lat, gb.lon)
        else {
            continue;
        };
        let arc_col = hop_rtt_color(palette, b.trace.avg_ms, false);
        let segments = geodesic_segments(lat1, lon1, lat2, lon2, 24);
        for seg in segments {
            let screen_pts: Vec<Pos2> = seg
                .into_iter()
                .map(|(lat, lon)| {
                    let [nx, ny] = lon_lat_to_norm(lon, lat);
                    project_norm(nx, ny)
                })
                .collect();
            if screen_pts.len() >= 2 {
                painter.add(Shape::Path(PathShape::line(
                    screen_pts,
                    PathStroke::new(2.4, arc_col),
                )));
            }
        }
    }

    // Draw numbered markers + hover tooltips + city callouts at zoom >= 3.0
    let pointer = ui.input(|i| i.pointer.hover_pos());
    let mut hovered: Option<&VisualHop> = None;

    // Count how many hops share roughly the same city/coordinate (~0.25 deg) so we can fan them cleanly when zoomed in
    let mut coord_counts: Vec<((i32, i32), usize, usize, String)> = Vec::new();
    for hop in &geo_hops {
        if let Some(ref g) = hop.geo
            && let (Some(lat), Some(lon)) = (g.lat, g.lon)
        {
            let key = ((lat * 4.0).round() as i32, (lon * 4.0).round() as i32);
            if let Some(entry) = coord_counts.iter_mut().find(|(k, _, _, _)| *k == key) {
                entry.1 += 1;
                let tag = if hop.trace.hop == 0 {
                    ", #0 [You]".to_string()
                } else {
                    match &g.anycast_pop {
                        Some(pop) => format!(", #{} [{pop}]", hop.trace.hop),
                        None => format!(", #{}", hop.trace.hop),
                    }
                };
                entry.3.push_str(&tag);
            } else {
                let first_tag = if hop.trace.hop == 0 {
                    "#0 [You]".to_string()
                } else {
                    match &g.anycast_pop {
                        Some(pop) => format!("#{} [{pop}]", hop.trace.hop),
                        None => format!("#{}", hop.trace.hop),
                    }
                };
                let city_base = match (&g.city, &g.country_code) {
                    (Some(c), Some(cc)) if !c.is_empty() => format!("{c}, {cc}"),
                    _ => g.short_place(),
                };
                coord_counts.push((key, 1, 0, format!("{city_base} ({first_tag}")));
            }
        }
    }

    let mut placed_obstacles: Vec<egui::Rect> = Vec::new();
    let mut deferred_pills: Vec<(Pos2, f32, String)> = Vec::new();
    for hop in &geo_hops {
        let Some(ref g) = hop.geo else {
            continue;
        };
        let (Some(lat), Some(lon)) = (g.lat, g.lon) else {
            continue;
        };
        let [nx, ny] = lon_lat_to_norm(lon, lat);
        let base_center = project_norm(nx, ny);

        let key = ((lat * 4.0).round() as i32, (lon * 4.0).round() as i32);
        let (total_at_spot, idx_at_spot, group_label) =
            if let Some(entry) = coord_counts.iter_mut().find(|(k, _, _, _)| *k == key) {
                let idx = entry.2;
                entry.2 += 1;
                (entry.1, idx, format!("{})", entry.3))
            } else {
                (1, 0, g.short_place())
            };

        // Fan co-located markers radially when zoomed in so every hop number is visible
        let center = if total_at_spot > 1 && zoom >= 2.5 {
            let angle = (idx_at_spot as f32 / total_at_spot as f32) * std::f32::consts::TAU
                - std::f32::consts::FRAC_PI_2;
            let min_ring_r = (total_at_spot as f32 * 3.1).max(13.5);
            let radius = min_ring_r.min(zoom * 2.1);
            base_center + vec2(angle.cos() * radius, angle.sin() * radius)
        } else {
            base_center
        };

        let selected = state.selected_hop == Some(hop.trace.hop);
        let marker_col = if hop.trace.hop == 0 || hop.trace.reached_target {
            palette.accent
        } else {
            hop_rtt_color(palette, hop.trace.avg_ms, false)
        };
        let r = if selected { 11.5 } else { 9.5 };

        if selected {
            painter.circle_stroke(center, r + 3.5, Stroke::new(2.0, Color32::WHITE));
        }
        if g.is_anycast || hop.trace.hop == 0 {
            painter.circle_stroke(center, r + 2.2, Stroke::new(1.5, palette.accent));
        }
        painter.circle_filled(center, r, marker_col);
        painter.circle_stroke(center, r, Stroke::new(1.5, Color32::WHITE));
        painter.text(
            center,
            Align2::CENTER_CENTER,
            hop.trace.hop.to_string(),
            FontId::proportional(10.0),
            Color32::WHITE,
        );
        placed_obstacles.push(egui::Rect::from_center_size(
            center,
            vec2((r + 3.0) * 2.0, (r + 3.0) * 2.0),
        ));

        // Queue city + hop callout pill once per coordinate cluster when zoomed in
        if zoom >= 3.0 && idx_at_spot == 0 {
            let rtt_txt = if hop.trace.hop == 0 {
                " • Origin".to_string()
            } else {
                hop.trace
                    .avg_ms
                    .map(|m| format!(" • {m:.1} ms"))
                    .unwrap_or_default()
            };
            let callout_text = format!("{group_label}{rtt_txt}");
            let ring_clearance = if total_at_spot > 1 {
                (total_at_spot as f32 * 3.1).max(13.5).min(zoom * 2.1) + 14.0
            } else {
                14.0
            };
            deferred_pills.push((base_center, ring_clearance, callout_text));
        }

        if let Some(ptr) = pointer
            && ptr.distance(center) <= r + 4.0
        {
            hovered = Some(hop);
            if resp.clicked() {
                state.selected_hop = Some(hop.trace.hop);
            }
        }
    }

    // Second pass: place and paint city callout pills avoiding all markers and earlier pills
    for (base_center, ring_clearance, callout_text) in deferred_pills {
        let galley = painter.layout_no_wrap(
            callout_text,
            FontId::proportional(11.0),
            palette.text_primary,
        );
        let pad = vec2(6.0, 3.0);
        let pill_size = galley.size() + pad * 2.0;
        let dy = ring_clearance + pill_size.y * 0.5;
        let dx_side = ring_clearance + pill_size.x * 0.5 + 2.0;

        let candidates = [
            pos2(base_center.x, base_center.y - dy),
            pos2(base_center.x, base_center.y + dy),
            pos2(base_center.x + dx_side, base_center.y),
            pos2(base_center.x - dx_side, base_center.y),
            pos2(base_center.x + pill_size.x * 0.45, base_center.y - dy - 16.0),
            pos2(base_center.x - pill_size.x * 0.45, base_center.y - dy - 16.0),
            pos2(base_center.x, base_center.y - dy - 22.0),
            pos2(base_center.x, base_center.y + dy + 22.0),
        ];
        let mut pill_rect = egui::Rect::from_center_size(candidates[0], pill_size);
        let safe_bounds = rect.shrink(6.0);
        for cand in candidates {
            let r_cand = egui::Rect::from_center_size(cand, pill_size);
            let inside = safe_bounds.contains(r_cand.min) && safe_bounds.contains(r_cand.max);
            if inside
                && !placed_obstacles
                    .iter()
                    .any(|p| p.expand(2.5).intersects(r_cand))
            {
                pill_rect = r_cand;
                break;
            }
        }
        placed_obstacles.push(pill_rect);
        let pill_bg = if palette.dark {
            Color32::from_rgba_unmultiplied(15, 23, 36, 228)
        } else {
            Color32::from_rgba_unmultiplied(255, 255, 255, 236)
        };
        painter.rect_filled(pill_rect, 5.0, pill_bg);
        painter.rect_stroke(
            pill_rect,
            5.0,
            Stroke::new(1.0, palette.card_border),
            egui::StrokeKind::Inside,
        );
        painter.galley(pill_rect.min + pad, galley, palette.text_primary);
    }

    if let Some(hop) = hovered
        && let Some(ref g) = hop.geo
    {
        let rtt = hop
            .trace
            .avg_ms
            .map(|m| format!("{m:.1} ms"))
            .unwrap_or_else(|| "*".into());
        let ip = hop
            .trace
            .ip
            .map(|i| i.to_string())
            .unwrap_or_default();
        let isp = g.isp.as_deref().unwrap_or("");
        let reg_line = g
            .registry_place
            .as_deref()
            .map(|r| format!("\nAnycast Registry HQ: {r}"))
            .unwrap_or_default();
        resp.on_hover_text(format!(
            "Hop #{} • {} ({ip})\nRTT: {rtt}{}{reg_line}",
            hop.trace.hop,
            g.short_place(),
            if isp.is_empty() {
                String::new()
            } else {
                format!("\nISP: {isp}")
            }
        ));
    }

    // Bottom-right overlay stats badge
    let badge_pos = pos2(rect.right() - 10.0, rect.bottom() - 10.0);
    let located = geo_hops.len();
    let total = state.hops.len() + usize::from(state.origin_geo.is_some());
    let label = format!("{located}/{total} points mapped (Origin + Hops)  •  Drag to pan, scroll to zoom");
    painter.text(
        badge_pos,
        Align2::RIGHT_BOTTOM,
        label,
        FontId::proportional(10.5),
        palette.text_muted,
    );
}

fn hop_rtt_color(palette: &AppPalette, rtt: Option<f64>, silent: bool) -> Color32 {
    if silent {
        return palette.text_muted;
    }
    match rtt {
        Some(ms) if ms >= 100.0 => palette.err,
        Some(ms) if ms >= 40.0 => palette.warn,
        Some(_) => palette.ok,
        None => palette.text_muted,
    }
}

/// Generates great-circle arc segments (lat, lon) split safely across the ±180° antimeridian.
fn geodesic_segments(
    lat1_deg: f64,
    lon1_deg: f64,
    lat2_deg: f64,
    lon2_deg: f64,
    steps: usize,
) -> Vec<Vec<(f64, f64)>> {
    let (lat1, lon1) = (lat1_deg.to_radians(), lon1_deg.to_radians());
    let (lat2, lon2) = (lat2_deg.to_radians(), lon2_deg.to_radians());

    let p1 = [
        lat1.cos() * lon1.cos(),
        lat1.cos() * lon1.sin(),
        lat1.sin(),
    ];
    let p2 = [
        lat2.cos() * lon2.cos(),
        lat2.cos() * lon2.sin(),
        lat2.sin(),
    ];
    let dot = (p1[0] * p2[0] + p1[1] * p2[1] + p1[2] * p2[2]).clamp(-1.0, 1.0);
    let omega = dot.acos();

    let mut segments: Vec<Vec<(f64, f64)>> = vec![Vec::new()];
    let mut prev_lon: Option<f64> = None;

    for i in 0..=steps {
        let t = i as f64 / steps as f64;
        let (x, y, z) = if omega.abs() < 1e-5 {
            (
                p1[0] + (p2[0] - p1[0]) * t,
                p1[1] + (p2[1] - p1[1]) * t,
                p1[2] + (p2[2] - p1[2]) * t,
            )
        } else {
            let sin_o = omega.sin();
            let a = ((1.0 - t) * omega).sin() / sin_o;
            let b = (t * omega).sin() / sin_o;
            (
                a * p1[0] + b * p2[0],
                a * p1[1] + b * p2[1],
                a * p1[2] + b * p2[2],
            )
        };
        let norm = (x * x + y * y + z * z).sqrt().max(1e-9);
        let lat = (z / norm).asin().to_degrees();
        let lon = y.atan2(x).to_degrees();

        if let Some(plon) = prev_lon
            && (lon - plon).abs() > 180.0
        {
            segments.push(Vec::new());
        }
        segments.last_mut().unwrap().push((lat, lon));
        prev_lon = Some(lon);
    }

    segments
}
