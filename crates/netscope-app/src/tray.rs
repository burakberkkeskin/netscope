use netscope_core::net_info::{DnsLeakStatus, PublicNetworkStatus};
use tracing::warn;
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder, TrayIconEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    ToggleWindow,
    RunInternetCheck,
    RefreshStatus,
    Quit,
}

pub struct TrayController {
    _tray: TrayIcon,
    ip_info_item: MenuItem,
    vpn_info_item: MenuItem,
    leak_info_item: MenuItem,
    id_toggle: MenuId,
    id_check: MenuId,
    id_refresh: MenuId,
    id_quit: MenuId,
}

impl TrayController {
    /// Must be called on the main thread after `winit`/`eframe` initializes the event loop.
    pub fn try_new() -> Option<Self> {
        let icon = match build_radar_icon() {
            Ok(i) => i,
            Err(e) => {
                warn!("Failed to build tray icon RGBA buffer: {e}");
                return None;
            }
        };

        let menu = Menu::new();
        let ip_info_item = MenuItem::new("Public IP: checking...", false, None);
        let vpn_info_item = MenuItem::new("VPN: checking...", false, None);
        let leak_info_item = MenuItem::new("DNS Leak: checking...", false, None);

        let toggle_item = MenuItem::new("Show / Hide NetScope", true, None);
        let check_item = MenuItem::new("Run Internet Check", true, None);
        let refresh_item = MenuItem::new("Refresh Network Info", true, None);
        let quit_item = MenuItem::new("Quit NetScope", true, None);

        let id_toggle = toggle_item.id().clone();
        let id_check = check_item.id().clone();
        let id_refresh = refresh_item.id().clone();
        let id_quit = quit_item.id().clone();

        if let Err(e) = menu.append_items(&[
            &ip_info_item,
            &vpn_info_item,
            &leak_info_item,
            &PredefinedMenuItem::separator(),
            &toggle_item,
            &check_item,
            &refresh_item,
            &PredefinedMenuItem::separator(),
            &quit_item,
        ]) {
            warn!("Failed populating tray menu: {e}");
            return None;
        }

        let builder = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("NetScope — Network Diagnostics");
        #[cfg(target_os = "macos")]
        let builder = builder.with_icon_templated(icon);
        #[cfg(not(target_os = "macos"))]
        let builder = builder.with_icon(icon);
        let tray = match builder.build()
        {
            Ok(t) => t,
            Err(e) => {
                warn!("TrayIcon unavailable in this environment: {e}");
                return None;
            }
        };

        Some(Self {
            _tray: tray,
            ip_info_item,
            vpn_info_item,
            leak_info_item,
            id_toggle,
            id_check,
            id_refresh,
            id_quit,
        })
    }

    pub fn update_status(&self, st: &PublicNetworkStatus) {
        let ip_str = st
            .public_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "Offline".into());
        let isp_part = st
            .isp_or_org
            .as_deref()
            .map(|o| format!(" ({o})"))
            .unwrap_or_default();
        self.ip_info_item
            .set_text(format!("Public IP: {ip_str}{isp_part}"));

        let vpn_text = if st.vpn_active {
            format!("VPN: Active ({})", st.vpn_interfaces.join(", "))
        } else {
            "VPN: Off".into()
        };
        self.vpn_info_item.set_text(vpn_text);

        let leak_text = match (st.dns_leak_status, st.dns_resolver_ip) {
            (DnsLeakStatus::NoLeak, Some(ip)) => format!("DNS: Matches IP ({ip})"),
            (DnsLeakStatus::ExternalResolver, Some(ip)) => format!("DNS: Upstream ({ip})"),
            (DnsLeakStatus::PossibleLeak, Some(ip)) => {
                format!("DNS Leak Warning: ({ip})")
            }
            _ => "DNS: Unknown".into(),
        };
        self.leak_info_item.set_text(leak_text);

        let tooltip = format!(
            "NetScope | IP: {ip_str} | VPN: {}",
            if st.vpn_active { "On" } else { "Off" }
        );
        let _ = self._tray.set_tooltip(Some(tooltip));
    }

    pub fn poll_actions(&self) -> Vec<TrayAction> {
        let mut actions = Vec::new();
        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            if ev.id == self.id_toggle {
                actions.push(TrayAction::ToggleWindow);
            } else if ev.id == self.id_check {
                actions.push(TrayAction::RunInternetCheck);
            } else if ev.id == self.id_refresh {
                actions.push(TrayAction::RefreshStatus);
            } else if ev.id == self.id_quit {
                actions.push(TrayAction::Quit);
            }
        }
        // Drain icon click events without leaking unread events
        while let Ok(ev) = TrayIconEvent::receiver().try_recv() {
            if matches!(ev, TrayIconEvent::DoubleClick { .. }) {
                actions.push(TrayAction::ToggleWindow);
            }
        }
        actions
    }
}

fn build_radar_icon() -> Result<Icon, tray_icon::BadIcon> {
    const SIZE: usize = 32;
    let mut rgba = vec![0u8; SIZE * SIZE * 4];
    let center = (SIZE as f32 - 1.0) / 2.0;

    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let dist = (dx * dx + dy * dy).sqrt();
            let idx = (y * SIZE + x) * 4;

            // Concentric radar rings + center pulse dot (monochrome template friendly)
            let on_outer_ring = (dist - 12.5).abs() < 1.35;
            let on_inner_ring = (dist - 7.5).abs() < 1.2;
            let on_center_dot = dist < 2.8;
            let on_crosshair = (dx.abs() < 0.9 || dy.abs() < 0.9) && dist <= 13.0;

            if on_outer_ring || on_inner_ring || on_center_dot || on_crosshair {
                rgba[idx] = 255;
                rgba[idx + 1] = 255;
                rgba[idx + 2] = 255;
                rgba[idx + 3] = if on_crosshair && !on_outer_ring && !on_inner_ring && !on_center_dot {
                    150
                } else {
                    255
                };
            }
        }
    }

    Icon::from_rgba(rgba, SIZE as u32, SIZE as u32)
}
