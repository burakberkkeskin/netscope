#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod theme;
mod tray;
mod views;
mod widgets;

use app::{NetScopeApp, ScreenshotConfig};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

fn parse_screenshot_config() -> Option<ScreenshotConfig> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--screenshot-dir" {
            return args.next().map(|p| ScreenshotConfig {
                dir: PathBuf::from(p),
                demo: false,
            });
        }
        if let Some(val) = arg.strip_prefix("--screenshot-dir=") {
            return Some(ScreenshotConfig {
                dir: PathBuf::from(val),
                demo: false,
            });
        }
        if arg == "--demo-screenshots" {
            return args.next().map(|p| ScreenshotConfig {
                dir: PathBuf::from(p),
                demo: true,
            });
        }
        if let Some(val) = arg.strip_prefix("--demo-screenshots=") {
            return Some(ScreenshotConfig {
                dir: PathBuf::from(val),
                demo: true,
            });
        }
    }
    None
}

fn main() -> eframe::Result<()> {
    netscope_core::ensure_crypto_provider();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let screenshot_cfg = parse_screenshot_config();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([920.0, 620.0])
            .with_app_id("dev.burakberk.netscope"),
        ..Default::default()
    };

    eframe::run_native(
        "NetScope",
        native_options,
        Box::new(move |cc| Ok(Box::new(NetScopeApp::new(cc, screenshot_cfg)))),
    )
}
