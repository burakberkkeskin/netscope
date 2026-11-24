pub mod dns;
pub mod dns_propagation;
pub mod geoip;
pub mod history;
pub mod icmp;
pub mod internet_check;
pub mod iperf3;
pub mod ipv6_check;
pub mod lan_scanner;
pub mod net_info;
pub mod path_troubleshoot;
pub mod port_scan;
pub mod speedtest;
pub mod stats;
pub mod subnet;
pub mod tls;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;

/// IP address family selection for active probing tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum IpFamily {
    #[default]
    Auto,
    Ipv4,
    Ipv6,
}

impl IpFamily {
    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "Auto",
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
        }
    }
}

/// Shared error type across `netscope-core` diagnostic engines.
#[derive(Debug, Error)]
pub enum NetError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("DNS resolution failed: {0}")]
    Dns(String),

    #[error("Network I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Operation timed out")]
    Timeout,

    #[error("Operation cancelled")]
    Cancelled,
}

/// Lightweight cooperative cancellation token avoiding external crate overhead.
#[derive(Clone, Debug, Default)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
}

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

/// Installs the process-wide `aws-lc-rs` crypto provider idempotently.
pub fn ensure_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
