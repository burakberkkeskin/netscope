use crate::speedtest::BufferbloatGrade;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

const MAX_RECENT_HOSTS: usize = 25;
const MAX_RECENT_TLS: usize = 20;
const MAX_RUN_HISTORY: usize = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsTargetEntry {
    pub host: String,
    pub port: u16,
    pub sni: String,
    pub custom_ca_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Iperf3ServerProfile {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub parallel_streams: u8,
    pub duration_secs: u16,
    pub reverse: bool,
    #[serde(default)]
    pub bidir: bool,
    pub use_udp: bool,
    pub udp_bandwidth_mbps: u32,
    #[serde(default)]
    pub omit_secs: u8,
    #[serde(default)]
    pub buffer_len_kb: u16,
    #[serde(default)]
    pub no_delay: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedTestRecord {
    pub timestamp: DateTime<Utc>,
    pub download_mbps: f64,
    pub upload_mbps: f64,
    pub idle_median_ms: f64,
    pub loaded_dl_median_ms: Option<f64>,
    pub loaded_ul_median_ms: Option<f64>,
    pub bufferbloat_grade: BufferbloatGrade,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iperf3Record {
    pub timestamp: DateTime<Utc>,
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub direction: String,
    pub streams: u8,
    pub duration_secs: f64,
    pub avg_mbps: f64,
    pub retransmits: Option<u64>,
    pub jitter_ms: Option<f64>,
    pub lost_pct: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownLanDevice {
    pub key: String, // normalized MAC address (or IP fallback when MAC unknown)
    pub last_ip: String,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistedState {
    #[serde(default)]
    pub recent_hosts: Vec<String>,
    #[serde(default)]
    pub recent_dns_queries: Vec<String>,
    #[serde(default)]
    pub recent_tls_targets: Vec<TlsTargetEntry>,
    #[serde(default)]
    pub iperf3_servers: Vec<Iperf3ServerProfile>,
    #[serde(default)]
    pub speedtest_history: Vec<SpeedTestRecord>,
    #[serde(default)]
    pub iperf3_history: Vec<Iperf3Record>,
    #[serde(default)]
    pub known_lan_devices: Vec<KnownLanDevice>,
}

impl PersistedState {
    pub fn default_path() -> Option<PathBuf> {
        #[cfg(target_os = "macos")]
        {
            std::env::var_os("HOME").map(|h| {
                PathBuf::from(h)
                    .join("Library")
                    .join("Application Support")
                    .join("NetScope")
                    .join("state.json")
            })
        }
        #[cfg(target_os = "windows")]
        {
            std::env::var_os("APPDATA")
                .map(|d| PathBuf::from(d).join("NetScope").join("state.json"))
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .or_else(|| {
                    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config"))
                })
                .map(|dir| dir.join("netscope").join("state.json"))
        }
    }

    pub fn load() -> Self {
        let Some(path) = Self::default_path() else {
            return Self::default();
        };
        Self::load_from(&path)
    }

    pub fn load_from(path: &Path) -> Self {
        let mut state: Self = match std::fs::read_to_string(path) {
            Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
            Err(_) => Self::default(),
        };
        state
            .known_lan_devices
            .retain(|d| d.key != "02:00:00:00:00:00");
        state
    }

    pub fn save(&self) -> io::Result<()> {
        let Some(path) = Self::default_path() else {
            return Ok(());
        };
        self.save_to(&path)
    }

    pub fn save_to(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }

    pub fn record_host(&mut self, host: &str) {
        push_mru(&mut self.recent_hosts, host, MAX_RECENT_HOSTS);
    }

    pub fn remove_host(&mut self, host: &str) {
        self.recent_hosts
            .retain(|h| !h.eq_ignore_ascii_case(host.trim()));
    }

    pub fn record_dns(&mut self, query: &str) {
        push_mru(&mut self.recent_dns_queries, query, MAX_RECENT_HOSTS);
        push_mru(&mut self.recent_hosts, query, MAX_RECENT_HOSTS);
    }

    pub fn record_tls(&mut self, entry: TlsTargetEntry) {
        if entry.host.trim().is_empty() {
            return;
        }
        self.recent_tls_targets.retain(|e| {
            !(e.host.eq_ignore_ascii_case(entry.host.trim()) && e.port == entry.port)
        });
        self.recent_tls_targets.insert(0, entry.clone());
        self.recent_tls_targets.truncate(MAX_RECENT_TLS);
        self.record_host(&entry.host);
    }

    pub fn upsert_iperf3_server(&mut self, profile: Iperf3ServerProfile) {
        if profile.host.trim().is_empty() {
            return;
        }
        self.iperf3_servers
            .retain(|p| !p.name.eq_ignore_ascii_case(profile.name.trim()));
        self.iperf3_servers.insert(0, profile.clone());
        self.record_host(&profile.host);
    }

    pub fn remove_iperf3_server(&mut self, name: &str) {
        self.iperf3_servers
            .retain(|p| !p.name.eq_ignore_ascii_case(name));
    }

    pub fn record_speedtest(&mut self, rec: SpeedTestRecord) {
        self.speedtest_history.insert(0, rec);
        self.speedtest_history.truncate(MAX_RUN_HISTORY);
    }

    pub fn record_iperf3(&mut self, rec: Iperf3Record) {
        self.iperf3_history.insert(0, rec.clone());
        self.iperf3_history.truncate(MAX_RUN_HISTORY);
        self.record_host(&rec.host);
    }

    pub fn is_known_lan_device(&self, key: &str) -> bool {
        self.known_lan_devices
            .iter()
            .any(|d| d.key.eq_ignore_ascii_case(key.trim()))
    }

    pub fn trust_lan_device(
        &mut self,
        key: &str,
        ip: &str,
        hostname: Option<String>,
        vendor: Option<String>,
    ) {
        let now = Utc::now();
        let k = key.trim().to_ascii_uppercase();
        if let Some(existing) = self
            .known_lan_devices
            .iter_mut()
            .find(|d| d.key.eq_ignore_ascii_case(&k))
        {
            existing.last_ip = ip.to_string();
            if hostname.is_some() {
                existing.hostname = hostname;
            }
            if vendor.is_some() {
                existing.vendor = vendor;
            }
            existing.last_seen = now;
        } else {
            self.known_lan_devices.push(KnownLanDevice {
                key: k,
                last_ip: ip.to_string(),
                hostname,
                vendor,
                first_seen: now,
                last_seen: now,
            });
        }
    }
}

fn push_mru(list: &mut Vec<String>, raw: &str, max_len: usize) {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return;
    }
    list.retain(|item| !item.eq_ignore_ascii_case(trimmed));
    list.insert(0, trimmed.to_string());
    list.truncate(max_len);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mru_deduplicates_case_insensitively_and_caps_size() {
        let mut st = PersistedState::default();
        for i in 0..30 {
            st.record_host(&format!("host-{i}.local"));
        }
        assert_eq!(st.recent_hosts.len(), MAX_RECENT_HOSTS);
        assert_eq!(st.recent_hosts[0], "host-29.local");

        st.record_host("HOST-25.LOCAL");
        assert_eq!(st.recent_hosts[0], "HOST-25.LOCAL");
        assert_eq!(st.recent_hosts.len(), MAX_RECENT_HOSTS);
    }

    #[test]
    fn save_and_load_roundtrip_via_temp_file() {
        let dir = std::env::temp_dir().join(format!("netscope_hist_{}", std::process::id()));
        let path = dir.join("state.json");
        let _ = std::fs::remove_dir_all(&dir);

        let mut st = PersistedState::default();
        st.record_host("1.1.1.1");
        st.record_dns("example.com");
        st.upsert_iperf3_server(Iperf3ServerProfile {
            name: "Homelab LAN".into(),
            host: "192.168.1.10".into(),
            port: 5201,
            parallel_streams: 4,
            duration_secs: 10,
            reverse: false,
            bidir: false,
            use_udp: false,
            udp_bandwidth_mbps: 100,
            omit_secs: 0,
            buffer_len_kb: 128,
            no_delay: false,
        });
        st.save_to(&path).expect("save should succeed");

        let loaded = PersistedState::load_from(&path);
        assert_eq!(loaded.recent_hosts[0], "192.168.1.10");
        assert!(loaded.recent_hosts.contains(&"example.com".to_string()));
        assert_eq!(loaded.iperf3_servers.len(), 1);
        assert_eq!(loaded.iperf3_servers[0].name, "Homelab LAN");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
