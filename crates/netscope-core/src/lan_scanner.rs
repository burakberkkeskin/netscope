use crate::CancelToken;
use crate::icmp::{ProbeOutcome, probe_once};
use crate::net_info::get_local_network_info;
use crate::port_scan::{PortScanEntry, probe_tcp_port};
use crate::subnet::enumerate_ipv4_hosts;
use hickory_resolver::{Resolver, TokioResolver};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::sync::{Semaphore, mpsc};

/// Quick service discovery ports probed on every alive LAN device.
const LAN_QUICK_PORTS: &[u16] = &[
    22, 53, 80, 443, 445, 548, 631, 3000, 3389, 5000, 5001, 7000, 8006, 8080, 8096, 8123, 8443,
    9000, 32400, 62078,
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanDevice {
    pub ip: Ipv4Addr,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub device_role: String,
    pub is_gateway: bool,
    pub is_this_host: bool,
    pub latency_ms: Option<f64>,
    pub open_ports: Vec<PortScanEntry>,
}

impl LanDevice {
    /// Stable identity key for Network Guard (`MAC` when available, otherwise `IP`).
    pub fn guard_key(&self) -> String {
        self.mac
            .clone()
            .unwrap_or_else(|| self.ip.to_string())
            .to_ascii_uppercase()
    }

    pub fn display_name(&self) -> String {
        if let Some(ref h) = self.hostname
            && !h.is_empty()
        {
            return h.clone();
        }
        if self.is_gateway {
            return "Router / Gateway".into();
        }
        if self.is_this_host {
            return "This Host".into();
        }
        if let Some(ref v) = self.vendor {
            return format!("{v} ({})", self.device_role);
        }
        self.device_role.clone()
    }

    pub fn open_ports_summary(&self) -> String {
        if self.open_ports.is_empty() {
            return "—".into();
        }
        let nums: Vec<String> = self
            .open_ports
            .iter()
            .take(5)
            .map(|p| p.port.to_string())
            .collect();
        if self.open_ports.len() > 5 {
            format!("{}, +{}", nums.join(", "), self.open_ports.len() - 5)
        } else {
            nums.join(", ")
        }
    }
}

#[derive(Debug, Clone)]
pub enum LanScanEvent {
    Started { cidr: String, total_hosts: usize },
    Progress { completed: usize, total: usize },
    DeviceFound(LanDevice),
    Finished,
    Error(String),
}

/// Normalizes any MAC format (`a4:83:e7:a:b:cc`, `a4-83-e7-0a-0b-cc`) into canonical `A4:83:E7:0A:0B:CC`.
pub fn normalize_mac(raw: &str) -> Option<String> {
    let cleaned = raw.trim().replace('-', ":");
    let parts: Vec<&str> = cleaned.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() || part.len() > 2 {
            return None;
        }
        bytes[i] = u8::from_str_radix(part, 16).ok()?;
    }
    // Ignore broadcast, all-zero, or macOS redacted privacy MAC (02:00:00:00:00:00)
    if bytes == [0, 0, 0, 0, 0, 0]
        || bytes == [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        || bytes == [0x02, 0, 0, 0, 0, 0]
    {
        return None;
    }
    Some(format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    ))
}

/// Looks up manufacturer / vendor from a normalized MAC address using an embedded IEEE OUI prefix table
/// plus Locally Administered Address (LAA) randomized MAC detection.
pub fn lookup_mac_vendor(mac: &str) -> Option<String> {
    let norm = normalize_mac(mac)?;
    let prefix = &norm[0..8];

    // Check high-priority exact 24-bit OUIs first (including hypervisor OUIs that have the LAA bit set, like Proxmox BC:24:11)
    for &(oui, vendor) in OUI_TABLE {
        if oui == prefix {
            return Some(vendor.to_string());
        }
    }

    // Check if the Universal/Local bit (bit 1 of first octet) is set => Locally Administered / Private Wi-Fi Address
    if let Ok(first_byte) = u8::from_str_radix(&norm[0..2], 16)
        && (first_byte & 0x02) != 0
    {
        return Some("Randomized / Private MAC".into());
    }

    None
}

const OUI_TABLE: &[(&str, &str)] = &[
    // Hypervisors, Containers & Virtualization
    ("BC:24:11", "Proxmox VE"),
    ("52:54:00", "QEMU / KVM"),
    ("00:50:56", "VMware"),
    ("00:0C:29", "VMware"),
    ("00:15:5D", "Microsoft Hyper-V"),
    ("08:00:27", "VirtualBox"),
    ("00:16:3E", "Xen / XCP-ng"),
    ("02:42:AC", "Docker Container"),
    // Apple
    ("84:2F:57", "Apple"),
    ("A4:83:E7", "Apple"),
    ("AC:BC:32", "Apple"),
    ("24:0A:C4", "Espressif (ESP32)"),
    ("F0:18:98", "Apple"),
    ("BC:D0:74", "Apple"),
    ("D0:81:7A", "Apple"),
    ("3C:22:FB", "Apple"),
    ("14:7D:DA", "Apple"),
    ("64:B0:A6", "Apple"),
    ("8C:85:90", "Apple"),
    ("A8:51:AB", "Apple"),
    ("C8:69:CD", "Apple"),
    ("DC:A9:04", "Apple"),
    ("E0:AC:CB", "Apple"),
    ("F8:FF:C2", "Apple"),
    // Synology & QNAP NAS
    ("00:11:32", "Synology"),
    ("90:09:D0", "Synology"),
    ("24:5E:BE", "QNAP"),
    ("00:08:9B", "QNAP"),
    // Raspberry Pi & SBCs
    ("B8:27:EB", "Raspberry Pi"),
    ("DC:A6:32", "Raspberry Pi"),
    ("E4:5F:01", "Raspberry Pi"),
    ("28:CD:C1", "Raspberry Pi"),
    ("D8:3A:DD", "Raspberry Pi"),
    ("2C:CF:67", "Raspberry Pi"),
    // Ubiquiti / UniFi
    ("F0:9F:C2", "Ubiquiti"),
    ("24:5A:4C", "Ubiquiti"),
    ("74:83:C2", "Ubiquiti"),
    ("80:2A:A8", "Ubiquiti"),
    ("B4:FB:E4", "Ubiquiti"),
    ("E0:63:DA", "Ubiquiti"),
    ("70:A7:41", "Ubiquiti"),
    // MikroTik, Netgear, Asus, TP-Link, Keenetic, Zyxel
    ("48:8F:5A", "MikroTik"),
    ("B8:69:F4", "MikroTik"),
    ("C4:AD:34", "MikroTik"),
    ("DC:2C:6E", "MikroTik"),
    ("50:C7:BF", "TP-Link"),
    ("60:32:B1", "TP-Link"),
    ("68:7F:F0", "TP-Link"),
    ("B0:BE:76", "TP-Link"),
    ("98:DA:C4", "TP-Link"),
    ("50:91:E3", "TP-Link"),
    ("04:D9:F5", "ASUS"),
    ("2C:FD:A1", "ASUS"),
    ("F0:2F:74", "ASUS"),
    ("50:46:5D", "ASUS"),
    ("9C:3D:CF", "Netgear"),
    ("B0:7F:B9", "Netgear"),
    ("50:FF:20", "Keenetic"),
    ("E4:18:6B", "Zyxel"),
    ("58:8B:F3", "Zyxel"),
    // Intel, Realtek, Gigabyte, Mellanox
    ("A0:36:9F", "Intel"),
    ("00:1B:21", "Intel"),
    ("3C:FD:FE", "Intel"),
    ("48:21:0B", "Intel"),
    ("84:47:09", "Intel"),
    ("D8:5E:D3", "Gigabyte"),
    ("A8:A1:59", "ASRock / Realtek"),
    ("00:E0:4C", "Realtek"),
    // Smart Home & Media (Philips Hue, Sonos, Espressif, Tuya, Xiaomi, Roborock, LG, Samsung, HP)
    ("00:17:88", "Philips Hue"),
    ("EC:B5:FA", "Philips Hue"),
    ("00:0E:58", "Sonos"),
    ("5C:AA:FD", "Sonos"),
    ("78:28:CA", "Sonos"),
    ("30:AE:A4", "Espressif"),
    ("84:F3:EB", "Espressif"),
    ("A4:CF:12", "Espressif"),
    ("CC:50:E3", "Espressif"),
    ("3C:2A:F4", "HP Printer"),
    ("70:5A:0F", "HP"),
    ("64:90:C1", "Xiaomi"),
    ("7C:49:EB", "Xiaomi"),
    ("B0:4A:39", "Roborock"),
    ("28:39:5E", "Samsung"),
    ("8C:79:F5", "Samsung"),
    ("AC:5A:F0", "LG Electronics"),
];

/// Parses cross-platform `arp -an` or `/proc/net/arp` lines into an `Ipv4Addr -> normalized MAC` table.
pub fn parse_arp_output(raw: &str) -> HashMap<Ipv4Addr, String> {
    let mut map = HashMap::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.contains("incomplete") {
            continue;
        }
        // Extract IPv4 address (either inside `(192.168.1.1)` on macOS/BSD or whitespace-delimited on Linux/Windows)
        let mut found_ip: Option<Ipv4Addr> = None;
        let mut found_mac: Option<String> = None;

        for token in trimmed.split_whitespace() {
            let clean_tok = token.trim_matches(|c| c == '(' || c == ')' || c == '[' || c == ']');
            if found_ip.is_none()
                && let Ok(ip) = clean_tok.parse::<Ipv4Addr>()
            {
                found_ip = Some(ip);
                continue;
            }
            if found_mac.is_none()
                && let Some(mac) = normalize_mac(clean_tok)
            {
                found_mac = Some(mac);
            }
        }

        if let (Some(ip), Some(mac)) = (found_ip, found_mac) {
            map.insert(ip, mac);
        }
    }
    map
}

pub async fn read_system_arp_table() -> HashMap<Ipv4Addr, String> {
    #[cfg(target_os = "linux")]
    if let Ok(proc_arp) = tokio::fs::read_to_string("/proc/net/arp").await {
        let map = parse_arp_output(&proc_arp);
        if !map.is_empty() {
            return map;
        }
    }

    #[cfg(target_os = "macos")]
    if let Ok(out) = Command::new("/usr/sbin/arp").arg("-an").output().await {
        let text = String::from_utf8_lossy(&out.stdout);
        let map = parse_arp_output(&text);
        if !map.is_empty() {
            return map;
        }
    }

    if let Ok(out) = Command::new("arp").arg("-an").output().await {
        let text = String::from_utf8_lossy(&out.stdout);
        return parse_arp_output(&text);
    }
    HashMap::new()
}

pub fn infer_device_role(
    is_gateway: bool,
    is_this_host: bool,
    vendor: Option<&str>,
    hostname: Option<&str>,
    open_ports: &[PortScanEntry],
) -> String {
    if is_gateway {
        return "Gateway / Router".into();
    }
    if is_this_host {
        return "This Host".into();
    }
    let has_port = |p: u16| open_ports.iter().any(|e| e.port == p);
    if has_port(8006) || vendor == Some("Proxmox VE") {
        return "Proxmox VE Node".into();
    }
    if has_port(8123) {
        return "Home Assistant".into();
    }
    if has_port(5000) || has_port(5001) || vendor == Some("Synology") || vendor == Some("QNAP") {
        return "NAS / Storage".into();
    }
    if has_port(631) || has_port(9100) || has_port(515) {
        return "Network Printer".into();
    }
    if has_port(62078) {
        return "iPhone / iPad".into();
    }
    if has_port(7000) && vendor == Some("Apple") {
        return "Apple TV / HomePod".into();
    }
    if has_port(32400) || has_port(8096) {
        return "Media Server".into();
    }
    if has_port(53) {
        return "DNS Server".into();
    }
    if has_port(445) || has_port(548) {
        return "File Server".into();
    }
    if has_port(22) {
        return "Linux / SSH Host".into();
    }
    if let Some(h) = hostname {
        let low = h.to_ascii_lowercase();
        if low.contains("iphone") || low.contains("ipad") {
            return "iOS Device".into();
        }
        if low.contains("macbook") || low.contains("imac") || low.contains("mac-") {
            return "Mac".into();
        }
    }
    if let Some(v) = vendor {
        return format!("{v} Device");
    }
    "LAN Host".into()
}

/// Auto-detects the default LAN CIDR (e.g. `"192.168.1.0/24"`) from the primary interface.
pub fn default_lan_cidr() -> String {
    if let Ok(info) = get_local_network_info()
        && let Some(v4) = info.local_ipv4
    {
        let o = v4.octets();
        return format!("{}.{}.{}.0/24", o[0], o[1], o[2]);
    }
    "192.168.1.0/24".into()
}

pub async fn run_lan_scan(
    cidr_input: String,
    tx: mpsc::UnboundedSender<LanScanEvent>,
    cancel: CancelToken,
) {
    let (cidr, hosts) = match enumerate_ipv4_hosts(&cidr_input, 512) {
        Ok(res) => res,
        Err(e) => {
            let _ = tx.send(LanScanEvent::Error(e));
            return;
        }
    };

    let hosts_set: std::collections::HashSet<Ipv4Addr> = hosts.iter().copied().collect();
    let local_info = get_local_network_info().ok();
    let local_ipv4 = local_info.as_ref().and_then(|i| i.local_ipv4);
    let gateway_ipv4 = local_info.as_ref().and_then(|i| match i.gateway_ip {
        Some(IpAddr::V4(v4)) => Some(v4),
        _ => None,
    });
    let local_mac = local_info
        .as_ref()
        .and_then(|i| i.mac_address.as_deref())
        .and_then(normalize_mac);

    let total = hosts.len();
    let _ = tx.send(LanScanEvent::Started {
        cidr,
        total_hosts: total,
    });

    // Phase 1: High-concurrency ping + quick TCP connect touch to trigger kernel ARP resolution
    let sem = Arc::new(Semaphore::new(64));
    let completed = Arc::new(AtomicUsize::new(0));
    let mut probe_tasks = Vec::with_capacity(total);

    for (idx, ip) in hosts.into_iter().enumerate() {
        if cancel.is_cancelled() {
            return;
        }
        let sem_c = sem.clone();
        let tx_c = tx.clone();
        let cancel_c = cancel.clone();
        let done_c = completed.clone();
        let seq = ((idx + 1) & 0xffff) as u16;

        probe_tasks.push(tokio::spawn(async move {
            let Ok(_permit) = sem_c.acquire().await else {
                return (ip, None);
            };
            if cancel_c.is_cancelled() {
                return (ip, None);
            }

            let ip_addr = IpAddr::V4(ip);
            let rtt = match probe_once(ip_addr, 64, seq, Duration::from_millis(320)).await {
                ProbeOutcome::EchoReply { rtt_ms, .. } => Some(rtt_ms),
                _ => {
                    // Fallback TCP touch on 80 or 443 to wake silent hosts & populate ARP cache
                    let started = std::time::Instant::now();
                    if tokio::time::timeout(
                        Duration::from_millis(180),
                        TcpStream::connect(SocketAddr::new(ip_addr, 80)),
                    )
                    .await
                    .is_ok_and(|r| r.is_ok())
                        || tokio::time::timeout(
                            Duration::from_millis(180),
                            TcpStream::connect(SocketAddr::new(ip_addr, 443)),
                        )
                        .await
                        .is_ok_and(|r| r.is_ok())
                    {
                        Some(started.elapsed().as_secs_f64() * 1000.0)
                    } else {
                        None
                    }
                }
            };

            let cur = done_c.fetch_add(1, Ordering::Relaxed) + 1;
            if cur.is_multiple_of(8) || cur == total {
                let _ = tx_c.send(LanScanEvent::Progress {
                    completed: cur,
                    total,
                });
            }
            (ip, rtt)
        }));
    }

    let mut rtt_map: HashMap<Ipv4Addr, f64> = HashMap::new();
    for h in probe_tasks {
        if let Ok((ip, Some(ms))) = h.await {
            rtt_map.insert(ip, ms);
        }
    }

    if cancel.is_cancelled() {
        return;
    }

    // Phase 2: Read OS ARP table to include firewalled hosts within the scanned subnet
    let mut arp_map = read_system_arp_table().await;
    if let (Some(lip), Some(lmac)) = (local_ipv4, local_mac)
        && hosts_set.contains(&lip)
    {
        arp_map.entry(lip).or_insert(lmac);
        rtt_map.entry(lip).or_insert(0.1);
    }

    let mut discovered_ips: Vec<Ipv4Addr> = rtt_map.keys().copied().collect();
    for &arp_ip in arp_map.keys() {
        if hosts_set.contains(&arp_ip) && !discovered_ips.contains(&arp_ip) {
            discovered_ips.push(arp_ip);
        }
    }
    discovered_ips.sort();

    // Phase 3: Enrich each alive host with reverse DNS, OUI vendor, and quick service port scan
    let resolver: Arc<Option<TokioResolver>> = Arc::new(
        Resolver::builder_tokio()
            .ok()
            .and_then(|b| b.build().ok()),
    );
    let enrich_sem = Arc::new(Semaphore::new(16));
    let mut enrich_tasks = Vec::with_capacity(discovered_ips.len());

    for ip in discovered_ips {
        if cancel.is_cancelled() {
            return;
        }
        let sem_c = enrich_sem.clone();
        let tx_c = tx.clone();
        let cancel_c = cancel.clone();
        let res_c = resolver.clone();
        let mac = arp_map.get(&ip).cloned();
        let mut latency_ms = rtt_map.get(&ip).copied();
        let is_gateway = gateway_ipv4 == Some(ip);
        let is_this_host = local_ipv4 == Some(ip);

        enrich_tasks.push(tokio::spawn(async move {
            let Ok(_permit) = sem_c.acquire().await else {
                return;
            };
            if cancel_c.is_cancelled() {
                return;
            }

            let ip_addr = IpAddr::V4(ip);
            let ptr_fut = async {
                if let Some(ref r) = *res_c {
                    tokio::time::timeout(Duration::from_millis(600), r.reverse_lookup(ip_addr))
                        .await
                        .ok()
                        .and_then(|res| res.ok())
                        .and_then(|lookup| {
                            lookup
                                .answers()
                                .first()
                                .map(|rec| rec.data.to_string().trim_end_matches('.').to_string())
                        })
                } else {
                    None
                }
            };

            let ip_str = ip.to_string();
            let mut port_futs = Vec::with_capacity(LAN_QUICK_PORTS.len());
            for &port in LAN_QUICK_PORTS {
                port_futs.push(probe_tcp_port(
                    ip_addr,
                    &ip_str,
                    port,
                    Duration::from_millis(320),
                    true,
                ));
            }

            let hostname = ptr_fut.await;
            let mut open_ports = Vec::new();
            for pf in port_futs {
                if let Some(entry) = pf.await {
                    if latency_ms.is_none() {
                        latency_ms = entry.rtt_ms;
                    }
                    open_ports.push(entry);
                }
            }
            open_ports.sort_by_key(|e| e.port);

            let vendor = mac.as_deref().and_then(lookup_mac_vendor);
            let device_role = infer_device_role(
                is_gateway,
                is_this_host,
                vendor.as_deref(),
                hostname.as_deref(),
                &open_ports,
            );

            let dev = LanDevice {
                ip,
                hostname,
                mac,
                vendor,
                device_role,
                is_gateway,
                is_this_host,
                latency_ms,
                open_ports,
            };
            let _ = tx_c.send(LanScanEvent::DeviceFound(dev));
        }));
    }

    for h in enrich_tasks {
        let _ = h.await;
    }
    let _ = tx.send(LanScanEvent::Finished);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_macos_short_hex_mac_and_looks_up_oui_vendor() {
        let mac = normalize_mac("a4:83:e7:a:b:cc").expect("valid short mac");
        assert_eq!(mac, "A4:83:E7:0A:0B:CC");
        assert_eq!(lookup_mac_vendor(&mac).as_deref(), Some("Apple"));

        let pve = normalize_mac("bc:24:11:42:1:9").unwrap();
        assert_eq!(lookup_mac_vendor(&pve).as_deref(), Some("Proxmox VE"));

        let laa = normalize_mac("da:a1:19:00:11:22").unwrap();
        assert_eq!(
            lookup_mac_vendor(&laa).as_deref(),
            Some("Randomized / Private MAC")
        );

        assert!(normalize_mac("02:00:00:00:00:00").is_none());
        assert!(normalize_mac("00:00:00:00:00:00").is_none());
        assert!(normalize_mac("ff:ff:ff:ff:ff:ff").is_none());
    }

    #[test]
    fn parses_macos_and_linux_arp_outputs() {
        let sample = "\
? (192.168.1.1) at 50:ff:20:1:2:3 on en0 ifscope [ethernet]
? (192.168.1.63) at 0:11:32:aa:bb:cc on en0 ifscope [ethernet]
? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]
192.168.1.100 ether bc:24:11:10:20:30 C eth0
";
        let map = parse_arp_output(sample);
        assert_eq!(map.len(), 3);
        assert_eq!(
            map.get(&Ipv4Addr::new(192, 168, 1, 1)).map(String::as_str),
            Some("50:FF:20:01:02:03")
        );
        assert_eq!(
            map.get(&Ipv4Addr::new(192, 168, 1, 63)).map(String::as_str),
            Some("00:11:32:AA:BB:CC")
        );
        assert_eq!(
            map.get(&Ipv4Addr::new(192, 168, 1, 100)).map(String::as_str),
            Some("BC:24:11:10:20:30")
        );
    }
}
