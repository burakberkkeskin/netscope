use crate::CancelToken;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::sync::{Semaphore, mpsc};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortPreset {
    Common30,
    WebAndInfra,
    Top100,
    Custom,
}

impl PortPreset {
    pub fn label(self) -> &'static str {
        match self {
            Self::Common30 => "Common 30",
            Self::WebAndInfra => "Web & Infra",
            Self::Top100 => "Top 100",
            Self::Custom => "Custom Range",
        }
    }

    pub fn spec_string(self) -> &'static str {
        match self {
            Self::Common30 => {
                "21,22,23,25,53,80,110,111,135,139,143,443,445,548,587,631,993,995,1433,1883,3000,3306,3389,5000,5001,5432,5900,6379,8006,8080,8123,8443"
            }
            Self::WebAndInfra => {
                "22,53,80,81,443,445,548,631,1883,2375,2376,3000,3389,5000,5001,5353,6443,7000,8000,8006,8080,8096,8123,8443,8888,9000,9090,9093,9100,9443,32400,62078"
            }
            Self::Top100 => {
                "20-23,25,53,67-69,80,81,88,110,111,119,123,135,137-139,143,161,162,179,389,443,445,465,500,514,515,548,554,587,631,636,873,902,990,993,995,1080,1194,1433,1521,1723,1883,2049,2082,2083,2181,2222,2375,2376,3000,3128,3268,3306,3389,3690,4000,4443,4500,5000,5001,5060,5201,5222,5353,5432,5672,5900,5984,6379,6443,6667,7000,7001,7443,8000,8006,8008,8080,8081,8086,8088,8096,8123,8200,8443,8500,8883,8888,9000,9042,9090,9092,9100,9200,9418,9443,11211,27017,32400,51820,62078"
            }
            Self::Custom => "22,53,80,443,445,3389,5000,8006,8080,8443",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

impl PortState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Closed => "Closed",
            Self::Filtered => "Filtered",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanEntry {
    pub port: u16,
    pub protocol: String,
    pub state: PortState,
    pub service: String,
    pub version_banner: Option<String>,
    pub rtt_ms: Option<f64>,
}

#[derive(Debug, Clone)]
pub enum PortScanEvent {
    Resolved { host: String, ip: IpAddr, total_ports: usize },
    Progress { completed: usize, total: usize },
    PortFound(PortScanEntry),
    Finished,
    Error(String),
}

#[derive(Debug, Clone)]
pub struct PortScanConfig {
    pub host: String,
    pub port_spec: String,
    pub include_udp: bool,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub grab_banners: bool,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port_spec: PortPreset::Common30.spec_string().into(),
            include_udp: false,
            concurrency: 64,
            timeout_ms: 750,
            grab_banners: true,
        }
    }
}

/// Parses a comma-separated port specification like `"22,80,443,8000-8010"` into a sorted, deduplicated vector of ports.
pub fn parse_port_spec(spec: &str) -> Result<Vec<u16>, String> {
    let mut ports = BTreeSet::new();
    for raw_part in spec.split(',') {
        let part = raw_part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start_s, end_s)) = part.split_once('-') {
            let start: u16 = start_s
                .trim()
                .parse()
                .map_err(|_| format!("Invalid start port in range '{part}'"))?;
            let end: u16 = end_s
                .trim()
                .parse()
                .map_err(|_| format!("Invalid end port in range '{part}'"))?;
            if start == 0 || end == 0 || start > end {
                return Err(format!("Invalid port range '{part}' (must be 1..=65535 and start <= end)"));
            }
            for p in start..=end {
                ports.insert(p);
                if ports.len() > 10_000 {
                    return Err("Port range exceeds 10,000 ports maximum per scan".into());
                }
            }
        } else {
            let p: u16 = part
                .parse()
                .map_err(|_| format!("Invalid port number '{part}'"))?;
            if p == 0 {
                return Err("Port 0 is not valid".into());
            }
            ports.insert(p);
        }
    }
    if ports.is_empty() {
        return Err("Specify at least one port (e.g. 22,80,443,8000-8010)".into());
    }
    Ok(ports.into_iter().collect())
}

/// Maps well-known TCP/UDP port numbers to service names.
pub fn well_known_service(port: u16, udp: bool) -> &'static str {
    if udp {
        return match port {
            53 => "DNS",
            67 | 68 => "DHCP",
            69 => "TFTP",
            123 => "NTP",
            137 => "NetBIOS-NS",
            138 => "NetBIOS-DGM",
            161 | 162 => "SNMP",
            500 | 4500 => "IPsec/IKE",
            514 => "Syslog",
            1194 => "OpenVPN",
            1900 => "SSDP/UPnP",
            5353 => "mDNS/Bonjour",
            51820 => "WireGuard",
            _ => "UDP",
        };
    }

    match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 | 81 | 8000 | 8008 | 8080 | 8081 | 8888 => "HTTP",
        88 => "Kerberos",
        110 => "POP3",
        111 => "RPCBind",
        119 => "NNTP",
        135 => "MS-RPC",
        139 => "NetBIOS-SSN",
        143 => "IMAP",
        179 => "BGP",
        389 => "LDAP",
        443 | 4443 | 7443 | 8443 | 9443 => "HTTPS",
        445 => "SMB",
        465 | 587 => "SMTPS/Submission",
        515 => "LPD Printer",
        548 => "AFP (Apple Filing)",
        554 => "RTSP",
        631 => "IPP / AirPrint",
        636 => "LDAPS",
        873 => "rsync",
        993 => "IMAPS",
        995 => "POP3S",
        1080 => "SOCKS",
        1433 => "MSSQL",
        1521 => "Oracle DB",
        1883 => "MQTT",
        2049 => "NFS",
        2222 => "SSH (Alt)",
        2375 | 2376 => "Docker API",
        3000 => "Grafana / Web",
        3128 => "Squid Proxy",
        3306 => "MySQL / MariaDB",
        3389 => "RDP",
        5000 => "HTTP / AirPlay / DSM",
        5001 => "HTTPS / Synology DSM",
        5060 => "SIP",
        5201 => "iperf3",
        5432 => "PostgreSQL",
        5672 => "AMQP / RabbitMQ",
        5900 => "VNC",
        6379 => "Redis",
        6443 => "Kubernetes API",
        7000 => "AirPlay / RTSP",
        8006 => "Proxmox VE",
        8086 => "InfluxDB",
        8096 => "Jellyfin",
        8123 => "Home Assistant",
        8200 => "Vault",
        8500 => "Consul",
        8883 => "MQTTS",
        9000 => "Portainer / MinIO",
        9090 => "Prometheus / Cockpit",
        9093 => "Alertmanager",
        9100 => "Node Exporter / JetDirect",
        9200 => "Elasticsearch",
        9418 => "Git",
        11211 => "Memcached",
        27017 => "MongoDB",
        32400 => "Plex Media Server",
        62078 => "Apple iOS Sync (lockdownd)",
        _ => "TCP",
    }
}

pub async fn run_port_scan(
    cfg: PortScanConfig,
    tx: mpsc::UnboundedSender<PortScanEvent>,
    cancel: CancelToken,
) {
    let host = cfg.host.trim().to_string();
    if host.is_empty() {
        let _ = tx.send(PortScanEvent::Error("Target host cannot be empty".into()));
        return;
    }

    let ports = match parse_port_spec(&cfg.port_spec) {
        Ok(p) => p,
        Err(e) => {
            let _ = tx.send(PortScanEvent::Error(e));
            return;
        }
    };

    let lookup_str = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:80")
    } else {
        format!("{host}:80")
    };
    let target_ip = match tokio::time::timeout(Duration::from_secs(4), lookup_host(&lookup_str)).await {
        Ok(Ok(mut addrs)) => match addrs.next() {
            Some(sa) => sa.ip(),
            None => {
                let _ = tx.send(PortScanEvent::Error(format!("No IP found for {host}")));
                return;
            }
        },
        _ => {
            let _ = tx.send(PortScanEvent::Error(format!("Failed resolving host {host}")));
            return;
        }
    };

    let mut work: Vec<(u16, bool)> = ports.iter().map(|&p| (p, false)).collect();
    if cfg.include_udp {
        for &p in &[53u16, 123, 137, 161, 500, 1900, 5353, 51820] {
            if ports.contains(&p) {
                work.push((p, true));
            }
        }
    }

    let total = work.len();
    let _ = tx.send(PortScanEvent::Resolved {
        host: host.clone(),
        ip: target_ip,
        total_ports: total,
    });

    let sem = Arc::new(Semaphore::new(cfg.concurrency.clamp(4, 256)));
    let completed = Arc::new(AtomicUsize::new(0));
    let timeout = Duration::from_millis(cfg.timeout_ms.clamp(150, 5000));
    let grab_banners = cfg.grab_banners;

    let mut handles = Vec::with_capacity(total);
    for (port, is_udp) in work {
        if cancel.is_cancelled() {
            break;
        }
        let sem_c = sem.clone();
        let tx_c = tx.clone();
        let cancel_c = cancel.clone();
        let done_c = completed.clone();
        let host_c = host.clone();

        handles.push(tokio::spawn(async move {
            let Ok(_permit) = sem_c.acquire().await else {
                return;
            };
            if cancel_c.is_cancelled() {
                return;
            }

            let entry_opt = if is_udp {
                probe_udp_port(target_ip, port, timeout).await
            } else {
                probe_tcp_port(target_ip, &host_c, port, timeout, grab_banners).await
            };

            if let Some(entry) = entry_opt {
                let _ = tx_c.send(PortScanEvent::PortFound(entry));
            }
            let cur = done_c.fetch_add(1, Ordering::Relaxed) + 1;
            let _ = tx_c.send(PortScanEvent::Progress {
                completed: cur,
                total,
            });
        }));
    }

    for h in handles {
        let _ = h.await;
    }
    let _ = tx.send(PortScanEvent::Finished);
}

/// Probes a single TCP port and optionally grabs its service/version banner if open.
pub async fn probe_tcp_port(
    ip: IpAddr,
    host_header: &str,
    port: u16,
    timeout: Duration,
    grab_banner: bool,
) -> Option<PortScanEntry> {
    let target = SocketAddr::new(ip, port);
    let started = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect(target)).await {
        Ok(Ok(mut stream)) => {
            let rtt_ms = started.elapsed().as_secs_f64() * 1000.0;
            let mut service = well_known_service(port, false).to_string();
            let banner = if grab_banner {
                grab_tcp_banner(&mut stream, host_header, port, &mut service).await
            } else {
                None
            };
            Some(PortScanEntry {
                port,
                protocol: "TCP".into(),
                state: PortState::Open,
                service,
                version_banner: banner,
                rtt_ms: Some(rtt_ms),
            })
        }
        Ok(Err(_)) | Err(_) => None,
    }
}

async fn grab_tcp_banner(
    stream: &mut TcpStream,
    host_header: &str,
    port: u16,
    service_out: &mut String,
) -> Option<String> {
    let _ = stream.set_nodelay(true);
    let mut buf = [0u8; 512];

    // 1. Wait briefly for server-first greeting (SSH, FTP, SMTP, POP3, IMAP)
    let is_http_port = matches!(
        port,
        80 | 81 | 443 | 3000 | 5000 | 5001 | 7000 | 8000 | 8006 | 8080 | 8081 | 8096 | 8123 | 8443 | 8888 | 9000 | 9090 | 32400
    );
    if !is_http_port
        && let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(240), stream.read(&mut buf)).await
        && n > 0
    {
        let line = sanitize_banner_line(&buf[..n]);
        if !line.is_empty() {
            if line.starts_with("SSH-") {
                *service_out = "SSH".into();
            }
            return Some(line);
        }
    }

    // 2. Send a lightweight HTTP/1.0 HEAD probe to extract Server: or HTTP status
    let req = format!("HEAD / HTTP/1.0\r\nHost: {host_header}\r\nUser-Agent: NetScope/0.1\r\nConnection: close\r\n\r\n");
    if stream.write_all(req.as_bytes()).await.is_ok()
        && let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(320), stream.read(&mut buf)).await
        && n > 0
    {
        let text = String::from_utf8_lossy(&buf[..n]);
        let mut status_line = None;
        let mut server_hdr = None;
        for line in text.lines() {
            let trimmed = line.trim();
            if status_line.is_none() && trimmed.starts_with("HTTP/") {
                status_line = Some(trimmed.to_string());
            } else if let Some(rest) = trimmed.strip_prefix("Server:").or_else(|| trimmed.strip_prefix("server:")) {
                server_hdr = Some(rest.trim().to_string());
            }
        }
        if let Some(srv) = server_hdr {
            let srv_low = srv.to_ascii_lowercase();
            if srv_low.contains("airtunes") || srv_low.contains("airplay") {
                *service_out = "AirPlay / AirTunes".into();
            } else if srv_low.contains("synology") {
                *service_out = "Synology DSM".into();
            } else if srv_low.contains("pve") || port == 8006 {
                *service_out = "Proxmox VE".into();
            }
            return Some(srv);
        }
        if let Some(st) = status_line {
            return Some(st);
        }
    }
    None
}

fn sanitize_banner_line(bytes: &[u8]) -> String {
    let raw = String::from_utf8_lossy(bytes);
    let first = raw.lines().next().unwrap_or("").trim();
    first
        .chars()
        .filter(|c| !c.is_control())
        .take(72)
        .collect::<String>()
}

async fn probe_udp_port(ip: IpAddr, port: u16, timeout: Duration) -> Option<PortScanEntry> {
    let bind_addr = match ip {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let sock = UdpSocket::bind(bind_addr).await.ok()?;
    sock.connect(SocketAddr::new(ip, port)).await.ok()?;

    // Protocol-specific UDP probe payload (DNS query for 53/5353, NTP client v3 for 123)
    let payload: &[u8] = match port {
        53 | 5353 => &[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'v',
            b'e', b'r', b's', b'i', b'o', b'n', 0x04, b'b', b'i', b'n', b'd', 0x00, 0x00, 0x10,
            0x00, 0x03,
        ],
        123 => &[
            0x1b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        _ => b"\r\n",
    };

    let started = Instant::now();
    sock.send(payload).await.ok()?;
    let mut buf = [0u8; 256];
    match tokio::time::timeout(timeout, sock.recv(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => Some(PortScanEntry {
            port,
            protocol: "UDP".into(),
            state: PortState::Open,
            service: well_known_service(port, true).into(),
            version_banner: Some(format!("{n}-byte UDP response")),
            rtt_ms: Some(started.elapsed().as_secs_f64() * 1000.0),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn parses_complex_port_specifications_and_rejects_invalid() {
        let ports = parse_port_spec("80, 22, 443, 8000-8003, 22").unwrap();
        assert_eq!(ports, vec![22, 80, 443, 8000, 8001, 8002, 8003]);
        assert!(parse_port_spec("0").is_err());
        assert!(parse_port_spec("9000-8000").is_err());
    }

    #[tokio::test]
    async fn scans_ephemeral_tcp_server_and_grabs_ssh_banner() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let _ = s.write_all(b"SSH-2.0-OpenSSH_9.8p1\r\n").await;
            }
        });

        let entry = probe_tcp_port(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "127.0.0.1",
            port,
            Duration::from_millis(500),
            true,
        )
        .await
        .expect("port should be detected as open");

        assert_eq!(entry.port, port);
        assert_eq!(entry.state, PortState::Open);
        assert_eq!(entry.service, "SSH");
        assert_eq!(
            entry.version_banner.as_deref(),
            Some("SSH-2.0-OpenSSH_9.8p1")
        );
    }
}
