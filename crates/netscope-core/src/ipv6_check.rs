use crate::dns::{DnsRecordType, DnsServerChoice};
use crate::icmp::{probe_once, probe_once_v6_scoped};
use crate::internet_check::{StageHealth, VerdictSeverity};
use crate::net_info::{LinkType, get_local_network_info};
use crate::stats::compute_latency_stats;
use crate::{CancelToken, NetError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const IPV6_PROBE_PRIMARY: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
const IPV6_PROBE_FALLBACK: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
const IPV4_PROBE_FALLBACK: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const LARGE_FRAME_TARGET_BYTES: usize = 32_768;
const RFC8200_MIN_MTU: u32 = 1280;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ipv6AddressScope {
    GlobalUnicast,
    UniqueLocal,
    LinkLocal,
    Loopback,
    Other,
}

impl Ipv6AddressScope {
    pub fn badge_label(self) -> &'static str {
        match self {
            Self::GlobalUnicast => "GUA",
            Self::UniqueLocal => "ULA",
            Self::LinkLocal => "LINK-LOCAL",
            Self::Loopback => "LOOPBACK",
            Self::Other => "OTHER",
        }
    }

    fn sort_rank(self) -> u8 {
        match self {
            Self::GlobalUnicast => 0,
            Self::UniqueLocal => 1,
            Self::LinkLocal => 2,
            Self::Other => 3,
            Self::Loopback => 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6AddressEntry {
    pub addr: Ipv6Addr,
    pub prefix_len: u8,
    pub scope: Ipv6AddressScope,
    pub is_slaac: bool,
    pub is_temporary: bool,
    pub is_secured: bool,
    pub is_deprecated: bool,
    pub is_tentative: bool,
    pub is_duplicated: bool,
    pub is_permanent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaPrefixInfo {
    pub prefix: String,
    pub autonomous: bool,
    pub on_link: bool,
    pub valid_lft: Option<String>,
    pub preferred_lft: Option<String>,
    #[serde(default)]
    pub expire: Option<String>,
    pub router: Option<String>,
    pub router_reachable: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RaInterfaceParams {
    pub ra_link_mtu: Option<u32>,
    pub cur_hop_limit: Option<u8>,
    pub base_reachable: Option<String>,
    pub reachable: Option<String>,
    pub retrans: Option<String>,
    pub nd6_flags: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RaRouterInfo {
    pub gateway: Option<Ipv6Addr>,
    pub gateway_display: Option<String>,
    pub managed_m: bool,
    pub other_o: bool,
    pub preference: Option<String>,
    pub expire: Option<String>,
    pub provisioning_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalIpv6Inventory {
    pub interface_name: String,
    pub interface_index: u32,
    pub link_type: LinkType,
    pub link_mtu: Option<u32>,
    pub nd6_options: Option<String>,
    pub addresses: Vec<Ipv6AddressEntry>,
    pub ra_router: RaRouterInfo,
    pub ra_prefixes: Vec<RaPrefixInfo>,
    #[serde(default)]
    pub ra_interface: RaInterfaceParams,
    #[serde(default)]
    pub raw_slaac_dump: String,
    pub ipv6_dns_servers: Vec<Ipv6Addr>,
    pub has_link_local: bool,
    pub has_gua: bool,
    pub has_ula: bool,
    pub has_privacy_temp: bool,
    pub has_dad_issue: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ipv6StageKind {
    LocalStack,
    Router,
    IcmpV6,
    DnsV6,
    HttpsV6,
    Pmtud,
}

impl Ipv6StageKind {
    pub fn title(self) -> &'static str {
        match self {
            Self::LocalStack => "Local Stack",
            Self::Router => "Router (NDP)",
            Self::IcmpV6 => "ICMPv6",
            Self::DnsV6 => "DNS v6",
            Self::HttpsV6 => "HTTPS v6",
            Self::Pmtud => "PMTUD",
        }
    }

    pub fn node_code(self) -> &'static str {
        match self {
            Self::LocalStack => "SLAAC",
            Self::Router => "GW",
            Self::IcmpV6 => "ICMP6",
            Self::DnsV6 => "AAAA",
            Self::HttpsV6 => "TLS6",
            Self::Pmtud => "MTU",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6Stage {
    pub kind: Ipv6StageKind,
    pub title: String,
    pub short_badge: String,
    pub health: StageHealth,
    pub detail: String,
    pub latency_ms: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EndpointProbe {
    pub ip: Option<IpAddr>,
    pub colo: Option<String>,
    pub http_version: Option<String>,
    pub latency_ms: Option<f64>,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DualStackComparison {
    pub ipv6: EndpointProbe,
    pub ipv4: EndpointProbe,
    pub delta_ms: Option<f64>,
    pub happy_eyeballs_winner: String,
    pub peering_note: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MtuReport {
    pub link_mtu: Option<u32>,
    #[serde(default)]
    pub ra_link_mtu: Option<u32>,
    pub path_mtu: Option<u32>,
    pub large_frame_ok: bool,
    pub large_frame_bytes: usize,
    pub large_frame_ms: Option<f64>,
    pub blackhole_suspected: bool,
    pub status_summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
    Info,
}

impl CheckStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
            Self::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6ChecklistItem {
    pub name: String,
    pub status: CheckStatus,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6Verdict {
    pub severity: VerdictSeverity,
    pub score: usize,
    pub max_score: usize,
    pub headline: String,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6CheckReport {
    pub checked_at: DateTime<Utc>,
    pub inventory: LocalIpv6Inventory,
    pub stages: Vec<Ipv6Stage>,
    pub dual_stack: DualStackComparison,
    pub mtu: MtuReport,
    pub checklist: Vec<Ipv6ChecklistItem>,
    pub verdict: Ipv6Verdict,
    pub nat66_detected: Option<bool>,
    pub dns_aaaa_ok: bool,
    pub dns_v6_transport_ok: bool,
}

#[derive(Debug, Clone)]
pub enum Ipv6CheckEvent {
    Progress(Box<Ipv6CheckReport>),
    Completed(Box<Ipv6CheckReport>),
}

/// Classifies an IPv6 address into GUA (`2000::/3`), ULA (`fc00::/7`), Link-Local (`fe80::/10`), Loopback, or Other.
pub fn classify_ipv6_scope(addr: Ipv6Addr) -> Ipv6AddressScope {
    if addr.is_loopback() {
        Ipv6AddressScope::Loopback
    } else if addr.is_unicast_link_local() {
        Ipv6AddressScope::LinkLocal
    } else if (addr.segments()[0] & 0xfe00) == 0xfc00 {
        Ipv6AddressScope::UniqueLocal
    } else if (addr.segments()[0] & 0xe000) == 0x2000 {
        Ipv6AddressScope::GlobalUnicast
    } else {
        Ipv6AddressScope::Other
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OsIpv6AddrFlags {
    pub autoconf: bool,
    pub secured: bool,
    pub temporary: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ParsedMacosIfconfig {
    pub mtu: Option<u32>,
    pub nd6_options: Option<String>,
    pub addr_flags: HashMap<Ipv6Addr, OsIpv6AddrFlags>,
}

/// Parses macOS `ifconfig <iface>` output for link MTU, `nd6 options`, and per-address flags.
pub fn parse_macos_ifconfig_ipv6(output: &str) -> ParsedMacosIfconfig {
    let mut mtu = None;
    let mut nd6_options = None;
    let mut addr_flags = HashMap::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if mtu.is_none() {
            let tokens: Vec<&str> = trimmed.split_whitespace().collect();
            for win in tokens.windows(2) {
                if win[0] == "mtu"
                    && let Ok(val) = win[1].parse::<u32>()
                {
                    mtu = Some(val);
                    break;
                }
            }
        }
        if let Some(rest) = trimmed.strip_prefix("nd6 options=") {
            nd6_options = Some(rest.trim().to_string());
        }
        if let Some(rest) = trimmed.strip_prefix("inet6 ") {
            let mut tokens = rest.split_whitespace();
            if let Some(addr_raw) = tokens.next() {
                let addr_no_scope = addr_raw.split('%').next().unwrap_or(addr_raw);
                if let Ok(ip) = addr_no_scope.parse::<Ipv6Addr>() {
                    let tail: Vec<&str> = tokens.collect();
                    addr_flags.insert(
                        ip,
                        OsIpv6AddrFlags {
                            autoconf: tail.contains(&"autoconf"),
                            secured: tail.contains(&"secured"),
                            temporary: tail.contains(&"temporary"),
                        },
                    );
                }
            }
        }
    }

    ParsedMacosIfconfig {
        mtu,
        nd6_options,
        addr_flags,
    }
}

/// Parses macOS `ndp -r` output for the default router matching `iface`.
pub fn parse_macos_ndp_r(output: &str, iface: &str) -> Option<RaRouterInfo> {
    let iface_tag = format!("if={iface}");
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        let has_iface = tokens.iter().any(|t| {
            let clean = t.trim_end_matches(',');
            clean == iface_tag
        });
        if !has_iface {
            continue;
        }
        let gw_display = tokens[0].to_string();
        let gw_no_scope = gw_display.split('%').next().unwrap_or(&gw_display);
        let gateway = gw_no_scope.parse::<Ipv6Addr>().ok();

        let mut managed_m = false;
        let mut other_o = false;
        let mut preference = None;
        let mut expire = None;

        for tok in &tokens[1..] {
            let clean = tok.trim_end_matches(',');
            if let Some(flags) = clean.strip_prefix("flags=") {
                managed_m = flags.contains('M');
                other_o = flags.contains('O');
            } else if let Some(pref) = clean.strip_prefix("pref=") {
                preference = Some(pref.to_string());
            } else if let Some(exp) = clean.strip_prefix("expire=") {
                expire = Some(exp.to_string());
            }
        }

        // Skip unconfigured tunnel pseudo-entries without a concrete router IP
        if gateway.is_none() || expire.as_deref() == Some("Never") && gw_no_scope == "fe80::" {
            continue;
        }

        return Some(RaRouterInfo {
            gateway,
            gateway_display: Some(gw_display),
            managed_m,
            other_o,
            preference,
            expire,
            provisioning_summary: String::new(),
        });
    }
    None
}

/// Parses macOS `ndp -p` output for SLAAC advertised prefixes on `iface` (skipping `fe80::` link-local entries).
pub fn parse_macos_ndp_p(output: &str, iface: &str) -> Vec<RaPrefixInfo> {
    let mut prefixes = Vec::new();
    let mut current: Option<RaPrefixInfo> = None;
    let iface_tag = format!("if={iface}");

    for line in output.lines() {
        if !line.starts_with(' ') && !line.starts_with('\t') && line.contains(" if=") {
            if let Some(prev) = current.take() {
                prefixes.push(prev);
            }
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() >= 2 && tokens[1] == iface_tag && !tokens[0].starts_with("fe80:") {
                current = Some(RaPrefixInfo {
                    prefix: tokens[0].to_string(),
                    autonomous: false,
                    on_link: false,
                    valid_lft: None,
                    preferred_lft: None,
                    expire: None,
                    router: None,
                    router_reachable: false,
                });
            }
            continue;
        }

        let Some(ref mut cur) = current else {
            continue;
        };
        let trimmed = line.trim();
        if trimmed.starts_with("flags=") {
            for tok in trimmed.split_whitespace() {
                let clean = tok.trim_end_matches(',');
                if let Some(flags) = clean.strip_prefix("flags=") {
                    cur.autonomous = flags.contains('A');
                    cur.on_link = flags.contains('L');
                } else if let Some(vl) = clean.strip_prefix("vltime=") {
                    cur.valid_lft = Some(vl.to_string());
                } else if let Some(pl) = clean.strip_prefix("pltime=") {
                    cur.preferred_lft = Some(pl.to_string());
                } else if let Some(exp) = clean.strip_prefix("expire=") {
                    cur.expire = Some(exp.to_string());
                }
            }
        } else if trimmed != "advertised by" && !trimmed.starts_with("No advertising") {
            let mut parts = trimmed.split_whitespace();
            if let Some(rtr) = parts.next()
                && cur.router.is_none()
            {
                cur.router = Some(rtr.to_string());
                cur.router_reachable = trimmed.contains("(reachable)");
            }
        }
    }

    if let Some(last) = current.take() {
        prefixes.push(last);
    }

    prefixes
}

/// Parses macOS `ndp -i <iface>` output for RA-advertised Link MTU, Hop Limit, and NDP timers.
pub fn parse_macos_ndp_i(output: &str) -> RaInterfaceParams {
    let mut params = RaInterfaceParams::default();
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Flags:") {
            let f = rest.trim();
            if !f.is_empty() {
                params.nd6_flags = Some(f.to_string());
            }
            continue;
        }
        for tok in trimmed.split_whitespace() {
            let clean = tok.trim_end_matches(',');
            if let Some(v) = clean.strip_prefix("linkmtu=") {
                if let Ok(m) = v.parse::<u32>()
                    && m > 0
                {
                    params.ra_link_mtu = Some(m);
                }
            } else if let Some(v) = clean.strip_prefix("curhlim=") {
                if let Ok(h) = v.parse::<u8>() {
                    params.cur_hop_limit = Some(h);
                }
            } else if let Some(v) = clean.strip_prefix("basereachable=") {
                params.base_reachable = Some(v.to_string());
            } else if let Some(v) = clean.strip_prefix("reachable=") {
                params.reachable = Some(v.to_string());
            } else if let Some(v) = clean.strip_prefix("retrans=") {
                params.retrans = Some(v.to_string());
            }
        }
    }
    params
}

/// Parses macOS `scutil --dns` output for unique IPv6 DNS server addresses.
pub fn parse_macos_scutil_ipv6_dns(output: &str) -> Vec<Ipv6Addr> {
    let mut servers = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("nameserver[")
            && let Some((_, val)) = trimmed.split_once(':')
        {
            let clean = val.trim().split('%').next().unwrap_or("");
            if let Ok(ip) = clean.parse::<Ipv6Addr>()
                && !servers.contains(&ip)
            {
                servers.push(ip);
            }
        }
    }
    servers
}

/// Parses macOS `route -n get -inet6 <target>` output for the learned route MTU.
pub fn parse_macos_route_mtu(output: &str) -> Option<u32> {
    let lines: Vec<&str> = output.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        let headers: Vec<&str> = line.split_whitespace().collect();
        if let Some(mtu_col) = headers.iter().position(|&h| h == "mtu")
            && let Some(next_line) = lines.get(idx + 1)
        {
            let values: Vec<&str> = next_line.split_whitespace().collect();
            if let Some(val) = values.get(mtu_col)
                && let Ok(mtu) = val.parse::<u32>()
            {
                return Some(mtu);
            }
        }
    }
    None
}

/// Parses Linux `ip -6 route get <target>` output for `mtu <N>`.
pub fn parse_linux_route_mtu(output: &str) -> Option<u32> {
    let tokens: Vec<&str> = output.split_whitespace().collect();
    for win in tokens.windows(2) {
        if win[0] == "mtu"
            && let Ok(mtu) = win[1].parse::<u32>()
        {
            return Some(mtu);
        }
    }
    None
}

/// Derives a concise provisioning label (`SLAAC`, `Stateless DHCPv6`, `Stateful DHCPv6`, etc.).
pub fn derive_provisioning_summary(
    ra_router: &RaRouterInfo,
    ra_prefixes: &[RaPrefixInfo],
    addresses: &[Ipv6AddressEntry],
) -> String {
    let has_slaac =
        ra_prefixes.iter().any(|p| p.autonomous) || addresses.iter().any(|a| a.is_slaac);
    let has_routable = addresses.iter().any(|a| {
        matches!(
            a.scope,
            Ipv6AddressScope::GlobalUnicast | Ipv6AddressScope::UniqueLocal
        )
    });

    if has_slaac && ra_router.managed_m {
        "SLAAC (A=1) + Stateful DHCPv6 (M=1)".into()
    } else if has_slaac && ra_router.other_o {
        "SLAAC (A=1) + Stateless DHCPv6 (O=1, M=0)".into()
    } else if has_slaac {
        "SLAAC Only (A=1, M=0, O=0)".into()
    } else if ra_router.managed_m {
        "Stateful DHCPv6 (M=1)".into()
    } else if ra_router.other_o {
        "Stateless DHCPv6 (O=1)".into()
    } else if has_routable
        && addresses.iter().any(|a| {
            matches!(
                a.scope,
                Ipv6AddressScope::GlobalUnicast | Ipv6AddressScope::UniqueLocal
            ) && a.is_permanent
        })
    {
        "Static / Manual".into()
    } else if has_routable {
        "Routable IPv6 (No RA Cache)".into()
    } else if addresses
        .iter()
        .any(|a| a.scope == Ipv6AddressScope::LinkLocal)
    {
        "Link-Local Only (No RA Prefix)".into()
    } else {
        "No IPv6 Provisioning".into()
    }
}

/// Collects local IPv6 stack inventory, OS RA/NDP flags, and IPv6 DNS servers.
pub fn collect_local_ipv6_inventory() -> Result<LocalIpv6Inventory, NetError> {
    let local = get_local_network_info()?;
    let interfaces = netdev::get_interfaces();
    let iface = interfaces
        .into_iter()
        .find(|i| i.name == local.interface_name)
        .or_else(|| netdev::get_default_interface().ok());

    let Some(iface) = iface else {
        return Ok(LocalIpv6Inventory {
            interface_name: local.interface_name,
            interface_index: 0,
            link_type: local.link_type,
            link_mtu: None,
            nd6_options: None,
            addresses: Vec::new(),
            ra_router: RaRouterInfo {
                provisioning_summary: "No active interface".into(),
                ..Default::default()
            },
            ra_prefixes: Vec::new(),
            ra_interface: RaInterfaceParams::default(),
            raw_slaac_dump: String::new(),
            ipv6_dns_servers: Vec::new(),
            has_link_local: false,
            has_gua: false,
            has_ula: false,
            has_privacy_temp: false,
            has_dad_issue: false,
        });
    };

    let mut ra_router = RaRouterInfo::default();
    #[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(unused_mut))]
    let mut ipv6_dns_servers: Vec<Ipv6Addr> = iface
        .dns_servers
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V6(v6) => Some(*v6),
            IpAddr::V4(_) => None,
        })
        .collect();

    if let Some(ref gw) = iface.gateway
        && let Some(&v6_gw) = gw.ipv6.first()
    {
        ra_router.gateway = Some(v6_gw);
        ra_router.gateway_display = Some(format!("{v6_gw}%{}", iface.name));
    }

    #[cfg(target_os = "macos")]
    let (link_mtu, nd6_options, os_addr_flags, ra_prefixes, ra_interface, raw_slaac_dump) = {
        let mut link_mtu = iface.mtu;
        let mut nd6_options = None;
        let mut os_addr_flags: HashMap<Ipv6Addr, OsIpv6AddrFlags> = HashMap::new();
        let mut ra_prefixes = Vec::new();
        let mut ra_interface = RaInterfaceParams::default();
        let mut raw_sections: Vec<String> = Vec::new();

        if let Ok(out) = std::process::Command::new("/usr/sbin/ndp")
            .arg("-rn")
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            if let Some(parsed_gw) = parse_macos_ndp_r(&text, &iface.name) {
                ra_router = parsed_gw;
            }
            if !text.trim().is_empty() {
                raw_sections.push(format!(
                    "=== ndp -rn (Default Routers / RA Flags) ===\n{}",
                    text.trim()
                ));
            }
        }
        if let Ok(out) = std::process::Command::new("/usr/sbin/ndp")
            .arg("-pn")
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            ra_prefixes = parse_macos_ndp_p(&text, &iface.name);
            if !text.trim().is_empty() {
                raw_sections.push(format!(
                    "=== ndp -pn (Advertised Prefixes / SLAAC Lifetimes) ===\n{}",
                    text.trim()
                ));
            }
        }
        if let Ok(out) = std::process::Command::new("/usr/sbin/ndp")
            .args(["-i", &iface.name])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            ra_interface = parse_macos_ndp_i(&text);
            if !text.trim().is_empty() {
                raw_sections.push(format!(
                    "=== ndp -i {} (RA Link MTU & Timers) ===\n{}",
                    iface.name,
                    text.trim()
                ));
            }
        }
        if let Ok(out) = std::process::Command::new("/sbin/ifconfig")
            .arg(&iface.name)
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            let parsed_if = parse_macos_ifconfig_ipv6(&text);
            if link_mtu.is_none() {
                link_mtu = parsed_if.mtu;
            }
            nd6_options = parsed_if.nd6_options;
            os_addr_flags = parsed_if.addr_flags;
            let relevant: Vec<&str> = text
                .lines()
                .filter(|l| {
                    l.starts_with(&format!("{}:", iface.name))
                        || l.contains("inet6 ")
                        || l.contains("nd6 ")
                })
                .collect();
            if !relevant.is_empty() {
                raw_sections.push(format!(
                    "=== ifconfig {} (IPv6 Interface State) ===\n{}",
                    iface.name,
                    relevant.join("\n")
                ));
            }
        }
        if ipv6_dns_servers.is_empty()
            && let Ok(out) = std::process::Command::new("/usr/sbin/scutil")
                .arg("--dns")
                .output()
        {
            ipv6_dns_servers = parse_macos_scutil_ipv6_dns(&String::from_utf8_lossy(&out.stdout));
        }
        (
            link_mtu,
            nd6_options,
            os_addr_flags,
            ra_prefixes,
            ra_interface,
            raw_sections.join("\n\n"),
        )
    };

    #[cfg(not(target_os = "macos"))]
    let link_mtu = iface.mtu;
    #[cfg(not(target_os = "macos"))]
    let nd6_options: Option<String> = None;
    #[cfg(not(target_os = "macos"))]
    let os_addr_flags: HashMap<Ipv6Addr, OsIpv6AddrFlags> = HashMap::new();
    #[cfg(not(target_os = "macos"))]
    let ra_prefixes: Vec<RaPrefixInfo> = Vec::new();
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let (ra_interface, raw_slaac_dump) = (RaInterfaceParams::default(), String::new());

    #[cfg(target_os = "linux")]
    let (ra_interface, raw_slaac_dump) = {
        let mut ra_interface = RaInterfaceParams::default();
        let mut raw_sections = Vec::new();
        if let Ok(out) = std::process::Command::new("ip")
            .args(["-6", "route", "show", "dev", &iface.name])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            if !text.trim().is_empty() {
                raw_sections.push(format!(
                    "=== ip -6 route show dev {} ===\n{}",
                    iface.name,
                    text.trim()
                ));
            }
            if ra_router.gateway.is_none() {
                for line in text.lines() {
                    if line.starts_with("default ") {
                        let tokens: Vec<&str> = line.split_whitespace().collect();
                        for win in tokens.windows(2) {
                            if win[0] == "via"
                                && let Ok(gw) =
                                    win[1].split('%').next().unwrap_or(win[1]).parse::<Ipv6Addr>()
                            {
                                ra_router.gateway = Some(gw);
                                ra_router.gateway_display = Some(format!("{gw}%{}", iface.name));
                                break;
                            }
                        }
                    }
                }
            }
        }
        if let Ok(out) = std::process::Command::new("ip")
            .args(["-6", "addr", "show", "dev", &iface.name])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            if !text.trim().is_empty() {
                raw_sections.push(format!(
                    "=== ip -6 addr show dev {} ===\n{}",
                    iface.name,
                    text.trim()
                ));
            }
        }
        if let Ok(mtu_txt) =
            std::fs::read_to_string(format!("/proc/sys/net/ipv6/conf/{}/mtu", iface.name))
            && let Ok(m) = mtu_txt.trim().parse::<u32>()
        {
            ra_interface.ra_link_mtu = Some(m);
        }
        if let Ok(hl_txt) =
            std::fs::read_to_string(format!("/proc/sys/net/ipv6/conf/{}/hop_limit", iface.name))
            && let Ok(h) = hl_txt.trim().parse::<u8>()
        {
            ra_interface.cur_hop_limit = Some(h);
        }
        if ipv6_dns_servers.is_empty()
            && let Ok(resolv) = std::fs::read_to_string("/etc/resolv.conf")
        {
            for line in resolv.lines() {
                let t = line.trim();
                if let Some(rest) = t.strip_prefix("nameserver")
                    && let Ok(v6) = rest.trim().split('%').next().unwrap_or("").parse::<Ipv6Addr>()
                    && !ipv6_dns_servers.contains(&v6)
                {
                    ipv6_dns_servers.push(v6);
                }
            }
        }
        (ra_interface, raw_sections.join("\n\n"))
    };

    let mut addresses = Vec::with_capacity(iface.ipv6.len());
    for (idx, net) in iface.ipv6.iter().enumerate() {
        let addr = net.addr();
        let scope = classify_ipv6_scope(addr);
        let netdev_flags = iface.ipv6_addr_flags.get(idx);
        let os_flags = os_addr_flags.get(&addr).copied().unwrap_or_default();

        let is_temporary = netdev_flags.is_some_and(|f| f.temporary) || os_flags.temporary;
        let is_deprecated = netdev_flags.is_some_and(|f| f.deprecated);
        let is_tentative = netdev_flags.is_some_and(|f| f.tentative);
        let is_duplicated = netdev_flags.is_some_and(|f| f.duplicated);
        let is_permanent = netdev_flags.is_some_and(|f| f.permanent);
        let is_secured = os_flags.secured;
        let is_slaac = os_flags.autoconf
            || (!is_permanent
                && matches!(
                    scope,
                    Ipv6AddressScope::GlobalUnicast | Ipv6AddressScope::UniqueLocal
                ));

        addresses.push(Ipv6AddressEntry {
            addr,
            prefix_len: net.prefix_len(),
            scope,
            is_slaac,
            is_temporary,
            is_secured,
            is_deprecated,
            is_tentative,
            is_duplicated,
            is_permanent,
        });
    }

    addresses.sort_by_key(|a| (a.scope.sort_rank(), a.is_temporary, a.addr.to_string()));

    let has_link_local = addresses
        .iter()
        .any(|a| a.scope == Ipv6AddressScope::LinkLocal);
    let has_gua = addresses
        .iter()
        .any(|a| a.scope == Ipv6AddressScope::GlobalUnicast);
    let has_ula = addresses
        .iter()
        .any(|a| a.scope == Ipv6AddressScope::UniqueLocal);
    let has_privacy_temp = addresses
        .iter()
        .any(|a| a.scope == Ipv6AddressScope::GlobalUnicast && a.is_temporary);
    let has_dad_issue = addresses.iter().any(|a| a.is_duplicated || a.is_tentative);

    ra_router.provisioning_summary =
        derive_provisioning_summary(&ra_router, &ra_prefixes, &addresses);

    Ok(LocalIpv6Inventory {
        interface_name: iface.name,
        interface_index: iface.index,
        link_type: local.link_type,
        link_mtu,
        nd6_options,
        addresses,
        ra_router,
        ra_prefixes,
        ra_interface,
        raw_slaac_dump,
        ipv6_dns_servers,
        has_link_local,
        has_gua,
        has_ula,
        has_privacy_temp,
        has_dad_issue,
    })
}

fn evaluate_local_stage(inv: &LocalIpv6Inventory) -> Ipv6Stage {
    let (health, short_badge, detail) = if inv.has_dad_issue {
        (
            StageHealth::Failed,
            "DAD Alert".into(),
            "Tentative or duplicated IPv6 address detected by DAD".into(),
        )
    } else if inv.has_link_local && inv.has_gua && inv.ra_router.gateway.is_some() {
        let prefix = inv
            .addresses
            .iter()
            .find(|a| a.scope == Ipv6AddressScope::GlobalUnicast)
            .map(|a| format!("GUA /{}", a.prefix_len))
            .unwrap_or_else(|| "GUA".into());
        (
            StageHealth::Ok,
            prefix,
            format!(
                "{} · {}",
                inv.interface_name, inv.ra_router.provisioning_summary
            ),
        )
    } else if inv.has_gua || inv.has_ula || inv.has_link_local {
        let badge = if inv.has_gua {
            "GUA (No GW)"
        } else if inv.has_ula {
            "ULA Only"
        } else {
            "LL Only"
        };
        (
            StageHealth::Warning,
            badge.into(),
            format!(
                "{} · {}",
                inv.interface_name, inv.ra_router.provisioning_summary
            ),
        )
    } else {
        (
            StageHealth::Failed,
            "No IPv6".into(),
            "No IPv6 addresses assigned to default interface".into(),
        )
    };

    Ipv6Stage {
        kind: Ipv6StageKind::LocalStack,
        title: Ipv6StageKind::LocalStack.title().into(),
        short_badge,
        health,
        detail,
        latency_ms: None,
    }
}

fn initial_stages(local_stage: Ipv6Stage) -> Vec<Ipv6Stage> {
    vec![
        local_stage,
        Ipv6Stage {
            kind: Ipv6StageKind::Router,
            title: Ipv6StageKind::Router.title().into(),
            short_badge: "Pending".into(),
            health: StageHealth::Pending,
            detail: "Waiting".into(),
            latency_ms: None,
        },
        Ipv6Stage {
            kind: Ipv6StageKind::IcmpV6,
            title: Ipv6StageKind::IcmpV6.title().into(),
            short_badge: "Pending".into(),
            health: StageHealth::Pending,
            detail: "Waiting".into(),
            latency_ms: None,
        },
        Ipv6Stage {
            kind: Ipv6StageKind::DnsV6,
            title: Ipv6StageKind::DnsV6.title().into(),
            short_badge: "Pending".into(),
            health: StageHealth::Pending,
            detail: "Waiting".into(),
            latency_ms: None,
        },
        Ipv6Stage {
            kind: Ipv6StageKind::HttpsV6,
            title: Ipv6StageKind::HttpsV6.title().into(),
            short_badge: "Pending".into(),
            health: StageHealth::Pending,
            detail: "Waiting".into(),
            latency_ms: None,
        },
        Ipv6Stage {
            kind: Ipv6StageKind::Pmtud,
            title: Ipv6StageKind::Pmtud.title().into(),
            short_badge: "Pending".into(),
            health: StageHealth::Pending,
            detail: "Waiting".into(),
            latency_ms: None,
        },
    ]
}

fn build_snapshot(
    inventory: &LocalIpv6Inventory,
    stages: &[Ipv6Stage],
    dual_stack: &DualStackComparison,
    mtu: &MtuReport,
    nat66_detected: Option<bool>,
    dns_aaaa_ok: bool,
    dns_v6_transport_ok: bool,
) -> Ipv6CheckReport {
    let (checklist, verdict) = build_checklist_and_verdict(
        inventory,
        stages,
        dual_stack,
        mtu,
        nat66_detected,
        dns_aaaa_ok,
        dns_v6_transport_ok,
    );
    Ipv6CheckReport {
        checked_at: Utc::now(),
        inventory: inventory.clone(),
        stages: stages.to_vec(),
        dual_stack: dual_stack.clone(),
        mtu: mtu.clone(),
        checklist,
        verdict,
        nat66_detected,
        dns_aaaa_ok,
        dns_v6_transport_ok,
    }
}

/// Evaluates the 10 core IPv6 checks and computes the overall readiness verdict.
pub fn build_checklist_and_verdict(
    inventory: &LocalIpv6Inventory,
    stages: &[Ipv6Stage],
    dual_stack: &DualStackComparison,
    mtu: &MtuReport,
    nat66_detected: Option<bool>,
    dns_aaaa_ok: bool,
    dns_v6_transport_ok: bool,
) -> (Vec<Ipv6ChecklistItem>, Ipv6Verdict) {
    let mut items = Vec::with_capacity(10);

    // 1. Link-Local
    let ll_addr = inventory
        .addresses
        .iter()
        .find(|a| a.scope == Ipv6AddressScope::LinkLocal)
        .map(|a| a.addr.to_string());
    items.push(Ipv6ChecklistItem {
        name: "Link-Local Address (fe80::/10)".into(),
        status: if inventory.has_link_local {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        evidence: ll_addr.unwrap_or_else(|| "Missing fe80::/10 address on active interface".into()),
    });

    // 2. Global Unicast Address
    let gua_addrs: Vec<String> = inventory
        .addresses
        .iter()
        .filter(|a| a.scope == Ipv6AddressScope::GlobalUnicast)
        .map(|a| format!("{}/{}", a.addr, a.prefix_len))
        .collect();
    items.push(Ipv6ChecklistItem {
        name: "Global Unicast Address (GUA 2000::/3)".into(),
        status: if inventory.has_gua {
            CheckStatus::Pass
        } else if inventory.has_ula {
            CheckStatus::Warn
        } else {
            CheckStatus::Fail
        },
        evidence: if !gua_addrs.is_empty() {
            gua_addrs.join(", ")
        } else if inventory.has_ula {
            "Only ULA (fc00::/7) present; no global IPv6 prefix".into()
        } else {
            "No 2000::/3 GUA assigned".into()
        },
    });

    // 3. Privacy Extensions
    let temp_count = inventory
        .addresses
        .iter()
        .filter(|a| a.scope == Ipv6AddressScope::GlobalUnicast && a.is_temporary)
        .count();
    items.push(Ipv6ChecklistItem {
        name: "Privacy Extensions (RFC 4941/8981)".into(),
        status: if inventory.has_privacy_temp {
            CheckStatus::Pass
        } else if inventory.has_gua {
            CheckStatus::Warn
        } else {
            CheckStatus::Fail
        },
        evidence: if temp_count > 0 {
            format!("{temp_count} temporary privacy GUA(s) active")
        } else if inventory.has_gua {
            "No temporary GUA found (stable GUA used for outbound traffic)".into()
        } else {
            "Requires GUA prefix".into()
        },
    });

    // 4. Router Advertisement & Default Route
    let ra_status = if inventory.ra_router.gateway.is_some()
        && (!inventory.ra_prefixes.is_empty() || inventory.has_gua)
    {
        CheckStatus::Pass
    } else if inventory.ra_router.gateway.is_some() {
        CheckStatus::Warn
    } else {
        CheckStatus::Fail
    };
    let ra_ev = if let Some(ref gw) = inventory.ra_router.gateway_display {
        let pfx = inventory
            .ra_prefixes
            .first()
            .map(|p| {
                format!(
                    " · {} (vltime={}, pltime={})",
                    p.prefix,
                    p.valid_lft.as_deref().unwrap_or("?"),
                    p.preferred_lft.as_deref().unwrap_or("?")
                )
            })
            .unwrap_or_default();
        format!("{gw} · {}{pfx}", inventory.ra_router.provisioning_summary)
    } else {
        "No IPv6 default router / RA discovered".into()
    };
    items.push(Ipv6ChecklistItem {
        name: "Router Advertisement & Default Route".into(),
        status: ra_status,
        evidence: ra_ev,
    });

    // 5. Address Health (DAD & Lifetimes)
    let deprecated_count = inventory
        .addresses
        .iter()
        .filter(|a| a.is_deprecated)
        .count();
    let dad_status = if inventory.has_dad_issue {
        CheckStatus::Fail
    } else if deprecated_count > 0 {
        CheckStatus::Warn
    } else if !inventory.addresses.is_empty() {
        CheckStatus::Pass
    } else {
        CheckStatus::Fail
    };
    let dad_ev = if inventory.has_dad_issue {
        "Duplicate Address Detection (DAD) tentative/conflict flag active".into()
    } else if deprecated_count > 0 {
        format!("{deprecated_count} deprecated IPv6 address(es) still present")
    } else if !inventory.addresses.is_empty() {
        format!(
            "All {} addresses DAD-clean & preferred{}",
            inventory.addresses.len(),
            inventory
                .nd6_options
                .as_deref()
                .map(|o| format!(" · nd6={o}"))
                .unwrap_or_default()
        )
    } else {
        "No IPv6 addresses to validate".into()
    };
    items.push(Ipv6ChecklistItem {
        name: "Address Health (DAD & Lifetimes)".into(),
        status: dad_status,
        evidence: dad_ev,
    });

    // 6. Native End-to-End (No NAT66)
    let (nat_status, nat_ev) = match nat66_detected {
        Some(false) => (
            CheckStatus::Pass,
            format!(
                "Egress IPv6 {} matches local GUA (native end-to-end)",
                dual_stack
                    .ipv6
                    .ip
                    .map(|i| i.to_string())
                    .unwrap_or_default()
            ),
        ),
        Some(true) => (
            CheckStatus::Warn,
            format!(
                "Egress IPv6 {} differs from local interface addresses (NAT66, VPN, or proxy)",
                dual_stack
                    .ipv6
                    .ip
                    .map(|i| i.to_string())
                    .unwrap_or_default()
            ),
        ),
        None => (
            CheckStatus::Fail,
            "Unable to verify public IPv6 egress".into(),
        ),
    };
    items.push(Ipv6ChecklistItem {
        name: "Native End-to-End (No NAT66)".into(),
        status: nat_status,
        evidence: nat_ev,
    });

    // 7. ICMPv6 Global Reachability
    let icmp_stage = stages.iter().find(|s| s.kind == Ipv6StageKind::IcmpV6);
    let (icmp_status, icmp_ev) = match icmp_stage {
        Some(s) if s.health == StageHealth::Ok => (CheckStatus::Pass, s.detail.clone()),
        Some(s) if s.health == StageHealth::Warning => (CheckStatus::Warn, s.detail.clone()),
        Some(s) => (CheckStatus::Fail, s.detail.clone()),
        None => (CheckStatus::Fail, "ICMPv6 probe not executed".into()),
    };
    items.push(Ipv6ChecklistItem {
        name: "ICMPv6 Global Reachability".into(),
        status: icmp_status,
        evidence: icmp_ev,
    });

    // 8. DNS AAAA & IPv6 Transport
    let (dns_status, dns_ev) = if dns_aaaa_ok && dns_v6_transport_ok {
        let local_v6_dns = if inventory.ipv6_dns_servers.is_empty() {
            "IPv6 DoH verified (OS DNS uses IPv4)".to_string()
        } else {
            format!(
                "OS IPv6 DNS: {} · IPv6 DoH verified",
                inventory
                    .ipv6_dns_servers
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        (CheckStatus::Pass, format!("AAAA OK · {local_v6_dns}"))
    } else if dns_aaaa_ok || dns_v6_transport_ok {
        (
            CheckStatus::Warn,
            format!(
                "AAAA={}, IPv6 DNS transport={}",
                if dns_aaaa_ok { "OK" } else { "Fail" },
                if dns_v6_transport_ok { "OK" } else { "Fail" }
            ),
        )
    } else {
        (
            CheckStatus::Fail,
            "AAAA lookup and IPv6 DNS transport both failed".into(),
        )
    };
    items.push(Ipv6ChecklistItem {
        name: "DNS AAAA & IPv6 Transport".into(),
        status: dns_status,
        evidence: dns_ev,
    });

    // 9. Path MTU & PMTUD (RFC 8200 >= 1280 B)
    let mtu_status = if mtu.blackhole_suspected || mtu.path_mtu.is_some_and(|m| m < RFC8200_MIN_MTU)
    {
        CheckStatus::Fail
    } else if mtu.large_frame_ok {
        CheckStatus::Pass
    } else {
        CheckStatus::Fail
    };
    items.push(Ipv6ChecklistItem {
        name: "Path MTU & PMTUD (RFC 8200 >= 1280 B)".into(),
        status: mtu_status,
        evidence: mtu.status_summary.clone(),
    });

    // 10. Dual-Stack Parity (IPv6 vs IPv4)
    let (ds_status, ds_ev) = if dual_stack.ipv6.ok && dual_stack.ipv4.ok {
        let v6_colo = dual_stack.ipv6.colo.as_deref().unwrap_or("?");
        let v4_colo = dual_stack.ipv4.colo.as_deref().unwrap_or("?");
        let delta = dual_stack.delta_ms.unwrap_or(0.0);
        if delta > 50.0 || (v6_colo != v4_colo && delta > 25.0) {
            (CheckStatus::Warn, dual_stack.peering_note.clone())
        } else {
            (CheckStatus::Pass, dual_stack.peering_note.clone())
        }
    } else if dual_stack.ipv6.ok {
        (CheckStatus::Pass, "IPv6 operational (IPv4 probe failed)".into())
    } else {
        (CheckStatus::Fail, dual_stack.peering_note.clone())
    };
    items.push(Ipv6ChecklistItem {
        name: "Dual-Stack Parity (IPv6 vs IPv4)".into(),
        status: ds_status,
        evidence: ds_ev,
    });

    let max_score = items.len();
    let score = items.iter().filter(|i| i.status == CheckStatus::Pass).count();
    let fail_count = items.iter().filter(|i| i.status == CheckStatus::Fail).count();
    let warn_count = items.iter().filter(|i| i.status == CheckStatus::Warn).count();

    let verdict = if !inventory.has_gua && !dual_stack.ipv6.ok && inventory.ra_router.gateway.is_none() {
        Ipv6Verdict {
            severity: VerdictSeverity::Error,
            score,
            max_score,
            headline: "IPv6 Not Available on This Network".into(),
            explanation: "No Global Unicast Address (2000::/3) or IPv6 default router was advertised on the active interface. Your ISP or router appears IPv4-only.".into(),
        }
    } else if mtu.blackhole_suspected {
        Ipv6Verdict {
            severity: VerdictSeverity::Error,
            score,
            max_score,
            headline: "IPv6 PMTUD Blackhole Detected".into(),
            explanation: "Small IPv6 HTTPS handshakes succeeded, but the 32 KB full-MSS frame test stalled. Check firewall rules for dropped ICMPv6 Type 2 (Packet Too Big) messages.".into(),
        }
    } else if !dual_stack.ipv6.ok {
        Ipv6Verdict {
            severity: VerdictSeverity::Error,
            score,
            max_score,
            headline: "IPv6 Local Stack Present, Global Internet Unreachable".into(),
            explanation: "Local IPv6 addressing exists, but outbound HTTPS over IPv6 failed. Check upstream IPv6 routing, prefix delegation, or firewall rules.".into(),
        }
    } else if fail_count == 0 && warn_count == 0 {
        Ipv6Verdict {
            severity: VerdictSeverity::Ok,
            score,
            max_score,
            headline: "IPv6 Ready & Fully Operational".into(),
            explanation: format!(
                "Native dual-stack IPv6 ({}) passed all {max_score} core checks cleanly, including PMTUD and end-to-end TLS.",
                inventory.ra_router.provisioning_summary
            ),
        }
    } else if fail_count == 0 {
        Ipv6Verdict {
            severity: VerdictSeverity::Ok,
            score,
            max_score,
            headline: "IPv6 Operational (Minor Advisories)".into(),
            explanation: format!(
                "Core IPv6 connectivity, SLAAC/GUA addressing, and PMTUD passed ({score}/{max_score} checks passed; {warn_count} advisory item(s) below)."
            ),
        }
    } else {
        Ipv6Verdict {
            severity: VerdictSeverity::Warning,
            score,
            max_score,
            headline: "IPv6 Partially Working".into(),
            explanation: format!(
                "IPv6 internet connectivity works, but {fail_count} core check(s) failed and {warn_count} advisory item(s) need attention."
            ),
        }
    };

    (items, verdict)
}

async fn probe_http_trace(
    resolved_ip: IpAddr,
    is_v6: bool,
) -> EndpointProbe {
    crate::ensure_crypto_provider();
    let local_bind = if is_v6 {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .local_address(local_bind)
        .resolve("cloudflare.com", SocketAddr::new(resolved_ip, 443))
        .user_agent("NetScope/0.5")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return EndpointProbe {
                error: Some(e.to_string()),
                ..Default::default()
            };
        }
    };

    let started = Instant::now();
    match client.get("https://cloudflare.com/cdn-cgi/trace").send().await {
        Ok(resp) => {
            let status = resp.status();
            let http_ver = format!("{:?}", resp.version());
            match resp.text().await {
                Ok(body) => {
                    let latency_ms = started.elapsed().as_secs_f64() * 1000.0;
                    if !status.is_success() {
                        return EndpointProbe {
                            http_version: Some(http_ver),
                            latency_ms: Some(latency_ms),
                            error: Some(format!("HTTP {}", status.as_u16())),
                            ..Default::default()
                        };
                    }
                    let mut ip = None;
                    let mut colo = None;
                    for line in body.lines() {
                        if let Some(v) = line.strip_prefix("ip=") {
                            ip = v.trim().parse::<IpAddr>().ok();
                        } else if let Some(v) = line.strip_prefix("colo=") {
                            colo = Some(v.trim().to_string());
                        }
                    }
                    EndpointProbe {
                        ip,
                        colo,
                        http_version: Some(http_ver),
                        latency_ms: Some(latency_ms),
                        ok: ip.is_some(),
                        error: if ip.is_none() {
                            Some("Missing ip in trace".into())
                        } else {
                            None
                        },
                    }
                }
                Err(e) => EndpointProbe {
                    error: Some(e.to_string()),
                    ..Default::default()
                },
            }
        }
        Err(e) => EndpointProbe {
            error: Some(if e.is_timeout() {
                "Timed out (4s)".into()
            } else {
                e.to_string()
            }),
            ..Default::default()
        },
    }
}

async fn test_dns_v6_transport() -> bool {
    crate::ensure_crypto_provider();
    let Ok(wire) = crate::dns_propagation::build_wire_query("cloudflare.com", DnsRecordType::AAAA)
    else {
        return false;
    };
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .local_address(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        .resolve(
            "cloudflare-dns.com",
            SocketAddr::new(IpAddr::V6(IPV6_PROBE_PRIMARY), 443),
        )
        .user_agent("NetScope/0.5")
        .build()
    else {
        return false;
    };

    let Ok(resp) = client
        .post("https://cloudflare-dns.com/dns-query")
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(wire)
        .send()
        .await
    else {
        return false;
    };
    if !resp.status().is_success() {
        return false;
    }
    resp.bytes().await.is_ok_and(|b| !b.is_empty())
}

async fn run_large_frame_v6_test(target_v6: Ipv6Addr) -> Result<(usize, f64), String> {
    crate::ensure_crypto_provider();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .local_address(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        .resolve(
            "speed.cloudflare.com",
            SocketAddr::new(IpAddr::V6(target_v6), 443),
        )
        .user_agent("NetScope/0.5")
        .build()
        .map_err(|e| e.to_string())?;

    let started = Instant::now();
    let resp = client
        .get(format!(
            "https://speed.cloudflare.com/__down?bytes={LARGE_FRAME_TARGET_BYTES}"
        ))
        .header(reqwest::header::REFERER, "https://speed.cloudflare.com/")
        .header(reqwest::header::ORIGIN, "https://speed.cloudflare.com")
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                "Timed out (5s)".to_string()
            } else {
                e.to_string()
            }
        })?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status().as_u16()));
    }
    let body = resp.bytes().await.map_err(|e| e.to_string())?;
    let ms = started.elapsed().as_secs_f64() * 1000.0;
    Ok((body.len(), ms))
}

fn query_os_path_mtu_v6(target_v6: Ipv6Addr, link_mtu: Option<u32>) -> Option<u32> {
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("/sbin/route")
            .args(["-n", "get", "-inet6", &target_v6.to_string()])
            .output()
            && let Some(mtu) = parse_macos_route_mtu(&String::from_utf8_lossy(&out.stdout))
        {
            return Some(mtu);
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(out) = std::process::Command::new("ip")
            .args(["-6", "route", "get", &target_v6.to_string()])
            .output()
            && let Some(mtu) = parse_linux_route_mtu(&String::from_utf8_lossy(&out.stdout))
        {
            return Some(mtu);
        }
    }
    let _ = target_v6;
    link_mtu
}

fn compute_dual_stack_comparison(ipv6: EndpointProbe, ipv4: EndpointProbe) -> DualStackComparison {
    let delta_ms = match (ipv6.latency_ms, ipv4.latency_ms) {
        (Some(v6), Some(v4)) => Some(v6 - v4),
        _ => None,
    };

    let happy_eyeballs_winner = match (ipv6.ok, ipv4.ok, delta_ms) {
        (true, true, Some(d)) if d <= 250.0 => "IPv6 Preferred (RFC 8305)".into(),
        (true, true, Some(_)) => "IPv4 Favored (>250ms IPv6 lag)".into(),
        (true, true, None) => "Dual-Stack Active".into(),
        (true, false, _) => "IPv6 Only".into(),
        (false, true, _) => "IPv4 Fallback (IPv6 Failed)".into(),
        (false, false, _) => "Offline / Unreachable".into(),
    };

    let peering_note = match (ipv6.ok, ipv4.ok, delta_ms) {
        (true, true, Some(d)) => {
            let c6 = ipv6.colo.as_deref().unwrap_or("?");
            let c4 = ipv4.colo.as_deref().unwrap_or("?");
            if c6 != c4 {
                format!("PoP mismatch: IPv6 via {c6} vs IPv4 via {c4} ({d:+.0} ms)")
            } else {
                format!("Symmetric PoP ({c6}) · IPv6 vs IPv4 delta {d:+.0} ms")
            }
        }
        (true, false, _) => format!(
            "IPv6 reachable via {}; IPv4 probe failed",
            ipv6.colo.as_deref().unwrap_or("?")
        ),
        (false, true, _) => format!(
            "IPv4 reachable via {}; IPv6 HTTPS failed ({})",
            ipv4.colo.as_deref().unwrap_or("?"),
            ipv6.error.as_deref().unwrap_or("unreachable")
        ),
        _ => "Neither IPv6 nor IPv4 reached Cloudflare trace endpoint".into(),
    };

    DualStackComparison {
        ipv6,
        ipv4,
        delta_ms,
        happy_eyeballs_winner,
        peering_note,
    }
}

/// Runs the full 6-stage IPv6 Readiness, Dual-Stack & PMTUD diagnostic pipeline.
pub async fn run_ipv6_check(
    tx: mpsc::UnboundedSender<Ipv6CheckEvent>,
    cancel: CancelToken,
) -> Ipv6CheckReport {
    let inventory = collect_local_ipv6_inventory().unwrap_or_else(|_| LocalIpv6Inventory {
        interface_name: "unknown".into(),
        interface_index: 0,
        link_type: LinkType::Unknown,
        link_mtu: None,
        nd6_options: None,
        addresses: Vec::new(),
        ra_router: RaRouterInfo {
            provisioning_summary: "Unknown".into(),
            ..Default::default()
        },
        ra_prefixes: Vec::new(),
        ra_interface: RaInterfaceParams::default(),
        raw_slaac_dump: String::new(),
        ipv6_dns_servers: Vec::new(),
        has_link_local: false,
        has_gua: false,
        has_ula: false,
        has_privacy_temp: false,
        has_dad_issue: false,
    });

    let mut stages = initial_stages(evaluate_local_stage(&inventory));
    let mut dual_stack = DualStackComparison::default();
    let mut mtu = MtuReport {
        link_mtu: inventory.link_mtu,
        ra_link_mtu: inventory.ra_interface.ra_link_mtu,
        status_summary: "Pending PMTUD check".into(),
        ..Default::default()
    };
    let mut nat66_detected = None;
    let mut dns_aaaa_ok = false;
    let mut dns_v6_transport_ok = false;

    macro_rules! emit_progress {
        () => {
            let snap = build_snapshot(
                &inventory,
                &stages,
                &dual_stack,
                &mtu,
                nat66_detected,
                dns_aaaa_ok,
                dns_v6_transport_ok,
            );
            let _ = tx.send(Ipv6CheckEvent::Progress(Box::new(snap)));
        };
    }

    stages[1].health = StageHealth::Running;
    stages[1].short_badge = "Probing".into();
    emit_progress!();

    // Stage 2: Scoped ICMPv6 probe to IPv6 default router
    if !cancel.is_cancelled() {
        let mut gw_filtered = false;
        stages[1] = if let Some(gw) = inventory.ra_router.gateway {
            let mut samples = Vec::with_capacity(2);
            for seq in 1..=2u16 {
                if cancel.is_cancelled() {
                    break;
                }
                let out = if gw.is_unicast_link_local() && inventory.interface_index > 0 {
                    probe_once_v6_scoped(
                        gw,
                        inventory.interface_index,
                        64,
                        seq,
                        Duration::from_millis(1200),
                    )
                    .await
                } else {
                    probe_once(IpAddr::V6(gw), 64, seq, Duration::from_millis(1200)).await
                };
                samples.push(out.rtt_ms());
            }
            let stats = compute_latency_stats(&samples);
            if stats.received > 0 {
                let med = stats.median_ms.unwrap_or(0.0);
                Ipv6Stage {
                    kind: Ipv6StageKind::Router,
                    title: Ipv6StageKind::Router.title().into(),
                    short_badge: format!("{med:.1} ms"),
                    health: StageHealth::Ok,
                    detail: format!(
                        "{} responded ({med:.1} ms median)",
                        inventory
                            .ra_router
                            .gateway_display
                            .as_deref()
                            .unwrap_or("Gateway")
                    ),
                    latency_ms: stats.median_ms,
                }
            } else {
                gw_filtered = true;
                Ipv6Stage {
                    kind: Ipv6StageKind::Router,
                    title: Ipv6StageKind::Router.title().into(),
                    short_badge: "Filtered?".into(),
                    health: StageHealth::Warning,
                    detail: format!(
                        "{} did not answer ICMPv6 echo (checking upstream)",
                        inventory
                            .ra_router
                            .gateway_display
                            .as_deref()
                            .unwrap_or("Gateway")
                    ),
                    latency_ms: None,
                }
            }
        } else {
            Ipv6Stage {
                kind: Ipv6StageKind::Router,
                title: Ipv6StageKind::Router.title().into(),
                short_badge: "No GW".into(),
                health: StageHealth::Failed,
                detail: "No IPv6 default gateway discovered".into(),
                latency_ms: None,
            }
        };

        // Stage 3: Global ICMPv6 reachability
        stages[2].health = StageHealth::Running;
        stages[2].short_badge = "Probing".into();
        emit_progress!();

        if !cancel.is_cancelled() {
            if !inventory.has_gua && !inventory.has_ula && inventory.ra_router.gateway.is_none() {
                stages[2] = Ipv6Stage {
                    kind: Ipv6StageKind::IcmpV6,
                    title: Ipv6StageKind::IcmpV6.title().into(),
                    short_badge: "No Route".into(),
                    health: StageHealth::Failed,
                    detail: "Skipped: no routable IPv6 address or default router".into(),
                    latency_ms: None,
                };
            } else {
                let mut target_used = IPV6_PROBE_PRIMARY;
                let mut samples = Vec::with_capacity(3);
                for seq in 1..=3u16 {
                    if cancel.is_cancelled() {
                        break;
                    }
                    let out = probe_once(
                        IpAddr::V6(IPV6_PROBE_PRIMARY),
                        64,
                        seq,
                        Duration::from_millis(1400),
                    )
                    .await;
                    samples.push(out.rtt_ms());
                }
                let mut stats = compute_latency_stats(&samples);
                if stats.received == 0 && !cancel.is_cancelled() {
                    target_used = IPV6_PROBE_FALLBACK;
                    let mut fb_samples = Vec::with_capacity(2);
                    for seq in 1..=2u16 {
                        let out = probe_once(
                            IpAddr::V6(IPV6_PROBE_FALLBACK),
                            64,
                            seq,
                            Duration::from_millis(1400),
                        )
                        .await;
                        fb_samples.push(out.rtt_ms());
                    }
                    let fb_stats = compute_latency_stats(&fb_samples);
                    if fb_stats.received > 0 {
                        stats = fb_stats;
                    }
                }
                stages[2] = if stats.received > 0 {
                    let med = stats.median_ms.unwrap_or(0.0);
                    let health = if stats.loss_pct > 0.0 {
                        StageHealth::Warning
                    } else {
                        StageHealth::Ok
                    };
                    Ipv6Stage {
                        kind: Ipv6StageKind::IcmpV6,
                        title: Ipv6StageKind::IcmpV6.title().into(),
                        short_badge: format!("{med:.0} ms"),
                        health,
                        detail: format!(
                            "{target_used} · {med:.1} ms median · {:.0}% loss",
                            stats.loss_pct
                        ),
                        latency_ms: stats.median_ms,
                    }
                } else {
                    Ipv6Stage {
                        kind: Ipv6StageKind::IcmpV6,
                        title: Ipv6StageKind::IcmpV6.title().into(),
                        short_badge: "Timeout".into(),
                        health: StageHealth::Failed,
                        detail: "Global ICMPv6 echo timed out (2606:4700:4700::1111 & 2001:4860:4860::8888)".into(),
                        latency_ms: None,
                    }
                };
            }
        }

        // Stage 4: DNS AAAA + IPv6 Transport
        stages[3].health = StageHealth::Running;
        stages[3].short_badge = "Resolving".into();
        emit_progress!();

        let mut resolved_cf_v6: Option<Ipv6Addr> = None;
        let mut resolved_cf_v4: Option<Ipv4Addr> = None;

        if !cancel.is_cancelled() {
            let dns_started = Instant::now();
            let (aaaa_res, a_res, v6_doh_ok) = tokio::join!(
                tokio::time::timeout(
                    Duration::from_secs(4),
                    crate::dns::lookup("cloudflare.com", DnsRecordType::AAAA, &DnsServerChoice::System)
                ),
                tokio::time::timeout(
                    Duration::from_secs(4),
                    crate::dns::lookup("cloudflare.com", DnsRecordType::A, &DnsServerChoice::System)
                ),
                test_dns_v6_transport()
            );
            let dns_ms = dns_started.elapsed().as_secs_f64() * 1000.0;

            if let Ok(Ok(res)) = aaaa_res {
                resolved_cf_v6 = res
                    .records
                    .iter()
                    .find_map(|r| r.value.trim().parse::<Ipv6Addr>().ok());
                dns_aaaa_ok = resolved_cf_v6.is_some();
            }
            if let Ok(Ok(res)) = a_res {
                resolved_cf_v4 = res
                    .records
                    .iter()
                    .find_map(|r| r.value.trim().parse::<Ipv4Addr>().ok());
            }
            dns_v6_transport_ok = v6_doh_ok;

            stages[3] = if dns_aaaa_ok && dns_v6_transport_ok {
                Ipv6Stage {
                    kind: Ipv6StageKind::DnsV6,
                    title: Ipv6StageKind::DnsV6.title().into(),
                    short_badge: "AAAA + v6".into(),
                    health: StageHealth::Ok,
                    detail: format!("AAAA resolved & IPv6 DNS transport verified ({dns_ms:.0} ms)"),
                    latency_ms: Some(dns_ms),
                }
            } else if dns_aaaa_ok {
                Ipv6Stage {
                    kind: Ipv6StageKind::DnsV6,
                    title: Ipv6StageKind::DnsV6.title().into(),
                    short_badge: "AAAA Only".into(),
                    health: StageHealth::Warning,
                    detail: "AAAA resolved via OS DNS, but direct IPv6 DNS transport failed".into(),
                    latency_ms: Some(dns_ms),
                }
            } else if dns_v6_transport_ok {
                Ipv6Stage {
                    kind: Ipv6StageKind::DnsV6,
                    title: Ipv6StageKind::DnsV6.title().into(),
                    short_badge: "v6 Transport".into(),
                    health: StageHealth::Warning,
                    detail: "IPv6 DoH succeeded, but System AAAA lookup failed".into(),
                    latency_ms: Some(dns_ms),
                }
            } else {
                Ipv6Stage {
                    kind: Ipv6StageKind::DnsV6,
                    title: Ipv6StageKind::DnsV6.title().into(),
                    short_badge: "Failed".into(),
                    health: StageHealth::Failed,
                    detail: "System AAAA and IPv6 DNS transport both failed".into(),
                    latency_ms: Some(dns_ms),
                }
            };
        }

        // Stage 5: Dual-Stack HTTPS + NAT66 Detection
        stages[4].health = StageHealth::Running;
        stages[4].short_badge = "Testing".into();
        emit_progress!();

        if !cancel.is_cancelled() {
            let v6_target = resolved_cf_v6.unwrap_or(IPV6_PROBE_PRIMARY);
            let v4_target = resolved_cf_v4.unwrap_or(IPV4_PROBE_FALLBACK);
            let (probe_v6, probe_v4) = tokio::join!(
                probe_http_trace(IpAddr::V6(v6_target), true),
                probe_http_trace(IpAddr::V4(v4_target), false),
            );

            nat66_detected = match probe_v6.ip {
                Some(IpAddr::V6(pub_v6)) => {
                    Some(!inventory.addresses.iter().any(|a| a.addr == pub_v6))
                }
                _ => None,
            };

            dual_stack = compute_dual_stack_comparison(probe_v6, probe_v4);

            stages[4] = if dual_stack.ipv6.ok {
                let colo = dual_stack.ipv6.colo.as_deref().unwrap_or("TLS OK");
                let ms = dual_stack.ipv6.latency_ms.unwrap_or(0.0);
                Ipv6Stage {
                    kind: Ipv6StageKind::HttpsV6,
                    title: Ipv6StageKind::HttpsV6.title().into(),
                    short_badge: format!("{colo} · {ms:.0}ms"),
                    health: StageHealth::Ok,
                    detail: dual_stack.peering_note.clone(),
                    latency_ms: dual_stack.ipv6.latency_ms,
                }
            } else {
                Ipv6Stage {
                    kind: Ipv6StageKind::HttpsV6,
                    title: Ipv6StageKind::HttpsV6.title().into(),
                    short_badge: "Failed".into(),
                    health: StageHealth::Failed,
                    detail: dual_stack
                        .ipv6
                        .error
                        .clone()
                        .unwrap_or_else(|| "HTTPS over IPv6 failed".into()),
                    latency_ms: None,
                }
            };

            // Upgrade Router stage if gateway drops ICMPv6 echo while global IPv6 traffic works
            if gw_filtered && (stages[2].health == StageHealth::Ok || stages[4].health == StageHealth::Ok) {
                stages[1].health = StageHealth::Ok;
                stages[1].short_badge = "Filtered".into();
                stages[1].detail = format!(
                    "{} reachable (ICMPv6 echo filtered by router)",
                    inventory
                        .ra_router
                        .gateway_display
                        .as_deref()
                        .unwrap_or("Gateway")
                );
            }
        }

        // Stage 6: PMTUD & 32 KB Full-MSS Frame Test
        stages[5].health = StageHealth::Running;
        stages[5].short_badge = "Probing".into();
        emit_progress!();

        if !cancel.is_cancelled() {
            if !dual_stack.ipv6.ok && !inventory.has_gua {
                mtu = MtuReport {
                    link_mtu: inventory.link_mtu,
                    ra_link_mtu: inventory.ra_interface.ra_link_mtu,
                    path_mtu: None,
                    large_frame_ok: false,
                    large_frame_bytes: 0,
                    large_frame_ms: None,
                    blackhole_suspected: false,
                    status_summary: "Skipped: IPv6 internet unreachable".into(),
                };
                stages[5] = Ipv6Stage {
                    kind: Ipv6StageKind::Pmtud,
                    title: Ipv6StageKind::Pmtud.title().into(),
                    short_badge: "No IPv6".into(),
                    health: StageHealth::Failed,
                    detail: mtu.status_summary.clone(),
                    latency_ms: None,
                };
            } else {
                let speed_v6 = match tokio::time::timeout(
                    Duration::from_secs(3),
                    crate::dns::lookup(
                        "speed.cloudflare.com",
                        DnsRecordType::AAAA,
                        &DnsServerChoice::System,
                    ),
                )
                .await
                {
                    Ok(Ok(res)) => res
                        .records
                        .iter()
                        .find_map(|r| r.value.trim().parse::<Ipv6Addr>().ok())
                        .or(resolved_cf_v6)
                        .unwrap_or(IPV6_PROBE_PRIMARY),
                    _ => resolved_cf_v6.unwrap_or(IPV6_PROBE_PRIMARY),
                };

                let frame_res = run_large_frame_v6_test(speed_v6).await;
                let path_mtu = query_os_path_mtu_v6(speed_v6, inventory.link_mtu);

                let (large_frame_ok, large_frame_bytes, large_frame_ms, err_note) = match frame_res
                {
                    Ok((bytes, ms)) => (bytes >= LARGE_FRAME_TARGET_BYTES, bytes, Some(ms), None),
                    Err(e) => (false, 0, None, Some(e)),
                };

                let blackhole_suspected = dual_stack.ipv6.ok && !large_frame_ok;
                let link_val = inventory.link_mtu;
                let ra_mtu_val = inventory.ra_interface.ra_link_mtu;
                let effective_mtu = path_mtu.or(ra_mtu_val).or(link_val);

                let (health, short_badge, status_summary) = if blackhole_suspected {
                    (
                        StageHealth::Failed,
                        "Blackhole!".into(),
                        format!(
                            "PMTUD blackhole suspected: small HTTPS passed, 32 KB transfer failed ({})",
                            err_note.as_deref().unwrap_or("stalled")
                        ),
                    )
                } else if path_mtu.is_some_and(|m| m < RFC8200_MIN_MTU) {
                    let m = path_mtu.unwrap_or(0);
                    (
                        StageHealth::Failed,
                        format!("{m} B!"),
                        format!("Path MTU {m} B violates RFC 8200 minimum (1280 B)"),
                    )
                } else if large_frame_ok {
                    let mtu_num = effective_mtu.unwrap_or(1500);
                    let ms = large_frame_ms.unwrap_or(0.0);
                    let ra_clamped = matches!((ra_mtu_val, link_val), (Some(ra), Some(l)) if ra < l);
                    let reduced = matches!((path_mtu, link_val), (Some(p), Some(l)) if p < l);
                    let badge = if ra_clamped {
                        format!("{mtu_num} B (RA)")
                    } else if reduced {
                        format!("{mtu_num} B (PMTUD)")
                    } else {
                        format!("{mtu_num} B")
                    };
                    let summary = if ra_clamped {
                        format!(
                            "Path MTU {mtu_num} B (RA AdvLinkMTU {} B, NIC {} B) · 32 KB TLS frame passed ({ms:.0} ms)",
                            ra_mtu_val.unwrap_or(mtu_num),
                            link_val.unwrap_or(1500)
                        )
                    } else if reduced {
                        format!(
                            "Path MTU {mtu_num} B (NIC {} B) · 32 KB TLS frame passed ({ms:.0} ms)",
                            link_val.unwrap_or(1500)
                        )
                    } else {
                        format!("Path MTU {mtu_num} B · 32 KB TLS frame passed ({ms:.0} ms)")
                    };
                    (StageHealth::Ok, badge, summary)
                } else {
                    (
                        StageHealth::Failed,
                        "Failed".into(),
                        format!(
                            "32 KB IPv6 TLS frame failed ({})",
                            err_note.as_deref().unwrap_or("unreachable")
                        ),
                    )
                };

                mtu = MtuReport {
                    link_mtu: link_val,
                    ra_link_mtu: ra_mtu_val,
                    path_mtu,
                    large_frame_ok,
                    large_frame_bytes,
                    large_frame_ms,
                    blackhole_suspected,
                    status_summary: status_summary.clone(),
                };
                stages[5] = Ipv6Stage {
                    kind: Ipv6StageKind::Pmtud,
                    title: Ipv6StageKind::Pmtud.title().into(),
                    short_badge,
                    health,
                    detail: status_summary,
                    latency_ms: large_frame_ms,
                };
            }
        }
    }

    let final_report = build_snapshot(
        &inventory,
        &stages,
        &dual_stack,
        &mtu,
        nat66_detected,
        dns_aaaa_ok,
        dns_v6_transport_ok,
    );
    let _ = tx.send(Ipv6CheckEvent::Completed(Box::new(final_report.clone())));
    final_report
}

/// Formats a copyable plain-text IPv6 readiness report.
pub fn format_ipv6_report_text(report: &Ipv6CheckReport) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "NetScope IPv6 Diagnostics Report ({})",
        report.checked_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    lines.push(format!(
        "Verdict: {} ({}/{})",
        report.verdict.headline, report.verdict.score, report.verdict.max_score
    ));
    lines.push(report.verdict.explanation.clone());
    lines.push(String::new());
    lines.push(format!(
        "Interface: {} ({}) | Link MTU: {} | Provisioning: {}",
        report.inventory.interface_name,
        report.inventory.link_type.label(),
        report
            .inventory
            .link_mtu
            .map(|m| format!("{m} B"))
            .unwrap_or_else(|| "—".into()),
        report.inventory.ra_router.provisioning_summary
    ));
    lines.push(format!(
        "Gateway: {} | Path MTU: {}",
        report
            .inventory
            .ra_router
            .gateway_display
            .as_deref()
            .unwrap_or("—"),
        report
            .mtu
            .path_mtu
            .map(|m| format!("{m} B"))
            .unwrap_or_else(|| "—".into())
    ));
    lines.push(String::new());
    lines.push("Addresses:".into());
    for a in &report.inventory.addresses {
        let mut tags = vec![a.scope.badge_label()];
        if a.is_temporary {
            tags.push("TEMP");
        }
        if a.is_slaac {
            tags.push("SLAAC");
        }
        if a.is_secured {
            tags.push("SECURED");
        }
        if a.is_deprecated {
            tags.push("DEPRECATED");
        }
        lines.push(format!("  {}/{} [{}]", a.addr, a.prefix_len, tags.join(", ")));
    }
    lines.push(String::new());
    lines.push("Core Checklist:".into());
    for item in &report.checklist {
        lines.push(format!(
            "  [{:<4}] {} — {}",
            item.status.label(),
            item.name,
            item.evidence
        ));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_gua_ula_link_local_loopback_scopes() {
        assert_eq!(
            classify_ipv6_scope("2001:db8:abcd::1".parse().unwrap()),
            Ipv6AddressScope::GlobalUnicast
        );
        assert_eq!(
            classify_ipv6_scope("fd00:db8:40::10".parse().unwrap()),
            Ipv6AddressScope::UniqueLocal
        );
        assert_eq!(
            classify_ipv6_scope("fe80::1".parse().unwrap()),
            Ipv6AddressScope::LinkLocal
        );
        assert_eq!(
            classify_ipv6_scope("::1".parse().unwrap()),
            Ipv6AddressScope::Loopback
        );
    }

    #[test]
    fn parses_macos_ndp_r_and_ndp_p_slaac_flags() {
        let ndp_r = "\
fe80::200:5eff:fe00:5301%en0 if=en0, flags=OT, pref=medium, expire=29m6s
fe80::%utun0 if=utun0, flags=IST, pref=medium, expire=Never
";
        let router = parse_macos_ndp_r(ndp_r, "en0").expect("should parse en0 router");
        assert_eq!(router.gateway, Some("fe80::200:5eff:fe00:5301".parse().unwrap()));
        assert!(!router.managed_m);
        assert!(router.other_o);
        assert_eq!(router.preference.as_deref(), Some("medium"));
        assert_eq!(router.expire.as_deref(), Some("29m6s"));

        let ndp_p = "\
fd00:db8:40::/64 if=en0
flags=ALO vltime=86400, pltime=14400, expire=23h58m46s, ref=1
  advertised by
    fe80::200:5eff:fe00:5301%en0 (reachable)
2001:db8:1234::/64 if=en0
flags=ALO vltime=86400, pltime=14400, expire=23h58m41s, ref=2
  advertised by
    fe80::200:5eff:fe00:5301%en0 (reachable)
fe80::%en0/64 if=en0
flags=AILSO vltime=infinity, pltime=infinity, expire=Never, ref=0
  No advertising router
";
        let prefixes = parse_macos_ndp_p(ndp_p, "en0");
        assert_eq!(prefixes.len(), 2);
        assert_eq!(prefixes[0].prefix, "fd00:db8:40::/64");
        assert!(prefixes[0].autonomous);
        assert!(prefixes[0].on_link);
        assert_eq!(prefixes[0].valid_lft.as_deref(), Some("86400"));
        assert_eq!(prefixes[0].preferred_lft.as_deref(), Some("14400"));
        assert_eq!(prefixes[0].expire.as_deref(), Some("23h58m46s"));
        assert!(prefixes[0].router_reachable);
        assert_eq!(prefixes[1].prefix, "2001:db8:1234::/64");
    }

    #[test]
    fn parses_macos_ndp_i_ra_link_mtu_and_timers() {
        let sample = "\
linkmtu=1484, curhlim=64, basereachable=30s0ms, reachable=15s, retrans=1s0ms
Flags: 0x201 PERFORMNUD DAD
";
        let params = parse_macos_ndp_i(sample);
        assert_eq!(params.ra_link_mtu, Some(1484));
        assert_eq!(params.cur_hop_limit, Some(64));
        assert_eq!(params.base_reachable.as_deref(), Some("30s0ms"));
        assert_eq!(params.reachable.as_deref(), Some("15s"));
        assert_eq!(params.retrans.as_deref(), Some("1s0ms"));
        assert_eq!(params.nd6_flags.as_deref(), Some("0x201 PERFORMNUD DAD"));
    }

    #[test]
    fn parses_macos_ifconfig_and_route_mtu_1484() {
        let ifconfig = "\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet6 fe80::1%en0 prefixlen 64 secured scopeid 0xe
\tinet6 2001:db8::10 prefixlen 64 autoconf secured
\tinet6 2001:db8::99 prefixlen 64 autoconf temporary
\tnd6 options=201<PERFORMNUD,DAD>
";
        let parsed = parse_macos_ifconfig_ipv6(ifconfig);
        assert_eq!(parsed.mtu, Some(1500));
        assert_eq!(parsed.nd6_options.as_deref(), Some("201<PERFORMNUD,DAD>"));
        assert_eq!(
            parsed.addr_flags.get(&"2001:db8::10".parse().unwrap()),
            Some(&OsIpv6AddrFlags {
                autoconf: true,
                secured: true,
                temporary: false
            })
        );
        assert_eq!(
            parsed.addr_flags.get(&"2001:db8::99".parse().unwrap()),
            Some(&OsIpv6AddrFlags {
                autoconf: true,
                secured: false,
                temporary: true
            })
        );

        let route_out = "\
   route to: 2001:db8::1
destination: ::
       mask: default
    gateway: fe80::200:5eff:fe00:5301%en0
  interface: en0
      flags: <UP,GATEWAY,DONE,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1484         0 
";
        assert_eq!(parse_macos_route_mtu(route_out), Some(1484));
    }

    #[test]
    fn parses_linux_ip_route_mtu() {
        let out = "2001:db8::1 from :: via fe80::1 dev eth0 proto ra src 2001:db8::10 metric 600 mtu 1492 pref medium";
        assert_eq!(parse_linux_route_mtu(out), Some(1492));
    }

    #[test]
    fn detects_pmtud_blackhole_when_small_https_works_but_large_frame_fails() {
        let inv = LocalIpv6Inventory {
            interface_name: "en0".into(),
            interface_index: 1,
            link_type: LinkType::WiFi,
            link_mtu: Some(1500),
            nd6_options: None,
            addresses: vec![Ipv6AddressEntry {
                addr: "2001:db8::99".parse().unwrap(),
                prefix_len: 64,
                scope: Ipv6AddressScope::GlobalUnicast,
                is_slaac: true,
                is_temporary: true,
                is_secured: false,
                is_deprecated: false,
                is_tentative: false,
                is_duplicated: false,
                is_permanent: false,
            }],
            ra_router: RaRouterInfo {
                gateway: Some("fe80::1".parse().unwrap()),
                gateway_display: Some("fe80::1%en0".into()),
                provisioning_summary: "SLAAC Only (A=1, M=0, O=0)".into(),
                ..Default::default()
            },
            ra_prefixes: Vec::new(),
            ra_interface: RaInterfaceParams::default(),
            raw_slaac_dump: String::new(),
            ipv6_dns_servers: Vec::new(),
            has_link_local: true,
            has_gua: true,
            has_ula: false,
            has_privacy_temp: true,
            has_dad_issue: false,
        };
        let dual_stack = DualStackComparison {
            ipv6: EndpointProbe {
                ip: Some(IpAddr::V6("2001:db8::99".parse().unwrap())),
                colo: Some("AMS".into()),
                http_version: Some("HTTP/2.0".into()),
                latency_ms: Some(45.0),
                ok: true,
                error: None,
            },
            ipv4: EndpointProbe {
                ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
                colo: Some("AMS".into()),
                http_version: Some("HTTP/2.0".into()),
                latency_ms: Some(40.0),
                ok: true,
                error: None,
            },
            delta_ms: Some(5.0),
            happy_eyeballs_winner: "IPv6 Preferred".into(),
            peering_note: "Symmetric PoP".into(),
        };
        let mtu = MtuReport {
            link_mtu: Some(1500),
            ra_link_mtu: Some(1484),
            path_mtu: Some(1500),
            large_frame_ok: false,
            large_frame_bytes: 0,
            large_frame_ms: None,
            blackhole_suspected: true,
            status_summary: "PMTUD blackhole suspected".into(),
        };
        let stages = initial_stages(evaluate_local_stage(&inv));
        let (items, verdict) =
            build_checklist_and_verdict(&inv, &stages, &dual_stack, &mtu, Some(false), true, true);
        assert_eq!(verdict.severity, VerdictSeverity::Error);
        assert!(verdict.headline.contains("PMTUD Blackhole"));
        assert_eq!(items[8].status, CheckStatus::Fail);
    }

    #[test]
    fn verdict_reports_ipv6_unavailable_when_no_gua_and_no_route() {
        let inv = LocalIpv6Inventory {
            interface_name: "en0".into(),
            interface_index: 1,
            link_type: LinkType::WiFi,
            link_mtu: Some(1500),
            nd6_options: None,
            addresses: Vec::new(),
            ra_router: RaRouterInfo {
                provisioning_summary: "No IPv6 Provisioning".into(),
                ..Default::default()
            },
            ra_prefixes: Vec::new(),
            ra_interface: RaInterfaceParams::default(),
            raw_slaac_dump: String::new(),
            ipv6_dns_servers: Vec::new(),
            has_link_local: false,
            has_gua: false,
            has_ula: false,
            has_privacy_temp: false,
            has_dad_issue: false,
        };
        let stages = initial_stages(evaluate_local_stage(&inv));
        let (_, verdict) = build_checklist_and_verdict(
            &inv,
            &stages,
            &DualStackComparison::default(),
            &MtuReport::default(),
            None,
            false,
            false,
        );
        assert_eq!(verdict.severity, VerdictSeverity::Error);
        assert_eq!(verdict.headline, "IPv6 Not Available on This Network");
    }

    #[tokio::test]
    async fn live_ipv6_check_completes() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let cancel = CancelToken::new();
        let report = run_ipv6_check(tx, cancel).await;
        let mut got_completed = false;
        while let Ok(ev) = rx.try_recv() {
            if matches!(ev, Ipv6CheckEvent::Completed(_)) {
                got_completed = true;
            }
        }
        assert!(got_completed);
        assert_eq!(report.stages.len(), 6);
        assert_eq!(report.checklist.len(), 10);
    }
}
