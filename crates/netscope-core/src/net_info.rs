use crate::NetError;
use chrono::{DateTime, Utc};
use hickory_resolver::Resolver;
use hickory_resolver::proto::rr::RecordType;
use netdev::interface::state::OperState;
use netdev::interface::types::InterfaceType;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkType {
    WiFi,
    Ethernet,
    Cellular,
    Tunnel,
    Unknown,
}

impl LinkType {
    pub fn label(self) -> &'static str {
        match self {
            Self::WiFi => "Wi-Fi",
            Self::Ethernet => "Ethernet",
            Self::Cellular => "Cellular",
            Self::Tunnel => "VPN / Tunnel",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalNetworkInfo {
    pub interface_name: String,
    pub friendly_name: Option<String>,
    pub link_type: LinkType,
    pub local_ipv4: Option<Ipv4Addr>,
    pub local_ipv6: Option<Ipv6Addr>,
    pub gateway_ip: Option<IpAddr>,
    pub mac_address: Option<String>,
    pub dns_servers: Vec<IpAddr>,
    pub vpn_active: bool,
    pub vpn_interfaces: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsLeakStatus {
    NoLeak,
    ExternalResolver,
    PossibleLeak,
    Unknown,
}

impl DnsLeakStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::NoLeak => "Matches public IP",
            Self::ExternalResolver => "External resolver (VPN off)",
            Self::PossibleLeak => "Possible DNS leak (VPN active)",
            Self::Unknown => "Unable to verify",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicNetworkStatus {
    pub public_ip: Option<IpAddr>,
    pub isp_or_org: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub colo: Option<String>,
    pub dns_resolver_ip: Option<IpAddr>,
    pub dns_leak_status: DnsLeakStatus,
    pub vpn_active: bool,
    pub vpn_interfaces: Vec<String>,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct IpInfoResponse {
    ip: Option<String>,
    org: Option<String>,
    country: Option<String>,
    city: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpGuideSelfResponse {
    ip: Option<String>,
}

fn classify_link_type(if_type: InterfaceType, name: &str, friendly: Option<&str>) -> LinkType {
    if matches!(
        if_type,
        InterfaceType::Tunnel | InterfaceType::Ppp | InterfaceType::ProprietaryVirtual
    ) || is_tunnel_name(name)
    {
        return LinkType::Tunnel;
    }
    if if_type == InterfaceType::Wireless80211
        || friendly.is_some_and(|f| f.to_ascii_lowercase().contains("wi-fi"))
    {
        return LinkType::WiFi;
    }
    if matches!(
        if_type,
        InterfaceType::Ethernet
            | InterfaceType::GigabitEthernet
            | InterfaceType::FastEthernetT
            | InterfaceType::FastEthernetFx
    ) {
        return LinkType::Ethernet;
    }
    if matches!(
        if_type,
        InterfaceType::Wwan | InterfaceType::Wwanpp | InterfaceType::Wwanpp2
    ) {
        return LinkType::Cellular;
    }
    LinkType::Unknown
}

fn is_tunnel_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["utun", "wg", "tun", "tap", "ppp", "ipsec", "tailscale", "zt"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

fn has_non_link_local_ip(iface: &netdev::Interface) -> bool {
    let v4_ok = iface
        .ipv4
        .iter()
        .any(|net| !net.addr().is_link_local() && !net.addr().is_loopback());
    let v6_ok = iface.ipv6.iter().any(|net| {
        let ip = net.addr();
        !ip.is_loopback() && !ip.is_unicast_link_local()
    });
    v4_ok || v6_ok
}

/// Collects local default interface, gateway, DNS servers, and active VPN tunnel interfaces.
pub fn get_local_network_info() -> Result<LocalNetworkInfo, NetError> {
    let interfaces = netdev::get_interfaces();

    let mut vpn_interfaces = Vec::new();
    for iface in &interfaces {
        if iface.oper_state == OperState::Up
            && (is_tunnel_name(&iface.name)
                || matches!(iface.if_type, InterfaceType::Tunnel | InterfaceType::Ppp))
            && has_non_link_local_ip(iface)
        {
            vpn_interfaces.push(iface.name.clone());
        }
    }

    let default_iface = netdev::get_default_interface().ok().or_else(|| {
        interfaces
            .iter()
            .find(|i| i.oper_state == OperState::Up && has_non_link_local_ip(i))
            .cloned()
    });

    let default_gw = netdev::get_default_gateway().ok();

    if let Some(iface) = default_iface {
        let link_type = classify_link_type(
            iface.if_type,
            &iface.name,
            iface.friendly_name.as_deref(),
        );
        let local_ipv4 = iface.ipv4.first().map(|n| n.addr());
        let local_ipv6 = iface
            .ipv6
            .iter()
            .map(|n| n.addr())
            .find(|ip| !ip.is_unicast_link_local())
            .or_else(|| iface.ipv6.first().map(|n| n.addr()));

        let gateway_ip = iface
            .gateway
            .as_ref()
            .and_then(|g| {
                g.ipv4
                    .first()
                    .copied()
                    .map(IpAddr::V4)
                    .or_else(|| g.ipv6.first().copied().map(IpAddr::V6))
            })
            .or_else(|| {
                default_gw.as_ref().and_then(|g| {
                    g.ipv4
                        .first()
                        .copied()
                        .map(IpAddr::V4)
                        .or_else(|| g.ipv6.first().copied().map(IpAddr::V6))
                })
            });

        let mac_address = iface.mac_addr.and_then(|m| {
            let s = m.address();
            if s == "00:00:00:00:00:00" {
                None
            } else {
                Some(s)
            }
        });

        return Ok(LocalNetworkInfo {
            interface_name: iface.name,
            friendly_name: iface.friendly_name,
            link_type,
            local_ipv4,
            local_ipv6,
            gateway_ip,
            mac_address,
            dns_servers: iface.dns_servers,
            vpn_active: !vpn_interfaces.is_empty(),
            vpn_interfaces,
        });
    }

    Ok(LocalNetworkInfo {
        interface_name: "none".to_string(),
        friendly_name: None,
        link_type: LinkType::Unknown,
        local_ipv4: None,
        local_ipv6: None,
        gateway_ip: None,
        mac_address: None,
        dns_servers: Vec::new(),
        vpn_active: !vpn_interfaces.is_empty(),
        vpn_interfaces,
    })
}

/// Checks if two IPv4 addresses sit in the same /24 subnet or IPv6 /48 prefix.
/// When VPN is OFF, differing DNS egress indicates an external resolver (e.g. DoT/DoH
/// upstream like AdGuard/Unbound or ISP recursive cluster) — informational, not a leak.
/// Only when VPN is ON and egress differs do we flag `PossibleLeak`.
pub fn compare_egress_ips(http_ip: IpAddr, dns_ip: IpAddr, vpn_active: bool) -> DnsLeakStatus {
    let same_prefix = match (http_ip, dns_ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let ao = a.octets();
            let bo = b.octets();
            a == b || (ao[0] == bo[0] && ao[1] == bo[1] && ao[2] == bo[2])
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let as_ = a.segments();
            let bs_ = b.segments();
            a == b || (as_[0] == bs_[0] && as_[1] == bs_[1] && as_[2] == bs_[2])
        }
        _ => false,
    };

    if same_prefix {
        DnsLeakStatus::NoLeak
    } else if vpn_active {
        DnsLeakStatus::PossibleLeak
    } else {
        DnsLeakStatus::ExternalResolver
    }
}

/// Fetches public IP, ISP/organization, and DNS resolver egress IP (for leak detection).
pub async fn fetch_public_network_status() -> PublicNetworkStatus {
    crate::ensure_crypto_provider();
    let local = get_local_network_info().ok();
    let vpn_active = local.as_ref().is_some_and(|l| l.vpn_active);
    let vpn_interfaces = local.map(|l| l.vpn_interfaces).unwrap_or_default();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .user_agent("NetScope/0.1")
        .build()
        .ok();

    let mut public_ip: Option<IpAddr> = None;
    let mut country: Option<String> = None;
    let mut city: Option<String> = None;
    let mut colo: Option<String> = None;
    let mut isp_or_org: Option<String> = None;

    if let Some(ref client) = client {
        // Fast, privacy-respecting trace endpoint first
        if let Ok(resp) = client.get("https://1.1.1.1/cdn-cgi/trace").send().await
            && let Ok(text) = resp.text().await
        {
            for line in text.lines() {
                if let Some(v) = line.strip_prefix("ip=")
                    && let Ok(ip) = v.trim().parse::<IpAddr>()
                {
                    public_ip = Some(ip);
                } else if let Some(v) = line.strip_prefix("loc=") {
                    country = Some(v.trim().to_string());
                } else if let Some(v) = line.strip_prefix("colo=") {
                    colo = Some(v.trim().to_string());
                }
            }
        }

        // Optional ISP/Org enrichment from ipinfo.io (best-effort)
        if let Ok(resp) = client.get("https://ipinfo.io/json").send().await
            && resp.status().is_success()
            && let Ok(info) = resp.json::<IpInfoResponse>().await
        {
            if public_ip.is_none()
                && let Some(ip_str) = info.ip
                && let Ok(ip) = ip_str.parse::<IpAddr>()
            {
                public_ip = Some(ip);
            }
            if let Some(org) = info.org {
                isp_or_org = Some(org);
            }
            if country.is_none() {
                country = info.country;
            }
            city = info.city;
        }

        // Fallback public IP lookup if both Cloudflare trace and ipinfo failed
        if public_ip.is_none()
            && let Ok(resp) = client.get("https://ip.guide/").send().await
            && resp.status().is_success()
            && let Ok(self_info) = resp.json::<IpGuideSelfResponse>().await
            && let Some(ip_str) = self_info.ip
            && let Ok(ip) = ip_str.trim().parse::<IpAddr>()
        {
            public_ip = Some(ip);
        }
    }

    // Fallback ISP/Org/location enrichment via multi-provider GeoIP (also warms GEO_CACHE for Visual Traceroute Hop 0)
    if isp_or_org.is_none()
        && let Some(ip) = public_ip
    {
        let geo = crate::geoip::lookup_ip(ip).await;
        isp_or_org = match (geo.asn, geo.isp) {
            (Some(asn), Some(isp)) => Some(format!("AS{asn} {isp}")),
            (None, Some(isp)) => Some(isp),
            (Some(asn), None) => Some(format!("AS{asn}")),
            (None, None) => None,
        };
        if city.is_none() {
            city = geo.city;
        }
        if country.is_none() {
            country = geo.country_code.or(geo.country);
        }
    }

    // DNS egress IP check via Google's authoritative `o-o.myaddr.l.google.com` TXT record
    let dns_resolver_ip = query_dns_egress_ip().await;

    let dns_leak_status = match (public_ip, dns_resolver_ip) {
        (Some(pub_ip), Some(dns_ip)) => compare_egress_ips(pub_ip, dns_ip, vpn_active),
        _ => DnsLeakStatus::Unknown,
    };

    PublicNetworkStatus {
        public_ip,
        isp_or_org,
        country,
        city,
        colo,
        dns_resolver_ip,
        dns_leak_status,
        vpn_active,
        vpn_interfaces,
        checked_at: Utc::now(),
    }
}

async fn query_dns_egress_ip() -> Option<IpAddr> {
    let resolver = Resolver::builder_tokio().ok()?.build().ok()?;
    let lookup = resolver
        .lookup("o-o.myaddr.l.google.com.", RecordType::TXT)
        .await
        .ok()?;
    for record in lookup.answers() {
        let s = record.data.to_string();
        let trimmed = s.trim().trim_matches('"');
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            return Some(ip);
        }
        // Sometimes TXT contains "edns0-client-subnet ..." alongside the IP
        for token in trimmed.split_whitespace() {
            if let Ok(ip) = token.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_comparison_same_subnet_no_leak() {
        let a: IpAddr = "203.0.113.10".parse().unwrap();
        let b: IpAddr = "203.0.113.25".parse().unwrap();
        assert_eq!(compare_egress_ips(a, b, false), DnsLeakStatus::NoLeak);
        assert_eq!(compare_egress_ips(a, b, true), DnsLeakStatus::NoLeak);
    }

    #[test]
    fn egress_comparison_different_subnet_depends_on_vpn() {
        let a: IpAddr = "203.0.113.10".parse().unwrap();
        let b: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(
            compare_egress_ips(a, b, false),
            DnsLeakStatus::ExternalResolver
        );
        assert_eq!(compare_egress_ips(a, b, true), DnsLeakStatus::PossibleLeak);
    }

    #[test]
    fn local_network_info_succeeds() {
        let info = get_local_network_info().expect("local net info should not fail");
        assert!(!info.interface_name.is_empty());
    }
}
