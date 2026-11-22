use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ipv4SubnetInfo {
    pub input_ip: Ipv4Addr,
    pub prefix_len: u8,
    pub cidr: String,
    pub network: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub wildcard: Ipv4Addr,
    pub first_usable: Ipv4Addr,
    pub last_usable: Ipv4Addr,
    pub total_addresses: u64,
    pub usable_hosts: u64,
    pub scope: String,
    pub binary_ip: String,
    pub binary_netmask: String,
    pub binary_network: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ipv4ChildSubnet {
    pub index: usize,
    pub cidr: String,
    pub network: Ipv4Addr,
    pub first_usable: Ipv4Addr,
    pub last_usable: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    pub usable_hosts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ipv6SubnetInfo {
    pub input_ip: Ipv6Addr,
    pub prefix_len: u8,
    pub cidr: String,
    pub network: Ipv6Addr,
    pub first_address: Ipv6Addr,
    pub last_address: Ipv6Addr,
    pub total_64_blocks: String,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SubnetCalculation {
    V4(Box<Ipv4SubnetInfo>),
    V6(Box<Ipv6SubnetInfo>),
}

/// Parses either `"192.168.1.10/24"` or `"192.168.1.10"` (using `fallback_prefix`).
pub fn calculate_subnet(input: &str, fallback_prefix: u8) -> Result<SubnetCalculation, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Enter an IPv4 or IPv6 address or CIDR (e.g. 192.168.1.0/24)".into());
    }

    let (ip_part, prefix_opt) = match trimmed.split_once('/') {
        Some((ip_s, p_s)) => {
            let p: u8 = p_s
                .trim()
                .parse()
                .map_err(|_| format!("Invalid CIDR prefix length: '/{p_s}'"))?;
            (ip_s.trim(), Some(p))
        }
        None => (trimmed, None),
    };

    let ip: IpAddr = ip_part
        .parse()
        .map_err(|_| format!("Invalid IP address: '{ip_part}'"))?;

    match ip {
        IpAddr::V4(v4) => {
            let prefix = prefix_opt.unwrap_or(fallback_prefix.clamp(1, 32));
            if prefix > 32 {
                return Err(format!("IPv4 prefix length /{prefix} exceeds /32"));
            }
            Ok(SubnetCalculation::V4(Box::new(calculate_ipv4(v4, prefix))))
        }
        IpAddr::V6(v6) => {
            let prefix = prefix_opt.unwrap_or(fallback_prefix.clamp(1, 128));
            if prefix > 128 {
                return Err(format!("IPv6 prefix length /{prefix} exceeds /128"));
            }
            Ok(SubnetCalculation::V6(Box::new(calculate_ipv6(v6, prefix))))
        }
    }
}

pub fn calculate_ipv4(ip: Ipv4Addr, prefix_len: u8) -> Ipv4SubnetInfo {
    let p = prefix_len.min(32);
    let mask_u32: u32 = if p == 0 {
        0
    } else {
        u32::MAX << (32 - p)
    };
    let wildcard_u32 = !mask_u32;
    let ip_u32 = u32::from(ip);
    let net_u32 = ip_u32 & mask_u32;
    let bcast_u32 = net_u32 | wildcard_u32;

    let network = Ipv4Addr::from(net_u32);
    let broadcast = Ipv4Addr::from(bcast_u32);
    let netmask = Ipv4Addr::from(mask_u32);
    let wildcard = Ipv4Addr::from(wildcard_u32);

    let total_addresses = 1u64 << (32 - u32::from(p));
    let (first_usable, last_usable, usable_hosts) = match p {
        32 => (network, network, 1),
        31 => (network, broadcast, 2), // RFC 3021 point-to-point link
        _ => (
            Ipv4Addr::from(net_u32.saturating_add(1)),
            Ipv4Addr::from(bcast_u32.saturating_sub(1)),
            total_addresses.saturating_sub(2),
        ),
    };

    Ipv4SubnetInfo {
        input_ip: ip,
        prefix_len: p,
        cidr: format!("{network}/{p}"),
        network,
        broadcast,
        netmask,
        wildcard,
        first_usable,
        last_usable,
        total_addresses,
        usable_hosts,
        scope: classify_ipv4_scope(network).into(),
        binary_ip: format_v4_binary(ip),
        binary_netmask: format_v4_binary(netmask),
        binary_network: format_v4_binary(network),
    }
}

/// Splits an IPv4 subnet into smaller child subnets of `target_prefix` (up to 64 rows).
pub fn split_ipv4_subnet(
    network: Ipv4Addr,
    parent_prefix: u8,
    target_prefix: u8,
) -> Vec<Ipv4ChildSubnet> {
    let p = parent_prefix.min(32);
    let t = target_prefix.clamp(p, 32);
    let delta = u32::from(t - p);
    let count = (1u64 << delta).min(64) as usize;
    let step = if t == 32 {
        1u64
    } else {
        1u64 << (32 - u32::from(t))
    };

    let base = u64::from(u32::from(network));
    let mut out = Vec::with_capacity(count);
    for idx in 0..count {
        let net_u32 = (base + (idx as u64) * step) as u32;
        let info = calculate_ipv4(Ipv4Addr::from(net_u32), t);
        out.push(Ipv4ChildSubnet {
            index: idx + 1,
            cidr: info.cidr,
            network: info.network,
            first_usable: info.first_usable,
            last_usable: info.last_usable,
            broadcast: info.broadcast,
            usable_hosts: info.usable_hosts,
        });
    }
    out
}

/// Enumerates individual host IPv4 addresses inside a subnet for LAN scanning (capped at `max_hosts`, default 1024).
pub fn enumerate_ipv4_hosts(cidr_or_ip: &str, max_hosts: usize) -> Result<(String, Vec<Ipv4Addr>), String> {
    let calc = calculate_subnet(cidr_or_ip, 24)?;
    let SubnetCalculation::V4(info) = calc else {
        return Err("LAN Scanner requires an IPv4 subnet (e.g. 192.168.1.0/24)".into());
    };
    let start = u32::from(info.first_usable);
    let end = u32::from(info.last_usable);
    let cap = max_hosts.clamp(1, 2048);
    let mut hosts = Vec::new();
    for raw in start..=end {
        hosts.push(Ipv4Addr::from(raw));
        if hosts.len() >= cap {
            break;
        }
    }
    Ok((info.cidr, hosts))
}

pub fn calculate_ipv6(ip: Ipv6Addr, prefix_len: u8) -> Ipv6SubnetInfo {
    let p = prefix_len.min(128);
    let mask: u128 = if p == 0 {
        0
    } else {
        u128::MAX << (128 - p)
    };
    let ip_u128 = u128::from(ip);
    let net_u128 = ip_u128 & mask;
    let last_u128 = net_u128 | (!mask);

    let network = Ipv6Addr::from(net_u128);
    let last_address = Ipv6Addr::from(last_u128);
    let total_64_blocks = if p <= 64 {
        let shift = 64 - p;
        if shift == 64 {
            "18,446,744,073,709,551,616 (/64 subnets)".into()
        } else {
            format!("{} (/64 subnets)", 1u64 << shift)
        }
    } else {
        format!("Single /64 host slice (2^{} addresses)", 128 - p)
    };

    Ipv6SubnetInfo {
        input_ip: ip,
        prefix_len: p,
        cidr: format!("{network}/{p}"),
        network,
        first_address: network,
        last_address,
        total_64_blocks,
        scope: classify_ipv6_scope(network).into(),
    }
}

fn format_v4_binary(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{:08b}.{:08b}.{:08b}.{:08b}", o[0], o[1], o[2], o[3])
}

fn classify_ipv4_scope(ip: Ipv4Addr) -> &'static str {
    let o = ip.octets();
    if ip.is_loopback() {
        "Loopback (RFC 1122, 127.0.0.0/8)"
    } else if ip.is_private() {
        "Private LAN (RFC 1918)"
    } else if ip.is_link_local() {
        "Link-Local / APIPA (RFC 3927, 169.254.0.0/16)"
    } else if o[0] == 100 && (64..=127).contains(&o[1]) {
        "Shared CGNAT / Tailscale (RFC 6598, 100.64.0.0/10)"
    } else if ip.is_multicast() {
        "Multicast (RFC 5771, 224.0.0.0/4)"
    } else if ip.is_documentation() {
        "Documentation / TEST-NET (RFC 5737)"
    } else {
        "Global Public Unicast"
    }
}

fn classify_ipv6_scope(ip: Ipv6Addr) -> &'static str {
    let s0 = ip.segments()[0];
    if ip.is_loopback() {
        "Loopback (::1/128)"
    } else if ip.is_unicast_link_local() {
        "Link-Local (fe80::/10)"
    } else if (s0 & 0xfe00) == 0xfc00 {
        "Unique Local Address / ULA (RFC 4193, fc00::/7)"
    } else if ip.is_multicast() {
        "Multicast (ff00::/8)"
    } else {
        "Global Unicast (2000::/3)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculates_standard_ipv4_24_and_31_correctly() {
        let info = calculate_ipv4(Ipv4Addr::new(192, 168, 1, 42), 24);
        assert_eq!(info.network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(info.broadcast, Ipv4Addr::new(192, 168, 1, 255));
        assert_eq!(info.first_usable, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(info.last_usable, Ipv4Addr::new(192, 168, 1, 254));
        assert_eq!(info.usable_hosts, 254);
        assert_eq!(info.wildcard, Ipv4Addr::new(0, 0, 0, 255));

        let p2p = calculate_ipv4(Ipv4Addr::new(10, 0, 0, 9), 31);
        assert_eq!(p2p.usable_hosts, 2);
        assert_eq!(p2p.first_usable, Ipv4Addr::new(10, 0, 0, 8));
        assert_eq!(p2p.last_usable, Ipv4Addr::new(10, 0, 0, 9));
    }

    #[test]
    fn splits_ipv4_24_into_four_26_subnets() {
        let children = split_ipv4_subnet(Ipv4Addr::new(192, 168, 10, 0), 24, 26);
        assert_eq!(children.len(), 4);
        assert_eq!(children[0].cidr, "192.168.10.0/26");
        assert_eq!(children[1].cidr, "192.168.10.64/26");
        assert_eq!(children[2].cidr, "192.168.10.128/26");
        assert_eq!(children[3].cidr, "192.168.10.192/26");
        assert_eq!(children[0].usable_hosts, 62);
    }

    #[test]
    fn calculates_ipv6_ula_prefix() {
        let calc = calculate_subnet("fd00:1234:5678:9abc::1/48", 64).unwrap();
        match calc {
            SubnetCalculation::V6(v6) => {
                assert_eq!(v6.cidr, "fd00:1234:5678::/48");
                assert!(v6.scope.contains("ULA"));
                assert!(v6.total_64_blocks.contains("65536"));
            }
            _ => panic!("expected ipv6"),
        }
    }
}
