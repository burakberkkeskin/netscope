use crate::NetError;
use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

/// Fast resolver timeout so firewalled/blocked external DNS (port 53) fails promptly.
pub const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsRecordType {
    All,
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    SOA,
    PTR,
    SRV,
    CAA,
}

impl DnsRecordType {
    /// Single-record types supported by Global DNS Propagation.
    pub const ALL: [DnsRecordType; 10] = [
        Self::A,
        Self::AAAA,
        Self::CNAME,
        Self::MX,
        Self::TXT,
        Self::NS,
        Self::SOA,
        Self::PTR,
        Self::SRV,
        Self::CAA,
    ];

    /// Record type pills for interactive DNS Lookup (starts with `ALL`).
    pub const LOOKUP_TYPES: [DnsRecordType; 11] = [
        Self::All,
        Self::A,
        Self::AAAA,
        Self::CNAME,
        Self::MX,
        Self::TXT,
        Self::NS,
        Self::SOA,
        Self::PTR,
        Self::SRV,
        Self::CAA,
    ];

    /// Canonical parallel fan-out set used when `DnsRecordType::All` is queried for a domain.
    pub const ALL_FANOUT: [DnsRecordType; 8] = [
        Self::A,
        Self::AAAA,
        Self::CNAME,
        Self::MX,
        Self::TXT,
        Self::NS,
        Self::SOA,
        Self::CAA,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "ALL",
            Self::A => "A",
            Self::AAAA => "AAAA",
            Self::CNAME => "CNAME",
            Self::MX => "MX",
            Self::TXT => "TXT",
            Self::NS => "NS",
            Self::SOA => "SOA",
            Self::PTR => "PTR",
            Self::SRV => "SRV",
            Self::CAA => "CAA",
        }
    }

    pub fn to_hickory(self) -> RecordType {
        match self {
            Self::All => RecordType::ANY,
            Self::A => RecordType::A,
            Self::AAAA => RecordType::AAAA,
            Self::CNAME => RecordType::CNAME,
            Self::MX => RecordType::MX,
            Self::TXT => RecordType::TXT,
            Self::NS => RecordType::NS,
            Self::SOA => RecordType::SOA,
            Self::PTR => RecordType::PTR,
            Self::SRV => RecordType::SRV,
            Self::CAA => RecordType::CAA,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsServerChoice {
    System,
    Cloudflare,
    Google,
    Quad9,
    Custom(String),
}

impl DnsServerChoice {
    pub fn label(&self) -> String {
        match self {
            Self::System => format_system_dns_label(&detect_system_dns_servers()),
            Self::Cloudflare => "Cloudflare (1.1.1.1)".into(),
            Self::Google => "Google (8.8.8.8)".into(),
            Self::Quad9 => "Quad9 (9.9.9.9)".into(),
            Self::Custom(s) => format!("Custom ({s})"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum DnsLookupStatus {
    #[default]
    Found,
    NoRecords,
    NxDomain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecordRow {
    pub name: String,
    pub ttl: u32,
    pub record_type: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLookupResult {
    pub query: String,
    pub record_type: DnsRecordType,
    pub server_label: String,
    pub query_time_ms: f64,
    pub records: Vec<DnsRecordRow>,
    pub raw_dig_text: String,
    #[serde(default)]
    pub status: DnsLookupStatus,
    #[serde(default)]
    pub resolved_servers: Vec<IpAddr>,
}

/// Parses macOS `scutil --dns` output for primary default-resolver DNS servers (skipping mDNS/scoped blocks).
pub fn parse_macos_scutil_dns_servers(output: &str) -> Vec<IpAddr> {
    let mut primary = Vec::new();
    let mut fallback = Vec::new();
    let mut in_block = false;
    let mut is_mdns = false;
    let mut is_scoped = false;
    let mut block_servers: Vec<IpAddr> = Vec::new();

    let flush_block = |block_servers: &mut Vec<IpAddr>,
                       is_mdns: bool,
                       is_scoped: bool,
                       primary: &mut Vec<IpAddr>,
                       fallback: &mut Vec<IpAddr>| {
        if !is_mdns {
            for &ip in block_servers.iter() {
                if !is_scoped {
                    if !primary.contains(&ip) {
                        primary.push(ip);
                    }
                } else if !fallback.contains(&ip) {
                    fallback.push(ip);
                }
            }
        }
        block_servers.clear();
    };

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("resolver #") {
            if in_block {
                flush_block(
                    &mut block_servers,
                    is_mdns,
                    is_scoped,
                    &mut primary,
                    &mut fallback,
                );
            }
            in_block = true;
            is_mdns = false;
            is_scoped = false;
            continue;
        }
        if trimmed.starts_with("DNS configuration (for scoped queries)") {
            // Everything after this banner is per-interface duplicate info.
            break;
        }
        if !in_block {
            continue;
        }
        if trimmed.starts_with("options") && trimmed.contains("mdns") {
            is_mdns = true;
        } else if trimmed.starts_with("domain") && !trimmed.starts_with("search domain") {
            is_scoped = true;
        } else if trimmed.starts_with("nameserver[")
            && let Some((_, val)) = trimmed.split_once(':')
        {
            let clean = val.trim().split('%').next().unwrap_or("");
            if let Ok(ip) = clean.parse::<IpAddr>()
                && !block_servers.contains(&ip)
            {
                block_servers.push(ip);
            }
        }
    }

    if in_block {
        flush_block(
            &mut block_servers,
            is_mdns,
            is_scoped,
            &mut primary,
            &mut fallback,
        );
    }

    if !primary.is_empty() {
        primary
    } else {
        fallback
    }
}

/// Detects the active OS default DNS server IP(s).
pub fn detect_system_dns_servers() -> Vec<IpAddr> {
    let mut servers = Vec::new();

    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("/usr/sbin/scutil")
            .arg("--dns")
            .output()
        {
            servers = parse_macos_scutil_dns_servers(&String::from_utf8_lossy(&out.stdout));
        }
    }

    if servers.is_empty()
        && let Ok((cfg, _)) = hickory_resolver::system_conf::read_system_conf()
    {
        for ns in cfg.name_servers() {
            let ip = ns.ip;
            if !servers.contains(&ip) {
                servers.push(ip);
            }
        }
    }

    if servers.is_empty()
        && let Ok(iface) = netdev::get_default_interface()
    {
        for ip in iface.dns_servers {
            if !servers.contains(&ip) {
                servers.push(ip);
            }
        }
    }

    servers
}

pub fn format_system_dns_label(servers: &[IpAddr]) -> String {
    match servers {
        [] => "System Default".into(),
        [only] => format!("System ({only})"),
        [first, rest @ ..] => format!("System ({first} +{})", rest.len()),
    }
}

pub fn format_system_dns_pill(servers: &[IpAddr]) -> String {
    match servers {
        [] => "System".into(),
        [only] => format!("System ({only})"),
        [first, rest @ ..] => format!("System ({first} +{})", rest.len()),
    }
}

enum SingleOutcome {
    Found(Vec<DnsRecordRow>),
    NoRecords,
    NxDomain,
    Error(String),
}

fn classify_resolve_error(err: &impl std::fmt::Display) -> SingleOutcome {
    let msg = err.to_string();
    let lower = msg.to_ascii_lowercase();
    if lower.contains("nxdomain") || lower.contains("non-existent domain") {
        SingleOutcome::NxDomain
    } else if lower.contains("no records found") {
        SingleOutcome::NoRecords
    } else {
        SingleOutcome::Error(msg)
    }
}

async fn run_single_record(
    resolver: &hickory_resolver::TokioResolver,
    trimmed: &str,
    record_type: DnsRecordType,
) -> (SingleOutcome, String) {
    if record_type == DnsRecordType::PTR
        && let Ok(ip) = trimmed.parse::<IpAddr>()
    {
        match resolver.reverse_lookup(ip).await {
            Ok(res) => {
                let rows = collect_rows(&res);
                if rows.is_empty() {
                    (SingleOutcome::NoRecords, ip.to_string())
                } else {
                    (SingleOutcome::Found(rows), ip.to_string())
                }
            }
            Err(e) => (classify_resolve_error(&e), ip.to_string()),
        }
    } else {
        let fqdn = if trimmed.ends_with('.') {
            trimmed.to_string()
        } else {
            format!("{trimmed}.")
        };
        match resolver.lookup(fqdn.clone(), record_type.to_hickory()).await {
            Ok(res) => {
                let rows = collect_rows(&res);
                if rows.is_empty() {
                    (SingleOutcome::NoRecords, fqdn)
                } else {
                    (SingleOutcome::Found(rows), fqdn)
                }
            }
            Err(e) => (classify_resolve_error(&e), fqdn),
        }
    }
}

fn collect_rows(lookup: &hickory_resolver::lookup::Lookup) -> Vec<DnsRecordRow> {
    lookup
        .answers()
        .iter()
        .map(|rec| DnsRecordRow {
            name: rec.name.to_string(),
            ttl: rec.ttl,
            record_type: rec.record_type().to_string(),
            value: rec.data.to_string(),
        })
        .collect()
}

pub async fn lookup(
    query: &str,
    record_type: DnsRecordType,
    server: &DnsServerChoice,
) -> Result<DnsLookupResult, NetError> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Err(NetError::InvalidInput(
            "Domain or IP cannot be empty".into(),
        ));
    }

    let (resolver, resolved_servers, server_label) = match server {
        DnsServerChoice::System => {
            let sys_servers = detect_system_dns_servers();
            let mut builder =
                Resolver::builder_tokio().map_err(|e| NetError::Dns(e.to_string()))?;
            builder.options_mut().timeout = DNS_LOOKUP_TIMEOUT;
            builder.options_mut().attempts = 1;
            let res = builder.build().map_err(|e| NetError::Dns(e.to_string()))?;
            let label = format_system_dns_label(&sys_servers);
            (res, sys_servers, label)
        }
        other => {
            let ip: IpAddr = match other {
                DnsServerChoice::Cloudflare => "1.1.1.1".parse().unwrap(),
                DnsServerChoice::Google => "8.8.8.8".parse().unwrap(),
                DnsServerChoice::Quad9 => "9.9.9.9".parse().unwrap(),
                DnsServerChoice::Custom(raw) => raw.trim().parse::<IpAddr>().map_err(|_| {
                    NetError::InvalidInput(format!("Invalid DNS server IP: '{raw}'"))
                })?,
                DnsServerChoice::System => unreachable!(),
            };
            let cfg = ResolverConfig::from_name_servers(vec![NameServerConfig::udp_and_tcp(ip)]);
            let mut builder = Resolver::builder_with_config(cfg, TokioRuntimeProvider::default());
            builder.options_mut().timeout = DNS_LOOKUP_TIMEOUT;
            builder.options_mut().attempts = 1;
            let res = builder.build().map_err(|e| NetError::Dns(e.to_string()))?;
            (res, vec![ip], other.label())
        }
    };

    let started = Instant::now();
    let resolver = Arc::new(resolver);

    let (status, records, effective_query) = if record_type == DnsRecordType::All {
        if trimmed.parse::<IpAddr>().is_ok() {
            let res = tokio::time::timeout(
                DNS_LOOKUP_TIMEOUT,
                run_single_record(&resolver, trimmed, DnsRecordType::PTR),
            )
            .await;
            match res {
                Ok((SingleOutcome::Found(rows), eff)) => (DnsLookupStatus::Found, rows, eff),
                Ok((SingleOutcome::NoRecords, eff)) => (DnsLookupStatus::NoRecords, Vec::new(), eff),
                Ok((SingleOutcome::NxDomain, eff)) => (DnsLookupStatus::NxDomain, Vec::new(), eff),
                Ok((SingleOutcome::Error(e), _)) => return Err(NetError::Dns(e)),
                Err(_) => {
                    return Err(timeout_error(&server_label, &resolved_servers));
                }
            }
        } else {
            let fqdn = if trimmed.ends_with('.') {
                trimmed.to_string()
            } else {
                format!("{trimmed}.")
            };
            let mut set = JoinSet::new();
            for (idx, rtype) in DnsRecordType::ALL_FANOUT.iter().copied().enumerate() {
                let r = resolver.clone();
                let q = trimmed.to_string();
                set.spawn(async move {
                    let (out, _) = run_single_record(&r, &q, rtype).await;
                    (idx, out)
                });
            }

            let mut buckets: Vec<Option<SingleOutcome>> =
                (0..DnsRecordType::ALL_FANOUT.len()).map(|_| None).collect();
            let collect_fut = async {
                while let Some(joined) = set.join_next().await {
                    if let Ok((idx, out)) = joined {
                        buckets[idx] = Some(out);
                    }
                }
            };
            let timed_out = tokio::time::timeout(DNS_LOOKUP_TIMEOUT, collect_fut)
                .await
                .is_err();
            set.abort_all();

            let mut merged = Vec::new();
            let mut seen = HashSet::new();
            let mut saw_nxdomain = false;
            let mut saw_norecords = false;
            let mut first_err: Option<String> = None;

            for outcome in buckets.into_iter().flatten() {
                match outcome {
                    SingleOutcome::Found(rows) => {
                        for row in rows {
                            let key = (
                                row.name.to_ascii_lowercase(),
                                row.record_type.clone(),
                                row.value.clone(),
                            );
                            if seen.insert(key) {
                                merged.push(row);
                            }
                        }
                    }
                    SingleOutcome::NoRecords => saw_norecords = true,
                    SingleOutcome::NxDomain => saw_nxdomain = true,
                    SingleOutcome::Error(e) => {
                        if first_err.is_none() {
                            first_err = Some(e);
                        }
                    }
                }
            }

            if !merged.is_empty() {
                (DnsLookupStatus::Found, merged, fqdn)
            } else if saw_nxdomain {
                (DnsLookupStatus::NxDomain, Vec::new(), fqdn)
            } else if saw_norecords {
                (DnsLookupStatus::NoRecords, Vec::new(), fqdn)
            } else if timed_out {
                return Err(timeout_error(&server_label, &resolved_servers));
            } else if let Some(err) = first_err {
                return Err(NetError::Dns(err));
            } else {
                (DnsLookupStatus::NoRecords, Vec::new(), fqdn)
            }
        }
    } else {
        let res = tokio::time::timeout(
            DNS_LOOKUP_TIMEOUT,
            run_single_record(&resolver, trimmed, record_type),
        )
        .await;
        match res {
            Ok((SingleOutcome::Found(rows), eff)) => (DnsLookupStatus::Found, rows, eff),
            Ok((SingleOutcome::NoRecords, eff)) => (DnsLookupStatus::NoRecords, Vec::new(), eff),
            Ok((SingleOutcome::NxDomain, eff)) => (DnsLookupStatus::NxDomain, Vec::new(), eff),
            Ok((SingleOutcome::Error(e), _)) => {
                if e.to_ascii_lowercase().contains("timed out")
                    || e.to_ascii_lowercase().contains("timeout")
                {
                    return Err(timeout_error(&server_label, &resolved_servers));
                }
                return Err(NetError::Dns(e));
            }
            Err(_) => {
                return Err(timeout_error(&server_label, &resolved_servers));
            }
        }
    };

    let query_time_ms = started.elapsed().as_secs_f64() * 1000.0;

    let status_str = match status {
        DnsLookupStatus::Found => "NOERROR",
        DnsLookupStatus::NoRecords => "NOERROR (NODATA)",
        DnsLookupStatus::NxDomain => "NXDOMAIN",
    };

    let mut dig_lines = Vec::new();
    dig_lines.push(format!(
        "; <<>> NetScope DNS <<>> {} {}",
        effective_query,
        record_type.label()
    ));
    let server_detail = if resolved_servers.is_empty() {
        server_label.clone()
    } else {
        let ips = resolved_servers
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        format!("{server_label} [{ips}]")
    };
    dig_lines.push(format!(";; SERVER: {server_detail}"));
    dig_lines.push(format!(";; STATUS: {status_str}"));
    dig_lines.push(format!(";; QUERY TIME: {query_time_ms:.1} ms"));
    dig_lines.push(String::new());
    dig_lines.push(";; ANSWER SECTION:".to_string());

    for rec in &records {
        dig_lines.push(format!(
            "{:<28} {:<6} IN {:<6} {}",
            rec.name, rec.ttl, rec.record_type, rec.value
        ));
    }

    if records.is_empty() {
        dig_lines.push(match status {
            DnsLookupStatus::NxDomain => "; (NXDOMAIN — domain does not exist)".to_string(),
            _ => format!(
                "; (no {} records returned for {})",
                record_type.label(),
                effective_query
            ),
        });
    }

    Ok(DnsLookupResult {
        query: trimmed.to_string(),
        record_type,
        server_label,
        query_time_ms,
        records,
        raw_dig_text: dig_lines.join("\n"),
        status,
        resolved_servers,
    })
}

fn timeout_error(server_label: &str, ips: &[IpAddr]) -> NetError {
    let ip_hint = ips
        .first()
        .map(|ip| format!(" ({ip}:53)"))
        .unwrap_or_default();
    NetError::Dns(format!(
        "Timed out after {:.0}s querying {server_label}{ip_hint} — direct port 53 may be blocked by firewall",
        DNS_LOOKUP_TIMEOUT.as_secs_f64()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_macos_scutil_primary_dns_servers_and_skips_mdns() {
        let sample = "\
DNS configuration

resolver #1
  search domain[0] : internal
  nameserver[0] : 192.168.20.10
  nameserver[1] : fdf8:79bc:8048:20:be24:11ff:fe5a:3754
  if_index : 14 (en0)

resolver #2
  domain   : local
  options  : mdns
  nameserver[0] : 224.0.0.251

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 10.0.0.1
";
        let servers = parse_macos_scutil_dns_servers(sample);
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0], "192.168.20.10".parse::<IpAddr>().unwrap());
        assert_eq!(
            servers[1],
            "fdf8:79bc:8048:20:be24:11ff:fe5a:3754"
                .parse::<IpAddr>()
                .unwrap()
        );
        assert_eq!(format_system_dns_pill(&servers), "System (192.168.20.10 +1)");
    }

    #[tokio::test]
    async fn live_dns_a_lookup_system() {
        let res = lookup("cloudflare.com", DnsRecordType::A, &DnsServerChoice::System)
            .await
            .expect("cloudflare.com A lookup via System resolver should succeed");
        assert_eq!(res.status, DnsLookupStatus::Found);
        assert!(!res.records.is_empty());
        assert!(res.raw_dig_text.contains("ANSWER SECTION"));
    }

    #[tokio::test]
    async fn live_dns_all_lookup_system_returns_multiple_types() {
        let res = lookup(
            "cloudflare.com",
            DnsRecordType::All,
            &DnsServerChoice::System,
        )
        .await
        .expect("cloudflare.com ALL lookup via System resolver should succeed");
        assert_eq!(res.status, DnsLookupStatus::Found);
        let types: HashSet<&str> = res.records.iter().map(|r| r.record_type.as_str()).collect();
        assert!(types.contains("A"), "expected A in {types:?}");
        assert!(types.contains("NS") || types.contains("MX") || types.contains("TXT"));
    }

    #[tokio::test]
    async fn live_dns_ptr_lookup_one_one_one_one_system() {
        let res = lookup("1.1.1.1", DnsRecordType::PTR, &DnsServerChoice::System)
            .await
            .expect("1.1.1.1 PTR lookup via System resolver should succeed");
        assert!(!res.records.is_empty());
        assert!(
            res.records
                .iter()
                .any(|r| r.value.contains("one.one.one.one"))
        );
    }

    #[tokio::test]
    async fn invalid_custom_dns_ip_returns_invalid_input() {
        let err = lookup(
            "cloudflare.com",
            DnsRecordType::A,
            &DnsServerChoice::Custom("not-an-ip".into()),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, NetError::InvalidInput(_)));
    }
}
