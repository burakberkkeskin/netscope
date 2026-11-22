use crate::NetError;
use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsRecordType {
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

    pub fn label(self) -> &'static str {
        match self {
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
            Self::System => "System Default".into(),
            Self::Cloudflare => "Cloudflare (1.1.1.1)".into(),
            Self::Google => "Google (8.8.8.8)".into(),
            Self::Quad9 => "Quad9 (9.9.9.9)".into(),
            Self::Custom(s) => format!("Custom ({s})"),
        }
    }
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
}

pub async fn lookup(
    query: &str,
    record_type: DnsRecordType,
    server: &DnsServerChoice,
) -> Result<DnsLookupResult, NetError> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Err(NetError::InvalidInput("Domain or IP cannot be empty".into()));
    }

    let resolver = match server {
        DnsServerChoice::System => Resolver::builder_tokio()
            .map_err(|e| NetError::Dns(e.to_string()))?
            .build()
            .map_err(|e| NetError::Dns(e.to_string()))?,
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
            Resolver::builder_with_config(cfg, TokioRuntimeProvider::default())
                .build()
                .map_err(|e| NetError::Dns(e.to_string()))?
        }
    };

    let started = Instant::now();
    let (lookup_result, effective_query) = if record_type == DnsRecordType::PTR
        && let Ok(ip) = trimmed.parse::<IpAddr>()
    {
        let res = resolver
            .reverse_lookup(ip)
            .await
            .map_err(|e| NetError::Dns(e.to_string()))?;
        (res, ip.to_string())
    } else {
        let fqdn = if trimmed.ends_with('.') {
            trimmed.to_string()
        } else {
            format!("{trimmed}.")
        };
        let res = resolver
            .lookup(fqdn.clone(), record_type.to_hickory())
            .await
            .map_err(|e| NetError::Dns(e.to_string()))?;
        (res, fqdn)
    };
    let query_time_ms = started.elapsed().as_secs_f64() * 1000.0;

    let mut records = Vec::new();
    let mut dig_lines = Vec::new();
    dig_lines.push(format!(
        "; <<>> NetScope DNS <<>> {} {}",
        effective_query,
        record_type.label()
    ));
    dig_lines.push(format!(";; SERVER: {}", server.label()));
    dig_lines.push(format!(";; QUERY TIME: {query_time_ms:.1} ms"));
    dig_lines.push(String::new());
    dig_lines.push(";; ANSWER SECTION:".to_string());

    for rec in lookup_result.answers() {
        let name = rec.name.to_string();
        let ttl = rec.ttl;
        let rtype = rec.record_type().to_string();
        let value = rec.data.to_string();
        dig_lines.push(format!("{name:<28} {ttl:<6} IN {rtype:<6} {value}"));
        records.push(DnsRecordRow {
            name,
            ttl,
            record_type: rtype,
            value,
        });
    }

    if records.is_empty() {
        dig_lines.push("; (no records returned)".to_string());
    }

    Ok(DnsLookupResult {
        query: trimmed.to_string(),
        record_type,
        server_label: server.label(),
        query_time_ms,
        records,
        raw_dig_text: dig_lines.join("\n"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn live_dns_a_lookup_system() {
        let res = lookup("cloudflare.com", DnsRecordType::A, &DnsServerChoice::System)
            .await
            .expect("cloudflare.com A lookup via System resolver should succeed");
        assert!(!res.records.is_empty());
        assert!(res.raw_dig_text.contains("ANSWER SECTION"));
    }

    #[tokio::test]
    async fn live_dns_ptr_lookup_one_one_one_one_system() {
        let res = lookup("1.1.1.1", DnsRecordType::PTR, &DnsServerChoice::System)
            .await
            .expect("1.1.1.1 PTR lookup via System resolver should succeed");
        assert!(!res.records.is_empty());
        assert!(res.records.iter().any(|r| r.value.contains("one.one.one.one")));
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
