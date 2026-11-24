use crate::dns::{DnsRecordType, DnsServerChoice};
use crate::{CancelToken, NetError};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::Name;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy)]
pub struct ResolverNode {
    pub id: &'static str,
    pub name: &'static str,
    pub region: &'static str,
    pub endpoint_hint: &'static str,
    /// `None` uses the local OS resolver (`System Default`); `Some(url)` uses RFC 8484 DoH POST.
    pub doh_url: Option<&'static str>,
}

pub const GLOBAL_RESOLVERS: &[ResolverNode] = &[
    ResolverNode {
        id: "system",
        name: "System Default",
        region: "Local",
        endpoint_hint: "OS Resolver",
        doh_url: None,
    },
    ResolverNode {
        id: "cloudflare",
        name: "Cloudflare",
        region: "Global",
        endpoint_hint: "1.1.1.1",
        doh_url: Some("https://cloudflare-dns.com/dns-query"),
    },
    ResolverNode {
        id: "google",
        name: "Google Public DNS",
        region: "Global",
        endpoint_hint: "8.8.8.8",
        doh_url: Some("https://dns.google/dns-query"),
    },
    ResolverNode {
        id: "quad9",
        name: "Quad9",
        region: "Switzerland / Global",
        endpoint_hint: "9.9.9.9",
        doh_url: Some("https://dns.quad9.net/dns-query"),
    },
    ResolverNode {
        id: "opendns",
        name: "OpenDNS (Cisco)",
        region: "US / Global",
        endpoint_hint: "208.67.222.222",
        doh_url: Some("https://doh.opendns.com/dns-query"),
    },
    ResolverNode {
        id: "adguard",
        name: "AdGuard Unfiltered",
        region: "Cyprus / EU",
        endpoint_hint: "94.140.14.140",
        doh_url: Some("https://unfiltered.adguard-dns.com/dns-query"),
    },
    ResolverNode {
        id: "mullvad",
        name: "Mullvad DNS",
        region: "Sweden / EU",
        endpoint_hint: "194.242.2.2",
        doh_url: Some("https://dns.mullvad.net/dns-query"),
    },
    ResolverNode {
        id: "switch",
        name: "SWITCH DNS",
        region: "Switzerland / EU",
        endpoint_hint: "130.59.31.248",
        doh_url: Some("https://dns.switch.ch/dns-query"),
    },
    ResolverNode {
        id: "dnssb",
        name: "DNS.SB",
        region: "Germany / EU",
        endpoint_hint: "185.222.222.222",
        doh_url: Some("https://doh.dns.sb/dns-query"),
    },
    ResolverNode {
        id: "libredns",
        name: "LibreDNS",
        region: "Greece / EU",
        endpoint_hint: "116.202.176.26",
        doh_url: Some("https://doh.libredns.gr/dns-query"),
    },
    ResolverNode {
        id: "controld",
        name: "Control D",
        region: "Canada / NA",
        endpoint_hint: "76.76.2.0",
        doh_url: Some("https://freedns.controld.com/p0"),
    },
    ResolverNode {
        id: "cira",
        name: "CIRA Shield",
        region: "Canada / NA",
        endpoint_hint: "149.112.121.10",
        doh_url: Some("https://private.canadianshield.cira.ca/dns-query"),
    },
    ResolverNode {
        id: "iij",
        name: "IIJ Public DNS",
        region: "Japan / APAC",
        endpoint_hint: "103.2.57.5",
        doh_url: Some("https://public.dns.iij.jp/dns-query"),
    },
    ResolverNode {
        id: "alidns",
        name: "AliDNS",
        region: "China / APAC",
        endpoint_hint: "223.5.5.5",
        doh_url: Some("https://dns.alidns.com/dns-query"),
    },
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PropagationOutcome {
    Resolved,
    NoData,
    NxDomain,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverResult {
    pub index: usize,
    pub resolver_name: String,
    pub region: String,
    pub endpoint_hint: String,
    pub outcome: PropagationOutcome,
    pub latency_ms: f64,
    pub min_ttl: Option<u32>,
    pub answers: Vec<String>,
    pub normalized_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolverVerdict {
    Match,
    Divergent,
    Missing,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationSummary {
    pub total: usize,
    pub completed: usize,
    pub matched: usize,
    pub divergent: usize,
    pub missing: usize,
    pub errors: usize,
    pub consensus_values: Vec<String>,
    pub avg_latency_ms: Option<f64>,
    pub verdicts: Vec<(usize, ResolverVerdict)>,
}

#[derive(Debug, Clone)]
pub enum PropagationEvent {
    Started { total: usize },
    ResolverDone(ResolverResult),
    Error(String),
    Finished,
}

/// Serializes an RFC 1035 / RFC 8484 DNS wire query (`id = 0`, `RD = 1`).
pub fn build_wire_query(query: &str, record_type: DnsRecordType) -> Result<Vec<u8>, NetError> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Err(NetError::InvalidInput("Domain or IP cannot be empty".into()));
    }

    let name = if record_type == DnsRecordType::PTR
        && let Ok(ip) = trimmed.parse::<IpAddr>()
    {
        Name::from(ip)
    } else {
        let fqdn = if trimmed.ends_with('.') {
            trimmed.to_string()
        } else {
            format!("{trimmed}.")
        };
        Name::from_utf8(fqdn)
            .map_err(|e| NetError::InvalidInput(format!("Invalid domain name '{trimmed}': {e}")))?
    };

    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name, record_type.to_hickory()));
    msg.to_vec()
        .map_err(|e| NetError::Dns(format!("Failed to encode DNS query: {e}")))
}

/// Decodes an RFC 8484 DNS wire response into outcome, sorted unique answers, and minimum TTL.
pub fn parse_wire_response(
    bytes: &[u8],
    requested: DnsRecordType,
) -> Result<(PropagationOutcome, Vec<String>, Option<u32>), NetError> {
    let msg = Message::from_vec(bytes)
        .map_err(|e| NetError::Parse(format!("Invalid DNS response: {e}")))?;

    match msg.metadata.response_code {
        ResponseCode::NXDomain => return Ok((PropagationOutcome::NxDomain, Vec::new(), None)),
        ResponseCode::NoError => {}
        other => {
            return Ok((
                PropagationOutcome::Error(format!("RCODE: {other}")),
                Vec::new(),
                None,
            ));
        }
    }

    let wanted = requested.to_hickory();
    let mut matching: Vec<(u32, String)> = Vec::new();
    let mut fallback: Vec<(u32, String)> = Vec::new();

    for rec in &msg.answers {
        let entry = (rec.ttl, rec.data.to_string());
        if rec.record_type() == wanted {
            matching.push(entry);
        } else {
            fallback.push(entry);
        }
    }

    let selected = if !matching.is_empty() {
        matching
    } else {
        fallback
    };

    if selected.is_empty() {
        return Ok((PropagationOutcome::NoData, Vec::new(), None));
    }

    let min_ttl = selected.iter().map(|(ttl, _)| *ttl).min();
    let mut values: Vec<String> = selected.into_iter().map(|(_, v)| v).collect();
    values.sort();
    values.dedup();

    Ok((PropagationOutcome::Resolved, values, min_ttl))
}

fn normalize_single(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Canonicalizes an answer list so identical round-robin RRsets compare equal regardless of order.
pub fn normalize_answer_key(answers: &[String]) -> String {
    let mut norm: Vec<String> = answers
        .iter()
        .map(|s| normalize_single(s))
        .filter(|s| !s.is_empty())
        .collect();
    norm.sort();
    norm.dedup();
    norm.join("|")
}

/// Evaluates propagation consensus (or checks against optional comma-separated expected values).
pub fn evaluate_propagation(
    results: &[ResolverResult],
    expected_filter: &str,
) -> PropagationSummary {
    let raw_terms: Vec<String> = expected_filter
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let norm_terms: Vec<String> = raw_terms.iter().map(|s| normalize_single(s)).collect();

    let mut matched = 0usize;
    let mut divergent = 0usize;
    let mut missing = 0usize;
    let mut errors = 0usize;
    let mut verdicts = Vec::with_capacity(results.len());

    let consensus_values: Vec<String>;

    if !norm_terms.is_empty() {
        consensus_values = raw_terms;
        for res in results {
            let verdict = match &res.outcome {
                PropagationOutcome::Resolved => {
                    let hits = res.answers.iter().any(|ans| {
                        let norm_ans = normalize_single(ans);
                        norm_terms.iter().any(|term| norm_ans.contains(term))
                    });
                    if hits {
                        matched += 1;
                        ResolverVerdict::Match
                    } else {
                        divergent += 1;
                        ResolverVerdict::Divergent
                    }
                }
                PropagationOutcome::NoData | PropagationOutcome::NxDomain => {
                    missing += 1;
                    ResolverVerdict::Missing
                }
                PropagationOutcome::Error(_) => {
                    errors += 1;
                    ResolverVerdict::Error
                }
            };
            verdicts.push((res.index, verdict));
        }
    } else {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for res in results {
            if res.outcome == PropagationOutcome::Resolved && !res.normalized_key.is_empty() {
                *counts.entry(res.normalized_key.as_str()).or_insert(0) += 1;
            }
        }

        let consensus_key = counts
            .into_iter()
            .max_by(|(ka, ca), (kb, cb)| ca.cmp(cb).then_with(|| kb.cmp(ka)))
            .map(|(k, _)| k.to_string())
            .unwrap_or_default();

        consensus_values = if consensus_key.is_empty() {
            Vec::new()
        } else {
            results
                .iter()
                .find(|r| {
                    r.outcome == PropagationOutcome::Resolved && r.normalized_key == consensus_key
                })
                .map(|r| r.answers.clone())
                .unwrap_or_default()
        };

        for res in results {
            let verdict = match &res.outcome {
                PropagationOutcome::Resolved => {
                    if !consensus_key.is_empty() && res.normalized_key == consensus_key {
                        matched += 1;
                        ResolverVerdict::Match
                    } else {
                        divergent += 1;
                        ResolverVerdict::Divergent
                    }
                }
                PropagationOutcome::NoData | PropagationOutcome::NxDomain => {
                    missing += 1;
                    ResolverVerdict::Missing
                }
                PropagationOutcome::Error(_) => {
                    errors += 1;
                    ResolverVerdict::Error
                }
            };
            verdicts.push((res.index, verdict));
        }
    }

    let mut latency_sum = 0.0;
    let mut latency_count = 0usize;
    for res in results {
        if !matches!(res.outcome, PropagationOutcome::Error(_)) {
            latency_sum += res.latency_ms;
            latency_count += 1;
        }
    }
    let avg_latency_ms = if latency_count > 0 {
        Some(latency_sum / latency_count as f64)
    } else {
        None
    };

    PropagationSummary {
        total: results.len(),
        completed: results.len(),
        matched,
        divergent,
        missing,
        errors,
        consensus_values,
        avg_latency_ms,
        verdicts,
    }
}

/// Runs concurrent propagation checks across the local OS resolver and all global DoH endpoints.
pub async fn run_propagation(
    query: String,
    record_type: DnsRecordType,
    tx: mpsc::UnboundedSender<PropagationEvent>,
    cancel: CancelToken,
) {
    let wire_bytes = match build_wire_query(&query, record_type) {
        Ok(b) => b,
        Err(e) => {
            let _ = tx.send(PropagationEvent::Error(e.to_string()));
            return;
        }
    };

    crate::ensure_crypto_provider();
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent("NetScope/0.4")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(PropagationEvent::Error(format!(
                "Failed to initialize HTTP client: {e}"
            )));
            return;
        }
    };

    let _ = tx.send(PropagationEvent::Started {
        total: GLOBAL_RESOLVERS.len(),
    });

    let mut handles = Vec::with_capacity(GLOBAL_RESOLVERS.len());
    for (index, node) in GLOBAL_RESOLVERS.iter().copied().enumerate() {
        let q = query.clone();
        let wire = wire_bytes.clone();
        let client = client.clone();
        let tx = tx.clone();
        let cancel = cancel.clone();

        handles.push(tokio::spawn(async move {
            if cancel.is_cancelled() {
                return;
            }
            let res = match node.doh_url {
                None => query_system_resolver(index, node, &q, record_type).await,
                Some(url) => query_doh_resolver(index, node, url, wire, record_type, &client).await,
            };
            if !cancel.is_cancelled() {
                let _ = tx.send(PropagationEvent::ResolverDone(res));
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    if !cancel.is_cancelled() {
        let _ = tx.send(PropagationEvent::Finished);
    }
}

async fn query_system_resolver(
    index: usize,
    node: ResolverNode,
    query: &str,
    record_type: DnsRecordType,
) -> ResolverResult {
    let started = Instant::now();
    let res = tokio::time::timeout(
        Duration::from_secs(5),
        crate::dns::lookup(query, record_type, &DnsServerChoice::System),
    )
    .await;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;

    match res {
        Ok(Ok(lookup_res)) => {
            let wanted = record_type.label();
            let mut matching: Vec<(u32, String)> = Vec::new();
            let mut fallback: Vec<(u32, String)> = Vec::new();
            for row in lookup_res.records {
                let entry = (row.ttl, row.value);
                if row.record_type.eq_ignore_ascii_case(wanted) {
                    matching.push(entry);
                } else {
                    fallback.push(entry);
                }
            }
            let selected = if !matching.is_empty() {
                matching
            } else {
                fallback
            };

            if selected.is_empty() {
                ResolverResult {
                    index,
                    resolver_name: node.name.into(),
                    region: node.region.into(),
                    endpoint_hint: node.endpoint_hint.into(),
                    outcome: PropagationOutcome::NoData,
                    latency_ms: lookup_res.query_time_ms.max(elapsed_ms),
                    min_ttl: None,
                    answers: Vec::new(),
                    normalized_key: String::new(),
                }
            } else {
                let min_ttl = selected.iter().map(|(ttl, _)| *ttl).min();
                let mut answers: Vec<String> = selected.into_iter().map(|(_, v)| v).collect();
                answers.sort();
                answers.dedup();
                let normalized_key = normalize_answer_key(&answers);
                ResolverResult {
                    index,
                    resolver_name: node.name.into(),
                    region: node.region.into(),
                    endpoint_hint: node.endpoint_hint.into(),
                    outcome: PropagationOutcome::Resolved,
                    latency_ms: lookup_res.query_time_ms,
                    min_ttl,
                    answers,
                    normalized_key,
                }
            }
        }
        Ok(Err(err)) => {
            let msg = err.to_string();
            let lower = msg.to_ascii_lowercase();
            let outcome = if lower.contains("nxdomain") || lower.contains("non-existent domain") {
                PropagationOutcome::NxDomain
            } else if lower.contains("no records") {
                PropagationOutcome::NoData
            } else {
                PropagationOutcome::Error(msg)
            };
            ResolverResult {
                index,
                resolver_name: node.name.into(),
                region: node.region.into(),
                endpoint_hint: node.endpoint_hint.into(),
                outcome,
                latency_ms: elapsed_ms,
                min_ttl: None,
                answers: Vec::new(),
                normalized_key: String::new(),
            }
        }
        Err(_) => ResolverResult {
            index,
            resolver_name: node.name.into(),
            region: node.region.into(),
            endpoint_hint: node.endpoint_hint.into(),
            outcome: PropagationOutcome::Error("Timed out (5s)".into()),
            latency_ms: elapsed_ms,
            min_ttl: None,
            answers: Vec::new(),
            normalized_key: String::new(),
        },
    }
}

async fn query_doh_resolver(
    index: usize,
    node: ResolverNode,
    url: &str,
    wire_bytes: Vec<u8>,
    record_type: DnsRecordType,
    client: &reqwest::Client,
) -> ResolverResult {
    let started = Instant::now();
    let resp = client
        .post(url)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(wire_bytes)
        .send()
        .await;

    let mut latency_ms = started.elapsed().as_secs_f64() * 1000.0;

    let (outcome, answers, min_ttl) = match resp {
        Ok(r) => {
            let status = r.status();
            if !status.is_success() {
                (
                    PropagationOutcome::Error(format!("HTTP {}", status.as_u16())),
                    Vec::new(),
                    None,
                )
            } else {
                match r.bytes().await {
                    Ok(body) => {
                        latency_ms = started.elapsed().as_secs_f64() * 1000.0;
                        match parse_wire_response(&body, record_type) {
                            Ok(parsed) => parsed,
                            Err(e) => (PropagationOutcome::Error(e.to_string()), Vec::new(), None),
                        }
                    }
                    Err(e) => (PropagationOutcome::Error(e.to_string()), Vec::new(), None),
                }
            }
        }
        Err(e) => {
            let label = if e.is_timeout() {
                "Timed out (5s)".to_string()
            } else {
                e.to_string()
            };
            (PropagationOutcome::Error(label), Vec::new(), None)
        }
    };

    let normalized_key = normalize_answer_key(&answers);
    ResolverResult {
        index,
        resolver_name: node.name.into(),
        region: node.region.into(),
        endpoint_hint: node.endpoint_hint.into(),
        outcome,
        latency_ms,
        min_ttl,
        answers,
        normalized_key,
    }
}

/// Formats a copyable plain-text propagation report.
pub fn format_propagation_report(
    query: &str,
    record_type: DnsRecordType,
    results: &[ResolverResult],
    summary: &PropagationSummary,
) -> String {
    let mut lines = Vec::with_capacity(results.len() + 6);
    lines.push(format!(
        "NetScope DNS Propagation Report — {} ({})",
        query.trim(),
        record_type.label()
    ));
    let avg = summary
        .avg_latency_ms
        .map(|v| format!("{v:.0} ms"))
        .unwrap_or_else(|| "—".into());
    lines.push(format!(
        "Summary: {}/{} Match | {} Divergent | {} Missing | {} Error | Avg Latency: {}",
        summary.matched,
        summary.completed,
        summary.divergent,
        summary.missing,
        summary.errors,
        avg
    ));
    if !summary.consensus_values.is_empty() {
        lines.push(format!(
            "Target / Consensus: {}",
            summary.consensus_values.join(", ")
        ));
    }
    lines.push(String::new());
    lines.push(format!(
        "{:<20} {:<20} {:<10} {:>8} {:>7} {}",
        "Resolver", "Region", "Status", "Latency", "TTL", "Answers"
    ));

    let verdict_map: HashMap<usize, ResolverVerdict> = summary.verdicts.iter().copied().collect();
    for res in results {
        let status_lbl = match (
            &res.outcome,
            verdict_map.get(&res.index).copied().unwrap_or(ResolverVerdict::Error),
        ) {
            (PropagationOutcome::Resolved, ResolverVerdict::Match) => "Match",
            (PropagationOutcome::Resolved, _) => "Divergent",
            (PropagationOutcome::NoData, _) => "No Data",
            (PropagationOutcome::NxDomain, _) => "NXDOMAIN",
            (PropagationOutcome::Error(_), _) => "Error",
        };
        let ttl_lbl = res
            .min_ttl
            .map(|t| format!("{t}s"))
            .unwrap_or_else(|| "—".into());
        let ans_lbl = match &res.outcome {
            PropagationOutcome::Resolved => res.answers.join(", "),
            PropagationOutcome::NoData => "(no records)".into(),
            PropagationOutcome::NxDomain => "(NXDOMAIN)".into(),
            PropagationOutcome::Error(e) => e.clone(),
        };
        lines.push(format!(
            "{:<20} {:<20} {:<10} {:>6.0}ms {:>7} {}",
            res.resolver_name, res.region, status_lbl, res.latency_ms, ttl_lbl, ans_lbl
        ));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{RData, Record};

    fn make_result(
        index: usize,
        name: &str,
        outcome: PropagationOutcome,
        answers: Vec<&str>,
    ) -> ResolverResult {
        let answers: Vec<String> = answers.into_iter().map(String::from).collect();
        let normalized_key = normalize_answer_key(&answers);
        ResolverResult {
            index,
            resolver_name: name.into(),
            region: "Global".into(),
            endpoint_hint: "1.1.1.1".into(),
            outcome,
            latency_ms: 25.0,
            min_ttl: Some(300),
            answers,
            normalized_key,
        }
    }

    #[test]
    fn wire_query_and_response_roundtrip() {
        let query_bytes = build_wire_query("example.com", DnsRecordType::A)
            .expect("query encoding should succeed");
        let req = Message::from_vec(&query_bytes).expect("query should decode");
        assert_eq!(req.metadata.id, 0);
        assert!(req.metadata.recursion_desired);
        assert_eq!(req.queries[0].name.to_string(), "example.com.");

        let mut resp = Message::response(0, OpCode::Query);
        let qname = Name::from_utf8("example.com.").unwrap();
        resp.add_query(req.queries[0].clone());
        resp.add_answer(Record::from_rdata(
            qname.clone(),
            300,
            RData::A(A::new(93, 184, 216, 34)),
        ));
        resp.add_answer(Record::from_rdata(
            qname,
            120,
            RData::A(A::new(93, 184, 216, 33)),
        ));

        let resp_bytes = resp.to_vec().expect("response should encode");
        let (outcome, answers, min_ttl) =
            parse_wire_response(&resp_bytes, DnsRecordType::A).expect("parse should succeed");

        assert_eq!(outcome, PropagationOutcome::Resolved);
        assert_eq!(min_ttl, Some(120));
        assert_eq!(answers, vec!["93.184.216.33", "93.184.216.34"]);
    }

    #[test]
    fn wire_query_ptr_converts_ipv4_to_in_addr_arpa() {
        let bytes = build_wire_query("1.1.1.1", DnsRecordType::PTR)
            .expect("PTR wire query should build");
        let msg = Message::from_vec(&bytes).expect("query should decode");
        assert_eq!(msg.queries[0].name.to_string(), "1.1.1.1.in-addr.arpa.");
    }

    #[test]
    fn consensus_ignores_answer_ordering_and_flags_divergent_resolver() {
        let results = vec![
            make_result(0, "System", PropagationOutcome::Resolved, vec!["1.1.1.1", "1.0.0.1"]),
            make_result(1, "Cloudflare", PropagationOutcome::Resolved, vec!["1.0.0.1", "1.1.1.1"]),
            make_result(2, "Google", PropagationOutcome::Resolved, vec!["8.8.8.8"]),
            make_result(3, "Quad9", PropagationOutcome::NxDomain, vec![]),
            make_result(4, "OpenDNS", PropagationOutcome::Error("Timed out".into()), vec![]),
        ];

        let summary = evaluate_propagation(&results, "");
        assert_eq!(summary.total, 5);
        assert_eq!(summary.completed, 5);
        assert_eq!(summary.matched, 2);
        assert_eq!(summary.divergent, 1);
        assert_eq!(summary.missing, 1);
        assert_eq!(summary.errors, 1);
        assert_eq!(summary.verdicts[0], (0, ResolverVerdict::Match));
        assert_eq!(summary.verdicts[1], (1, ResolverVerdict::Match));
        assert_eq!(summary.verdicts[2], (2, ResolverVerdict::Divergent));
        assert_eq!(summary.verdicts[3], (3, ResolverVerdict::Missing));
        assert_eq!(summary.verdicts[4], (4, ResolverVerdict::Error));
    }

    #[test]
    fn expected_value_override_grades_against_target() {
        let results = vec![
            make_result(0, "System", PropagationOutcome::Resolved, vec!["198.51.100.1"]),
            make_result(1, "Cloudflare", PropagationOutcome::Resolved, vec!["203.0.113.50"]),
            make_result(2, "Google", PropagationOutcome::Resolved, vec!["203.0.113.50"]),
            make_result(3, "Quad9", PropagationOutcome::Resolved, vec!["198.51.100.1"]),
        ];

        let summary = evaluate_propagation(&results, "203.0.113.50");
        assert_eq!(summary.matched, 2);
        assert_eq!(summary.divergent, 2);
        assert_eq!(summary.verdicts[0], (0, ResolverVerdict::Divergent));
        assert_eq!(summary.verdicts[1], (1, ResolverVerdict::Match));
        assert_eq!(summary.verdicts[2], (2, ResolverVerdict::Match));
        assert_eq!(summary.verdicts[3], (3, ResolverVerdict::Divergent));
    }

    #[tokio::test]
    async fn live_dns_propagation_cloudflare_a() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let cancel = CancelToken::new();
        run_propagation("cloudflare.com".into(), DnsRecordType::A, tx, cancel).await;

        let mut results = Vec::new();
        while let Some(ev) = rx.recv().await {
            if let PropagationEvent::ResolverDone(res) = ev {
                results.push(res);
            }
        }
        assert_eq!(results.len(), GLOBAL_RESOLVERS.len());
        let resolved_count = results
            .iter()
            .filter(|r| r.outcome == PropagationOutcome::Resolved && !r.answers.is_empty())
            .count();
        assert!(
            resolved_count >= 10,
            "expected >= 10/14 resolvers to resolve cloudflare.com A, got {resolved_count}"
        );
    }
}
