use crate::CancelToken;
use crate::icmp::probe_once;
use crate::net_info::{
    LocalNetworkInfo, PublicNetworkStatus, fetch_public_network_status, get_local_network_info,
};
use crate::stats::{LatencyStats, compute_latency_stats};
use chrono::{DateTime, Utc};
use hickory_resolver::Resolver;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckStage {
    LocalLink,
    Router,
    Internet,
    Dns,
    Web,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StageHealth {
    Pending,
    Running,
    Ok,
    Warning,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeStageResult {
    pub target_label: String,
    pub health: StageHealth,
    pub samples_ms: Vec<Option<f64>>,
    pub stats: LatencyStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsStageResult {
    pub resolver_label: String,
    pub health: StageHealth,
    pub resolved_count: usize,
    pub total_count: usize,
    pub median_ms: Option<f64>,
    pub sample_ms: Vec<Option<f64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebStageResult {
    pub url: String,
    pub health: StageHealth,
    pub ttfb_ms: Option<f64>,
    pub status_code: Option<u16>,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictSeverity {
    Ok,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosisVerdict {
    pub severity: VerdictSeverity,
    pub headline: String,
    pub explanation: String,
    pub failing_stage: Option<CheckStage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternetCheckReport {
    pub checked_at: DateTime<Utc>,
    pub local: LocalNetworkInfo,
    pub public: Option<PublicNetworkStatus>,
    pub local_health: StageHealth,
    pub router: Option<ProbeStageResult>,
    pub internet: Option<ProbeStageResult>,
    pub dns: Option<DnsStageResult>,
    pub web: Option<WebStageResult>,
    pub verdict: DiagnosisVerdict,
}

#[derive(Debug, Clone)]
pub enum InternetCheckEvent {
    Progress(Box<InternetCheckReport>),
    Completed(Box<InternetCheckReport>),
}

/// Evaluates all 5 stages and produces a single clear diagnosis.
pub fn diagnose(
    local: &LocalNetworkInfo,
    router: Option<&ProbeStageResult>,
    internet: Option<&ProbeStageResult>,
    dns: Option<&DnsStageResult>,
    web: Option<&WebStageResult>,
) -> DiagnosisVerdict {
    if local.local_ipv4.is_none() && local.local_ipv6.is_none() {
        return DiagnosisVerdict {
            severity: VerdictSeverity::Error,
            headline: "No active local network connection".into(),
            explanation: "This machine has no active IPv4 or IPv6 address on its default interface. Check Wi-Fi, Ethernet cable, or DHCP lease.".into(),
            failing_stage: Some(CheckStage::LocalLink),
        };
    }

    let internet_alive = internet.is_some_and(|n| n.stats.received > 0);
    let mut router_note: Option<String> = None;

    if let Some(r) = router {
        if r.stats.received == 0 && !internet_alive {
            return DiagnosisVerdict {
                severity: VerdictSeverity::Error,
                headline: "Your router is unreachable".into(),
                explanation: format!(
                    "Packets to your local gateway ({}) timed out completely and upstream internet did not respond. Check Wi-Fi signal, switch port, or router power/ARP.",
                    r.target_label
                ),
                failing_stage: Some(CheckStage::Router),
            };
        }
        if r.stats.received == 0 && internet_alive {
            router_note = Some(format!(
                "Note: gateway ({}) dropped direct ICMP echo (common when router firewall rate-limits or blocks ping), while upstream internet passed.",
                r.target_label
            ));
        } else if r.stats.loss_pct >= 20.0 {
            if !internet_alive {
                return DiagnosisVerdict {
                    severity: VerdictSeverity::Warning,
                    headline: "Unstable connection to your router".into(),
                    explanation: format!(
                        "{:.0}% packet loss between this device and gateway ({}). If on Wi-Fi, move closer to the AP or test via Ethernet.",
                        r.stats.loss_pct, r.target_label
                    ),
                    failing_stage: Some(CheckStage::Router),
                };
            }
            router_note = Some(format!(
                "Note: gateway ({}) showed {:.0}% ICMP drop (likely control-plane rate limiting).",
                r.target_label, r.stats.loss_pct
            ));
        }
    }

    if let Some(net) = internet {
        if net.stats.received == 0 {
            return DiagnosisVerdict {
                severity: VerdictSeverity::Error,
                headline: "Internet unreachable past your router".into(),
                explanation: "Your local gateway responds normally, but ICMP packets to 1.1.1.1 and 8.8.8.8 are dropped. Check WAN link, modem, PPPoE/DHCP lease, or ISP outage.".into(),
                failing_stage: Some(CheckStage::Internet),
            };
        }
        if net.stats.loss_pct >= 10.0 || net.stats.jitter_ms.unwrap_or(0.0) >= 80.0 {
            return DiagnosisVerdict {
                severity: VerdictSeverity::Warning,
                headline: "Most likely your provider or WAN link".into(),
                explanation: format!(
                    "Your router responds fine, but packets past it show {:.0}% loss and {:.1} ms jitter. Check modem line stats or connect directly over Ethernet to rule out local congestion.",
                    net.stats.loss_pct,
                    net.stats.jitter_ms.unwrap_or(0.0)
                ),
                failing_stage: Some(CheckStage::Internet),
            };
        }
    }

    if let Some(d) = dns {
        if d.resolved_count == 0 {
            return DiagnosisVerdict {
                severity: VerdictSeverity::Error,
                headline: "DNS resolution is failing".into(),
                explanation: "IP connectivity to the internet works, but domain lookups failed (0/3). Check local DNS resolver (AdGuard/Unbound/router DNS) or VPN split-DNS rules.".into(),
                failing_stage: Some(CheckStage::Dns),
            };
        }
        if d.resolved_count < d.total_count {
            return DiagnosisVerdict {
                severity: VerdictSeverity::Warning,
                headline: "Partial DNS resolution failures".into(),
                explanation: format!(
                    "Only {}/{} test domains resolved. One of your upstream DNS resolvers may be timing out.",
                    d.resolved_count, d.total_count
                ),
                failing_stage: Some(CheckStage::Dns),
            };
        }
    }

    if let Some(w) = web
        && w.health == StageHealth::Failed
    {
        return DiagnosisVerdict {
            severity: VerdictSeverity::Error,
            headline: "HTTPS / Web access is blocked or failing".into(),
            explanation: format!(
                "Ping and DNS succeeded, but HTTPS probe to {} failed ({}). Check corporate proxy, firewall, captive portal, or TLS trust.",
                w.url, w.detail
            ),
            failing_stage: Some(CheckStage::Web),
        };
    }

    let router_ms = router
        .and_then(|r| r.stats.median_ms)
        .map(|v| format!("{v:.1} ms"))
        .unwrap_or_else(|| "—".into());
    let net_ms = internet
        .and_then(|i| i.stats.median_ms)
        .map(|v| format!("{v:.1} ms"))
        .unwrap_or_else(|| "—".into());

    if let Some(note) = router_note {
        return DiagnosisVerdict {
            severity: VerdictSeverity::Warning,
            headline: "Connected (gateway ignores ICMP)".into(),
            explanation: format!(
                "Internet ({net_ms}), DNS, and HTTPS web connectivity are healthy. {note}"
            ),
            failing_stage: None,
        };
    }

    DiagnosisVerdict {
        severity: VerdictSeverity::Ok,
        headline: "Everything looks fine".into(),
        explanation: format!(
            "Local link, router ({router_ms}), internet ({net_ms}), DNS, and HTTPS web connectivity are all healthy."
        ),
        failing_stage: None,
    }
}

pub async fn run_internet_check(
    tx: mpsc::UnboundedSender<InternetCheckEvent>,
    cancel: CancelToken,
) -> InternetCheckReport {
    crate::ensure_crypto_provider();
    let local = get_local_network_info().unwrap_or(LocalNetworkInfo {
        interface_name: "unknown".into(),
        friendly_name: None,
        link_type: crate::net_info::LinkType::Unknown,
        local_ipv4: None,
        local_ipv6: None,
        gateway_ip: None,
        mac_address: None,
        dns_servers: Vec::new(),
        vpn_active: false,
        vpn_interfaces: Vec::new(),
    });

    let local_health = if local.local_ipv4.is_some() || local.local_ipv6.is_some() {
        StageHealth::Ok
    } else {
        StageHealth::Failed
    };

    let mut report = InternetCheckReport {
        checked_at: Utc::now(),
        local: local.clone(),
        public: None,
        local_health,
        router: None,
        internet: None,
        dns: None,
        web: None,
        verdict: DiagnosisVerdict {
            severity: VerdictSeverity::Ok,
            headline: "Running diagnostics...".into(),
            explanation: "Checking local gateway, upstream internet, DNS, and HTTPS reachability.".into(),
            failing_stage: None,
        },
    };
    let _ = tx.send(InternetCheckEvent::Progress(Box::new(report.clone())));

    if local_health == StageHealth::Failed || cancel.is_cancelled() {
        report.verdict = diagnose(&report.local, None, None, None, None);
        let _ = tx.send(InternetCheckEvent::Completed(Box::new(report.clone())));
        return report;
    }

    // Stage 2: Router check (10 rapid pings)
    if let Some(gw_ip) = local.gateway_ip {
        let mut r_res = ProbeStageResult {
            target_label: gw_ip.to_string(),
            health: StageHealth::Running,
            samples_ms: Vec::with_capacity(10),
            stats: LatencyStats::default(),
        };
        report.router = Some(r_res.clone());
        let _ = tx.send(InternetCheckEvent::Progress(Box::new(report.clone())));

        for seq in 1..=10u16 {
            if cancel.is_cancelled() {
                break;
            }
            let outcome = probe_once(gw_ip, 64, seq, Duration::from_millis(800)).await;
            r_res.samples_ms.push(outcome.rtt_ms());
            r_res.stats = compute_latency_stats(&r_res.samples_ms);
            report.router = Some(r_res.clone());
            let _ = tx.send(InternetCheckEvent::Progress(Box::new(report.clone())));
            tokio::time::sleep(Duration::from_millis(75)).await;
        }
        r_res.health = if r_res.stats.received == 0 {
            StageHealth::Failed
        } else if r_res.stats.loss_pct >= 20.0 {
            StageHealth::Warning
        } else {
            StageHealth::Ok
        };
        report.router = Some(r_res);
    }

    if cancel.is_cancelled() {
        report.verdict = diagnose(
            &report.local,
            report.router.as_ref(),
            None,
            None,
            None,
        );
        let _ = tx.send(InternetCheckEvent::Completed(Box::new(report.clone())));
        return report;
    }

    // Stage 3: Internet check (10 rapid pings to 1.1.1.1, fallback check 8.8.8.8)
    let mut inet_target: IpAddr = "1.1.1.1".parse().unwrap();
    let mut i_res = ProbeStageResult {
        target_label: inet_target.to_string(),
        health: StageHealth::Running,
        samples_ms: Vec::with_capacity(10),
        stats: LatencyStats::default(),
    };
    report.internet = Some(i_res.clone());
    let _ = tx.send(InternetCheckEvent::Progress(Box::new(report.clone())));

    for seq in 1..=10u16 {
        if cancel.is_cancelled() {
            break;
        }
        let mut outcome = probe_once(inet_target, 64, seq, Duration::from_millis(1000)).await;
        if seq == 1 && outcome.rtt_ms().is_none() {
            // Check secondary public target in case 1.1.1.1 ICMP is filtered upstream
            let fallback_ip: IpAddr = "8.8.8.8".parse().unwrap();
            let alt = probe_once(fallback_ip, 64, seq, Duration::from_millis(1000)).await;
            if alt.rtt_ms().is_some() {
                inet_target = fallback_ip;
                i_res.target_label = inet_target.to_string();
                outcome = alt;
            }
        }
        i_res.samples_ms.push(outcome.rtt_ms());
        i_res.stats = compute_latency_stats(&i_res.samples_ms);
        report.internet = Some(i_res.clone());
        let _ = tx.send(InternetCheckEvent::Progress(Box::new(report.clone())));
        tokio::time::sleep(Duration::from_millis(75)).await;
    }
    i_res.health = if i_res.stats.received == 0 {
        StageHealth::Failed
    } else if i_res.stats.loss_pct >= 10.0 || i_res.stats.jitter_ms.unwrap_or(0.0) >= 80.0 {
        StageHealth::Warning
    } else {
        StageHealth::Ok
    };
    report.internet = Some(i_res);

    if cancel.is_cancelled() {
        report.verdict = diagnose(
            &report.local,
            report.router.as_ref(),
            report.internet.as_ref(),
            None,
            None,
        );
        let _ = tx.send(InternetCheckEvent::Completed(Box::new(report.clone())));
        return report;
    }

    // Stage 4: DNS check (3 well-known domains via system resolver)
    let dns_res = run_dns_stage().await;
    report.dns = Some(dns_res);
    let _ = tx.send(InternetCheckEvent::Progress(Box::new(report.clone())));

    if cancel.is_cancelled() {
        report.verdict = diagnose(
            &report.local,
            report.router.as_ref(),
            report.internet.as_ref(),
            report.dns.as_ref(),
            None,
        );
        let _ = tx.send(InternetCheckEvent::Completed(Box::new(report.clone())));
        return report;
    }

    // Stage 5: Web HTTPS check + Public IP metadata
    let (web_res, pub_status) = tokio::join!(run_web_stage(), fetch_public_network_status());
    report.web = Some(web_res);
    report.public = Some(pub_status);

    report.verdict = diagnose(
        &report.local,
        report.router.as_ref(),
        report.internet.as_ref(),
        report.dns.as_ref(),
        report.web.as_ref(),
    );
    report.checked_at = Utc::now();

    let _ = tx.send(InternetCheckEvent::Completed(Box::new(report.clone())));
    report
}

async fn run_dns_stage() -> DnsStageResult {
    let domains = ["cloudflare.com.", "google.com.", "apple.com."];
    let Ok(builder) = Resolver::builder_tokio() else {
        return DnsStageResult {
            resolver_label: "System resolver".into(),
            health: StageHealth::Failed,
            resolved_count: 0,
            total_count: domains.len(),
            median_ms: None,
            sample_ms: vec![None; domains.len()],
        };
    };
    let Ok(resolver) = builder.build() else {
        return DnsStageResult {
            resolver_label: "System resolver".into(),
            health: StageHealth::Failed,
            resolved_count: 0,
            total_count: domains.len(),
            median_ms: None,
            sample_ms: vec![None; domains.len()],
        };
    };

    let mut samples = Vec::with_capacity(domains.len());
    let mut resolved = 0usize;
    for d in domains {
        let t0 = Instant::now();
        let res = tokio::time::timeout(Duration::from_secs(3), resolver.lookup_ip(d)).await;
        match res {
            Ok(Ok(ips)) if ips.iter().next().is_some() => {
                resolved += 1;
                samples.push(Some(t0.elapsed().as_secs_f64() * 1000.0));
            }
            _ => samples.push(None),
        }
    }

    let stats = compute_latency_stats(&samples);
    let health = if resolved == 0 {
        StageHealth::Failed
    } else if resolved < domains.len() {
        StageHealth::Warning
    } else {
        StageHealth::Ok
    };

    DnsStageResult {
        resolver_label: "System resolver".into(),
        health,
        resolved_count: resolved,
        total_count: domains.len(),
        median_ms: stats.median_ms,
        sample_ms: samples,
    }
}

async fn run_web_stage() -> WebStageResult {
    let target_url = "https://speed.cloudflare.com/__down?bytes=0";
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent("NetScope/0.1")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return WebStageResult {
                url: "speed.cloudflare.com".into(),
                health: StageHealth::Failed,
                ttfb_ms: None,
                status_code: None,
                detail: e.to_string(),
            };
        }
    };

    let t0 = Instant::now();
    match client.get(target_url).send().await {
        Ok(resp) => {
            let ms = t0.elapsed().as_secs_f64() * 1000.0;
            let code = resp.status().as_u16();
            let health = if resp.status().is_success() || resp.status().is_redirection() {
                StageHealth::Ok
            } else {
                StageHealth::Warning
            };
            WebStageResult {
                url: "speed.cloudflare.com".into(),
                health,
                ttfb_ms: Some(ms),
                status_code: Some(code),
                detail: format!("HTTP {code}"),
            }
        }
        Err(e) => WebStageResult {
            url: "speed.cloudflare.com".into(),
            health: StageHealth::Failed,
            ttfb_ms: None,
            status_code: None,
            detail: e.to_string(),
        },
    }
}

/// Formats a complete text summary for clipboard export.
pub fn format_report_text(r: &InternetCheckReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "NetScope Internet Check — {}\n",
        r.checked_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    out.push_str(&format!("Verdict: {}\n{}\n\n", r.verdict.headline, r.verdict.explanation));
    out.push_str(&format!(
        "Interface: {} ({}) | Local IP: {} | Gateway: {}\n",
        r.local.interface_name,
        r.local.link_type.label(),
        r.local
            .local_ipv4
            .map(|i| i.to_string())
            .unwrap_or_else(|| "—".into()),
        r.local
            .gateway_ip
            .map(|i| i.to_string())
            .unwrap_or_else(|| "—".into()),
    ));
    if let Some(ref pub_st) = r.public {
        out.push_str(&format!(
            "Public IP: {} | ISP: {} | VPN: {} | DNS Leak: {}\n",
            pub_st
                .public_ip
                .map(|i| i.to_string())
                .unwrap_or_else(|| "—".into()),
            pub_st.isp_or_org.as_deref().unwrap_or("—"),
            if pub_st.vpn_active { "On" } else { "Off" },
            pub_st.dns_leak_status.label(),
        ));
    }
    if let Some(ref rt) = r.router {
        out.push_str(&format!(
            "Router ({}): median {:.1} ms, jitter {:.1} ms, loss {:.0}%\n",
            rt.target_label,
            rt.stats.median_ms.unwrap_or(0.0),
            rt.stats.jitter_ms.unwrap_or(0.0),
            rt.stats.loss_pct
        ));
    }
    if let Some(ref net) = r.internet {
        out.push_str(&format!(
            "Internet ({}): median {:.1} ms, jitter {:.1} ms, loss {:.0}%\n",
            net.target_label,
            net.stats.median_ms.unwrap_or(0.0),
            net.stats.jitter_ms.unwrap_or(0.0),
            net.stats.loss_pct
        ));
    }
    if let Some(ref d) = r.dns {
        out.push_str(&format!(
            "DNS ({}): {}/{} resolved, median {:.1} ms\n",
            d.resolver_label,
            d.resolved_count,
            d.total_count,
            d.median_ms.unwrap_or(0.0)
        ));
    }
    if let Some(ref w) = r.web {
        out.push_str(&format!(
            "Web ({}): {} ({})\n",
            w.url,
            w.detail,
            w.ttfb_ms
                .map(|ms| format!("{ms:.0} ms"))
                .unwrap_or_else(|| "—".into())
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net_info::LinkType;

    fn dummy_local(has_ip: bool) -> LocalNetworkInfo {
        LocalNetworkInfo {
            interface_name: "en0".into(),
            friendly_name: Some("Wi-Fi".into()),
            link_type: LinkType::WiFi,
            local_ipv4: if has_ip {
                Some("192.168.1.24".parse().unwrap())
            } else {
                None
            },
            local_ipv6: None,
            gateway_ip: Some("192.168.1.1".parse().unwrap()),
            mac_address: None,
            dns_servers: vec!["192.168.1.1".parse().unwrap()],
            vpn_active: false,
            vpn_interfaces: Vec::new(),
        }
    }

    fn probe_stage(label: &str, samples: &[Option<f64>]) -> ProbeStageResult {
        ProbeStageResult {
            target_label: label.into(),
            health: StageHealth::Ok,
            samples_ms: samples.to_vec(),
            stats: compute_latency_stats(samples),
        }
    }

    #[test]
    fn diagnoses_isp_issue_when_router_ok_and_internet_lossy() {
        let local = dummy_local(true);
        let router = probe_stage("192.168.1.1", &[Some(2.0); 10]);
        let internet = probe_stage(
            "1.1.1.1",
            &[
                Some(46.0),
                None,
                Some(200.0),
                Some(45.0),
                None,
                None,
                Some(50.0),
                Some(42.0),
                Some(190.0),
                Some(44.0),
            ],
        );
        let dns = DnsStageResult {
            resolver_label: "System".into(),
            health: StageHealth::Ok,
            resolved_count: 3,
            total_count: 3,
            median_ms: Some(27.0),
            sample_ms: vec![Some(27.0); 3],
        };
        let web = WebStageResult {
            url: "speed.cloudflare.com".into(),
            health: StageHealth::Ok,
            ttfb_ms: Some(120.0),
            status_code: Some(200),
            detail: "HTTP 200".into(),
        };

        let verdict = diagnose(&local, Some(&router), Some(&internet), Some(&dns), Some(&web));
        assert_eq!(verdict.failing_stage, Some(CheckStage::Internet));
        assert_eq!(verdict.severity, VerdictSeverity::Warning);
    }

    #[test]
    fn diagnoses_dns_failure_when_ip_connectivity_works() {
        let local = dummy_local(true);
        let router = probe_stage("192.168.1.1", &[Some(1.5); 10]);
        let internet = probe_stage("1.1.1.1", &[Some(14.0); 10]);
        let dns = DnsStageResult {
            resolver_label: "System".into(),
            health: StageHealth::Failed,
            resolved_count: 0,
            total_count: 3,
            median_ms: None,
            sample_ms: vec![None, None, None],
        };

        let verdict = diagnose(&local, Some(&router), Some(&internet), Some(&dns), None);
        assert_eq!(verdict.failing_stage, Some(CheckStage::Dns));
        assert_eq!(verdict.severity, VerdictSeverity::Error);
    }

    #[test]
    fn diagnoses_healthy_network() {
        let local = dummy_local(true);
        let router = probe_stage("192.168.1.1", &[Some(1.8); 10]);
        let internet = probe_stage("1.1.1.1", &[Some(14.0); 10]);
        let dns = DnsStageResult {
            resolver_label: "System".into(),
            health: StageHealth::Ok,
            resolved_count: 3,
            total_count: 3,
            median_ms: Some(18.0),
            sample_ms: vec![Some(18.0); 3],
        };
        let web = WebStageResult {
            url: "speed.cloudflare.com".into(),
            health: StageHealth::Ok,
            ttfb_ms: Some(60.0),
            status_code: Some(200),
            detail: "HTTP 200".into(),
        };

        let verdict = diagnose(&local, Some(&router), Some(&internet), Some(&dns), Some(&web));
        assert_eq!(verdict.severity, VerdictSeverity::Ok);
        assert!(verdict.failing_stage.is_none());
    }

    #[test]
    fn router_icmp_drop_with_healthy_internet_is_not_unreachable_error() {
        let local = dummy_local(true);
        let router = probe_stage("192.168.1.1", &[None; 10]);
        let internet = probe_stage("1.1.1.1", &[Some(14.0); 10]);
        let dns = DnsStageResult {
            resolver_label: "System".into(),
            health: StageHealth::Ok,
            resolved_count: 3,
            total_count: 3,
            median_ms: Some(18.0),
            sample_ms: vec![Some(18.0); 3],
        };
        let web = WebStageResult {
            url: "speed.cloudflare.com".into(),
            health: StageHealth::Ok,
            ttfb_ms: Some(60.0),
            status_code: Some(200),
            detail: "HTTP 200".into(),
        };

        let verdict = diagnose(&local, Some(&router), Some(&internet), Some(&dns), Some(&web));
        assert_eq!(verdict.severity, VerdictSeverity::Warning);
        assert!(verdict.failing_stage.is_none());
        assert!(verdict.headline.contains("gateway ignores ICMP"));
    }

    #[tokio::test]
    async fn live_internet_check_completes_all_stages() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let cancel = CancelToken::new();
        let report = run_internet_check(tx, cancel).await;
        assert!(!report.local.interface_name.is_empty());
        assert!(report.dns.is_some());
        assert!(report.web.is_some());
        let mut saw_completed = false;
        while let Ok(ev) = rx.try_recv() {
            if matches!(ev, InternetCheckEvent::Completed(_)) {
                saw_completed = true;
            }
        }
        assert!(saw_completed);
    }
}
