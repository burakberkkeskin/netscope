use crate::CancelToken;
use crate::geoip::{GeoLocation, lookup_ip};
use crate::icmp::{ProbeOutcome, probe_once, resolve_host, reverse_dns_cached};
use crate::internet_check::VerdictSeverity;
use crate::stats::{LatencyStats, compute_latency_stats};
use chrono::{DateTime, Utc};
use hickory_resolver::Resolver;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HopSegment {
    LocalLan,
    Cgnat,
    IspAccess,
    Transit,
    Destination,
    Unresponsive,
}

impl HopSegment {
    pub fn label(self) -> &'static str {
        match self {
            Self::LocalLan => "LAN",
            Self::Cgnat => "CGNAT",
            Self::IspAccess => "ISP",
            Self::Transit => "Transit",
            Self::Destination => "Target",
            Self::Unresponsive => "Silent",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum HopAnomaly {
    Healthy,
    IcmpRateLimited,
    LatencyJump { delta_ms: f64 },
    PacketLossOrigin { loss_pct: f64 },
    HighJitter { jitter_ms: f64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TroubleshootHop {
    pub hop: u8,
    pub ip: Option<IpAddr>,
    pub hostname: Option<String>,
    pub geo: Option<GeoLocation>,
    pub segment: HopSegment,
    pub stats: LatencyStats,
    pub delta_ms: Option<f64>,
    pub anomaly: HopAnomaly,
    pub note: String,
    pub reached_target: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathTroubleshootReport {
    pub target_host: String,
    pub target_ip: IpAddr,
    pub hops: Vec<TroubleshootHop>,
    pub severity: VerdictSeverity,
    pub bottleneck_summary: String,
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub enum PathTroubleshootEvent {
    Progress(Box<PathTroubleshootReport>),
    Completed(Box<PathTroubleshootReport>),
    Error(String),
}

fn classify_segment(
    hop_num: u8,
    ip: Option<IpAddr>,
    geo: Option<&GeoLocation>,
    first_public_asn: Option<u64>,
    reached_target: bool,
) -> HopSegment {
    let Some(addr) = ip else {
        return HopSegment::Unresponsive;
    };
    if reached_target {
        return HopSegment::Destination;
    }
    if let Some(g) = geo
        && g.is_private
    {
        if g.label.contains("CGNAT") {
            return HopSegment::Cgnat;
        }
        return HopSegment::LocalLan;
    }
    if hop_num == 1 && matches!(addr, IpAddr::V4(v4) if v4.is_private()) {
        return HopSegment::LocalLan;
    }
    if let (Some(g), Some(isp_asn)) = (geo, first_public_asn)
        && g.asn == Some(isp_asn)
    {
        return HopSegment::IspAccess;
    }
    if first_public_asn.is_none() {
        return HopSegment::IspAccess;
    }
    HopSegment::Transit
}

/// Evaluates all hops together to isolate real latency/loss origin vs harmless ICMP rate-limiting.
pub fn analyze_path_hops(hops: &mut [TroubleshootHop]) -> (VerdictSeverity, String) {
    // Identify lowest downstream median RTT & destination loss to separate control-plane ICMP drops
    let last_responsive = hops
        .iter()
        .rfind(|h| h.ip.is_some() && h.stats.received > 0);
    let dest_loss = last_responsive.map_or(100.0, |h| h.stats.loss_pct);

    let mut min_later_median = vec![f64::INFINITY; hops.len()];
    let mut min_later_loss = vec![100.0_f64; hops.len()];
    let mut running_min_med = f64::INFINITY;
    let mut running_min_loss = 100.0_f64;

    for i in (0..hops.len()).rev() {
        min_later_median[i] = running_min_med;
        min_later_loss[i] = running_min_loss;
        if hops[i].stats.received > 0 {
            if let Some(med) = hops[i].stats.median_ms {
                running_min_med = running_min_med.min(med);
            }
            running_min_loss = running_min_loss.min(hops[i].stats.loss_pct);
        }
    }

    let mut baseline_ms: Option<f64> = None;
    let mut worst_jump: Option<(u8, HopSegment, String, f64)> = None;
    let mut loss_origin: Option<(u8, HopSegment, String, f64)> = None;
    let mut rate_limited_count = 0usize;

    let total_hops = hops.len();
    for i in 0..total_hops {
        let h = &mut hops[i];
        h.delta_ms = None;
        h.anomaly = HopAnomaly::Healthy;
        h.note.clear();

        if h.ip.is_none() {
            if i + 1 < total_hops && min_later_loss[i] < 100.0 {
                h.anomaly = HopAnomaly::IcmpRateLimited;
                h.note = "Silent hop (ICMP disabled; traffic forwarded cleanly)".into();
                rate_limited_count += 1;
            } else {
                h.note = "No ICMP replies received".into();
            }
            continue;
        }

        let downstream_healthy = i + 1 < total_hops && min_later_loss[i] < 5.0;

        // Check packet loss
        if h.stats.loss_pct >= 5.0 {
            if downstream_healthy && dest_loss < 5.0 {
                h.anomaly = HopAnomaly::IcmpRateLimited;
                h.note = format!(
                    "Control-plane ICMP rate-limit ({:.0}% hop drop, downstream healthy)",
                    h.stats.loss_pct
                );
                rate_limited_count += 1;
            } else {
                h.anomaly = HopAnomaly::PacketLossOrigin {
                    loss_pct: h.stats.loss_pct,
                };
                h.note = format!("Packet loss begins here ({:.0}%)", h.stats.loss_pct);
                if loss_origin.is_none() {
                    let who = h
                        .ip
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "unknown".into());
                    loss_origin = Some((h.hop, h.segment, who, h.stats.loss_pct));
                }
            }
        }

        // Check RTT spike / jump
        if let Some(med) = h.stats.median_ms {
            let later_med = min_later_median[i];
            if i + 1 < total_hops && later_med.is_finite() && med > later_med + 10.0 {
                // Router CPU slow on ICMP reply, but actual transit path past it is faster
                if matches!(h.anomaly, HopAnomaly::Healthy) {
                    h.anomaly = HopAnomaly::IcmpRateLimited;
                    h.note = format!(
                        "High ICMP reply latency ({med:.1} ms), downstream is faster ({later_med:.1} ms)"
                    );
                    rate_limited_count += 1;
                }
            } else {
                let prev = baseline_ms.unwrap_or(0.0);
                let delta = (med - prev).max(0.0);
                h.delta_ms = Some(delta);

                if delta >= 15.0 {
                    if matches!(h.anomaly, HopAnomaly::Healthy) {
                        h.anomaly = HopAnomaly::LatencyJump { delta_ms: delta };
                        h.note = format!("+{delta:.1} ms step ({} segment)", h.segment.label());
                    }
                    let replace = worst_jump.as_ref().is_none_or(|w| delta > w.3);
                    if replace {
                        let who = h
                            .ip
                            .map(|a| a.to_string())
                            .unwrap_or_else(|| "unknown".into());
                        worst_jump = Some((h.hop, h.segment, who, delta));
                    }
                } else if h.stats.jitter_ms.unwrap_or(0.0) >= 20.0
                    && matches!(h.anomaly, HopAnomaly::Healthy)
                {
                    let j = h.stats.jitter_ms.unwrap_or(0.0);
                    h.anomaly = HopAnomaly::HighJitter { jitter_ms: j };
                    h.note = format!("Elevated jitter ({j:.1} ms)");
                } else if matches!(h.anomaly, HopAnomaly::Healthy) {
                    h.note = "Normal".into();
                }

                baseline_ms = Some(baseline_ms.map_or(med, |b| b.max(med)));
            }
        }
    }

    if let Some((hop, seg, who, pct)) = loss_origin {
        return (
            VerdictSeverity::Error,
            format!(
                "Sustained packet loss ({pct:.0}%) starts at Hop #{hop} ({} • {who}).",
                seg.label()
            ),
        );
    }

    if let Some((hop, seg, who, delta)) = worst_jump {
        let extra = if rate_limited_count > 0 {
            format!(" ({rate_limited_count} intermediate hop(s) showed harmless ICMP rate-limiting.)")
        } else {
            String::new()
        };
        let sev = if delta >= 45.0 {
            VerdictSeverity::Warning
        } else {
            VerdictSeverity::Ok
        };
        return (
            sev,
            format!(
                "Primary latency step (+{delta:.1} ms) occurs at Hop #{hop} ({} • {who}).{extra}",
                seg.label()
            ),
        );
    }

    let final_med = hops
        .last()
        .and_then(|h| h.stats.median_ms)
        .map(|m| format!("{m:.1} ms"))
        .unwrap_or_else(|| "—".into());
    let extra = if rate_limited_count > 0 {
        format!(" Note: {rate_limited_count} hop(s) rate-limited direct ICMP while forwarding cleanly.")
    } else {
        String::new()
    };
    (
        VerdictSeverity::Ok,
        format!("Clean path to target (end-to-end median {final_med}, 0% sustained loss).{extra}"),
    )
}

pub async fn run_path_troubleshoot(
    target_host: String,
    max_hops: u8,
    probes_per_hop: usize,
    tx: mpsc::UnboundedSender<PathTroubleshootEvent>,
    cancel: CancelToken,
) {
    let target_ip = match resolve_host(&target_host).await {
        Ok(ip) => ip,
        Err(e) => {
            let _ = tx.send(PathTroubleshootEvent::Error(e.to_string()));
            return;
        }
    };

    let resolver = Resolver::builder_tokio().ok().and_then(|b| b.build().ok());
    let mut ptr_cache: HashMap<IpAddr, Option<String>> = HashMap::new();
    let probes = probes_per_hop.clamp(3, 10);

    let mut report = PathTroubleshootReport {
        target_host: target_host.clone(),
        target_ip,
        hops: Vec::new(),
        severity: VerdictSeverity::Ok,
        bottleneck_summary: "Discovering path and measuring per-hop latency/loss...".into(),
        completed_at: Utc::now(),
    };
    let _ = tx.send(PathTroubleshootEvent::Progress(Box::new(report.clone())));

    let mut first_public_asn: Option<u64> = None;

    for ttl in 1..=max_hops {
        if cancel.is_cancelled() {
            break;
        }

        let mut set = tokio::task::JoinSet::new();
        for p in 0..probes {
            let seq = (u16::from(ttl) << 4) | (p as u16);
            set.spawn(async move {
                (
                    p,
                    probe_once(target_ip, ttl, seq, Duration::from_millis(1200)).await,
                )
            });
        }

        let mut samples = vec![None; probes];
        let mut responder: Option<IpAddr> = None;
        let mut reached = false;

        while let Some(res) = set.join_next().await {
            if let Ok((idx, outcome)) = res {
                match outcome {
                    ProbeOutcome::EchoReply { from, rtt_ms, .. } => {
                        if responder.is_none() {
                            responder = Some(from);
                        }
                        reached = true;
                        if idx < samples.len() {
                            samples[idx] = Some(rtt_ms);
                        }
                    }
                    ProbeOutcome::TimeExceeded { from, rtt_ms }
                    | ProbeOutcome::Unreachable { from, rtt_ms, .. } => {
                        if responder.is_none() {
                            responder = Some(from);
                        }
                        if idx < samples.len() {
                            samples[idx] = Some(rtt_ms);
                        }
                    }
                    _ => {}
                }
            }
        }

        if cancel.is_cancelled() {
            break;
        }

        let hostname = match (responder, &resolver) {
            (Some(ip), Some(res)) => reverse_dns_cached(res, ip, &mut ptr_cache).await,
            _ => None,
        };
        let geo = match responder {
            Some(ip) => {
                let g = lookup_ip(ip).await;
                if !g.is_private && first_public_asn.is_none() {
                    first_public_asn = g.asn;
                }
                Some(g)
            }
            None => None,
        };

        let segment = classify_segment(ttl, responder, geo.as_ref(), first_public_asn, reached);
        let stats = compute_latency_stats(&samples);

        report.hops.push(TroubleshootHop {
            hop: ttl,
            ip: responder,
            hostname,
            geo,
            segment,
            stats,
            delta_ms: None,
            anomaly: HopAnomaly::Healthy,
            note: String::new(),
            reached_target: reached,
        });

        let (sev, summary) = analyze_path_hops(&mut report.hops);
        report.severity = sev;
        report.bottleneck_summary = summary;
        report.completed_at = Utc::now();

        let _ = tx.send(PathTroubleshootEvent::Progress(Box::new(report.clone())));

        if reached {
            break;
        }
    }

    let (sev, summary) = analyze_path_hops(&mut report.hops);
    report.severity = sev;
    report.bottleneck_summary = summary;
    report.completed_at = Utc::now();

    let _ = tx.send(PathTroubleshootEvent::Completed(Box::new(report)));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_hop(hop: u8, ip: Option<&str>, seg: HopSegment, samples: &[Option<f64>]) -> TroubleshootHop {
        TroubleshootHop {
            hop,
            ip: ip.map(|s| s.parse().unwrap()),
            hostname: None,
            geo: None,
            segment: seg,
            stats: compute_latency_stats(samples),
            delta_ms: None,
            anomaly: HopAnomaly::Healthy,
            note: String::new(),
            reached_target: seg == HopSegment::Destination,
        }
    }

    #[test]
    fn ignores_mid_hop_icmp_rate_limiting_when_destination_is_healthy() {
        let mut hops = vec![
            mk_hop(1, Some("192.168.1.1"), HopSegment::LocalLan, &[Some(2.0); 5]),
            // Hop 2 drops 60% of direct ICMP probes and responds slowly at 75ms,
            // while Hop 3 responds cleanly at 12ms with 0% loss!
            mk_hop(
                2,
                Some("100.64.0.1"),
                HopSegment::Cgnat,
                &[Some(75.0), None, None, Some(80.0), None],
            ),
            mk_hop(3, Some("1.1.1.1"), HopSegment::Destination, &[Some(12.0); 5]),
        ];

        let (sev, summary) = analyze_path_hops(&mut hops);
        assert_eq!(sev, VerdictSeverity::Ok);
        assert_eq!(hops[1].anomaly, HopAnomaly::IcmpRateLimited);
        assert!(summary.contains("Clean path"));
    }

    #[test]
    fn identifies_real_isp_latency_jump() {
        let mut hops = vec![
            mk_hop(1, Some("192.168.1.1"), HopSegment::LocalLan, &[Some(2.0); 5]),
            mk_hop(2, Some("100.64.0.1"), HopSegment::Cgnat, &[Some(6.0); 5]),
            mk_hop(3, Some("195.175.1.1"), HopSegment::IspAccess, &[Some(38.0); 5]),
            mk_hop(4, Some("1.1.1.1"), HopSegment::Destination, &[Some(40.0); 5]),
        ];

        let (_sev, summary) = analyze_path_hops(&mut hops);
        assert!(matches!(
            hops[2].anomaly,
            HopAnomaly::LatencyJump { delta_ms } if delta_ms > 30.0
        ));
        assert!(summary.contains("Hop #3"));
    }

    #[test]
    fn identifies_sustained_packet_loss_origin() {
        let mut hops = vec![
            mk_hop(1, Some("192.168.1.1"), HopSegment::LocalLan, &[Some(2.0); 5]),
            mk_hop(
                2,
                Some("100.64.0.1"),
                HopSegment::Cgnat,
                &[Some(8.0), None, None, Some(9.0), Some(8.5)],
            ),
            mk_hop(
                3,
                Some("1.1.1.1"),
                HopSegment::Destination,
                &[Some(28.0), None, None, Some(29.0), Some(30.0)],
            ),
        ];

        let (sev, summary) = analyze_path_hops(&mut hops);
        assert_eq!(sev, VerdictSeverity::Error);
        assert!(matches!(
            hops[1].anomaly,
            HopAnomaly::PacketLossOrigin { .. }
        ));
        assert!(summary.contains("Hop #2"));
    }
}
