use crate::stats::{LatencyStats, compute_latency_stats};
use crate::{CancelToken, NetError};
use chrono::{DateTime, Utc};
use hickory_resolver::Resolver;
use hickory_resolver::TokioResolver;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::{HashMap, VecDeque};
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

static NEXT_PROBE_ID: AtomicU16 = AtomicU16::new(1);

const ICMPV4_ECHO_REPLY: u8 = 0;
const ICMPV4_DEST_UNREACH: u8 = 3;
const ICMPV4_ECHO_REQUEST: u8 = 8;
const ICMPV4_TIME_EXCEEDED: u8 = 11;

const ICMPV6_TIME_EXCEEDED: u8 = 3;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;

const MTR_HISTORY_CAPACITY: usize = 40;

#[derive(Debug, Clone, PartialEq)]
pub enum ProbeOutcome {
    EchoReply {
        from: IpAddr,
        rtt_ms: f64,
        ttl: Option<u8>,
    },
    TimeExceeded {
        from: IpAddr,
        rtt_ms: f64,
    },
    Unreachable {
        from: IpAddr,
        code: u8,
        rtt_ms: f64,
    },
    Timeout,
    Error(String),
}

impl ProbeOutcome {
    pub fn responder_ip(&self) -> Option<IpAddr> {
        match self {
            Self::EchoReply { from, .. }
            | Self::TimeExceeded { from, .. }
            | Self::Unreachable { from, .. } => Some(*from),
            Self::Timeout | Self::Error(_) => None,
        }
    }

    pub fn rtt_ms(&self) -> Option<f64> {
        match self {
            Self::EchoReply { rtt_ms, .. }
            | Self::TimeExceeded { rtt_ms, .. }
            | Self::Unreachable { rtt_ms, .. } => Some(*rtt_ms),
            Self::Timeout | Self::Error(_) => None,
        }
    }
}

/// Computes RFC 1071 Internet Checksum over a byte slice.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (chunks, rem) = data.as_chunks::<2>();
    for chunk in chunks {
        sum += u32::from(u16::from_be_bytes(*chunk));
    }
    if let Some(&b) = rem.first() {
        sum += u32::from(b) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Builds an 8-byte header + payload ICMP echo request packet.
pub fn build_icmp_echo_packet(is_v6: bool, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let icmp_type = if is_v6 {
        ICMPV6_ECHO_REQUEST
    } else {
        ICMPV4_ECHO_REQUEST
    };
    let mut pkt = Vec::with_capacity(8 + payload.len());
    pkt.push(icmp_type);
    pkt.push(0); // code
    pkt.extend_from_slice(&[0, 0]); // checksum placeholder
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(payload);

    if !is_v6 {
        let csum = internet_checksum(&pkt);
        pkt[2..4].copy_from_slice(&csum.to_be_bytes());
    }
    pkt
}

/// Parsed ICMPv4 packet fields relevant for probe demultiplexing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsedIcmpV4 {
    EchoReply {
        id: u16,
        seq: u16,
        reply_ttl: Option<u8>,
    },
    TimeExceeded {
        orig_id: Option<u16>,
        orig_seq: Option<u16>,
        orig_is_icmp_echo: bool,
    },
    DestUnreach {
        code: u8,
        orig_id: Option<u16>,
        orig_seq: Option<u16>,
        orig_is_icmp_echo: bool,
    },
    Other,
}

/// Parses an ICMPv4 response buffer, transparently stripping any leading IPv4 header
/// (macOS `SOCK_DGRAM` returns IPv4 + ICMP; Linux returns raw ICMP) and extracting
/// embedded original `(id, seq)` on error responses for concurrent probe demultiplexing.
pub fn parse_icmpv4_packet(raw: &[u8]) -> Option<ParsedIcmpV4> {
    if raw.is_empty() {
        return None;
    }
    let (icmp, reply_ttl) = if raw.len() >= 20 && (raw[0] >> 4) == 4 {
        let ihl = usize::from(raw[0] & 0x0f) * 4;
        if ihl < 20 || raw.len() < ihl + 8 {
            return None;
        }
        (&raw[ihl..], Some(raw[8]))
    } else {
        if raw.len() < 8 {
            return None;
        }
        (raw, None)
    };

    let icmp_type = icmp[0];
    let code = icmp[1];
    match icmp_type {
        ICMPV4_ECHO_REPLY => {
            let id = u16::from_be_bytes([icmp[4], icmp[5]]);
            let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
            Some(ParsedIcmpV4::EchoReply { id, seq, reply_ttl })
        }
        ICMPV4_TIME_EXCEEDED | ICMPV4_DEST_UNREACH => {
            // ICMP error payload starts at byte 8: original IPv4 header + first 8 bytes of L4/ICMP
            let (orig_id, orig_seq, orig_is_icmp_echo) = if icmp.len() >= 8 + 20 {
                let orig_ip = &icmp[8..];
                if (orig_ip[0] >> 4) == 4 {
                    let orig_ihl = usize::from(orig_ip[0] & 0x0f) * 4;
                    let orig_proto = orig_ip[9];
                    if orig_proto == 1 && orig_ihl >= 20 && orig_ip.len() >= orig_ihl + 8 {
                        let orig_icmp = &orig_ip[orig_ihl..];
                        let is_echo = orig_icmp[0] == ICMPV4_ECHO_REQUEST;
                        let oid = u16::from_be_bytes([orig_icmp[4], orig_icmp[5]]);
                        let oseq = u16::from_be_bytes([orig_icmp[6], orig_icmp[7]]);
                        (Some(oid), Some(oseq), is_echo)
                    } else {
                        (None, None, false)
                    }
                } else {
                    (None, None, false)
                }
            } else {
                (None, None, false)
            };

            if icmp_type == ICMPV4_TIME_EXCEEDED {
                Some(ParsedIcmpV4::TimeExceeded {
                    orig_id,
                    orig_seq,
                    orig_is_icmp_echo,
                })
            } else {
                Some(ParsedIcmpV4::DestUnreach {
                    code,
                    orig_id,
                    orig_seq,
                    orig_is_icmp_echo,
                })
            }
        }
        _ => Some(ParsedIcmpV4::Other),
    }
}

/// Parses an ICMPv6 response buffer, extracting `(id, seq)` or embedded ICMPv6 echo identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsedIcmpV6 {
    EchoReply {
        id: u16,
        seq: u16,
    },
    TimeExceeded {
        orig_id: Option<u16>,
        orig_seq: Option<u16>,
        orig_is_icmp_echo: bool,
    },
    DestUnreach {
        code: u8,
        orig_id: Option<u16>,
        orig_seq: Option<u16>,
        orig_is_icmp_echo: bool,
    },
    Other,
}

pub fn parse_icmpv6_packet(raw: &[u8]) -> Option<ParsedIcmpV6> {
    if raw.len() < 8 {
        return None;
    }
    let icmp_type = raw[0];
    let code = raw[1];
    match icmp_type {
        ICMPV6_ECHO_REPLY => {
            let id = u16::from_be_bytes([raw[4], raw[5]]);
            let seq = u16::from_be_bytes([raw[6], raw[7]]);
            Some(ParsedIcmpV6::EchoReply { id, seq })
        }
        ICMPV6_TIME_EXCEEDED | 1 => {
            let (orig_id, orig_seq, orig_is_icmp_echo) = if raw.len() >= 8 + 40 + 8 {
                let orig_ip6 = &raw[8..];
                if (orig_ip6[0] >> 4) == 6 && orig_ip6[6] == 58 {
                    let orig_icmp6 = &orig_ip6[40..];
                    let is_echo = orig_icmp6[0] == ICMPV6_ECHO_REQUEST;
                    let oid = u16::from_be_bytes([orig_icmp6[4], orig_icmp6[5]]);
                    let oseq = u16::from_be_bytes([orig_icmp6[6], orig_icmp6[7]]);
                    (Some(oid), Some(oseq), is_echo)
                } else {
                    (None, None, false)
                }
            } else {
                (None, None, false)
            };

            if icmp_type == ICMPV6_TIME_EXCEEDED {
                Some(ParsedIcmpV6::TimeExceeded {
                    orig_id,
                    orig_seq,
                    orig_is_icmp_echo,
                })
            } else {
                Some(ParsedIcmpV6::DestUnreach {
                    code,
                    orig_id,
                    orig_seq,
                    orig_is_icmp_echo,
                })
            }
        }
        _ => Some(ParsedIcmpV6::Other),
    }
}

/// Resolves a host or literal IP string into an `IpAddr` (preferring IPv4 if both exist).
pub async fn resolve_host(host: &str) -> Result<IpAddr, NetError> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err(NetError::InvalidInput("Target host cannot be empty".into()));
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(ip);
    }

    let resolver = Resolver::builder_tokio()
        .map_err(|e| NetError::Dns(e.to_string()))?
        .build()
        .map_err(|e| NetError::Dns(e.to_string()))?;

    let lookup = resolver
        .lookup_ip(trimmed)
        .await
        .map_err(|e| NetError::Dns(format!("{trimmed}: {e}")))?;

    let mut first_v6 = None;
    for ip in lookup.iter() {
        if ip.is_ipv4() {
            return Ok(ip);
        }
        if first_v6.is_none() {
            first_v6 = Some(ip);
        }
    }
    first_v6.ok_or_else(|| NetError::Dns(format!("No IP addresses found for {trimmed}")))
}

/// Best-effort reverse DNS lookup with short timeout.
pub async fn reverse_dns_cached(
    resolver: &TokioResolver,
    ip: IpAddr,
    cache: &mut HashMap<IpAddr, Option<String>>,
) -> Option<String> {
    if let Some(cached) = cache.get(&ip) {
        return cached.clone();
    }
    let result = tokio::time::timeout(Duration::from_millis(750), resolver.reverse_lookup(ip))
        .await
        .ok()
        .and_then(|res| res.ok())
        .and_then(|lookup| {
            lookup
                .answers()
                .first()
                .map(|r| r.data.to_string().trim_end_matches('.').to_string())
        });
    cache.insert(ip, result.clone());
    result
}

/// Performs one unprivileged ICMP probe with specified TTL and sequence number.
pub async fn probe_once(target: IpAddr, ttl: u8, seq: u16, timeout: Duration) -> ProbeOutcome {
    let dest_addr = SocketAddr::new(target, 0);
    tokio::task::spawn_blocking(move || probe_once_sockaddr_blocking(dest_addr, ttl, seq, timeout))
        .await
        .unwrap_or_else(|e| ProbeOutcome::Error(e.to_string()))
}

/// Performs one unprivileged ICMPv6 probe toward a scoped IPv6 address (e.g. `fe80::...%scope_id`).
pub async fn probe_once_v6_scoped(
    target: std::net::Ipv6Addr,
    scope_id: u32,
    ttl: u8,
    seq: u16,
    timeout: Duration,
) -> ProbeOutcome {
    let dest_addr = SocketAddr::V6(std::net::SocketAddrV6::new(target, 0, 0, scope_id));
    tokio::task::spawn_blocking(move || probe_once_sockaddr_blocking(dest_addr, ttl, seq, timeout))
        .await
        .unwrap_or_else(|e| ProbeOutcome::Error(e.to_string()))
}

fn probe_once_sockaddr_blocking(
    dest_addr: SocketAddr,
    ttl: u8,
    seq: u16,
    timeout: Duration,
) -> ProbeOutcome {
    let target = dest_addr.ip();
    let is_v6 = target.is_ipv6();
    let domain = if is_v6 { Domain::IPV6 } else { Domain::IPV4 };
    let proto = if is_v6 {
        Protocol::ICMPV6
    } else {
        Protocol::ICMPV4
    };

    let sock = match Socket::new(domain, Type::DGRAM, Some(proto)) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return fallback_system_ping(target, ttl, timeout);
        }
        Err(e) => return ProbeOutcome::Error(e.to_string()),
    };

    if is_v6 {
        if let Err(e) = sock.set_unicast_hops_v6(u32::from(ttl)) {
            return ProbeOutcome::Error(format!("set_unicast_hops_v6: {e}"));
        }
    } else if let Err(e) = sock.set_ttl_v4(u32::from(ttl)) {
        return ProbeOutcome::Error(format!("set_ttl_v4: {e}"));
    }

    if let Err(e) = sock.set_read_timeout(Some(timeout)) {
        return ProbeOutcome::Error(format!("set_read_timeout: {e}"));
    }

    let id = ((std::process::id() as u16) & 0xFF00) ^ NEXT_PROBE_ID.fetch_add(1, Ordering::Relaxed);
    let packet = build_icmp_echo_packet(is_v6, id, seq, b"NetScopeICMP01");
    let dest = SockAddr::from(dest_addr);

    let started = Instant::now();
    if let Err(e) = sock.send_to(&packet, &dest) {
        return ProbeOutcome::Error(e.to_string());
    }

    // On Linux DGRAM ICMP sockets, the kernel rewrites ICMP identifier to the socket's bound port.
    let local_port = sock
        .local_addr()
        .ok()
        .and_then(|sa| sa.as_socket().map(|s| s.port()))
        .filter(|&p| p != 0);

    let matches_id_seq = |rid: u16, rseq: u16| -> bool {
        rseq == seq && (rid == id || local_port == Some(rid))
    };

    let mut buf = [MaybeUninit::<u8>::uninit(); 1500];
    loop {
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return ProbeOutcome::Timeout;
        }
        let remaining = timeout.saturating_sub(elapsed);
        let _ = sock.set_read_timeout(Some(remaining));

        match sock.recv_from(&mut buf) {
            Ok((n, addr)) => {
                let rtt_ms = started.elapsed().as_secs_f64() * 1000.0;
                // SAFETY: `recv_from` guarantees `0..n` bytes of `buf` are initialized.
                let slice = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
                let from = addr
                    .as_socket()
                    .map(|sa| sa.ip())
                    .unwrap_or(target);

                if is_v6 {
                    match parse_icmpv6_packet(slice) {
                        Some(ParsedIcmpV6::EchoReply { id: rid, seq: rseq })
                            if matches_id_seq(rid, rseq) =>
                        {
                            return ProbeOutcome::EchoReply {
                                from,
                                rtt_ms,
                                ttl: None,
                            };
                        }
                        Some(ParsedIcmpV6::TimeExceeded {
                            orig_id: Some(oid),
                            orig_seq: Some(oseq),
                            orig_is_icmp_echo: true,
                        }) if matches_id_seq(oid, oseq) => {
                            return ProbeOutcome::TimeExceeded { from, rtt_ms };
                        }
                        Some(ParsedIcmpV6::DestUnreach {
                            code,
                            orig_id: Some(oid),
                            orig_seq: Some(oseq),
                            orig_is_icmp_echo: true,
                        }) if matches_id_seq(oid, oseq) => {
                            return ProbeOutcome::Unreachable { from, code, rtt_ms };
                        }
                        _ => {}
                    }
                } else {
                    match parse_icmpv4_packet(slice) {
                        Some(ParsedIcmpV4::EchoReply {
                            id: rid,
                            seq: rseq,
                            reply_ttl,
                        }) if matches_id_seq(rid, rseq) => {
                            return ProbeOutcome::EchoReply {
                                from,
                                rtt_ms,
                                ttl: reply_ttl,
                            };
                        }
                        Some(ParsedIcmpV4::TimeExceeded {
                            orig_id: Some(oid),
                            orig_seq: Some(oseq),
                            orig_is_icmp_echo: true,
                        }) if matches_id_seq(oid, oseq) => {
                            return ProbeOutcome::TimeExceeded { from, rtt_ms };
                        }
                        Some(ParsedIcmpV4::DestUnreach {
                            code,
                            orig_id: Some(oid),
                            orig_seq: Some(oseq),
                            orig_is_icmp_echo: true,
                        }) if matches_id_seq(oid, oseq) => {
                            return ProbeOutcome::Unreachable { from, code, rtt_ms };
                        }
                        _ => {}
                    }
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return ProbeOutcome::Timeout;
            }
            Err(e) => return ProbeOutcome::Error(e.to_string()),
        }
    }
}

/// Fallback when unprivileged ICMP sockets are blocked by OS policy.
fn fallback_system_ping(target: IpAddr, ttl: u8, timeout: Duration) -> ProbeOutcome {
    let mut cmd = std::process::Command::new("ping");
    #[cfg(target_os = "windows")]
    {
        cmd.args([
            "-n",
            "1",
            "-i",
            &ttl.to_string(),
            "-w",
            &timeout.as_millis().max(500).to_string(),
            &target.to_string(),
        ]);
    }
    #[cfg(target_os = "macos")]
    {
        let secs = timeout.as_millis().max(1000).div_ceil(1000);
        cmd.args([
            "-c",
            "1",
            "-m",
            &ttl.to_string(),
            "-t",
            &secs.to_string(),
            &target.to_string(),
        ]);
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let secs = timeout.as_secs().max(1);
        cmd.args([
            "-c",
            "1",
            "-t",
            &ttl.to_string(),
            "-W",
            &secs.to_string(),
            &target.to_string(),
        ]);
    }

    let started = Instant::now();
    match cmd.output() {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let rtt_ms = extract_ping_time_ms(&stdout)
                .unwrap_or_else(|| started.elapsed().as_secs_f64() * 1000.0);
            if out.status.success() {
                ProbeOutcome::EchoReply {
                    from: target,
                    rtt_ms,
                    ttl: None,
                }
            } else if stdout.to_ascii_lowercase().contains("time to live exceeded") {
                ProbeOutcome::TimeExceeded {
                    from: target,
                    rtt_ms,
                }
            } else {
                ProbeOutcome::Timeout
            }
        }
        Err(e) => ProbeOutcome::Error(format!("ICMP permission denied and ping failed: {e}")),
    }
}

fn extract_ping_time_ms(output: &str) -> Option<f64> {
    let idx = output.find("time=")?;
    let rest = &output[idx + 5..];
    let num_str: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    num_str.parse::<f64>().ok()
}

// ---------------------------------------------------------------------------
// Ping Runner
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PingConfig {
    pub interval: Duration,
    pub timeout: Duration,
    pub count: Option<usize>,
}

impl Default for PingConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            count: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingSample {
    pub seq: usize,
    pub timestamp: DateTime<Utc>,
    pub from: Option<IpAddr>,
    pub ttl: Option<u8>,
    pub rtt_ms: Option<f64>,
    pub status: String,
}

#[derive(Debug, Clone)]
pub enum PingEvent {
    Resolved { target: String, ip: IpAddr },
    Sample(PingSample),
    Finished(LatencyStats),
    Error(String),
}

pub async fn run_ping(
    target_host: String,
    config: PingConfig,
    tx: mpsc::UnboundedSender<PingEvent>,
    cancel: CancelToken,
) {
    let target_ip = match resolve_host(&target_host).await {
        Ok(ip) => ip,
        Err(e) => {
            let _ = tx.send(PingEvent::Error(e.to_string()));
            return;
        }
    };
    let _ = tx.send(PingEvent::Resolved {
        target: target_host,
        ip: target_ip,
    });

    let mut samples_for_stats: Vec<Option<f64>> = Vec::new();
    let mut seq = 1usize;

    loop {
        if cancel.is_cancelled() {
            break;
        }
        if let Some(max_count) = config.count
            && seq > max_count
        {
            break;
        }

        let started = Instant::now();
        let outcome = probe_once(target_ip, 64, (seq & 0xffff) as u16, config.timeout).await;
        if cancel.is_cancelled() {
            break;
        }

        let sample = match outcome {
            ProbeOutcome::EchoReply { from, rtt_ms, ttl } => {
                samples_for_stats.push(Some(rtt_ms));
                PingSample {
                    seq,
                    timestamp: Utc::now(),
                    from: Some(from),
                    ttl,
                    rtt_ms: Some(rtt_ms),
                    status: "Reply".to_string(),
                }
            }
            ProbeOutcome::Timeout => {
                samples_for_stats.push(None);
                PingSample {
                    seq,
                    timestamp: Utc::now(),
                    from: None,
                    ttl: None,
                    rtt_ms: None,
                    status: "Timeout".to_string(),
                }
            }
            ProbeOutcome::Unreachable { from, code, .. } => {
                samples_for_stats.push(None);
                PingSample {
                    seq,
                    timestamp: Utc::now(),
                    from: Some(from),
                    ttl: None,
                    rtt_ms: None,
                    status: format!("Unreachable (code {code})"),
                }
            }
            ProbeOutcome::TimeExceeded { from, .. } => {
                samples_for_stats.push(None);
                PingSample {
                    seq,
                    timestamp: Utc::now(),
                    from: Some(from),
                    ttl: None,
                    rtt_ms: None,
                    status: "TTL Exceeded".to_string(),
                }
            }
            ProbeOutcome::Error(err) => {
                samples_for_stats.push(None);
                PingSample {
                    seq,
                    timestamp: Utc::now(),
                    from: None,
                    ttl: None,
                    rtt_ms: None,
                    status: format!("Error: {err}"),
                }
            }
        };

        let _ = tx.send(PingEvent::Sample(sample));
        seq += 1;

        let elapsed = started.elapsed();
        if elapsed < config.interval {
            let mut remaining = config.interval - elapsed;
            while remaining > Duration::ZERO && !cancel.is_cancelled() {
                let step = remaining.min(Duration::from_millis(100));
                tokio::time::sleep(step).await;
                remaining = remaining.saturating_sub(step);
            }
        }
    }

    let _ = tx.send(PingEvent::Finished(compute_latency_stats(
        &samples_for_stats,
    )));
}

// ---------------------------------------------------------------------------
// Traceroute Runner
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteHop {
    pub hop: u8,
    pub ip: Option<IpAddr>,
    pub hostname: Option<String>,
    pub probe_rtts_ms: Vec<Option<f64>>,
    pub avg_ms: Option<f64>,
    pub reached_target: bool,
}

#[derive(Debug, Clone)]
pub enum TracerouteEvent {
    Resolved { target: String, ip: IpAddr },
    HopUpdate(TracerouteHop),
    Finished,
    Error(String),
}

pub async fn run_traceroute(
    target_host: String,
    max_hops: u8,
    probes_per_hop: usize,
    tx: mpsc::UnboundedSender<TracerouteEvent>,
    cancel: CancelToken,
) {
    let target_ip = match resolve_host(&target_host).await {
        Ok(ip) => ip,
        Err(e) => {
            let _ = tx.send(TracerouteEvent::Error(e.to_string()));
            return;
        }
    };
    let _ = tx.send(TracerouteEvent::Resolved {
        target: target_host,
        ip: target_ip,
    });

    let resolver = Resolver::builder_tokio().ok().and_then(|b| b.build().ok());
    let mut ptr_cache: HashMap<IpAddr, Option<String>> = HashMap::new();
    let probes_per_hop = probes_per_hop.clamp(1, 5);

    for ttl in 1..=max_hops {
        if cancel.is_cancelled() {
            break;
        }

        let mut join_set = tokio::task::JoinSet::new();
        for idx in 0..probes_per_hop {
            let seq = (u16::from(ttl) << 4) | (idx as u16);
            join_set.spawn(async move {
                (
                    idx,
                    probe_once(target_ip, ttl, seq, Duration::from_millis(1500)).await,
                )
            });
        }

        let mut outcomes: Vec<Option<ProbeOutcome>> = vec![None; probes_per_hop];
        while let Some(res) = join_set.join_next().await {
            if let Ok((idx, outcome)) = res
                && idx < outcomes.len()
            {
                outcomes[idx] = Some(outcome);
            }
        }

        if cancel.is_cancelled() {
            break;
        }

        let mut responder: Option<IpAddr> = None;
        let mut reached = false;
        let mut rtts = Vec::with_capacity(probes_per_hop);

        for maybe_out in outcomes {
            match maybe_out {
                Some(ProbeOutcome::EchoReply { from, rtt_ms, .. }) => {
                    if responder.is_none() {
                        responder = Some(from);
                    }
                    reached = true;
                    rtts.push(Some(rtt_ms));
                }
                Some(ProbeOutcome::TimeExceeded { from, rtt_ms })
                | Some(ProbeOutcome::Unreachable { from, rtt_ms, .. }) => {
                    if responder.is_none() {
                        responder = Some(from);
                    }
                    rtts.push(Some(rtt_ms));
                }
                _ => rtts.push(None),
            }
        }

        let hostname = match (responder, &resolver) {
            (Some(ip), Some(res)) => reverse_dns_cached(res, ip, &mut ptr_cache).await,
            _ => None,
        };

        let valid: Vec<f64> = rtts.iter().filter_map(|x| *x).collect();
        let avg_ms = if valid.is_empty() {
            None
        } else {
            Some(valid.iter().sum::<f64>() / valid.len() as f64)
        };

        let _ = tx.send(TracerouteEvent::HopUpdate(TracerouteHop {
            hop: ttl,
            ip: responder,
            hostname,
            probe_rtts_ms: rtts,
            avg_ms,
            reached_target: reached,
        }));

        if reached {
            break;
        }
    }

    let _ = tx.send(TracerouteEvent::Finished);
}

// ---------------------------------------------------------------------------
// MTR Runner (Continuous Hop Stats + Heatmap + Outage Log)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum HopProbeMark {
    Ok(f64),
    Lost,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtrHopStats {
    pub hop: u8,
    pub ip: Option<IpAddr>,
    pub hostname: Option<String>,
    pub sent: usize,
    pub received: usize,
    pub loss_pct: f64,
    pub last_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub best_ms: Option<f64>,
    pub worst_ms: Option<f64>,
    pub stdev_ms: Option<f64>,
    pub recent_history: VecDeque<HopProbeMark>,
    pub consecutive_losses: usize,
    rtts: Vec<f64>,
}

impl MtrHopStats {
    fn new(hop: u8) -> Self {
        Self {
            hop,
            ip: None,
            hostname: None,
            sent: 0,
            received: 0,
            loss_pct: 0.0,
            last_ms: None,
            avg_ms: None,
            best_ms: None,
            worst_ms: None,
            stdev_ms: None,
            recent_history: VecDeque::with_capacity(MTR_HISTORY_CAPACITY),
            consecutive_losses: 0,
            rtts: Vec::new(),
        }
    }

    fn record(&mut self, from: Option<IpAddr>, rtt_ms: Option<f64>) -> bool {
        self.sent += 1;
        if self.ip.is_none()
            && let Some(addr) = from
        {
            self.ip = Some(addr);
        }

        let mut outage_triggered = false;
        match rtt_ms {
            Some(rtt) => {
                self.received += 1;
                self.last_ms = Some(rtt);
                self.rtts.push(rtt);
                self.consecutive_losses = 0;

                if self.recent_history.len() == MTR_HISTORY_CAPACITY {
                    self.recent_history.pop_front();
                }
                self.recent_history.push_back(HopProbeMark::Ok(rtt));

                let sum: f64 = self.rtts.iter().sum();
                let avg = sum / self.rtts.len() as f64;
                self.avg_ms = Some(avg);
                self.best_ms = Some(self.best_ms.map_or(rtt, |b| b.min(rtt)));
                self.worst_ms = Some(self.worst_ms.map_or(rtt, |w| w.max(rtt)));
                if self.rtts.len() >= 2 {
                    let var = self
                        .rtts
                        .iter()
                        .map(|v| (*v - avg).powi(2))
                        .sum::<f64>()
                        / (self.rtts.len() as f64 - 1.0);
                    self.stdev_ms = Some(var.sqrt());
                } else {
                    self.stdev_ms = Some(0.0);
                }
            }
            None => {
                self.last_ms = None;
                self.consecutive_losses += 1;
                if self.consecutive_losses == 2 {
                    outage_triggered = true;
                }
                if self.recent_history.len() == MTR_HISTORY_CAPACITY {
                    self.recent_history.pop_front();
                }
                self.recent_history.push_back(HopProbeMark::Lost);
            }
        }

        self.loss_pct = if self.sent == 0 {
            0.0
        } else {
            ((self.sent - self.received) as f64 / self.sent as f64) * 100.0
        };
        outage_triggered
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtrOutageEvent {
    pub timestamp: DateTime<Utc>,
    pub hop: u8,
    pub ip: Option<IpAddr>,
    pub hostname: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone)]
pub enum MtrEvent {
    Resolved { target: String, ip: IpAddr },
    Snapshot {
        hops: Vec<MtrHopStats>,
        rounds: usize,
    },
    Outage(MtrOutageEvent),
    Finished,
    Error(String),
}

pub async fn run_mtr(
    target_host: String,
    max_hops: u8,
    interval: Duration,
    tx: mpsc::UnboundedSender<MtrEvent>,
    cancel: CancelToken,
) {
    let target_ip = match resolve_host(&target_host).await {
        Ok(ip) => ip,
        Err(e) => {
            let _ = tx.send(MtrEvent::Error(e.to_string()));
            return;
        }
    };
    let _ = tx.send(MtrEvent::Resolved {
        target: target_host,
        ip: target_ip,
    });

    let resolver = Resolver::builder_tokio().ok().and_then(|b| b.build().ok());
    let mut ptr_cache: HashMap<IpAddr, Option<String>> = HashMap::new();

    // Initial path length discovery: probe 1..=max_hops concurrently
    let mut path_len = max_hops;
    {
        let mut set = tokio::task::JoinSet::new();
        for ttl in 1..=max_hops {
            set.spawn(async move {
                (
                    ttl,
                    probe_once(target_ip, ttl, u16::from(ttl), Duration::from_millis(1200)).await,
                )
            });
        }
        let mut earliest_echo: Option<u8> = None;
        while let Some(res) = set.join_next().await {
            if let Ok((ttl, ProbeOutcome::EchoReply { .. })) = res {
                earliest_echo = Some(earliest_echo.map_or(ttl, |e| e.min(ttl)));
            }
        }
        if let Some(len) = earliest_echo {
            path_len = len;
        }
    }

    if cancel.is_cancelled() {
        let _ = tx.send(MtrEvent::Finished);
        return;
    }

    let mut hops: Vec<MtrHopStats> = (1..=path_len).map(MtrHopStats::new).collect();
    let mut round = 0usize;

    while !cancel.is_cancelled() {
        round += 1;
        let round_started = Instant::now();

        let mut set = tokio::task::JoinSet::new();
        for ttl in 1..=path_len {
            let seq = ((round & 0xff) as u16) << 6 | u16::from(ttl);
            set.spawn(async move {
                (
                    ttl,
                    probe_once(target_ip, ttl, seq, Duration::from_millis(1100)).await,
                )
            });
        }

        let mut round_results: Vec<Option<ProbeOutcome>> = vec![None; usize::from(path_len)];
        while let Some(res) = set.join_next().await {
            if let Ok((ttl, outcome)) = res
                && ttl >= 1
                && usize::from(ttl) <= round_results.len()
            {
                round_results[usize::from(ttl - 1)] = Some(outcome);
            }
        }

        if cancel.is_cancelled() {
            break;
        }

        for (idx, hop_stat) in hops.iter_mut().enumerate() {
            let outcome = round_results.get(idx).and_then(|o| o.as_ref());
            let from = outcome.and_then(|o| o.responder_ip());
            let rtt = outcome.and_then(|o| o.rtt_ms());
            let triggered = hop_stat.record(from, rtt);

            if hop_stat.hostname.is_none()
                && let Some(ip) = hop_stat.ip
                && let Some(res) = &resolver
            {
                hop_stat.hostname = reverse_dns_cached(res, ip, &mut ptr_cache).await;
            }

            if triggered {
                let _ = tx.send(MtrEvent::Outage(MtrOutageEvent {
                    timestamp: Utc::now(),
                    hop: hop_stat.hop,
                    ip: hop_stat.ip,
                    hostname: hop_stat.hostname.clone(),
                    description: format!(
                        "Hop {} ({}) dropped 2+ consecutive probes",
                        hop_stat.hop,
                        hop_stat
                            .ip
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "*".into())
                    ),
                }));
            }
        }

        let _ = tx.send(MtrEvent::Snapshot {
            hops: hops.clone(),
            rounds: round,
        });

        let elapsed = round_started.elapsed();
        if elapsed < interval {
            let mut rem = interval - elapsed;
            while rem > Duration::ZERO && !cancel.is_cancelled() {
                let step = rem.min(Duration::from_millis(100));
                tokio::time::sleep(step).await;
                rem = rem.saturating_sub(step);
            }
        }
    }

    let _ = tx.send(MtrEvent::Finished);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_rfc1071_known_echo() {
        // ICMP Echo Request: type 8, code 0, checksum 0, id 0x04d2, seq 0x0001
        let pkt = build_icmp_echo_packet(false, 0x04d2, 1, b"netprobe");
        assert_eq!(internet_checksum(&pkt), 0);
    }

    #[test]
    fn parse_ipv4_strips_macos_ip_header() {
        // Simulated 20-byte IPv4 header (version 4, IHL 5 -> 20 bytes, TTL=57) + 8-byte ICMP Echo Reply
        let mut raw = vec![0u8; 28];
        raw[0] = 0x45; // v4, ihl=5
        raw[8] = 57; // ttl
        raw[20] = 0; // ICMP Echo Reply
        raw[21] = 0; // code
        raw[24..26].copy_from_slice(&0x1234u16.to_be_bytes());
        raw[26..28].copy_from_slice(&42u16.to_be_bytes());
        let parsed = parse_icmpv4_packet(&raw).expect("should parse");
        assert_eq!(
            parsed,
            ParsedIcmpV4::EchoReply {
                id: 0x1234,
                seq: 42,
                reply_ttl: Some(57)
            }
        );
    }

    #[test]
    fn parse_ipv4_handles_linux_stripped_icmp_time_exceeded_with_embedded_echo() {
        // Simulated Linux DGRAM ICMP Time Exceeded without outer IP header, carrying embedded IPv4+ICMP Echo
        let mut raw = vec![0u8; 8 + 20 + 8];
        raw[0] = 11; // Time Exceeded
        raw[8] = 0x45; // embedded IPv4 IHL=5
        raw[8 + 9] = 1; // proto=ICMP
        raw[8 + 20] = 8; // Echo Request
        raw[8 + 24..8 + 26].copy_from_slice(&0xABCDu16.to_be_bytes());
        raw[8 + 26..8 + 28].copy_from_slice(&7u16.to_be_bytes());
        let parsed = parse_icmpv4_packet(&raw).expect("should parse");
        assert_eq!(
            parsed,
            ParsedIcmpV4::TimeExceeded {
                orig_id: Some(0xABCD),
                orig_seq: Some(7),
                orig_is_icmp_echo: true,
            }
        );
    }

    #[tokio::test]
    async fn live_icmp_echo_and_ttl1_on_host() {
        let target: IpAddr = "1.1.1.1".parse().unwrap();
        let hop1 = probe_once(target, 1, 1, Duration::from_secs(2)).await;
        // On a connected machine, hop 1 should return TimeExceeded (or EchoReply on direct bridge)
        assert!(
            matches!(
                hop1,
                ProbeOutcome::TimeExceeded { .. } | ProbeOutcome::EchoReply { .. } | ProbeOutcome::Timeout
            ),
            "Unexpected error from TTL=1 probe: {hop1:?}"
        );

        let echo = probe_once(target, 64, 2, Duration::from_secs(2)).await;
        assert!(
            matches!(echo, ProbeOutcome::EchoReply { .. }),
            "Expected EchoReply from 1.1.1.1, got: {echo:?}"
        );
    }
}
