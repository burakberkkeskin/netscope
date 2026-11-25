use crate::icmp::probe_once;
use crate::stats::{LatencyStats, compute_latency_stats};
use crate::{CancelToken, IpFamily};
use chrono::{DateTime, Utc};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use rustls_platform_verifier::Verifier as PlatformVerifier;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;

const CF_SPEED_HOST: &str = "speed.cloudflare.com";
const CF_SPEED_REFERER: &str = "https://speed.cloudflare.com/";
const CF_SPEED_ORIGIN: &str = "https://speed.cloudflare.com";
const CF_USER_AGENT: &str = "NetScope/0.7";
const PING_TARGET_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
const PING_TARGET_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));
const UPLOAD_POST_BYTES: usize = 16 * 1024 * 1024; // 16 MiB streaming POST per keep-alive cycle
const UPLOAD_SLICE_BYTES: usize = 32 * 1024; // 32 KiB write slices for smooth real-time accounting
const STREAM_COUNT: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BufferbloatGrade {
    APlus,
    A,
    B,
    C,
    D,
    F,
}

impl BufferbloatGrade {
    pub fn label(self) -> &'static str {
        match self {
            Self::APlus => "A+",
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
            Self::D => "D",
            Self::F => "F",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::APlus => "Zero latency bloat under load (<5 ms)",
            Self::A => "Minimal latency increase under load (<15 ms)",
            Self::B => "Moderate bufferbloat (<30 ms)",
            Self::C => "Noticeable queue delay under load (<60 ms)",
            Self::D => "Significant bufferbloat (<120 ms)",
            Self::F => "Severe bufferbloat (>=120 ms) — enable SQM/FQ-CoDel",
        }
    }
}

/// Grades bufferbloat from the worst latency increase observed during download/upload vs idle.
pub fn grade_bufferbloat(unloaded_ms: f64, worst_loaded_ms: f64) -> BufferbloatGrade {
    let delta = (worst_loaded_ms - unloaded_ms).max(0.0);
    if delta < 5.0 {
        BufferbloatGrade::APlus
    } else if delta < 15.0 {
        BufferbloatGrade::A
    } else if delta < 30.0 {
        BufferbloatGrade::B
    } else if delta < 60.0 {
        BufferbloatGrade::C
    } else if delta < 120.0 {
        BufferbloatGrade::D
    } else {
        BufferbloatGrade::F
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpeedTestPhase {
    IdleLatency,
    Download,
    Upload,
    Completed,
}

impl SpeedTestPhase {
    pub fn label(self) -> &'static str {
        match self {
            Self::IdleLatency => "Measuring idle latency...",
            Self::Download => "Testing download (4 parallel streams)...",
            Self::Upload => "Testing upload (4 parallel streams)...",
            Self::Completed => "Completed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedTestServerInfo {
    pub ip: IpAddr,
    pub colo: Option<String>,
    pub is_ipv6: bool,
}

impl SpeedTestServerInfo {
    pub fn badge_label(&self) -> String {
        let stack = if self.is_ipv6 { "IPv6" } else { "IPv4" };
        match &self.colo {
            Some(c) => format!("Cloudflare {c} ({stack})"),
            None => format!("Cloudflare ({stack})"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedTestSample {
    pub elapsed_sec: f64,
    pub mbps: f64,
    pub loaded_rtt_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedTestResult {
    pub timestamp: DateTime<Utc>,
    pub download_mbps: f64,
    pub upload_mbps: f64,
    pub unloaded_stats: LatencyStats,
    pub loaded_dl_stats: LatencyStats,
    pub loaded_ul_stats: LatencyStats,
    pub bufferbloat_grade: BufferbloatGrade,
    #[serde(default)]
    pub server_colo: Option<String>,
    #[serde(default)]
    pub server_ip: Option<IpAddr>,
    #[serde(default)]
    pub is_ipv6: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkloadQuality {
    Smooth,
    LagSpikes,
    Poor,
}

impl WorkloadQuality {
    pub fn label(self) -> &'static str {
        match self {
            Self::Smooth => "Smooth",
            Self::LagSpikes => "Lag Spikes",
            Self::Poor => "Poor",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferbloatWorkloadSummary {
    pub video_calls: WorkloadQuality,
    pub gaming: WorkloadQuality,
    pub voip: WorkloadQuality,
    pub web_browsing: WorkloadQuality,
    pub dl_bloat_ms: f64,
    pub ul_bloat_ms: f64,
    pub recommendation: String,
}

/// Evaluates real-time application quality and tuning advice from loaded vs idle latency inflation.
pub fn evaluate_bufferbloat_workloads(res: &SpeedTestResult) -> BufferbloatWorkloadSummary {
    let idle = res.unloaded_stats.median_ms.unwrap_or(0.0);
    let dl_bloat_ms = (res.loaded_dl_stats.median_ms.unwrap_or(idle) - idle).max(0.0);
    let ul_bloat_ms = (res.loaded_ul_stats.median_ms.unwrap_or(idle) - idle).max(0.0);
    let worst = dl_bloat_ms.max(ul_bloat_ms);

    let grade_app = |smooth_lim: f64, warn_lim: f64| -> WorkloadQuality {
        if worst < smooth_lim {
            WorkloadQuality::Smooth
        } else if worst < warn_lim {
            WorkloadQuality::LagSpikes
        } else {
            WorkloadQuality::Poor
        }
    };

    let gaming = grade_app(15.0, 35.0);
    let voip = grade_app(25.0, 60.0);
    let video_calls = grade_app(35.0, 85.0);
    let web_browsing = grade_app(75.0, 150.0);

    let direction_hint = if ul_bloat_ms > dl_bloat_ms + 10.0 {
        "Upload saturation causes the highest delay."
    } else if dl_bloat_ms > ul_bloat_ms + 10.0 {
        "Download saturation causes the highest delay."
    } else {
        "Both download and upload show similar queueing behavior."
    };

    let recommendation = match res.bufferbloat_grade {
        BufferbloatGrade::APlus | BufferbloatGrade::A => {
            format!("Queue latency stays tight under full saturation. {direction_hint}")
        }
        BufferbloatGrade::B | BufferbloatGrade::C => {
            format!(
                "{direction_hint} Enabling SQM (FQ-CoDel or CAKE) on your router will keep interactive traffic snappy."
            )
        }
        BufferbloatGrade::D | BufferbloatGrade::F => {
            format!(
                "{direction_hint} Configure router SQM/CAKE traffic shaping (~90–95% of line rate) to eliminate lag spikes."
            )
        }
    };

    BufferbloatWorkloadSummary {
        video_calls,
        gaming,
        voip,
        web_browsing,
        dl_bloat_ms,
        ul_bloat_ms,
        recommendation,
    }
}

#[derive(Debug, Clone)]
pub enum SpeedTestEvent {
    ServerInfo(SpeedTestServerInfo),
    PhaseChanged(SpeedTestPhase),
    IdleSample(f64),
    DownloadSample(SpeedTestSample),
    UploadSample(SpeedTestSample),
    Completed(Box<SpeedTestResult>),
    Error(String),
}

/// Sliding-window throughput estimator to keep live chart samples smooth without sawtooth spikes.
pub(crate) struct SlidingThroughput {
    window: Duration,
    points: VecDeque<(Instant, u64)>,
}

impl SlidingThroughput {
    pub(crate) fn new(window: Duration, start: Instant) -> Self {
        let mut points = VecDeque::with_capacity(8);
        points.push_back((start, 0));
        Self { window, points }
    }

    pub(crate) fn record(&mut self, now: Instant, total_bytes: u64) -> f64 {
        self.points.push_back((now, total_bytes));
        while self.points.len() > 2 {
            if let Some(&(oldest_t, _)) = self.points.front() {
                if now.duration_since(oldest_t) > self.window {
                    self.points.pop_front();
                } else {
                    break;
                }
            }
        }
        let Some(&(anchor_t, anchor_b)) = self.points.front() else {
            return 0.0;
        };
        let dt = now.duration_since(anchor_t).as_secs_f64();
        if dt < 0.05 {
            return 0.0;
        }
        let delta_b = total_bytes.saturating_sub(anchor_b);
        (delta_b as f64 * 8.0) / (dt * 1_000_000.0)
    }
}

/// Extracts Cloudflare edge PoP IATA code from `CF-RAY: <hex>-<COLO>`.
pub fn parse_cf_ray_colo(header_val: &str) -> Option<String> {
    let (_, colo) = header_val.trim().rsplit_once('-')?;
    let clean = colo.trim();
    if clean.len() == 3 && clean.bytes().all(|b| b.is_ascii_alphabetic()) {
        Some(clean.to_ascii_uppercase())
    } else {
        None
    }
}

/// Resolves `speed.cloudflare.com:443` respecting `IpFamily`.
/// Under `Auto`, races TCP connect on IPv4 vs IPv6 and picks whichever reaches the closest edge PoP first.
async fn resolve_speed_target(family: IpFamily) -> Result<IpAddr, String> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((CF_SPEED_HOST, 443))
        .await
        .map_err(|e| format!("DNS resolution failed for {CF_SPEED_HOST}: {e}"))?
        .collect();

    let first_v4 = addrs.iter().find(|a| a.is_ipv4()).map(|a| a.ip());
    let first_v6 = addrs.iter().find(|a| a.is_ipv6()).map(|a| a.ip());

    match family {
        IpFamily::Ipv4 => first_v4.ok_or_else(|| format!("No IPv4 (A) record for {CF_SPEED_HOST}")),
        IpFamily::Ipv6 => {
            first_v6.ok_or_else(|| format!("No IPv6 (AAAA) record for {CF_SPEED_HOST}"))
        }
        IpFamily::Auto => match (first_v4, first_v6) {
            (Some(v4), Some(v6)) => {
                let f4 = tokio::time::timeout(
                    Duration::from_secs(2),
                    TcpStream::connect(SocketAddr::new(v4, 443)),
                );
                let f6 = tokio::time::timeout(
                    Duration::from_secs(2),
                    TcpStream::connect(SocketAddr::new(v6, 443)),
                );
                tokio::pin!(f4);
                tokio::pin!(f6);
                tokio::select! {
                    r4 = &mut f4 => {
                        if matches!(r4, Ok(Ok(_))) {
                            Ok(v4)
                        } else if matches!(f6.await, Ok(Ok(_))) {
                            Ok(v6)
                        } else {
                            Err(format!("Unable to connect to {CF_SPEED_HOST} over IPv4 or IPv6"))
                        }
                    }
                    r6 = &mut f6 => {
                        if matches!(r6, Ok(Ok(_))) {
                            Ok(v6)
                        } else if matches!(f4.await, Ok(Ok(_))) {
                            Ok(v4)
                        } else {
                            Err(format!("Unable to connect to {CF_SPEED_HOST} over IPv4 or IPv6"))
                        }
                    }
                }
            }
            (Some(v4), None) => Ok(v4),
            (None, Some(v6)) => Ok(v6),
            (None, None) => Err(format!("No addresses resolved for {CF_SPEED_HOST}")),
        },
    }
}

fn build_cf_http1_client(target_ip: IpAddr, timeout: Duration) -> Result<reqwest::Client, String> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::REFERER,
        reqwest::header::HeaderValue::from_static(CF_SPEED_REFERER),
    );
    headers.insert(
        reqwest::header::ORIGIN,
        reqwest::header::HeaderValue::from_static(CF_SPEED_ORIGIN),
    );
    reqwest::Client::builder()
        .http1_only()
        .timeout(timeout)
        .default_headers(headers)
        .resolve(CF_SPEED_HOST, SocketAddr::new(target_ip, 443))
        .user_agent(CF_USER_AGENT)
        .build()
        .map_err(|e| format!("HTTP client build failed: {e}"))
}

async fn preflight_cf_edge(target_ip: IpAddr) -> Result<SpeedTestServerInfo, String> {
    let client = build_cf_http1_client(target_ip, Duration::from_secs(5))?;
    let resp = client
        .get("https://speed.cloudflare.com/__down?bytes=0")
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                format!("Timed out connecting to {CF_SPEED_HOST} ({target_ip})")
            } else {
                format!("Failed to reach {CF_SPEED_HOST} ({target_ip}): {e}")
            }
        })?;

    if !resp.status().is_success() {
        let code = resp.status().as_u16();
        let hint = if code == 429 {
            " — Cloudflare rate-limited the request; retry shortly"
        } else {
            ""
        };
        return Err(format!("Speed test edge returned HTTP {code}{hint}"));
    }

    let colo = resp
        .headers()
        .get("cf-ray")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_cf_ray_colo);

    Ok(SpeedTestServerInfo {
        ip: target_ip,
        colo,
        is_ipv6: target_ip.is_ipv6(),
    })
}

fn build_rustls_client_config() -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let os_verifier = Arc::new(
        PlatformVerifier::new(provider.clone())
            .map_err(|e| format!("OS TLS verifier init failed: {e}"))?,
    );
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS protocol config failed: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(os_verifier)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// Runs the full 4-stream Speed Test + concurrent Bufferbloat probe against Cloudflare Speed Edge.
pub async fn run_speedtest(
    family: IpFamily,
    tx: mpsc::UnboundedSender<SpeedTestEvent>,
    cancel: CancelToken,
) {
    crate::ensure_crypto_provider();

    // 0. Resolve closest edge PoP & verify endpoint reachability before starting phases
    let _ = tx.send(SpeedTestEvent::PhaseChanged(SpeedTestPhase::IdleLatency));
    let target_ip = match resolve_speed_target(family).await {
        Ok(ip) => ip,
        Err(e) => {
            let _ = tx.send(SpeedTestEvent::Error(e));
            return;
        }
    };
    if cancel.is_cancelled() {
        return;
    }

    let server_info = match preflight_cf_edge(target_ip).await {
        Ok(info) => info,
        Err(e) => {
            let _ = tx.send(SpeedTestEvent::Error(e));
            return;
        }
    };
    let _ = tx.send(SpeedTestEvent::ServerInfo(server_info.clone()));
    if cancel.is_cancelled() {
        return;
    }

    let ping_target = if server_info.is_ipv6 {
        PING_TARGET_V6
    } else {
        PING_TARGET_V4
    };

    // 1. Unloaded latency baseline (10 probes on the same IP stack as the transfer)
    let mut idle_samples = Vec::with_capacity(10);
    for seq in 1..=10u16 {
        if cancel.is_cancelled() {
            return;
        }
        let out = probe_once(ping_target, 64, seq, Duration::from_millis(900)).await;
        if let Some(rtt) = out.rtt_ms() {
            let _ = tx.send(SpeedTestEvent::IdleSample(rtt));
        }
        idle_samples.push(out.rtt_ms());
        tokio::time::sleep(Duration::from_millis(55)).await;
    }
    let unloaded_stats = compute_latency_stats(&idle_samples);

    // 2. 4-Stream Download + concurrent loaded ping
    let _ = tx.send(SpeedTestEvent::PhaseChanged(SpeedTestPhase::Download));
    let (dl_mbps, dl_rtts, dl_err) = run_parallel_transfer(
        true,
        target_ip,
        ping_target,
        Duration::from_secs(8),
        &tx,
        &cancel,
    )
    .await;
    if cancel.is_cancelled() {
        return;
    }
    if let Some(err) = dl_err {
        let _ = tx.send(SpeedTestEvent::Error(err));
        return;
    }
    let loaded_dl_stats = compute_latency_stats(&dl_rtts);

    // 3. 4-Stream Streaming Upload + concurrent loaded ping
    let _ = tx.send(SpeedTestEvent::PhaseChanged(SpeedTestPhase::Upload));
    let (ul_mbps, ul_rtts, ul_err) = run_parallel_transfer(
        false,
        target_ip,
        ping_target,
        Duration::from_secs(8),
        &tx,
        &cancel,
    )
    .await;
    if cancel.is_cancelled() {
        return;
    }
    if let Some(err) = ul_err {
        let _ = tx.send(SpeedTestEvent::Error(err));
        return;
    }
    let loaded_ul_stats = compute_latency_stats(&ul_rtts);

    let idle_med = unloaded_stats.median_ms.unwrap_or(0.0);
    let worst_loaded = loaded_dl_stats
        .median_ms
        .unwrap_or(idle_med)
        .max(loaded_ul_stats.median_ms.unwrap_or(idle_med));
    let bufferbloat_grade = grade_bufferbloat(idle_med, worst_loaded);

    let _ = tx.send(SpeedTestEvent::PhaseChanged(SpeedTestPhase::Completed));
    let _ = tx.send(SpeedTestEvent::Completed(Box::new(SpeedTestResult {
        timestamp: Utc::now(),
        download_mbps: dl_mbps,
        upload_mbps: ul_mbps,
        unloaded_stats,
        loaded_dl_stats,
        loaded_ul_stats,
        bufferbloat_grade,
        server_colo: server_info.colo,
        server_ip: Some(server_info.ip),
        is_ipv6: server_info.is_ipv6,
    })));
}

async fn run_parallel_transfer(
    is_download: bool,
    target_ip: IpAddr,
    ping_target: IpAddr,
    duration: Duration,
    tx: &mpsc::UnboundedSender<SpeedTestEvent>,
    cancel: &CancelToken,
) -> (f64, Vec<Option<f64>>, Option<String>) {
    let total_bytes = Arc::new(AtomicU64::new(0));
    let first_err: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let local_stop = CancelToken::new();
    let started = Instant::now();

    let mut worker_handles = Vec::with_capacity(STREAM_COUNT);

    if is_download {
        for _ in 0..STREAM_COUNT {
            let bytes_counter = total_bytes.clone();
            let err_slot = first_err.clone();
            let worker_stop = local_stop.clone();
            let global_cancel = cancel.clone();

            worker_handles.push(tokio::spawn(async move {
                let Ok(client) = build_cf_http1_client(target_ip, Duration::from_secs(12)) else {
                    return;
                };

                while !worker_stop.is_cancelled()
                    && !global_cancel.is_cancelled()
                    && started.elapsed() < duration
                {
                    match client
                        .get("https://speed.cloudflare.com/__down?bytes=50000000")
                        .send()
                        .await
                    {
                        Ok(mut resp) => {
                            if !resp.status().is_success() {
                                let code = resp.status().as_u16();
                                if let Ok(mut guard) = err_slot.lock()
                                    && guard.is_none()
                                {
                                    *guard = Some(format!(
                                        "Download rejected by Cloudflare Edge (HTTP {code})"
                                    ));
                                }
                                tokio::time::sleep(Duration::from_millis(250)).await;
                                continue;
                            }
                            while !worker_stop.is_cancelled()
                                && !global_cancel.is_cancelled()
                                && started.elapsed() < duration
                            {
                                match resp.chunk().await {
                                    Ok(Some(c)) => {
                                        bytes_counter.fetch_add(c.len() as u64, Ordering::Relaxed);
                                    }
                                    _ => break,
                                }
                            }
                        }
                        Err(e) => {
                            if let Ok(mut guard) = err_slot.lock()
                                && guard.is_none()
                            {
                                *guard = Some(format!("Download connection error: {e}"));
                            }
                            tokio::time::sleep(Duration::from_millis(200)).await;
                        }
                    }
                }
            }));
        }
    } else {
        let tls_cfg = match build_rustls_client_config() {
            Ok(c) => c,
            Err(e) => return (0.0, Vec::new(), Some(e)),
        };
        let slice_buf = Arc::new(vec![0x5Au8; UPLOAD_SLICE_BYTES]);
        let post_header = Arc::new(
            format!(
                "POST /__up HTTP/1.1\r\n\
                 Host: {CF_SPEED_HOST}\r\n\
                 Referer: {CF_SPEED_REFERER}\r\n\
                 Origin: {CF_SPEED_ORIGIN}\r\n\
                 User-Agent: {CF_USER_AGENT}\r\n\
                 Content-Type: application/octet-stream\r\n\
                 Content-Length: {UPLOAD_POST_BYTES}\r\n\
                 Connection: keep-alive\r\n\r\n"
            )
            .into_bytes(),
        );

        for _ in 0..STREAM_COUNT {
            let bytes_counter = total_bytes.clone();
            let err_slot = first_err.clone();
            let worker_stop = local_stop.clone();
            let global_cancel = cancel.clone();
            let tls_cfg = tls_cfg.clone();
            let slice = slice_buf.clone();
            let header = post_header.clone();

            worker_handles.push(tokio::spawn(async move {
                let connector = TlsConnector::from(tls_cfg);
                let Ok(sni) = ServerName::try_from(CF_SPEED_HOST.to_string()) else {
                    return;
                };

                while !worker_stop.is_cancelled()
                    && !global_cancel.is_cancelled()
                    && started.elapsed() < duration
                {
                    let tcp = match tokio::time::timeout(
                        Duration::from_secs(4),
                        TcpStream::connect(SocketAddr::new(target_ip, 443)),
                    )
                    .await
                    {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => {
                            if let Ok(mut g) = err_slot.lock()
                                && g.is_none()
                            {
                                *g = Some(format!("Upload TCP connect failed: {e}"));
                            }
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            continue;
                        }
                        Err(_) => {
                            if let Ok(mut g) = err_slot.lock()
                                && g.is_none()
                            {
                                *g = Some("Upload TCP connect timed out".into());
                            }
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            continue;
                        }
                    };
                    let _ = tcp.set_nodelay(true);

                    let mut tls = match tokio::time::timeout(
                        Duration::from_secs(4),
                        connector.connect(sni.clone(), tcp),
                    )
                    .await
                    {
                        Ok(Ok(s)) => s,
                        _ => {
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            continue;
                        }
                    };

                    // Keep streaming 16 MiB POST cycles over the same TLS keep-alive socket.
                    'keepalive: while !worker_stop.is_cancelled()
                        && !global_cancel.is_cancelled()
                        && started.elapsed() < duration
                    {
                        if tls.write_all(&header).await.is_err() {
                            break 'keepalive;
                        }
                        let mut sent_in_post = 0usize;
                        while sent_in_post < UPLOAD_POST_BYTES
                            && !worker_stop.is_cancelled()
                            && !global_cancel.is_cancelled()
                            && started.elapsed() < duration
                        {
                            let remaining = UPLOAD_POST_BYTES - sent_in_post;
                            let n = remaining.min(slice.len());
                            if tls.write_all(&slice[..n]).await.is_err() {
                                break 'keepalive;
                            }
                            sent_in_post += n;
                            bytes_counter.fetch_add(n as u64, Ordering::Relaxed);
                        }

                        if sent_in_post < UPLOAD_POST_BYTES
                            || worker_stop.is_cancelled()
                            || global_cancel.is_cancelled()
                        {
                            break 'keepalive;
                        }

                        // Drain the tiny HTTP/1.1 200 OK response before reusing the keep-alive stream.
                        let mut resp_buf = [0u8; 512];
                        match tokio::time::timeout(
                            Duration::from_secs(3),
                            tls.read(&mut resp_buf),
                        )
                        .await
                        {
                            Ok(Ok(n)) if n > 0 => {
                                let head = String::from_utf8_lossy(&resp_buf[..n]);
                                if !head.starts_with("HTTP/1.1 200")
                                    && !head.starts_with("HTTP/1.0 200")
                                {
                                    if let Ok(mut g) = err_slot.lock()
                                        && g.is_none()
                                    {
                                        let first_line =
                                            head.lines().next().unwrap_or("non-200").trim();
                                        *g = Some(format!(
                                            "Upload rejected by Cloudflare Edge ({first_line})"
                                        ));
                                    }
                                    break 'keepalive;
                                }
                            }
                            _ => break 'keepalive,
                        }
                    }
                }
            }));
        }
    }

    let mut loaded_rtts = Vec::new();
    let mut seq = 100u16;
    let mut smoother = SlidingThroughput::new(Duration::from_secs(1), started);

    // 1.0s warm-up lets TCP slow-start stabilize and cancels initial SO_SNDBUF prefill on upload.
    let warmup_end = Duration::from_secs(1);
    let mut measured_bytes_start: Option<(u64, Instant)> = None;

    while started.elapsed() < duration && !cancel.is_cancelled() {
        let tick_start = Instant::now();
        let probe = probe_once(ping_target, 64, seq, Duration::from_millis(400)).await;
        seq = seq.wrapping_add(1);
        let rtt_ms = probe.rtt_ms();
        loaded_rtts.push(rtt_ms);

        let now = Instant::now();
        let cur_bytes = total_bytes.load(Ordering::Relaxed);
        if started.elapsed() >= warmup_end && measured_bytes_start.is_none() {
            measured_bytes_start = Some((cur_bytes, now));
        }

        let smooth_mbps = smoother.record(now, cur_bytes);
        let sample = SpeedTestSample {
            elapsed_sec: started.elapsed().as_secs_f64(),
            mbps: smooth_mbps,
            loaded_rtt_ms: rtt_ms,
        };
        if is_download {
            let _ = tx.send(SpeedTestEvent::DownloadSample(sample));
        } else {
            let _ = tx.send(SpeedTestEvent::UploadSample(sample));
        }

        let elapsed_tick = tick_start.elapsed();
        if elapsed_tick < Duration::from_millis(250) {
            tokio::time::sleep(Duration::from_millis(250) - elapsed_tick).await;
        }
    }

    let final_bytes = total_bytes.load(Ordering::Relaxed);
    let avg_mbps = match measured_bytes_start {
        Some((start_b, start_t)) => {
            let dt = start_t.elapsed().as_secs_f64().max(0.1);
            (final_bytes.saturating_sub(start_b) as f64 * 8.0) / (dt * 1_000_000.0)
        }
        None => {
            let dt = started.elapsed().as_secs_f64().max(0.1);
            (final_bytes as f64 * 8.0) / (dt * 1_000_000.0)
        }
    };

    local_stop.cancel();
    for h in worker_handles {
        let _ = tokio::time::timeout(Duration::from_millis(500), h).await;
    }

    let phase_err = if final_bytes == 0 {
        let recorded = first_err.lock().ok().and_then(|g| g.clone());
        Some(recorded.unwrap_or_else(|| {
            if is_download {
                "Download transferred 0 bytes — verify connectivity to speed.cloudflare.com".into()
            } else {
                "Upload transferred 0 bytes — verify connectivity to speed.cloudflare.com".into()
            }
        }))
    } else {
        None
    };

    (avg_mbps, loaded_rtts, phase_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bufferbloat_grading_boundaries() {
        assert_eq!(grade_bufferbloat(14.0, 17.5), BufferbloatGrade::APlus);
        assert_eq!(grade_bufferbloat(14.0, 25.0), BufferbloatGrade::A);
        assert_eq!(grade_bufferbloat(14.0, 38.0), BufferbloatGrade::B);
        assert_eq!(grade_bufferbloat(14.0, 65.0), BufferbloatGrade::C);
        assert_eq!(grade_bufferbloat(14.0, 100.0), BufferbloatGrade::D);
        assert_eq!(grade_bufferbloat(14.0, 150.0), BufferbloatGrade::F);
    }

    #[test]
    fn parses_cf_ray_colo() {
        assert_eq!(
            parse_cf_ray_colo("a5f87d2b3943a61b-IST"),
            Some("IST".to_string())
        );
        assert_eq!(
            parse_cf_ray_colo("a5f87d2f5fe8ebdc-ams"),
            Some("AMS".to_string())
        );
        assert_eq!(parse_cf_ray_colo("malformed"), None);
        assert_eq!(parse_cf_ray_colo("1234-99"), None);
    }

    #[test]
    fn sliding_throughput_smooths_bursty_ticks() {
        let t0 = Instant::now();
        let mut s = SlidingThroughput::new(Duration::from_secs(1), t0);
        // 5 MB/s = 40 Mbps steady over 1 second
        let m1 = s.record(t0 + Duration::from_millis(250), 1_250_000);
        let m2 = s.record(t0 + Duration::from_millis(500), 2_500_000);
        let m3 = s.record(t0 + Duration::from_millis(750), 3_750_000);
        let m4 = s.record(t0 + Duration::from_millis(1000), 5_000_000);
        assert!((m1 - 40.0).abs() < 0.5, "m1={m1}");
        assert!((m2 - 40.0).abs() < 0.5, "m2={m2}");
        assert!((m3 - 40.0).abs() < 0.5, "m3={m3}");
        assert!((m4 - 40.0).abs() < 0.5, "m4={m4}");
    }

    #[test]
    fn bufferbloat_workload_evaluation_grades_real_time_apps() {
        let mk_res = |idle: f64, dl: f64, ul: f64| SpeedTestResult {
            timestamp: Utc::now(),
            download_mbps: 100.0,
            upload_mbps: 50.0,
            unloaded_stats: compute_latency_stats(&[Some(idle)]),
            loaded_dl_stats: compute_latency_stats(&[Some(dl)]),
            loaded_ul_stats: compute_latency_stats(&[Some(ul)]),
            bufferbloat_grade: grade_bufferbloat(idle, dl.max(ul)),
            server_colo: Some("IST".into()),
            server_ip: Some("162.159.140.220".parse().unwrap()),
            is_ipv6: false,
        };

        let crisp = evaluate_bufferbloat_workloads(&mk_res(15.0, 18.0, 17.0));
        assert_eq!(crisp.gaming, WorkloadQuality::Smooth);
        assert_eq!(crisp.video_calls, WorkloadQuality::Smooth);
        assert_eq!(crisp.voip, WorkloadQuality::Smooth);

        let mid = evaluate_bufferbloat_workloads(&mk_res(15.0, 42.0, 65.0));
        assert_eq!(mid.gaming, WorkloadQuality::Poor);
        assert_eq!(mid.voip, WorkloadQuality::LagSpikes);
        assert_eq!(mid.video_calls, WorkloadQuality::LagSpikes);
        assert_eq!(mid.web_browsing, WorkloadQuality::Smooth);

        let severe = evaluate_bufferbloat_workloads(&mk_res(15.0, 220.0, 180.0));
        assert_eq!(severe.gaming, WorkloadQuality::Poor);
        assert_eq!(severe.video_calls, WorkloadQuality::Poor);
        assert_eq!(severe.web_browsing, WorkloadQuality::Poor);
        assert!(severe.recommendation.contains("SQM"));
    }

    #[tokio::test]
    #[ignore = "burns live bandwidth (~200 MB); run explicitly with --ignored --nocapture"]
    async fn live_speedtest_smoke_auto() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let cancel = CancelToken::new();
        run_speedtest(IpFamily::Auto, tx, cancel).await;

        let mut ul_pts = Vec::new();
        let mut final_res = None;
        let mut err = None;
        while let Ok(ev) = rx.try_recv() {
            match ev {
                SpeedTestEvent::ServerInfo(info) => {
                    println!("SERVER: {} ({})", info.badge_label(), info.ip);
                }
                SpeedTestEvent::UploadSample(s) => {
                    ul_pts.push((s.elapsed_sec, s.mbps));
                }
                SpeedTestEvent::Completed(r) => {
                    final_res = Some(*r);
                }
                SpeedTestEvent::Error(e) => {
                    err = Some(e);
                }
                _ => {}
            }
        }
        assert!(err.is_none(), "speedtest error: {err:?}");
        let res = final_res.expect("speedtest should produce Completed event");
        println!(
            "RESULT: DL={:.1} Mbps, UL={:.1} Mbps, Idle={:?} ms, DL_RTT={:?} ms, UL_RTT={:?} ms, Grade={}",
            res.download_mbps,
            res.upload_mbps,
            res.unloaded_stats.median_ms,
            res.loaded_dl_stats.median_ms,
            res.loaded_ul_stats.median_ms,
            res.bufferbloat_grade.label()
        );
        let ul_rounded: Vec<f64> = ul_pts.iter().map(|(_, m)| (m * 10.0).round() / 10.0).collect();
        println!("UL SAMPLES: {ul_rounded:?}");
        assert!(res.download_mbps > 50.0, "download too low: {}", res.download_mbps);
        assert!(res.upload_mbps > 15.0, "upload too low: {}", res.upload_mbps);
    }
}
