use crate::CancelToken;
use crate::icmp::probe_once;
use crate::stats::{LatencyStats, compute_latency_stats};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

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
    PhaseChanged(SpeedTestPhase),
    IdleSample(f64),
    DownloadSample(SpeedTestSample),
    UploadSample(SpeedTestSample),
    Completed(Box<SpeedTestResult>),
    Error(String),
}

pub async fn run_speedtest(tx: mpsc::UnboundedSender<SpeedTestEvent>, cancel: CancelToken) {
    crate::ensure_crypto_provider();
    let ping_target: IpAddr = "1.1.1.1".parse().unwrap();

    // 1. Unloaded latency baseline (10 probes)
    let _ = tx.send(SpeedTestEvent::PhaseChanged(SpeedTestPhase::IdleLatency));
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
        tokio::time::sleep(Duration::from_millis(60)).await;
    }
    let unloaded_stats = compute_latency_stats(&idle_samples);

    // 2. 4-Stream Download + concurrent loaded ping
    let _ = tx.send(SpeedTestEvent::PhaseChanged(SpeedTestPhase::Download));
    let (dl_mbps, dl_rtts) =
        run_parallel_transfer(true, ping_target, Duration::from_secs(8), &tx, &cancel).await;
    if cancel.is_cancelled() {
        return;
    }
    let loaded_dl_stats = compute_latency_stats(&dl_rtts);

    // 3. 4-Stream Upload + concurrent loaded ping
    let _ = tx.send(SpeedTestEvent::PhaseChanged(SpeedTestPhase::Upload));
    let (ul_mbps, ul_rtts) =
        run_parallel_transfer(false, ping_target, Duration::from_secs(8), &tx, &cancel).await;
    if cancel.is_cancelled() {
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
    })));
}

async fn run_parallel_transfer(
    is_download: bool,
    ping_target: IpAddr,
    duration: Duration,
    tx: &mpsc::UnboundedSender<SpeedTestEvent>,
    cancel: &CancelToken,
) -> (f64, Vec<Option<f64>>) {
    let total_bytes = Arc::new(AtomicU64::new(0));
    let local_stop = CancelToken::new();
    let started = Instant::now();

    let mut worker_handles = Vec::with_capacity(4);
    let payload_chunk = Arc::new(vec![0x5Au8; 1024 * 1024]); // 1 MiB chunk

    for _ in 0..4 {
        let bytes_counter = total_bytes.clone();
        let worker_stop = local_stop.clone();
        let global_cancel = cancel.clone();
        let chunk = payload_chunk.clone();

        worker_handles.push(tokio::spawn(async move {
            // Separate HTTP/1.1 clients ensure 4 distinct parallel TCP connections.
            let Ok(client) = reqwest::Client::builder()
                .http1_only()
                .timeout(Duration::from_secs(10))
                .user_agent("NetScope/0.1")
                .build()
            else {
                return;
            };

            while !worker_stop.is_cancelled()
                && !global_cancel.is_cancelled()
                && started.elapsed() < duration
            {
                if is_download {
                    let Ok(mut resp) = client
                        .get("https://speed.cloudflare.com/__down?bytes=25000000")
                        .send()
                        .await
                    else {
                        tokio::time::sleep(Duration::from_millis(150)).await;
                        continue;
                    };
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
                } else {
                    let body = chunk.as_ref().clone();
                    match client
                        .post("https://speed.cloudflare.com/__up")
                        .body(body)
                        .send()
                        .await
                    {
                        Ok(resp) if resp.status().is_success() => {
                            bytes_counter.fetch_add(chunk.len() as u64, Ordering::Relaxed);
                        }
                        _ => {
                            tokio::time::sleep(Duration::from_millis(150)).await;
                        }
                    }
                }
            }
        }));
    }

    let mut loaded_rtts = Vec::new();
    let mut prev_bytes = 0u64;
    let mut prev_time = Instant::now();
    let mut seq = 100u16;

    // Warm-up 400ms before scoring final average so TCP slow-start doesn't skew results
    let warmup_end = Duration::from_millis(500);
    let mut measured_bytes_start: Option<(u64, Instant)> = None;

    while started.elapsed() < duration && !cancel.is_cancelled() {
        let tick_start = Instant::now();
        let probe = probe_once(ping_target, 64, seq, Duration::from_millis(450)).await;
        seq = seq.wrapping_add(1);
        let rtt_ms = probe.rtt_ms();
        loaded_rtts.push(rtt_ms);

        let now = Instant::now();
        let cur_bytes = total_bytes.load(Ordering::Relaxed);
        if started.elapsed() >= warmup_end && measured_bytes_start.is_none() {
            measured_bytes_start = Some((cur_bytes, now));
        }

        let dt = now.duration_since(prev_time).as_secs_f64().max(0.05);
        let delta_b = cur_bytes.saturating_sub(prev_bytes);
        let inst_mbps = (delta_b as f64 * 8.0) / (dt * 1_000_000.0);
        prev_bytes = cur_bytes;
        prev_time = now;

        let sample = SpeedTestSample {
            elapsed_sec: started.elapsed().as_secs_f64(),
            mbps: inst_mbps,
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

    local_stop.cancel();
    for h in worker_handles {
        let _ = tokio::time::timeout(Duration::from_millis(600), h).await;
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

    (avg_mbps, loaded_rtts)
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
    fn bufferbloat_workload_evaluation_grades_real_time_apps() {
        let mk_res = |idle: f64, dl: f64, ul: f64| SpeedTestResult {
            timestamp: Utc::now(),
            download_mbps: 100.0,
            upload_mbps: 50.0,
            unloaded_stats: compute_latency_stats(&[Some(idle)]),
            loaded_dl_stats: compute_latency_stats(&[Some(dl)]),
            loaded_ul_stats: compute_latency_stats(&[Some(ul)]),
            bufferbloat_grade: grade_bufferbloat(idle, dl.max(ul)),
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
}
