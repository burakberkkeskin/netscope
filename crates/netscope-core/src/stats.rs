use serde::{Deserialize, Serialize};

/// Aggregated latency and loss statistics over a series of probe samples.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct LatencyStats {
    pub sent: usize,
    pub received: usize,
    pub lost: usize,
    pub loss_pct: f64,
    pub min_ms: Option<f64>,
    pub median_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub stdev_ms: Option<f64>,
}

/// Computes `LatencyStats` from optional round-trip time samples (`Some(ms)` or `None` for timeout).
pub fn compute_latency_stats(samples: &[Option<f64>]) -> LatencyStats {
    let sent = samples.len();
    let mut rtts: Vec<f64> = samples.iter().filter_map(|s| *s).collect();
    let received = rtts.len();
    let lost = sent.saturating_sub(received);
    let loss_pct = if sent == 0 {
        0.0
    } else {
        (lost as f64 / sent as f64) * 100.0
    };

    if received == 0 {
        return LatencyStats {
            sent,
            received,
            lost,
            loss_pct,
            ..Default::default()
        };
    }

    let sum: f64 = rtts.iter().sum();
    let avg = sum / received as f64;

    // Mean absolute difference between consecutive received samples (jitter)
    let jitter = if received >= 2 {
        let mut diffs_sum = 0.0;
        let mut diffs_count = 0usize;
        let mut prev: Option<f64> = None;
        for s in samples.iter().flatten() {
            if let Some(p) = prev {
                diffs_sum += (*s - p).abs();
                diffs_count += 1;
            }
            prev = Some(*s);
        }
        if diffs_count > 0 {
            Some(diffs_sum / diffs_count as f64)
        } else {
            None
        }
    } else {
        Some(0.0)
    };

    let variance = if received >= 2 {
        rtts.iter().map(|v| (*v - avg).powi(2)).sum::<f64>() / (received as f64 - 1.0)
    } else {
        0.0
    };
    let stdev = variance.sqrt();

    rtts.sort_by(|a, b| a.total_cmp(b));
    let min = rtts.first().copied();
    let max = rtts.last().copied();
    let median = if received % 2 == 1 {
        Some(rtts[received / 2])
    } else {
        Some((rtts[received / 2 - 1] + rtts[received / 2]) / 2.0)
    };

    LatencyStats {
        sent,
        received,
        lost,
        loss_pct,
        min_ms: min,
        median_ms: median,
        avg_ms: Some(avg),
        max_ms: max,
        jitter_ms: jitter,
        stdev_ms: Some(stdev),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_samples() {
        let s = compute_latency_stats(&[]);
        assert_eq!(s.sent, 0);
        assert_eq!(s.received, 0);
        assert_eq!(s.loss_pct, 0.0);
        assert!(s.median_ms.is_none());
    }

    #[test]
    fn all_lost_samples() {
        let s = compute_latency_stats(&[None, None, None]);
        assert_eq!(s.sent, 3);
        assert_eq!(s.received, 0);
        assert_eq!(s.lost, 3);
        assert!((s.loss_pct - 100.0).abs() < 1e-6);
        assert!(s.avg_ms.is_none());
    }

    #[test]
    fn mixed_samples_odd_received() {
        let s = compute_latency_stats(&[Some(10.0), None, Some(20.0), Some(14.0)]);
        assert_eq!(s.sent, 4);
        assert_eq!(s.received, 3);
        assert_eq!(s.lost, 1);
        assert!((s.loss_pct - 25.0).abs() < 1e-6);
        assert_eq!(s.min_ms, Some(10.0));
        assert_eq!(s.median_ms, Some(14.0));
        assert_eq!(s.max_ms, Some(20.0));
        assert!((s.avg_ms.unwrap() - 14.666666).abs() < 1e-4);
        // Consecutive received diffs: |20-10| = 10, |14-20| = 6 -> jitter = 8.0
        assert!((s.jitter_ms.unwrap() - 8.0).abs() < 1e-6);
    }

    #[test]
    fn even_received_median() {
        let s = compute_latency_stats(&[Some(2.0), Some(4.0), Some(10.0), Some(12.0)]);
        assert_eq!(s.median_ms, Some(7.0));
    }
}
