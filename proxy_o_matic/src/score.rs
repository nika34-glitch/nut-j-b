use serde::{Serialize, Deserialize};

/// Metrics measured for a proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    pub success: bool,
    pub tcp_connect_ms: i64,
    pub tls_handshake_ms: i64,
    pub first_byte_ms: i64,
    pub throughput_kbps: f64,
    pub error: String,
    pub timestamp: i64,
}

/// Compute score from averages and counts.
pub fn compute_score(avg_rtt_ms: f64, avg_throughput_kbps: f64, success_ratio: f64, hours_since_last_success: f64) -> f64 {
    use std::f64::consts::LOG10_E;
    let mut base = 100f64;
    if avg_rtt_ms > 0.0 {
        base -= avg_rtt_ms.log10() * 10.0;
    }
    if avg_throughput_kbps > 0.0 {
        base += avg_throughput_kbps.log10();
    }
    base += success_ratio * 40.0;
    let decay_penalty = hours_since_last_success * 2.0;
    let score = base - decay_penalty;
    score.clamp(0.0, 100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_bounds() {
        let s = compute_score(100.0, 1000.0, 1.0, 0.0);
        assert!(s <= 100.0 && s >= 0.0);
    }
}
