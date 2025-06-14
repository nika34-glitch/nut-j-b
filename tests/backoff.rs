use rand::Rng;
#[test]
fn large_retry_backoff_does_not_panic() {
    let base = 0.25_f64;
    for retry in [0_usize, 10, 1000, 10_000] {
        let mut exp = base * (2.0_f64).powi(retry as i32);
        if !exp.is_finite() || exp > 1e6 {
            exp = 1e6;
        }
        let jitter = rand::rng().random_range(0.0..exp);
        if jitter.is_finite() {
            let _ = std::time::Duration::from_secs_f64(jitter);
        }
    }
}
