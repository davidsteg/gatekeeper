//! Timestamps in the formats the Python code wrote.

use chrono::{Local, Utc};

/// `time.strftime("%Y-%m-%dT%H:%M:%S%z")` -- local time, as in audit lines.
pub fn now_local_iso() -> String {
    Local::now().format("%Y-%m-%dT%H:%M:%S%z").to_string()
}

/// `datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z")`.
pub fn now_utc_iso() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S%z").to_string()
}

/// `time.time()`.
pub fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// `time.monotonic()`.
pub fn monotonic() -> f64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_secs_f64() + 1.0
}
