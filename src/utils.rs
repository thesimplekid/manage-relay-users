use std::time::SystemTime;

/// Seconds since 1970.
#[must_use]
pub fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|x| x.as_secs())
        .unwrap_or(0)
}
