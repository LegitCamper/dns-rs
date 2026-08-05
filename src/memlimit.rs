use tracing::warn;

/// Explicit override, highest precedence — for platforms where you want to
/// set/adjust the cache budget without touching the rest of config.
pub const CACHE_MAX_BYTES_ENV: &str = "DNS_RS_CACHE_MAX_BYTES";

/// Used when nothing else (env var, explicit `[cache].max_size_bytes`, or a
/// detected cgroup limit) applies — same value this crate has always
/// defaulted to.
const DEFAULT_CACHE_MAX_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB

/// Share of a detected cgroup memory limit given to the response cache when
/// nothing more specific is configured. Leaves the rest of the container's
/// budget for everything else the process needs: the blocklist set, tokio,
/// connection buffers. Only kicks in when a real (non-"max"/unlimited) limit
/// is found, which in practice means "running in a memory-capped
/// container" — a bare-metal/systemd self-hosted install typically has no
/// cgroup memory limit at all, so this is a no-op there and
/// `DEFAULT_CACHE_MAX_BYTES` applies exactly as it always has.
const CGROUP_CACHE_FRACTION: f64 = 0.7;

/// cgroup v1's "unlimited" sentinel for `memory.limit_in_bytes` is a huge
/// number (`LONG_MAX` rounded down to the page size), not a real limit.
const V1_UNLIMITED_THRESHOLD: u64 = 1 << 62;

/// Resolves the cache byte budget: env var override, else the explicit
/// config value, else a share of a detected cgroup memory limit, else the
/// fixed fallback.
pub fn resolve_cache_max_bytes(explicit: Option<u64>) -> u64 {
    decide(parse_env_cache_max_bytes(), explicit, detect_cgroup_memory_limit())
}

fn decide(env: Option<u64>, explicit: Option<u64>, cgroup_limit: Option<u64>) -> u64 {
    env.or(explicit)
        .or_else(|| cgroup_limit.map(|limit| (limit as f64 * CGROUP_CACHE_FRACTION) as u64))
        .unwrap_or(DEFAULT_CACHE_MAX_BYTES)
}

fn parse_env_cache_max_bytes() -> Option<u64> {
    let raw = std::env::var(CACHE_MAX_BYTES_ENV).ok()?;
    match raw.trim().parse::<u64>() {
        Ok(bytes) => Some(bytes),
        Err(err) => {
            warn!(error = %err, value = %raw, "{CACHE_MAX_BYTES_ENV} is not a valid byte count, ignoring");
            None
        }
    }
}

fn detect_cgroup_memory_limit() -> Option<u64> {
    if let Ok(content) = std::fs::read_to_string("/sys/fs/cgroup/memory.max") {
        return parse_cgroup_v2(&content);
    }
    if let Ok(content) = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes") {
        return parse_cgroup_v1(&content);
    }
    None
}

fn parse_cgroup_v2(content: &str) -> Option<u64> {
    let trimmed = content.trim();
    if trimmed == "max" {
        return None;
    }
    trimmed.parse().ok()
}

fn parse_cgroup_v1(content: &str) -> Option<u64> {
    let value: u64 = content.trim().parse().ok()?;
    if value >= V1_UNLIMITED_THRESHOLD { None } else { Some(value) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_max_is_unbounded() {
        assert_eq!(parse_cgroup_v2("max\n"), None);
    }

    #[test]
    fn v2_numeric_limit_parses() {
        assert_eq!(parse_cgroup_v2("536870912\n"), Some(536870912));
    }

    #[test]
    fn v1_huge_sentinel_is_unbounded() {
        assert_eq!(parse_cgroup_v1("9223372036854771712\n"), None);
    }

    #[test]
    fn v1_numeric_limit_parses() {
        assert_eq!(parse_cgroup_v1("268435456\n"), Some(268435456));
    }

    #[test]
    fn decide_prefers_env_over_everything() {
        assert_eq!(decide(Some(111), Some(222), Some(1_000_000_000)), 111);
    }

    #[test]
    fn decide_prefers_explicit_over_cgroup() {
        assert_eq!(decide(None, Some(222), Some(1_000_000_000)), 222);
    }

    #[test]
    fn decide_uses_cgroup_fraction_when_nothing_explicit() {
        assert_eq!(decide(None, None, Some(1_000_000_000)), 700_000_000);
    }

    #[test]
    fn decide_falls_back_to_default_when_nothing_detected() {
        assert_eq!(decide(None, None, None), DEFAULT_CACHE_MAX_BYTES);
    }
}
