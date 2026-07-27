/// Normalizes a DNS name for use as a lookup key: lowercased, with exactly
/// one trailing dot (the canonical wire-format style), and no leading dot.
pub fn normalize_name(name: &str) -> String {
    let trimmed = name.trim().trim_end_matches('.').trim_start_matches('.');
    if trimmed.is_empty() {
        return ".".to_string();
    }
    let mut normalized = trimmed.to_ascii_lowercase();
    normalized.push('.');
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_and_trailing_dot() {
        assert_eq!(normalize_name("Example.COM"), "example.com.");
        assert_eq!(normalize_name("example.com."), "example.com.");
        assert_eq!(normalize_name("example.com"), "example.com.");
        assert_eq!(normalize_name(""), ".");
        assert_eq!(normalize_name("."), ".");
    }
}
