/// Parse the unread count from a Zalo Web document title like "(3) Zalo" or
/// "[3] Zalo". Zalo Web's exact title format has not been verified against a live
/// account, so both bracket styles are accepted; the page bridge also logs the
/// title's *shape* (digits masked) so the format can be confirmed from a log.
/// Returns 0 when there is no leading "(n)" / "[n]" group.
pub fn parse_unread(title: &str) -> u32 {
    let t = title.trim_start();
    let Some(rest) = t.strip_prefix('(').or_else(|| t.strip_prefix('[')) else {
        return 0;
    };
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::parse_unread;

    #[test]
    fn no_parentheses_is_zero() {
        assert_eq!(parse_unread("Zalo"), 0);
    }

    #[test]
    fn simple_count() {
        assert_eq!(parse_unread("(3) Zalo"), 3);
    }

    #[test]
    fn leading_whitespace_ok() {
        assert_eq!(parse_unread("  (12) Zalo"), 12);
    }

    #[test]
    fn plus_suffix_takes_digits() {
        assert_eq!(parse_unread("(99+) Zalo"), 99);
    }

    #[test]
    fn square_brackets_count() {
        assert_eq!(parse_unread("[7] Zalo"), 7);
        assert_eq!(parse_unread("[x] Zalo"), 0);
    }

    #[test]
    fn zero_count() {
        assert_eq!(parse_unread("(0) Zalo"), 0);
    }

    #[test]
    fn malformed_is_zero() {
        assert_eq!(parse_unread("(abc) Zalo"), 0);
        assert_eq!(parse_unread(""), 0);
        assert_eq!(parse_unread("()"), 0);
    }
}
