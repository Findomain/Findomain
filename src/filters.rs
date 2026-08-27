//! Validation of targets and of the subdomains reported by the sources.

use {crate::config::Filters, addr::parse_domain_name};

/// Bytes allowed in a hostname: letters, digits, `-`, `.` and `_`.
///
/// Underscores are not valid in hostnames proper but do occur in real DNS
/// names such as `_dmarc`. Anything else is rejected here; a linear scan over
/// a blacklist of punctuation used to cost far more per name.
const fn allowed_table() -> [bool; 256] {
    let mut table = [false; 256];
    let mut byte = 0usize;
    while byte < 256 {
        let value = byte as u8;
        table[byte] =
            value.is_ascii_alphanumeric() || value == b'-' || value == b'.' || value == b'_';
        byte += 1;
    }
    table
}

static ALLOWED_BYTE: [bool; 256] = allowed_table();

/// Reports whether every byte of `name` can appear in a hostname.
fn has_only_host_bytes(name: &str) -> bool {
    name.as_bytes()
        .iter()
        .all(|byte| ALLOWED_BYTE[*byte as usize])
}

/// Reports whether `target` is a syntactically valid, enumerable domain.
#[must_use]
pub fn validate_target(target: &str) -> bool {
    !target.starts_with('.')
        && target.contains('.')
        && has_only_host_bytes(target)
        && parse_domain_name(target).is_ok()
}

/// Reports whether `subdomain` belongs to `target` and passes `filters`.
///
/// `base_target` is the target prefixed with a dot, precomputed by the caller
/// because this runs once per discovered subdomain.
#[must_use]
pub fn validate_subdomain(
    base_target: &str,
    target: &str,
    subdomain: &str,
    filters: &Filters,
) -> bool {
    !subdomain.is_empty()
        && !subdomain.starts_with('.')
        && (subdomain.ends_with(base_target) || subdomain == target)
        && has_only_host_bytes(subdomain)
        && filters.accepts(subdomain)
        && parse_domain_name(subdomain).is_ok()
}

#[cfg(test)]
mod tests {
    use {super::*, std::collections::HashSet};

    #[test]
    fn accepts_ordinary_domains() {
        assert!(validate_target("example.com"));
        assert!(validate_target("sub.example.com"));
        assert!(validate_target("example.co.uk"));
        assert!(validate_target("xn--80ak6aa92e.com"));
    }

    #[test]
    fn rejects_malformed_targets() {
        assert!(!validate_target(""));
        assert!(!validate_target("example"));
        assert!(!validate_target(".example.com"));
        assert!(!validate_target("not_a_domain"));
        assert!(!validate_target("exa mple.com"));
        assert!(!validate_target("example.com/path"));
        assert!(!validate_target("*.example.com"));
        assert!(!validate_target("ejemplo.com¿"));
        assert!(!validate_target("exämple.com"));
    }

    fn unfiltered() -> Filters {
        Filters::default()
    }

    #[test]
    fn accepts_subdomains_of_the_target() {
        let filters = unfiltered();
        assert!(validate_subdomain(
            ".example.com",
            "example.com",
            "a.example.com",
            &filters
        ));
        assert!(validate_subdomain(
            ".example.com",
            "example.com",
            "a.b.example.com",
            &filters
        ));
        // The apex itself counts as a result.
        assert!(validate_subdomain(
            ".example.com",
            "example.com",
            "example.com",
            &filters
        ));
    }

    #[test]
    fn rejects_subdomains_of_other_targets() {
        let filters = unfiltered();
        assert!(!validate_subdomain(
            ".example.com",
            "example.com",
            "a.other.com",
            &filters
        ));
        // A suffix match must land on a dot boundary.
        assert!(!validate_subdomain(
            ".example.com",
            "example.com",
            "notexample.com",
            &filters
        ));
        assert!(!validate_subdomain(
            ".example.com",
            "example.com",
            "",
            &filters
        ));
        assert!(!validate_subdomain(
            ".example.com",
            "example.com",
            ".example.com",
            &filters
        ));
        assert!(!validate_subdomain(
            ".example.com",
            "example.com",
            "*.example.com",
            &filters
        ));
    }

    #[test]
    fn applies_the_keyword_filters() {
        let include = Filters {
            include: HashSet::from(["dev".to_owned()]),
            exclude: HashSet::new(),
        };
        assert!(validate_subdomain(
            ".example.com",
            "example.com",
            "dev.example.com",
            &include
        ));
        assert!(!validate_subdomain(
            ".example.com",
            "example.com",
            "prod.example.com",
            &include
        ));
    }
}
