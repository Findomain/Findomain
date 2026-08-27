//! Candidate hostnames derived from the ones already discovered.
//!
//! Enumeration finds `dev.example.com`; permutation asks whether
//! `dev-staging.example.com`, `staging.dev.example.com` or `dev2.example.com`
//! also exist. The names generated here are guesses, so they are only worth
//! producing when the run resolves them.

use std::collections::HashSet;

/// Separators tried between an existing label and a wordlist entry.
const JOINERS: [&str; 3] = ["-", ".", ""];

/// Largest number a trailing counter is incremented to.
const MAX_COUNTER: u32 = 9;

/// How many candidates one subdomain and one word produce.
///
/// Three joiners, each tried with the word before and after the label.
const VARIANTS_PER_PAIR: usize = JOINERS.len() * 2;

/// Number of candidates `generate` would produce before deduplication.
///
/// Grows as subdomains times words times [`VARIANTS_PER_PAIR`], so a few
/// thousand hosts against an ordinary wordlist reaches tens of millions.
#[must_use]
pub fn projected(subdomains: usize, words: usize) -> usize {
    subdomains
        .saturating_mul(words)
        .saturating_mul(VARIANTS_PER_PAIR)
        .saturating_add(subdomains.saturating_mul(MAX_COUNTER as usize))
}

/// Builds permutations of `subdomains` under `target` using `words`.
///
/// Names already present in `subdomains`, and the apex itself, are never
/// returned: the caller would just resolve what it already has.
#[must_use]
pub fn generate(
    subdomains: &HashSet<String>,
    target: &str,
    words: &HashSet<String>,
) -> HashSet<String> {
    let suffix = format!(".{target}");
    let mut generated = HashSet::new();

    for subdomain in subdomains {
        let Some(prefix) = subdomain.strip_suffix(&suffix) else {
            continue;
        };
        if prefix.is_empty() {
            continue;
        }

        for word in words {
            if word.is_empty() {
                continue;
            }
            for joiner in JOINERS {
                generated.insert(format!("{word}{joiner}{prefix}{suffix}"));
                generated.insert(format!("{prefix}{joiner}{word}{suffix}"));
            }
        }

        generated.extend(counter_variants(prefix, &suffix));
    }

    generated.retain(|candidate| !subdomains.contains(candidate) && candidate != target);
    generated
}

/// Produces `dev1`, `dev2`, ... from `dev`, and neighbours of `dev3`.
fn counter_variants(prefix: &str, suffix: &str) -> HashSet<String> {
    let stem = prefix.trim_end_matches(|c: char| c.is_ascii_digit());
    if stem.is_empty() {
        return HashSet::new();
    }

    (1..=MAX_COUNTER)
        .map(|counter| format!("{stem}{counter}{suffix}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_projection_matches_what_is_generated() {
        let subs = set(&["a.example.com", "b.example.com"]);
        let words = set(&["dev", "test"]);
        let generated = generate(&subs, "example.com", &words);
        // The projection counts before deduplication, so it is an upper bound.
        assert!(generated.len() <= projected(subs.len(), words.len()));
        assert_eq!(projected(2, 2), 2 * 2 * 6 + 2 * 9);
    }

    #[test]
    fn the_projection_saturates_instead_of_wrapping() {
        assert_eq!(projected(usize::MAX, usize::MAX), usize::MAX);
    }

    fn set(values: &[&str]) -> HashSet<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn combines_each_word_with_each_label() {
        let generated = generate(&set(&["dev.example.com"]), "example.com", &set(&["api"]));

        for expected in [
            "api-dev.example.com",
            "api.dev.example.com",
            "apidev.example.com",
            "dev-api.example.com",
            "dev.api.example.com",
            "devapi.example.com",
        ] {
            assert!(generated.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn adds_numbered_variants() {
        let generated = generate(&set(&["dev.example.com"]), "example.com", &HashSet::new());
        assert!(generated.contains("dev1.example.com"));
        assert!(generated.contains("dev9.example.com"));
        assert!(!generated.contains("dev0.example.com"));
    }

    #[test]
    fn renumbers_a_label_that_already_ends_in_digits() {
        let generated = generate(&set(&["web3.example.com"]), "example.com", &HashSet::new());
        assert!(generated.contains("web1.example.com"));
        assert!(generated.contains("web2.example.com"));
        // The input itself is never handed back.
        assert!(!generated.contains("web3.example.com"));
    }

    #[test]
    fn keeps_deeper_labels_intact() {
        let generated = generate(&set(&["a.b.example.com"]), "example.com", &set(&["x"]));
        assert!(generated.contains("x-a.b.example.com"));
        assert!(generated.contains("a.b-x.example.com"));
    }

    #[test]
    fn never_returns_something_already_known() {
        let known = set(&["dev.example.com", "dev1.example.com", "api-dev.example.com"]);
        let generated = generate(&known, "example.com", &set(&["api"]));

        for name in &known {
            assert!(!generated.contains(name), "{name} was regenerated");
        }
    }

    #[test]
    fn never_returns_the_apex() {
        let generated = generate(&set(&["dev.example.com"]), "example.com", &set(&[""]));
        assert!(!generated.contains("example.com"));
    }

    #[test]
    fn ignores_hosts_of_another_target() {
        let generated = generate(&set(&["dev.other.com"]), "example.com", &set(&["api"]));
        assert!(generated.is_empty());
    }

    #[test]
    fn ignores_the_apex_as_an_input() {
        let generated = generate(&set(&["example.com"]), "example.com", &set(&["api"]));
        assert!(generated.is_empty());
    }

    #[test]
    fn an_all_digit_label_gets_no_counter_variants() {
        let generated = generate(&set(&["123.example.com"]), "example.com", &HashSet::new());
        assert!(generated.is_empty());
    }

    #[test]
    fn no_input_means_no_output() {
        assert!(generate(&HashSet::new(), "example.com", &set(&["api"])).is_empty());
    }

    #[test]
    fn every_candidate_stays_under_the_target() {
        let generated = generate(
            &set(&["dev.example.com", "api.example.com"]),
            "example.com",
            &set(&["stage", "test"]),
        );
        assert!(!generated.is_empty());
        assert!(generated
            .iter()
            .all(|candidate| candidate.ends_with(".example.com")));
    }
}
