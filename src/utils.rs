//! Small helpers shared across modules.

use {
    rand::seq::IndexedRandom,
    std::io::{self, Read},
};

const SCHEMES: [&str; 2] = ["https://", "http://"];

/// Reduces a user supplied target to a bare hostname.
///
/// Strips a URL scheme, a leading `www.` label and anything from the first
/// path separator onwards, so that `https://www.example.com/a/b` becomes
/// `example.com`.
#[must_use]
pub fn sanitize_target_string(target: &str) -> String {
    let host = sanitize_host_string(target);
    host.strip_prefix("www.").unwrap_or(&host).to_owned()
}

/// Reduces a user supplied hostname to its bare form.
///
/// Keeps every label: unlike a target, `www.example.com` is a hostname worth
/// reporting on its own. Everything else that real input carries is shed,
/// because validation rejects the whole name over any of it: surrounding
/// whitespace, a URL scheme, a path, a port, and the trailing dot that DNS
/// tooling writes on a fully qualified name.
#[must_use]
pub fn sanitize_host_string(value: &str) -> String {
    let mut host = value.trim();
    for scheme in SCHEMES {
        if let Some(stripped) = host.strip_prefix(scheme) {
            host = stripped;
            break;
        }
    }
    host = host.split('/').next().unwrap_or_default();
    host = host.split(':').next().unwrap_or_default();
    host.trim_end_matches('.').to_owned()
}

/// Reads every line from stdin, sorted and deduplicated.
///
/// Bytes that are not valid text are replaced rather than rejected, so one
/// stray line cannot cost the whole list; what survives still has to pass
/// hostname validation.
#[must_use]
pub fn read_stdin() -> Vec<String> {
    let mut buffer = Vec::new();
    if let Err(e) = io::stdin().read_to_end(&mut buffer) {
        eprintln!("Error reading the input list: {e}");
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&buffer);
    let mut targets: Vec<String> = text.lines().map(str::to_owned).collect();
    targets.sort();
    targets.dedup();
    targets
}

/// Picks one of `strings` at random, or an empty string when there is none.
#[must_use]
pub fn random_from(strings: &[String]) -> String {
    strings
        .choose(&mut rand::rng())
        .cloned()
        .unwrap_or_default()
}

/// Splits `string` into chunks of at most `len` bytes, never cutting a line.
///
/// Used to fit alert payloads into the per-message limits of the webhooks. A
/// single line longer than `len` is emitted whole, because there is no safe
/// place to break it.
#[must_use]
pub fn split_string_at_len(string: &str, len: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = String::new();
    for line in string.split('\n') {
        if current.len() + line.len() + 1 > len {
            chunks.push(current);
            current = String::new();
        }
        current.push_str(line);
        current.push('\n');
    }
    chunks.push(current);
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hostname_survives_what_real_input_carries() {
        // Each of these used to be dropped whole by validation.
        for (given, want) in [
            ("  b.example.com  ", "b.example.com"),
            ("c.example.com\t", "c.example.com"),
            ("https://a.example.com:8443/path", "a.example.com"),
            ("http://d.example.com:80", "d.example.com"),
            ("e.example.com.", "e.example.com"),
            ("f.example.com", "f.example.com"),
            ("www.g.example.com", "www.g.example.com"),
        ] {
            assert_eq!(sanitize_host_string(given), want, "input: {given:?}");
        }
    }

    #[test]
    fn a_target_loses_its_leading_www_as_well() {
        assert_eq!(
            sanitize_target_string("https://www.example.com:443/x/y"),
            "example.com"
        );
        assert_eq!(sanitize_target_string("  example.com.  "), "example.com");
        assert_eq!(sanitize_target_string("www.example.com"), "example.com");
        // Only the leading label goes; an inner www is part of the name.
        assert_eq!(
            sanitize_target_string("a.www.example.com"),
            "a.www.example.com"
        );
    }

    #[test]
    fn sanitize_strips_scheme_www_and_path() {
        assert_eq!(sanitize_target_string("example.com"), "example.com");
        assert_eq!(sanitize_target_string("www.example.com"), "example.com");
        assert_eq!(
            sanitize_target_string("https://www.example.com/"),
            "example.com"
        );
        assert_eq!(
            sanitize_target_string("http://example.com/a/b?c=d"),
            "example.com"
        );
        assert_eq!(sanitize_target_string("example.com/"), "example.com");
    }

    #[test]
    fn host_sanitising_keeps_every_label() {
        assert_eq!(sanitize_host_string("www.example.com"), "www.example.com");
        assert_eq!(
            sanitize_host_string("https://www.shop.example.com/cart"),
            "www.shop.example.com"
        );
        assert_eq!(sanitize_host_string("a.example.com"), "a.example.com");
    }

    #[test]
    fn sanitize_only_strips_a_leading_www_label() {
        // The old implementation replaced every occurrence of "www.".
        assert_eq!(
            sanitize_target_string("mywww.example.com"),
            "mywww.example.com"
        );
        assert_eq!(
            sanitize_target_string("sub.www.example.com"),
            "sub.www.example.com"
        );
    }

    #[test]
    fn sanitize_keeps_inner_dashes_and_digits() {
        assert_eq!(
            sanitize_target_string("https://my-host1.example.com"),
            "my-host1.example.com"
        );
    }

    #[test]
    fn random_from_handles_the_empty_pool() {
        assert_eq!(random_from(&[]), "");
        assert_eq!(random_from(&["only".to_owned()]), "only");
    }

    #[test]
    fn split_keeps_chunks_under_the_limit() {
        let text = (1..=10)
            .map(|i| format!("line{i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let chunks = split_string_at_len(&text, 20);
        assert!(chunks.len() > 1);
        assert!(chunks.iter().all(|chunk| chunk.len() <= 20));
        let rejoined: String = chunks.concat();
        for i in 1..=10 {
            assert!(rejoined.contains(&format!("line{i}")));
        }
    }

    #[test]
    fn split_never_breaks_a_single_long_line() {
        let long = "x".repeat(50);
        let chunks = split_string_at_len(&long, 10);
        assert!(chunks.iter().any(|chunk| chunk.trim() == long));
    }

    #[test]
    fn split_of_an_empty_string_yields_one_chunk() {
        assert_eq!(split_string_at_len("", 10), vec!["\n".to_owned()]);
    }
}
