//! Fan-out over the passive discovery sources.
//!
//! Every enabled source runs on its own thread against a shared HTTP client;
//! results are merged, lowercased and validated against the target before
//! being handed back.

use {
    crate::{
        config::{Config, CREDENTIAL_KEYS},
        filters::validate_subdomain,
        sources::{self, crtsh, BufferoverTier, SourceContext},
        utils::random_from,
    },
    std::{collections::HashSet, thread},
};

/// A single source ready to run, borrowing the target and its credentials.
type Job<'a> = Box<dyn FnOnce(&SourceContext) -> Option<HashSet<String>> + Send + 'a>;

/// Runs every enabled source against `target`.
///
/// Failures are contained per source: a dead API contributes nothing instead
/// of aborting the enumeration.
#[must_use]
pub fn search(config: &Config, target: &str) -> HashSet<String> {
    let context = SourceContext::new(config);
    let context = &context;

    // Deduplicated as the sources are joined rather than after: the raw union
    // repeats heavily, and a busy domain would otherwise hold every copy.
    let mut subdomains: HashSet<String> = thread::scope(|scope| {
        let handles: Vec<_> = jobs(config, target)
            .into_iter()
            .map(|job| scope.spawn(move || job(context)))
            .collect();

        handles
            .into_iter()
            .filter_map(|handle| handle.join().ok().flatten())
            .flatten()
            .map(|mut subdomain| {
                // Hostnames are case insensitive, and validation below drops
                // anything non-ASCII, so lowercasing in place is enough.
                subdomain.make_ascii_lowercase();
                subdomain
            })
            .collect()
    });

    let base_target = format!(".{target}");
    subdomains
        .retain(|subdomain| validate_subdomain(&base_target, target, subdomain, &config.filters));

    if !config.general.quiet {
        println!();
    }

    subdomains
}

/// A source that only needs the target.
type PlainSource = fn(&SourceContext, &str) -> Option<HashSet<String>>;

/// A source that also takes a credential, which may be an empty string when
/// the service works unauthenticated.
type KeyedSource = fn(&SourceContext, &str, &str) -> Option<HashSet<String>>;

/// Sources reachable without any credential.
const PLAIN_SOURCES: &[(&str, PlainSource)] = &[
    ("crtsh", crtsh::subdomains),
    ("crtname", sources::crtname),
    ("anubis", sources::anubisdb),
    ("arquivo", sources::arquivo),
    ("sublist3r", sources::sublist3r),
    ("threatminer", sources::threatminer),
    ("ukwebarchive", sources::uk_web_archive),
    ("subdomaincenter", sources::subdomain_center),
    ("mnemonic", sources::mnemonic),
    ("maltiverse", sources::maltiverse),
    ("urlscan", sources::urlscan),
    ("wayback", sources::wayback),
    ("commoncrawl", sources::commoncrawl),
];

/// Sources that take a credential.
///
/// The flag marks the ones that only ever answer with an error when no
/// credential is configured; the rest take one to lift their quota.
const KEYED_SOURCES: &[(&str, KeyedSource, bool)] = &[
    ("certspotter", sources::certspotter, false),
    ("hackertarget", sources::hackertarget, false),
    ("alienvault", sources::alienvault, true),
    ("bevigil", sources::bevigil, true),
    ("binaryedge", sources::binaryedge, true),
    ("builtwith", sources::builtwith, true),
    ("bufferover_free", bufferover_free, true),
    ("bufferover_paid", bufferover_paid, true),
    ("c99", sources::c99, true),
    ("chaos", sources::chaos, true),
    ("deepinfo", sources::deepinfo, true),
    ("dnsdb", sources::dnsdb, true),
    ("dnsrepo", sources::dnsrepo, true),
    ("facebook", sources::facebook, true),
    ("fullhunt", sources::fullhunt, true),
    ("hunter", sources::hunter, true),
    ("leakix", sources::leakix, true),
    ("netlas", sources::netlas, true),
    ("onyphe", sources::onyphe, true),
    ("securitytrails", sources::securitytrails, true),
    ("shodan", sources::shodan, true),
    ("socradar", sources::socradar, true),
    ("threatbook", sources::threatbook, true),
    ("virustotalapikey", sources::virustotal, true),
    ("whoisxmlapi", sources::whoisxmlapi, true),
    ("zetalytics", sources::zetalytics, true),
    ("zoomeye", sources::zoomeye, true),
    ("ahrefs", sources::ahrefs, true),
    ("censys", sources::censys, true),
    ("certcentral", sources::certcentral, true),
    ("circl", sources::circl, true),
    ("detectify", sources::detectify, true),
    ("dnslytics", sources::dnslytics, true),
    ("fofa", sources::fofa, true),
    ("intelx", sources::intelx, true),
    ("passivedns360", sources::passivedns360, true),
    ("passivetotal", sources::passivetotal, true),
    ("pentesttools", sources::pentesttools, true),
    ("publicwww", sources::publicwww, true),
    ("pulsedive", sources::pulsedive, true),
    ("quake", sources::quake, true),
    ("spamhaus", sources::spamhaus, true),
];

/// Builds the list of sources to run, skipping the excluded ones and those
/// missing the credentials they require.
fn jobs<'a>(config: &'a Config, target: &'a str) -> Vec<Job<'a>> {
    let sources = &config.sources;
    let tokens = &sources.tokens;
    let mut jobs: Vec<Job<'a>> = Vec::with_capacity(PLAIN_SOURCES.len() + KEYED_SOURCES.len());

    for (id, source) in PLAIN_SOURCES {
        if sources.is_enabled(id) {
            jobs.push(Box::new(move |context| source(context, target)));
        }
    }

    for (id, source, requires_key) in KEYED_SOURCES {
        let keys = tokens.get(id);
        if !sources.is_enabled(id) || (*requires_key && keys.is_empty()) {
            continue;
        }
        let token = random_from(keys);
        jobs.push(Box::new(move |context| source(context, target, &token)));
    }

    jobs
}

/// Adapts the free `BufferOver` tier to the shared keyed-source signature.
fn bufferover_free(
    context: &SourceContext,
    target: &str,
    api_key: &str,
) -> Option<HashSet<String>> {
    sources::bufferover(context, target, BufferoverTier::Free, api_key)
}

/// Adapts the paid `BufferOver` tier to the shared keyed-source signature.
fn bufferover_paid(
    context: &SourceContext,
    target: &str,
    api_key: &str,
) -> Option<HashSet<String>> {
    sources::bufferover(context, target, BufferoverTier::Paid, api_key)
}

/// One source that takes a credential, and what is configured for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyEntry {
    pub source: &'static str,
    /// Key in the configuration file.
    pub setting: &'static str,
    /// Environment variable that sets the same thing.
    pub env: String,
    /// Credentials configured for it; several can be rotated through.
    pub configured: usize,
    /// Whether the source answers nothing without one.
    pub required: bool,
}

/// Reports whether `id` only ever answers with an error when no credential
/// is configured.
fn requires_key(id: &str) -> bool {
    KEYED_SOURCES
        .iter()
        .any(|(source, _, required)| *source == id && *required)
}

/// Every source that takes a credential, with what is configured for it.
///
/// Only counts, never values: this exists to be printed, and a terminal
/// scrollback or a CI log is no place for forty API keys.
#[must_use]
pub fn key_inventory(config: &Config) -> Vec<KeyEntry> {
    let mut entries: Vec<KeyEntry> = CREDENTIAL_KEYS
        .iter()
        .map(|(source, setting)| KeyEntry {
            source,
            setting,
            env: format!("FINDOMAIN_{}", setting.to_uppercase()),
            configured: config.sources.tokens.get(source).len(),
            required: requires_key(source),
        })
        .collect();
    entries.sort_unstable_by_key(|entry| entry.source);
    entries
}

/// Every source identifier accepted by `--exclude-sources`.
#[must_use]
pub fn all_source_ids() -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = PLAIN_SOURCES
        .iter()
        .map(|(id, _)| *id)
        .chain(KEYED_SOURCES.iter().map(|(id, _, _)| *id))
        .collect();
    ids.sort_unstable();
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_excluding(excluded: &[&str]) -> Config {
        let mut config = Config::default();
        config.sources.excluded = excluded.iter().map(|id| (*id).to_owned()).collect();
        config
    }

    /// Sources that run with no configuration at all.
    fn default_source_count() -> usize {
        PLAIN_SOURCES.len() + KEYED_SOURCES.iter().filter(|(_, _, req)| !req).count()
    }

    #[test]
    fn credential_free_sources_are_scheduled_by_default() {
        assert_eq!(
            jobs(&config_excluding(&[]), "example.com").len(),
            default_source_count()
        );
    }

    #[test]
    fn excluded_sources_are_not_scheduled() {
        let config = config_excluding(&["crtsh", "urlscan", "wayback", "certspotter"]);
        assert_eq!(
            jobs(&config, "example.com").len(),
            default_source_count() - 4
        );
    }

    #[test]
    fn a_configured_credential_enables_its_source() {
        let mut config = config_excluding(&[]);
        let baseline = jobs(&config, "example.com").len();

        // Required credential: the source appears only once it is configured.
        config.sources.tokens.set("shodan", vec!["key".to_owned()]);
        assert_eq!(jobs(&config, "example.com").len(), baseline + 1);

        config.sources.tokens.set("netlas", vec!["key".to_owned()]);
        assert_eq!(jobs(&config, "example.com").len(), baseline + 2);

        // Excluding it wins over having a key.
        config.sources.excluded = HashSet::from(["netlas".to_owned()]);
        assert_eq!(jobs(&config, "example.com").len(), baseline + 1);
    }

    #[test]
    fn an_optional_credential_does_not_gate_the_source() {
        let mut config = config_excluding(&[]);
        let baseline = jobs(&config, "example.com").len();

        // These two run with or without a key, so the count must not move.
        config
            .sources
            .tokens
            .set("certspotter", vec!["key".to_owned()]);
        config
            .sources
            .tokens
            .set("hackertarget", vec!["key".to_owned()]);
        assert_eq!(jobs(&config, "example.com").len(), baseline);
    }

    #[test]
    fn the_key_inventory_covers_every_credential_and_knows_which_are_required() {
        let inventory = key_inventory(&Config::default());
        assert_eq!(inventory.len(), CREDENTIAL_KEYS.len());
        assert!(
            inventory
                .windows(2)
                .all(|pair| pair[0].source < pair[1].source),
            "sorted by source"
        );

        let entry = |id: &str| inventory.iter().find(|e| e.source == id).expect(id).clone();
        assert!(entry("shodan").required);
        // These two run without a key and only use one to lift their quota.
        assert!(!entry("certspotter").required);
        assert!(!entry("hackertarget").required);

        assert_eq!(entry("shodan").setting, "shodan_api_key");
        assert_eq!(entry("shodan").env, "FINDOMAIN_SHODAN_API_KEY");
        assert!(inventory.iter().all(|e| e.configured == 0));
    }

    #[test]
    fn configured_keys_are_counted_not_carried() {
        let mut config = Config::default();
        config.sources.tokens.set(
            "netlas",
            vec!["one".to_owned(), "two".to_owned(), "three".to_owned()],
        );
        let entry = key_inventory(&config)
            .into_iter()
            .find(|e| e.source == "netlas")
            .expect("netlas");
        assert_eq!(entry.configured, 3);
        assert!(!format!("{entry:?}").contains("one"), "no value leaks");
    }

    #[test]
    fn every_source_identifier_is_unique() {
        let ids = all_source_ids();
        let mut unique = ids.clone();
        unique.dedup();
        assert_eq!(unique.len(), ids.len(), "duplicate source identifier");
    }

    #[test]
    fn every_credentialed_source_can_be_configured() {
        let configurable: HashSet<&str> = CREDENTIAL_KEYS.iter().map(|(id, _)| *id).collect();

        for (id, _, _) in KEYED_SOURCES {
            assert!(
                configurable.contains(id),
                "{id} takes a credential but has no configuration key"
            );
        }
    }

    #[test]
    fn every_configuration_key_belongs_to_a_real_source() {
        let ids: HashSet<&str> = all_source_ids().into_iter().collect();
        for (id, setting) in CREDENTIAL_KEYS {
            assert!(ids.contains(id), "{setting} configures unknown source {id}");
        }
    }
}
