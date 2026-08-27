//! Immutable run configuration.
//!
//! [`Config`] is built once from the command line, the configuration file and
//! the environment (see [`builder`]) and is then shared, read-only, by every
//! stage of the enumeration. Per-target mutable state lives in
//! [`Session`](crate::session::Session) instead.

pub mod builder;
pub mod settings;

use std::{
    collections::{HashMap, HashSet},
    ops::RangeInclusive,
};

/// Default recursive resolvers used when `--resolvers` is not given, and always
/// used as the trustable set for the double DNS check.
pub const DEFAULT_RESOLVERS: [&str; 14] = [
    // Cloudflare
    "1.1.1.1",
    "1.0.0.1",
    // Google
    "8.8.8.8",
    "8.8.4.4",
    // Quad9
    "9.9.9.9",
    "149.112.112.112",
    // OpenDNS
    "208.67.222.222",
    "208.67.220.220",
    // Verisign
    "64.6.64.6",
    "64.6.65.6",
    // UncensoredDNS
    "91.239.100.100",
    "89.233.43.71",
    // dns.watch
    "84.200.69.80",
    "84.200.70.40",
];

/// Everything the run needs to know, resolved once at startup.
#[derive(Clone, Debug, Default)]
pub struct Config {
    pub general: General,
    pub input: Input,
    pub output: Output,
    pub filters: Filters,
    pub resolution: Resolution,
    pub http: Http,
    pub ports: PortScan,
    pub screenshots: Screenshots,
    pub database: Database,
    pub monitoring: Monitoring,
    pub sources: Sources,
    pub nuclei: Nuclei,
    pub ffuf: Ffuf,
    pub email: Email,
}

impl Config {
    /// Reports whether any per-subdomain network work is requested.
    ///
    /// When false the discovered subdomains are simply printed as they are.
    #[must_use]
    pub const fn needs_network_checks(&self) -> bool {
        self.resolution.discover_ip || self.http.enabled || self.ports.enabled
    }
}

/// Cross-cutting knobs.
#[derive(Clone, Debug)]
pub struct General {
    pub quiet: bool,
    pub verbose: bool,
    pub rate_limit: u64,
    pub lightweight_threads: usize,
}

impl Default for General {
    fn default() -> Self {
        Self {
            quiet: false,
            verbose: false,
            rate_limit: 5,
            lightweight_threads: 50,
        }
    }
}

/// Where the targets and the extra subdomains come from.
#[derive(Clone, Debug, Default)]
pub struct Input {
    /// Single target given with `--target`, empty when absent or invalid.
    pub target: String,
    pub files: Vec<String>,
    pub from_stdin: bool,
    pub import_from: Vec<String>,
    /// Wordlist files; a non empty list enables bruteforce.
    pub wordlists: Vec<String>,
    pub wordlist_words: HashSet<String>,
    pub randomize: bool,
    pub as_resolver: bool,
    pub no_discover: bool,
    pub validate_only: bool,
    pub permutations: bool,
    pub permutation_words: HashSet<String>,
}

impl Input {
    /// Reports whether bruteforce mode is active.
    #[must_use]
    pub fn bruteforce(&self) -> bool {
        !self.wordlists.is_empty()
    }

    /// Reports whether targets come from a list rather than from `--target`.
    #[must_use]
    pub fn from_target_list(&self) -> bool {
        !self.files.is_empty() || self.from_stdin
    }
}

/// Result file handling.
#[derive(Clone, Debug, Default)]
pub struct Output {
    pub enabled: bool,
    pub unique: bool,
    /// Explicit file name; empty means "derive one per target".
    pub file_name: String,
}

/// Keyword based inclusion and exclusion of subdomains.
#[derive(Clone, Debug, Default)]
pub struct Filters {
    pub include: HashSet<String>,
    pub exclude: HashSet<String>,
}

impl Filters {
    /// Reports whether `subdomain` survives the configured keyword filters.
    ///
    /// `include` wins when both are set, matching the historical behaviour.
    #[must_use]
    pub fn accepts(&self, subdomain: &str) -> bool {
        if !self.include.is_empty() {
            self.include.iter().any(|key| subdomain.contains(key))
        } else if !self.exclude.is_empty() {
            !self.exclude.iter().any(|key| subdomain.contains(key))
        } else {
            true
        }
    }

    /// Reports whether every include keyword is also excluded, which can only
    /// ever produce an empty result set.
    #[must_use]
    pub fn are_contradictory(&self) -> bool {
        !self.include.is_empty()
            && !self.exclude.is_empty()
            && self.include.difference(&self.exclude).next().is_none()
    }
}

/// DNS resolution settings.
#[derive(Clone, Debug)]
pub struct Resolution {
    pub discover_ip: bool,
    pub only_resolved: bool,
    pub with_ip: bool,
    pub ipv6_only: bool,
    /// Skip resolution altogether (screenshot only mode).
    pub skip: bool,
    pub timeout: u64,
    /// Resolvers to query, already in `ip:port` form.
    pub resolvers: Vec<String>,
    /// Well known resolvers used to confirm positive answers.
    pub trustable_resolvers: Vec<String>,
    /// Re-check positive answers against [`Self::trustable_resolvers`].
    pub double_check: bool,
    pub wildcard_check: bool,
    pub track_cname: bool,
}

impl Default for Resolution {
    fn default() -> Self {
        Self {
            discover_ip: false,
            only_resolved: false,
            with_ip: false,
            ipv6_only: false,
            skip: false,
            timeout: 3,
            resolvers: default_resolver_addresses(),
            trustable_resolvers: default_resolver_addresses(),
            double_check: false,
            wildcard_check: true,
            track_cname: false,
        }
    }
}

impl Resolution {
    /// Reports whether the DNS resolution stage should run.
    #[must_use]
    pub const fn is_enabled(&self, port_scan: bool) -> bool {
        !self.skip && (port_scan || self.discover_ip)
    }
}

/// Returns [`DEFAULT_RESOLVERS`] as `ip:53` socket addresses.
#[must_use]
pub fn default_resolver_addresses() -> Vec<String> {
    DEFAULT_RESOLVERS
        .iter()
        .map(|ip| format!("{ip}:53"))
        .collect()
}

/// HTTP probing settings.
#[derive(Clone, Debug)]
pub struct Http {
    pub enabled: bool,
    pub timeout: u64,
    pub retries: usize,
    pub max_redirects: usize,
    pub user_agents: Vec<String>,
}

impl Default for Http {
    fn default() -> Self {
        Self {
            enabled: false,
            timeout: 5,
            retries: 2,
            max_redirects: 0,
            user_agents: builder::default_user_agents(),
        }
    }
}

/// TCP port scanning settings.
#[derive(Clone, Debug)]
pub struct PortScan {
    pub enabled: bool,
    /// Explicit range from `--iport`/`--lport`; `None` scans the top 1000.
    pub range: Option<RangeInclusive<u16>>,
    /// Skip service detection and NSE scripts. On by default: the report only
    /// carries port numbers, so the extra probing would be thrown away.
    pub fast_scan: bool,
    /// Use a SYN scan, which needs root.
    pub syn_scan: bool,
    /// nmap `--min-rate`; 0 leaves the decision to nmap.
    pub min_rate: usize,
    /// Seconds nmap may spend on a single host.
    pub host_timeout: u64,
    /// Extra arguments handed to nmap verbatim.
    pub extra_args: Vec<String>,
    /// Seconds the whole scan may take before it is killed.
    pub scan_timeout: u64,
}

impl Default for PortScan {
    fn default() -> Self {
        Self {
            enabled: false,
            range: None,
            fast_scan: true,
            syn_scan: false,
            min_rate: 0,
            host_timeout: 900,
            scan_timeout: 3600,
            extra_args: Vec::new(),
        }
    }
}

/// Vulnerability scanning with nuclei.
#[derive(Clone, Debug)]
pub struct Nuclei {
    pub enabled: bool,
    /// Template path or tag expression; empty leaves nuclei's default set.
    pub templates: String,
    pub severity: String,
    pub tags: String,
    pub exclude_templates: String,
    /// Requests per second; 0 leaves the decision to nuclei.
    pub rate_limit: usize,
    /// Seconds the whole scan may take before it is killed.
    pub timeout: u64,
    /// Extra arguments handed to nuclei verbatim.
    pub extra_args: Vec<String>,
}

impl Default for Nuclei {
    fn default() -> Self {
        Self {
            enabled: false,
            templates: String::new(),
            severity: String::new(),
            tags: String::new(),
            exclude_templates: String::new(),
            rate_limit: 0,
            timeout: 5400,
            extra_args: Vec::new(),
        }
    }
}

/// Content discovery with ffuf.
#[derive(Clone, Debug)]
pub struct Ffuf {
    pub enabled: bool,
    pub wordlist: String,
    pub threads: usize,
    pub recursion: bool,
    pub recursion_depth: usize,
    pub timeout: u64,
    /// Extra arguments handed to ffuf verbatim.
    pub extra_args: Vec<String>,
}

impl Default for Ffuf {
    fn default() -> Self {
        Self {
            enabled: false,
            wordlist: String::new(),
            threads: 40,
            recursion: false,
            recursion_depth: 2,
            timeout: 5400,
            extra_args: Vec::new(),
        }
    }
}

/// SMTP delivery of the monitoring report.
#[derive(Clone, Debug)]
pub struct Email {
    pub server: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub recipients: Vec<String>,
}

impl Default for Email {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 587,
            user: String::new(),
            password: String::new(),
            recipients: Vec::new(),
        }
    }
}

impl Email {
    /// Reports whether enough was configured to send anything.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        !self.server.is_empty() && !self.recipients.is_empty()
    }
}

/// Headless Chrome screenshot settings.
#[derive(Clone, Debug)]
pub struct Screenshots {
    pub enabled: bool,
    pub path: String,
    pub threads: usize,
    pub sandbox: bool,
}

impl Default for Screenshots {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "screenshots".to_owned(),
            threads: 10,
            sandbox: false,
        }
    }
}

/// Where results are persisted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Backend {
    Postgres,
    Sqlite(String),
}

/// Persistence settings.
#[derive(Clone, Debug)]
pub struct Database {
    pub backend: Backend,
    /// libpq connection string, used by the `PostgreSQL` backend.
    pub connection: String,
    /// Label stored next to every row, groups related targets.
    pub jobname: String,
    pub query_by_target: bool,
    pub query_by_jobname: bool,
    pub reset: bool,
}

impl Default for Database {
    fn default() -> Self {
        Self {
            backend: Backend::Sqlite("findomain.db".to_owned()),
            connection: builder::postgres_connection_string(None, None, None, None, None),
            jobname: "findomain".to_owned(),
            query_by_target: false,
            query_by_jobname: false,
            reset: false,
        }
    }
}

impl Database {
    /// Reports whether one of the read-only database queries was requested.
    #[must_use]
    pub const fn is_query(&self) -> bool {
        self.query_by_target || self.query_by_jobname
    }
}

/// Telegram needs both halves of the credentials to build a webhook URL.
#[derive(Clone, Debug)]
pub struct Telegram {
    pub webhook: String,
    pub chat_id: String,
}

/// Monitoring mode and its alerting targets.
#[derive(Clone, Debug, Default)]
pub struct Monitoring {
    /// Compare against the database and alert on new subdomains.
    pub enabled: bool,
    /// Store results in the database without alerting.
    pub no_monitor: bool,
    /// Alert even when nothing new was found.
    pub push_when_empty: bool,
    /// Store results anyway when a webhook times out.
    pub push_on_timeout: bool,
    pub discord_webhook: String,
    pub slack_webhook: String,
    pub telegram: Option<Telegram>,
}

impl Monitoring {
    /// Reports whether results should be persisted to the database.
    #[must_use]
    pub const fn uses_database(&self) -> bool {
        self.enabled || self.no_monitor
    }

    /// Reports whether at least one alerting destination is configured.
    #[must_use]
    pub fn has_webhooks(&self) -> bool {
        !self.discord_webhook.is_empty()
            || !self.slack_webhook.is_empty()
            || self.telegram.is_some()
    }
}

/// Which discovery sources to use and how to authenticate against them.
#[derive(Clone, Debug)]
pub struct Sources {
    pub excluded: HashSet<String>,
    pub tokens: ApiTokens,
    /// Seconds any single source request may take.
    pub timeout: u64,
    /// Seconds the whole discovery phase may spend, or 0 for no limit.
    pub budget: u64,
    /// Seconds the archive indexes may spend, or 0 to hold them to `budget`.
    pub archive_budget: u64,
}

impl Default for Sources {
    fn default() -> Self {
        Self {
            excluded: HashSet::new(),
            tokens: ApiTokens::default(),
            timeout: builder::DEFAULT_SOURCE_TIMEOUT,
            budget: builder::DEFAULT_SOURCE_BUDGET,
            archive_budget: builder::DEFAULT_ARCHIVE_BUDGET,
        }
    }
}

impl Sources {
    /// Reports whether the source identified by `id` should run.
    #[must_use]
    pub fn is_enabled(&self, id: &str) -> bool {
        !self.excluded.contains(id)
    }
}

/// Settings key holding the credentials of each source.
///
/// The names of the older entries predate the `<id>_api_key` convention and
/// are kept so that existing configuration files keep working.
pub const CREDENTIAL_KEYS: &[(&str, &str)] = &[
    ("alienvault", "alienvault_api_key"),
    ("bevigil", "bevigil_api_key"),
    ("binaryedge", "binaryedge_api_key"),
    ("bufferover_free", "bufferover_free_api_key"),
    ("bufferover_paid", "bufferover_paid_api_key"),
    ("builtwith", "builtwith_api_key"),
    ("c99", "c99_api_key"),
    ("certspotter", "certspotter_token"),
    ("chaos", "chaos_api_key"),
    ("deepinfo", "deepinfo_api_key"),
    ("dnsdb", "dnsdb_api_key"),
    ("dnsrepo", "dnsrepo_api_key"),
    ("facebook", "fb_token"),
    ("fullhunt", "fullhunt_api_key"),
    ("hackertarget", "hackertarget_api_key"),
    ("hunter", "hunter_api_key"),
    ("leakix", "leakix_api_key"),
    ("netlas", "netlas_api_key"),
    ("onyphe", "onyphe_api_key"),
    ("securitytrails", "securitytrails_token"),
    ("shodan", "shodan_api_key"),
    ("socradar", "socradar_api_key"),
    ("threatbook", "threatbook_api_key"),
    ("virustotalapikey", "virustotal_token"),
    ("whoisxmlapi", "whoisxmlapi_api_key"),
    ("zetalytics", "zetalytics_api_key"),
    ("zoomeye", "zoomeye_api_key"),
    ("ahrefs", "ahrefs_api_key"),
    ("censys", "censys_api_key"),
    ("certcentral", "certcentral_api_key"),
    ("circl", "circl_api_key"),
    ("detectify", "detectify_api_key"),
    ("dnslytics", "dnslytics_api_key"),
    ("fofa", "fofa_api_key"),
    ("intelx", "intelx_api_key"),
    ("passivedns360", "passivedns360_api_key"),
    ("passivetotal", "passivetotal_api_key"),
    ("pentesttools", "pentesttools_api_key"),
    ("publicwww", "publicwww_api_key"),
    ("pulsedive", "pulsedive_api_key"),
    ("quake", "quake_api_key"),
    ("spamhaus", "spamhaus_api_key"),
];

/// Credentials configured for each source, keyed by source identifier.
///
/// Every source accepts a comma separated list so that several keys can be
/// rotated through across targets.
#[derive(Clone, Debug, Default)]
pub struct ApiTokens(HashMap<&'static str, Vec<String>>);

impl ApiTokens {
    pub fn set(&mut self, id: &'static str, tokens: Vec<String>) {
        if !tokens.is_empty() {
            self.0.insert(id, tokens);
        }
    }

    /// Returns the credentials configured for `id`, empty when there are none.
    #[must_use]
    pub fn get(&self, id: &str) -> &[String] {
        self.0.get(id).map_or(&[], Vec::as_slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keywords(values: &[&str]) -> HashSet<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn no_filters_accepts_everything() {
        let filters = Filters::default();
        assert!(filters.accepts("anything.example.com"));
    }

    #[test]
    fn include_keeps_only_matching_subdomains() {
        let filters = Filters {
            include: keywords(&["dev", "stage"]),
            exclude: HashSet::new(),
        };
        assert!(filters.accepts("dev.example.com"));
        assert!(filters.accepts("stage.example.com"));
        assert!(!filters.accepts("prod.example.com"));
    }

    #[test]
    fn exclude_drops_matching_subdomains() {
        let filters = Filters {
            include: HashSet::new(),
            exclude: keywords(&["prod"]),
        };
        assert!(filters.accepts("dev.example.com"));
        assert!(!filters.accepts("prod.example.com"));
    }

    #[test]
    fn include_takes_precedence_over_exclude() {
        let filters = Filters {
            include: keywords(&["dev"]),
            exclude: keywords(&["example"]),
        };
        assert!(filters.accepts("dev.example.com"));
        assert!(!filters.accepts("prod.example.com"));
    }

    #[test]
    fn contradictory_filters_are_detected() {
        assert!(Filters {
            include: keywords(&["dev"]),
            exclude: keywords(&["dev"]),
        }
        .are_contradictory());

        assert!(Filters {
            include: keywords(&["dev"]),
            exclude: keywords(&["dev", "prod"]),
        }
        .are_contradictory());

        assert!(!Filters {
            include: keywords(&["dev", "stage"]),
            exclude: keywords(&["dev"]),
        }
        .are_contradictory());

        assert!(!Filters::default().are_contradictory());
    }

    #[test]
    fn the_port_scan_defaults_to_a_fast_unprivileged_sweep() {
        let scan = PortScan::default();
        assert!(scan.range.is_none(), "no range means nmap's top ports");
        assert!(scan.fast_scan, "service detection is opt in");
        assert!(!scan.syn_scan, "a SYN scan would need root");
    }

    #[test]
    fn an_explicit_port_range_is_kept_inclusive() {
        let scan = PortScan {
            range: Some(80..=83),
            ..PortScan::default()
        };
        let range = scan.range.expect("a range was set");
        assert_eq!((*range.start(), *range.end()), (80, 83));
    }

    #[test]
    fn default_resolvers_get_the_dns_port() {
        let resolvers = default_resolver_addresses();
        assert_eq!(resolvers.len(), DEFAULT_RESOLVERS.len());
        assert!(resolvers.iter().all(|r| r.ends_with(":53")));
        assert_eq!(resolvers[0], "1.1.1.1:53");
    }

    #[test]
    fn resolution_is_skipped_when_nothing_needs_an_ip() {
        let resolution = Resolution::default();
        assert!(!resolution.is_enabled(false));
        assert!(resolution.is_enabled(true));

        let skipped = Resolution {
            skip: true,
            discover_ip: true,
            ..Resolution::default()
        };
        assert!(!skipped.is_enabled(true));
    }
}
