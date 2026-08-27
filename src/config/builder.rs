//! Turns the parsed [`Cli`] plus the [`Settings`] into a [`Config`].
//!
//! Precedence is always: command line flag, then configuration file or
//! environment variable, then the built-in default.

use {
    super::{
        default_resolver_addresses, settings::Settings, ApiTokens, Backend, Config, Database,
        Email, Ffuf, Filters, General, Http, Input, Monitoring, Nuclei, Output, PortScan,
        Resolution, Screenshots, Sources, Telegram, CREDENTIAL_KEYS,
    },
    crate::{
        cli::Cli,
        errors::fatal,
        files::{self, LineKind},
        filters::validate_target,
        utils::sanitize_target_string,
    },
    std::{
        collections::HashSet,
        fs::File,
        io::{BufRead, BufReader},
        path::Path,
    },
};

/// Default concurrency for IP discovery and HTTP checks.
const DEFAULT_LIGHTWEIGHT_THREADS: usize = 50;
/// Default number of concurrent headless browsers.
const DEFAULT_SCREENSHOTS_THREADS: usize = 10;
/// Default seconds nmap may spend on one host.
const DEFAULT_HOST_TIMEOUT: u64 = 900;
/// Default seconds a whole external scan may take.
const DEFAULT_SCAN_TIMEOUT: u64 = 3600;
/// Default seconds nuclei and ffuf may each run for.
const DEFAULT_TOOL_TIMEOUT: u64 = 5400;
/// Default concurrent ffuf requests.
const DEFAULT_FFUF_THREADS: usize = 40;
/// Default SMTP submission port.
const DEFAULT_SMTP_PORT: u16 = 587;
/// Default per-query DNS timeout, in seconds.
const DEFAULT_RESOLVER_TIMEOUT: u64 = 3;
/// Default number of HTTP retries per host.
const DEFAULT_HTTP_RETRIES: usize = 2;
/// Default HTTP request timeout, in seconds.
const DEFAULT_HTTP_TIMEOUT: u64 = 5;
/// Default number of redirects followed by the HTTP check.
const DEFAULT_MAX_HTTP_REDIRECTS: usize = 0;
/// Default seconds a single discovery request may take.
///
/// Generous on purpose: the archive indexes answer a mid sized domain with
/// megabytes of URLs and legitimately need tens of seconds to send them. What
/// keeps a run short is the budget below, not this.
pub(super) const DEFAULT_SOURCE_TIMEOUT: u64 = 30;
/// Default seconds the whole discovery phase may spend querying sources.
///
/// Sources run in parallel, so this is the wall clock of the search rather than
/// a sum, and it is deliberately far above what a healthy run needs: a real
/// search settles in about twenty seconds. This is the backstop for a source
/// that hangs, not the thing that decides how long a run takes. Sources that
/// cannot stop on their own are held to their own much tighter limit instead,
/// so raising this one never has to mean waiting for them.
pub(super) const DEFAULT_SOURCE_BUDGET: u64 = 300;
/// Default seconds the archive indexes may spend.
///
/// Far below the global budget because these are the only sources that cannot
/// stop on their own. See `ARCHIVE_BUDGET` in `sources` for why.
pub(super) const DEFAULT_ARCHIVE_BUDGET: u64 = 20;
/// Where results go when no database was named.
const DEFAULT_SQLITE_PATH: &str = "findomain.db";
/// Default pause between targets, in seconds.
const DEFAULT_RATE_LIMIT: u64 = 5;
/// Default first port when only `--lport` is given.
const DEFAULT_INITIAL_PORT: u16 = 1;
/// Default last port when only `--iport` is given.
const DEFAULT_LAST_PORT: u16 = 1000;

impl Config {
    /// Builds the run configuration, terminating the process on invalid input.
    #[must_use]
    pub fn from_cli(cli: &Cli) -> Self {
        let settings = Settings::load(cli.config_file.as_deref());
        Self::build(cli, &settings)
    }

    /// Builds the run configuration from already loaded settings.
    #[must_use]
    pub fn build(cli: &Cli, settings: &Settings) -> Self {
        // `--enable-dot` is meaningless without a resolution mode.
        if cli.enable_dot && !(cli.ip || cli.ipv6_only || cli.resolved) {
            fatal("Error: --enable-dot flag needs -i/--ip or -r/--resolved");
        }

        Self {
            general: general(cli, settings),
            input: input(cli, settings),
            output: output(cli),
            filters: filters(cli),
            resolution: resolution(cli, settings),
            http: http(cli, settings),
            ports: ports(cli, settings),
            screenshots: screenshots(cli, settings),
            database: database(cli, settings),
            monitoring: monitoring(cli, settings),
            sources: sources(cli, settings),
            nuclei: nuclei(cli, settings),
            ffuf: ffuf(cli, settings),
            email: email(cli, settings),
        }
    }
}

fn general(cli: &Cli, settings: &Settings) -> General {
    General {
        quiet: cli.quiet,
        verbose: cli.verbose,
        rate_limit: cli
            .rate_limit
            .unwrap_or_else(|| settings.parse("rate_limit", DEFAULT_RATE_LIMIT)),
        lightweight_threads: lightweight_threads(cli, settings),
    }
}

fn input(cli: &Cli, settings: &Settings) -> Input {
    let target = sanitize_target_string(cli.target.as_deref().unwrap_or_default());

    Input {
        target: if validate_target(&target) {
            target
        } else {
            String::new()
        },
        files: cli.files.clone(),
        from_stdin: cli.stdin,
        import_from: {
            let mut paths = cli.import_subdomains.clone();
            paths.extend(settings.list::<Vec<String>>("import_subdomains_from"));
            paths
        },
        wordlist_words: if cli.wordlists.is_empty() {
            HashSet::new()
        } else {
            files::read_lines(&cli.wordlists, LineKind::Raw, cli.quiet)
                .into_iter()
                .collect()
        },
        wordlists: cli.wordlists.clone(),
        randomize: cli.randomize || settings.parse("randomize", false),
        as_resolver: cli.as_resolver,
        no_discover: cli.no_discover,
        validate_only: cli.validate_subdomains,
        permutations: cli.permutations || !cli.permutations_wordlist.is_empty(),
        permutation_words: if cli.permutations_wordlist.is_empty() {
            HashSet::new()
        } else {
            files::read_lines(&cli.permutations_wordlist, LineKind::Raw, cli.quiet)
                .into_iter()
                .collect()
        },
    }
}

fn output(cli: &Cli) -> Output {
    Output {
        enabled: cli.output || cli.unique_output.is_some(),
        unique: cli.unique_output.is_some(),
        file_name: output_file_name(cli.output, cli.target.as_deref(), cli.unique_output.clone()),
    }
}

fn filters(cli: &Cli) -> Filters {
    Filters {
        include: cli.string_filter.iter().cloned().collect(),
        exclude: cli.string_exclude.iter().cloned().collect(),
    }
}

fn resolution(cli: &Cli, settings: &Settings) -> Resolution {
    Resolution {
        discover_ip: cli.ip || cli.resolved || cli.ipv6_only,
        only_resolved: cli.resolved,
        with_ip: cli.ip,
        ipv6_only: cli.ipv6_only,
        skip: cli.no_resolve,
        timeout: cli
            .resolver_timeout
            .unwrap_or_else(|| settings.parse("resolver_timeout", DEFAULT_RESOLVER_TIMEOUT)),
        resolvers: resolver_addresses(&cli.custom_resolvers, cli.quiet),
        trustable_resolvers: default_resolver_addresses(),
        double_check: cli.enable_double_dns_check,
        wildcard_check: !cli.no_wildcards,
        track_cname: cli.cname,
    }
}

fn http(cli: &Cli, settings: &Settings) -> Http {
    Http {
        // These all work from the live URL the HTTP check discovers.
        enabled: cli.http_status
            || cli.screenshots_path.is_some()
            || cli.nuclei
            || cli.nuclei_templates.is_some()
            || cli.ffuf
            || cli.ffuf_wordlist.is_some(),
        timeout: cli
            .http_timeout
            .unwrap_or_else(|| settings.parse("http_timeout", DEFAULT_HTTP_TIMEOUT)),
        retries: cli
            .http_retries
            .unwrap_or_else(|| settings.parse("http_retries", DEFAULT_HTTP_RETRIES)),
        max_redirects: cli
            .max_http_redirects
            .unwrap_or_else(|| settings.parse("max_http_redirects", DEFAULT_MAX_HTTP_REDIRECTS)),
        user_agents: user_agents(cli.user_agents_file.clone(), settings),
    }
}

fn ports(cli: &Cli, settings: &Settings) -> PortScan {
    let custom_range = cli.initial_port.is_some() || cli.last_port.is_some();

    PortScan {
        // So that `--nmap-full` on its own is not a silent no-op.
        enabled: cli.port_scan || custom_range || cli.nmap_full || cli.nmap_syn,
        range: custom_range.then(|| {
            cli.initial_port.unwrap_or(DEFAULT_INITIAL_PORT)
                ..=cli.last_port.unwrap_or(DEFAULT_LAST_PORT)
        }),
        fast_scan: !cli.nmap_full,
        syn_scan: cli.nmap_syn,
        min_rate: cli
            .min_rate
            .unwrap_or_else(|| settings.parse("nmap_min_rate", 0)),
        host_timeout: cli
            .nmap_host_timeout
            .unwrap_or_else(|| settings.parse("nmap_host_timeout", DEFAULT_HOST_TIMEOUT)),
        scan_timeout: settings.parse("nmap_timeout", DEFAULT_SCAN_TIMEOUT),
        extra_args: extra_args(&cli.nmap_args, settings, "nmap_args"),
    }
}

fn nuclei(cli: &Cli, settings: &Settings) -> Nuclei {
    Nuclei {
        enabled: cli.nuclei || cli.nuclei_templates.is_some(),
        templates: cli
            .nuclei_templates
            .clone()
            .unwrap_or_else(|| settings.string("nuclei_templates", "")),
        severity: cli
            .nuclei_severity
            .clone()
            .unwrap_or_else(|| settings.string("nuclei_severity", "")),
        tags: cli
            .nuclei_tags
            .clone()
            .unwrap_or_else(|| settings.string("nuclei_tags", "")),
        exclude_templates: cli
            .nuclei_exclude_templates
            .clone()
            .unwrap_or_else(|| settings.string("nuclei_exclude_templates", "")),
        rate_limit: cli
            .nuclei_rate_limit
            .unwrap_or_else(|| settings.parse("nuclei_rate_limit", 0)),
        timeout: settings.parse("nuclei_timeout", DEFAULT_TOOL_TIMEOUT),
        extra_args: extra_args(&cli.nuclei_args, settings, "nuclei_args"),
    }
}

fn ffuf(cli: &Cli, settings: &Settings) -> Ffuf {
    Ffuf {
        enabled: cli.ffuf || cli.ffuf_wordlist.is_some(),
        wordlist: cli
            .ffuf_wordlist
            .clone()
            .unwrap_or_else(|| settings.string("ffuf_wordlist", "")),
        threads: cli
            .ffuf_threads
            .unwrap_or_else(|| settings.parse("ffuf_threads", DEFAULT_FFUF_THREADS)),
        recursion: cli.ffuf_recursion,
        recursion_depth: cli
            .ffuf_recursion_depth
            .unwrap_or_else(|| settings.parse("ffuf_recursion_depth", 2)),
        timeout: settings.parse("ffuf_timeout", DEFAULT_TOOL_TIMEOUT),
        extra_args: extra_args(&cli.ffuf_args, settings, "ffuf_args"),
    }
}

fn email(cli: &Cli, settings: &Settings) -> Email {
    Email {
        server: cli
            .smtp_server
            .clone()
            .unwrap_or_else(|| settings.string("smtp_server", "")),
        port: cli
            .smtp_port
            .unwrap_or_else(|| settings.parse("smtp_port", DEFAULT_SMTP_PORT)),
        user: cli
            .smtp_user
            .clone()
            .unwrap_or_else(|| settings.string("smtp_user", "")),
        password: cli
            .smtp_password
            .clone()
            .unwrap_or_else(|| settings.string("smtp_password", "")),
        recipients: if cli.email_to.is_empty() {
            settings.list("email_to")
        } else {
            cli.email_to.clone()
        },
    }
}

fn screenshots(cli: &Cli, settings: &Settings) -> Screenshots {
    Screenshots {
        enabled: cli.screenshots_path.is_some(),
        path: cli
            .screenshots_path
            .clone()
            .unwrap_or_else(|| "screenshots".to_owned()),
        threads: cli
            .screenshots_threads
            .unwrap_or_else(|| settings.parse("screenshots_threads", DEFAULT_SCREENSHOTS_THREADS)),
        sandbox: cli.sandbox,
    }
}

fn database(cli: &Cli, settings: &Settings) -> Database {
    Database {
        backend: backend(cli, settings),
        connection: settings.string(
            "postgres_connection",
            &postgres_connection_string(
                cli.postgres_user.clone(),
                cli.postgres_password.clone(),
                cli.postgres_host.clone(),
                cli.postgres_port,
                cli.postgres_database.clone(),
            ),
        ),
        jobname: cli
            .jobname
            .clone()
            .unwrap_or_else(|| settings.string("jobname", "findomain")),
        query_by_target: cli.query_database,
        query_by_jobname: cli.query_jobname,
        reset: cli.reset_database,
    }
}

fn monitoring(cli: &Cli, settings: &Settings) -> Monitoring {
    Monitoring {
        enabled: cli.monitoring_flag,
        no_monitor: cli.no_monitor || settings.parse("no_monitor", false),
        push_when_empty: cli.enable_empty_push,
        push_on_timeout: cli.dbpush_if_timeout || settings.parse("dbpush_if_timeout", false),
        discord_webhook: settings.string("discord_webhook", ""),
        slack_webhook: settings.string("slack_webhook", ""),
        telegram: telegram(settings),
    }
}

fn sources(cli: &Cli, settings: &Settings) -> Sources {
    Sources {
        excluded: if cli.exclude_sources.is_empty() {
            settings.list("exclude_sources")
        } else {
            cli.exclude_sources.iter().cloned().collect()
        },
        timeout: cli
            .source_timeout
            .unwrap_or_else(|| settings.parse("source_timeout", DEFAULT_SOURCE_TIMEOUT))
            .max(1),
        budget: cli
            .source_budget
            .unwrap_or_else(|| settings.parse("source_budget", DEFAULT_SOURCE_BUDGET)),
        archive_budget: cli
            .archive_budget
            .unwrap_or_else(|| settings.parse("archive_budget", DEFAULT_ARCHIVE_BUDGET)),
        tokens: {
            let mut tokens = ApiTokens::default();
            for (id, setting) in CREDENTIAL_KEYS {
                tokens.set(id, settings.list(setting));
            }
            tokens
        },
    }
}

/// Resolves the output file name from the mutually exclusive `-o`/`-u` flags.
///
/// An empty name means "derive one per target while walking a target list".
fn output_file_name(auto: bool, target: Option<&str>, unique: Option<String>) -> String {
    match (auto, target, unique) {
        (true, Some(target), _) => format!("{}.txt", sanitize_target_string(target)),
        (_, _, Some(unique)) => unique,
        _ => String::new(),
    }
}

/// Applies the `--lightweight-threads` / deprecated `--threads` fallback chain.
///
/// The result is never zero: the resolver and HTTP stages feed it straight to
/// `buffer_unordered`, which with a limit of zero polls nothing and leaves the
/// stream pending forever.
fn lightweight_threads(cli: &Cli, settings: &Settings) -> usize {
    cli.lightweight_threads
        .or(cli.threads)
        .or_else(|| settings.get("lightweight_threads"))
        .or_else(|| settings.get("threads"))
        .unwrap_or(DEFAULT_LIGHTWEIGHT_THREADS)
        .max(1)
}

/// Reads the resolver IPs and turns them into `ip:53` socket addresses.
///
/// `--resolvers` takes paths to files holding one IP per line; without it the
/// built-in [`DEFAULT_RESOLVERS`] are used. An entry that already names a port
/// keeps it, so a resolver on anything other than 53 can be reached.
fn resolver_addresses(resolver_files: &[String], quiet: bool) -> Vec<String> {
    if resolver_files.is_empty() {
        return default_resolver_addresses();
    }
    files::read_lines(resolver_files, LineKind::Raw, quiet)
        .iter()
        .map(|ip| {
            if ip.contains(':') {
                ip.clone()
            } else {
                format!("{ip}:53")
            }
        })
        .collect()
}

/// Chooses where results are stored.
///
/// SQLite unless the run names a `PostgreSQL` server, because it needs no
/// service to be running and covers what most people do with the database.
/// Naming any `PostgreSQL` setting, on the command line or in the
/// configuration file, is what asks for the server instead.
fn backend(cli: &Cli, settings: &Settings) -> Backend {
    if let Some(path) = cli
        .sqlite
        .clone()
        .or_else(|| settings.get::<String>("sqlite_path"))
    {
        return Backend::Sqlite(path);
    }

    let postgres_requested = cli.postgres_user.is_some()
        || cli.postgres_password.is_some()
        || cli.postgres_host.is_some()
        || cli.postgres_port.is_some()
        || cli.postgres_database.is_some()
        || settings.get::<String>("postgres_connection").is_some();

    if postgres_requested {
        Backend::Postgres
    } else {
        Backend::Sqlite(DEFAULT_SQLITE_PATH.to_owned())
    }
}

/// Extra arguments for an external tool, from the command line or the file.
///
/// The command line replaces the configured list rather than adding to it, so
/// a run can drop what the file sets without editing the file.
fn extra_args(from_cli: &[String], settings: &Settings, key: &str) -> Vec<String> {
    if from_cli.is_empty() {
        settings.args(key)
    } else {
        from_cli.to_vec()
    }
}

/// Assembles the libpq connection string from its individual parts.
#[must_use]
pub fn postgres_connection_string(
    user: Option<String>,
    password: Option<String>,
    host: Option<String>,
    port: Option<usize>,
    database: Option<String>,
) -> String {
    format!(
        "postgresql://{}:{}@{}:{}/{}",
        user.unwrap_or_else(|| "postgres".to_owned()),
        password.unwrap_or_else(|| "postgres".to_owned()),
        host.unwrap_or_else(|| "localhost".to_owned()),
        port.unwrap_or(5432),
        database.unwrap_or_default(),
    )
}

/// Builds the Telegram destination, which needs both a bot token and a chat ID.
fn telegram(settings: &Settings) -> Option<Telegram> {
    let bot_token = settings.string("telegrambot_token", "");
    let chat_id = settings.string("telegram_chat_id", "");
    (!bot_token.is_empty() && !chat_id.is_empty()).then(|| Telegram {
        webhook: format!("https://api.telegram.org/bot{bot_token}/sendMessage"),
        chat_id,
    })
}

/// Loads the user agent pool, falling back to the built-in list.
fn user_agents(cli_file: Option<String>, settings: &Settings) -> Vec<String> {
    let file_name = cli_file.unwrap_or_else(|| settings.string("user_agents_file", ""));
    if file_name.is_empty() {
        return default_user_agents();
    }
    if !Path::new(&file_name).exists() {
        fatal("Error reading the user agents file, please make sure that the path is correct. Leaving");
    }
    match File::open(&file_name) {
        Ok(file) => BufReader::new(file).lines().map_while(Result::ok).collect(),
        Err(_) => fatal(
            "Error reading the user agents file, please make sure that the file format is correct.",
        ),
    }
}

/// The user agents used when no `--ua` file is given.
#[must_use]
pub fn default_user_agents() -> Vec<String> {
    [
        "APIs-Google (+https://developers.google.com/webmasters/APIs-Google.html)",
        "Mozilla/5.0 (Linux; Android 8.0.0; SM-G960F Build/R16NW) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.84 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
        "Mozilla/5.0 (X1s1; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2919.83 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2919.83 Safari/537.36",
    ]
    .iter()
    .map(|agent| (*agent).to_owned())
    .collect()
}

#[cfg(test)]
mod tests {
    use {super::*, crate::config::DEFAULT_RESOLVERS, std::collections::HashMap};

    fn settings_from(pairs: &[(&str, &str)]) -> Settings {
        Settings::from_map(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect::<HashMap<_, _>>(),
        )
    }

    #[test]
    fn extra_tool_arguments_come_from_the_command_line_or_the_file() {
        let from_file = settings_from(&[("nuclei_args", "-proxy,http://127.0.0.1:8080")]);
        assert_eq!(
            extra_args(&[], &from_file, "nuclei_args"),
            vec!["-proxy".to_owned(), "http://127.0.0.1:8080".to_owned()]
        );

        // The command line replaces the file rather than adding to it.
        assert_eq!(
            extra_args(&["-headless".to_owned()], &from_file, "nuclei_args"),
            vec!["-headless".to_owned()]
        );

        assert!(extra_args(&[], &settings_from(&[]), "nuclei_args").is_empty());
    }

    #[test]
    fn a_list_in_the_file_keeps_arguments_that_contain_a_comma() {
        // `-mc 200,301` is two arguments, not three; splitting it on commas
        // would hand ffuf a bare `301` it has no flag for.
        let from_file = Settings::from_sequence("ffuf_args", &["-mc", "200,301"]);
        assert_eq!(
            extra_args(&[], &from_file, "ffuf_args"),
            vec!["-mc".to_owned(), "200,301".to_owned()]
        );
    }

    #[test]
    fn sqlite_is_the_default_and_postgres_is_opt_in() {
        use clap::Parser;

        let plain = Cli::parse_from(["findomain", "-t", "example.com"]);
        assert_eq!(
            backend(&plain, &settings_from(&[])),
            Backend::Sqlite(DEFAULT_SQLITE_PATH.to_owned())
        );

        let named = Cli::parse_from(["findomain", "-t", "example.com", "--sqlite", "mine.db"]);
        assert_eq!(
            backend(&named, &settings_from(&[])),
            Backend::Sqlite("mine.db".to_owned())
        );

        assert_eq!(
            backend(&plain, &settings_from(&[("sqlite_path", "from-config.db")])),
            Backend::Sqlite("from-config.db".to_owned())
        );

        // Any PostgreSQL setting, from either source, asks for the server.
        let with_host = Cli::parse_from([
            "findomain",
            "-t",
            "example.com",
            "--postgres-host",
            "db.local",
        ]);
        assert_eq!(backend(&with_host, &settings_from(&[])), Backend::Postgres);
        assert_eq!(
            backend(
                &plain,
                &settings_from(&[("postgres_connection", "postgresql://x/y")])
            ),
            Backend::Postgres
        );

        // An explicit SQLite path still wins over a PostgreSQL setting.
        let both = Cli::parse_from([
            "findomain",
            "-t",
            "example.com",
            "--sqlite",
            "mine.db",
            "--postgres-host",
            "db.local",
        ]);
        assert_eq!(
            backend(&both, &settings_from(&[])),
            Backend::Sqlite("mine.db".to_owned())
        );
    }

    #[test]
    fn a_resolver_keeps_the_port_it_names() {
        let dir = crate::test_support::TempDir::new("resolver-ports");
        dir.write("resolvers.txt", "1.1.1.1\n9.9.9.9:5353\n");
        let path = dir.path("resolvers.txt");

        let addresses = resolver_addresses(&[path], true);
        assert!(addresses.contains(&"1.1.1.1:53".to_owned()));
        assert!(
            addresses.contains(&"9.9.9.9:5353".to_owned()),
            "a resolver on another port must not be given a second one: {addresses:?}"
        );
    }

    #[test]
    fn no_resolvers_file_means_the_built_in_list() {
        assert_eq!(resolver_addresses(&[], true), default_resolver_addresses());
    }

    fn cli() -> Cli {
        use clap::Parser;
        Cli::parse_from(["findomain", "--target", "example.com"])
    }

    #[test]
    fn output_file_name_prefers_the_auto_generated_name() {
        assert_eq!(
            output_file_name(true, Some("https://www.example.com"), None),
            "example.com.txt"
        );
        assert_eq!(
            output_file_name(false, Some("example.com"), Some("out.txt".to_owned())),
            "out.txt"
        );
        assert_eq!(output_file_name(false, Some("example.com"), None), "");
        // `-o` without `--target` defers naming to the per-target loop.
        assert_eq!(output_file_name(true, None, None), "");
    }

    #[test]
    fn lightweight_threads_follow_the_documented_precedence() {
        let settings = settings_from(&[("lightweight_threads", "30"), ("threads", "20")]);

        let mut cli = cli();
        cli.lightweight_threads = Some(11);
        cli.threads = Some(12);
        assert_eq!(lightweight_threads(&cli, &settings), 11);

        cli.lightweight_threads = None;
        assert_eq!(lightweight_threads(&cli, &settings), 12);

        cli.threads = None;
        assert_eq!(lightweight_threads(&cli, &settings), 30);

        let only_deprecated = settings_from(&[("threads", "20")]);
        assert_eq!(lightweight_threads(&cli, &only_deprecated), 20);

        assert_eq!(lightweight_threads(&cli, &Settings::default()), 50);
    }

    #[test]
    fn a_thread_count_of_zero_is_lifted_to_one() {
        // Zero reaches `buffer_unordered`, which then polls nothing and leaves
        // the resolution stage pending forever.
        let mut cli = cli();
        cli.lightweight_threads = Some(0);
        assert_eq!(lightweight_threads(&cli, &Settings::default()), 1);

        cli.lightweight_threads = None;
        cli.threads = Some(0);
        assert_eq!(lightweight_threads(&cli, &Settings::default()), 1);

        cli.threads = None;
        let from_config = settings_from(&[("lightweight_threads", "0")]);
        assert_eq!(lightweight_threads(&cli, &from_config), 1);
    }

    #[test]
    fn postgres_connection_string_uses_sane_defaults() {
        assert_eq!(
            postgres_connection_string(None, None, None, None, None),
            "postgresql://postgres:postgres@localhost:5432/"
        );
        assert_eq!(
            postgres_connection_string(
                Some("me".to_owned()),
                Some("secret".to_owned()),
                Some("db.local".to_owned()),
                Some(6543),
                Some("findomain".to_owned()),
            ),
            "postgresql://me:secret@db.local:6543/findomain"
        );
    }

    #[test]
    fn telegram_needs_both_halves_of_the_credentials() {
        assert!(telegram(&Settings::default()).is_none());
        assert!(telegram(&settings_from(&[("telegrambot_token", "abc")])).is_none());
        assert!(telegram(&settings_from(&[("telegram_chat_id", "42")])).is_none());

        let telegram = telegram(&settings_from(&[
            ("telegrambot_token", "abc"),
            ("telegram_chat_id", "42"),
        ]))
        .expect("both halves present");
        assert_eq!(
            telegram.webhook,
            "https://api.telegram.org/botabc/sendMessage"
        );
        assert_eq!(telegram.chat_id, "42");
    }

    #[test]
    fn resolvers_default_to_the_built_in_list() {
        assert_eq!(resolver_addresses(&[], true).len(), DEFAULT_RESOLVERS.len());
    }

    #[test]
    fn user_agents_default_when_no_file_is_configured() {
        assert_eq!(
            user_agents(None, &Settings::default()),
            default_user_agents()
        );
    }

    #[test]
    fn build_applies_flag_over_config_over_default() {
        use clap::Parser;

        let settings = settings_from(&[("http_timeout", "9"), ("jobname", "from-config")]);

        let config = Config::build(
            &Cli::parse_from(["findomain", "--target", "example.com"]),
            &settings,
        );
        assert_eq!(config.http.timeout, 9);
        assert_eq!(config.database.jobname, "from-config");
        assert_eq!(config.input.target, "example.com");

        let config = Config::build(
            &Cli::parse_from([
                "findomain",
                "--target",
                "example.com",
                "--http-status",
                "--http-timeout",
                "3",
                "--jobname",
                "from-flag",
            ]),
            &settings,
        );
        assert_eq!(config.http.timeout, 3);
        assert_eq!(config.database.jobname, "from-flag");

        let config = Config::build(
            &Cli::parse_from(["findomain", "--target", "example.com"]),
            &Settings::default(),
        );
        assert_eq!(config.http.timeout, DEFAULT_HTTP_TIMEOUT);
        assert_eq!(config.database.jobname, "findomain");
    }

    #[test]
    fn the_scanners_that_need_a_live_url_enable_the_http_check() {
        use clap::Parser;

        for flag in [
            vec!["findomain", "-t", "example.com", "--nuclei"],
            vec!["findomain", "-t", "example.com", "--ffuf"],
            vec![
                "findomain",
                "-t",
                "example.com",
                "--ffuf-wordlist",
                "/w.txt",
            ],
            vec!["findomain", "-t", "example.com", "--nuclei-templates", "/t"],
        ] {
            let config = Config::build(&Cli::parse_from(&flag), &Settings::default());
            assert!(config.http.enabled, "{flag:?} must imply the HTTP check");
        }
    }

    #[test]
    fn build_rejects_an_invalid_target_without_failing() {
        use clap::Parser;

        let config = Config::build(
            &Cli::parse_from(["findomain", "--target", "not_a_domain"]),
            &Settings::default(),
        );
        assert!(config.input.target.is_empty());
    }

    #[test]
    fn build_derives_the_dependent_flags() {
        use clap::Parser;

        let config = Config::build(
            &Cli::parse_from([
                "findomain",
                "--target",
                "example.com",
                "--screenshots",
                "shots",
            ]),
            &Settings::default(),
        );
        // Screenshots imply an HTTP check.
        assert!(config.screenshots.enabled);
        assert!(config.http.enabled);

        let config = Config::build(
            &Cli::parse_from(["findomain", "--target", "example.com", "--lport", "90"]),
            &Settings::default(),
        );
        // A custom port bound implies the port scanner.
        assert!(config.ports.enabled);
        assert_eq!(config.ports.range, Some(1..=90));

        let config = Config::build(
            &Cli::parse_from(["findomain", "--target", "example.com", "--pscan"]),
            &Settings::default(),
        );
        assert!(config.ports.enabled);
        assert_eq!(config.ports.range, None);
    }

    #[test]
    fn the_nmap_style_flags_imply_a_port_scan() {
        use clap::Parser;

        for flag in ["--nmap-full", "--nmap-syn"] {
            let config = Config::build(
                &Cli::parse_from(["findomain", "--target", "example.com", flag]),
                &Settings::default(),
            );
            assert!(config.ports.enabled, "{flag} must imply the port scan");
        }
    }
}
