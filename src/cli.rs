//! Command line interface definition.
//!
//! This module only describes the accepted flags. Turning them into the
//! runtime [`Config`](crate::config::Config) is the job of
//! [`crate::config::builder`].

use clap::Parser;

/// The fastest and cross-platform subdomain enumerator, do not waste your time.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, arg_required_else_help = true)]
pub struct Cli {
    /// Target host.
    #[clap(short = 't', long = "target", conflicts_with_all = &["files", "stdin"])]
    pub target: Option<String>,

    /// Show/write only resolved subdomains.
    #[clap(short = 'r', long = "resolved", conflicts_with_all = &["ip", "ipv6_only"])]
    pub resolved: bool,

    /// Show/write the ip address of resolved subdomains.
    #[clap(short = 'i', long = "ip", conflicts_with_all = &["resolved", "ipv6_only"])]
    pub ip: bool,

    /// Use a list of subdomains writen in a file as input.
    #[clap(short = 'f', long = "file", conflicts_with_all = &["target", "stdin"])]
    pub files: Vec<String>,

    /// Write to an automatically generated output file. The name of the output file is generated using the format: target.txt. If you want a custom output file name, use the -u/--unique-output option.
    #[clap(short = 'o', long = "output")]
    pub output: bool,

    /// Write all the results for a target or a list of targets to a specified filename.
    #[clap(short = 'u', long = "unique-output", conflicts_with = "output")]
    pub unique_output: Option<String>,

    /// Activate Findomain monitoring mode.
    #[clap(short = 'm', long = "monitoring-flag")]
    pub monitoring_flag: bool,

    /// Postgresql username.
    #[clap(long = "postgres-user")]
    pub postgres_user: Option<String>,

    /// Postgresql password.
    #[clap(long = "postgres-password")]
    pub postgres_password: Option<String>,

    /// Postgresql host.
    #[clap(long = "postgres-host")]
    pub postgres_host: Option<String>,

    /// Postgresql port.
    #[clap(long = "postgres-port")]
    pub postgres_port: Option<usize>,

    /// Postgresql database.
    #[clap(long = "postgres-database")]
    pub postgres_database: Option<String>,

    /// Remove informative messages but show fatal errors or subdomains not found message.
    #[clap(short = 'q', long = "quiet", conflicts_with = "verbose")]
    pub quiet: bool,

    /// Query the findomain database to search subdomains that have already been discovered.
    #[clap(long = "query-database", conflicts_with = "monitoring_flag")]
    pub query_database: bool,

    /// Import subdomains from one or multiple files. Subdomains need to be one per line in the file to import.
    #[clap(long = "import-subdomains", num_args = 1..)]
    pub import_subdomains: Vec<String>,

    /// Enable DNS over TLS for resolving subdomains IPs.
    #[clap(long = "enable-dot")]
    pub enable_dot: bool,

    /// Perform a IPv6 lookup only.
    #[clap(long = "ipv6-only", conflicts_with_all = &["ip", "resolved"])]
    pub ipv6_only: bool,

    /// Number of threads to use for lightweight tasks such as IP discovery and HTTP checks. Deprecated option, use --lightweight-threads instead. This would be removed in the future.
    #[clap(long = "threads")]
    pub threads: Option<usize>,

    /// Number of threads to use for lightweight tasks such as IP discovery and HTTP checks. Default is 50.
    #[clap(long = "lightweight-threads")]
    pub lightweight_threads: Option<usize>,

    /// Number of threads to use to use for taking screenshots. Default is 10.
    #[clap(long = "screenshots-threads")]
    pub screenshots_threads: Option<usize>,

    /// Path to a file (or files) containing a list of DNS IP address. If no specified then Google, Cloudflare and Quad9 DNS servers are used.
    #[clap(long = "resolvers")]
    pub custom_resolvers: Vec<String>,

    /// Send alert to webhooks still when no new subdomains have been found.
    #[clap(long = "aempty")]
    pub enable_empty_push: bool,

    /// Use Findomain as resolver for a list of domains in a file.
    #[clap(short = 'x', long = "as-resolver", conflicts_with_all = &["query_database", "monitoring_flag"])]
    pub as_resolver: bool,

    /// Wordlist file to use in the bruteforce process. Using it option automatically enables bruteforce mode.
    #[clap(short = 'w', long = "wordlist")]
    pub wordlists: Vec<String>,

    /// Disable wilcard detection when resolving subdomains.
    #[clap(long = "no-wildcards", conflicts_with = "query_database")]
    pub no_wildcards: bool,

    /// Filter subdomains containing specifics strings.
    #[clap(long = "filter")]
    pub string_filter: Vec<String>,

    /// Exclude subdomains containing specifics strings.
    #[clap(long = "exclude")]
    pub string_exclude: Vec<String>,

    /// Exclude sources from searching subdomains in.
    #[clap(
        use_value_delimiter = true,
        value_delimiter = ',',
        long = "exclude-sources",
        value_parser = clap::builder::PossibleValuesParser::new(crate::discovery::all_source_ids())
    )]
    pub exclude_sources: Vec<String>,

    /// Timeout in seconds for a single request to a source. Default 30.
    #[clap(long = "source-timeout")]
    pub source_timeout: Option<u64>,

    /// Seconds the search across all sources may take, 0 for no limit. Default 300.
    #[clap(long = "source-budget")]
    pub source_budget: Option<u64>,

    /// Seconds the archive indexes may spend, 0 to hold them to the source budget. Default 20.
    #[clap(long = "archive-budget")]
    pub archive_budget: Option<u64>,

    /// Check the HTTP status of subdomains.
    #[clap(long = "http-status")]
    pub http_status: bool,

    /// Use a configuration file. The default configuration file is findomain and the format can be toml, json, ini or yml.
    #[clap(short = 'c', long = "config")]
    pub config_file: Option<String>,

    /// Set the rate limit in seconds for each target during enumeration.
    #[clap(long = "rate-limit")]
    pub rate_limit: Option<u64>,

    /// Extra argument passed to nmap verbatim. Repeat it once per argument.
    #[clap(long = "nmap-arg", allow_hyphen_values = true)]
    pub nmap_args: Vec<String>,

    /// Enable port scanner.
    #[clap(long = "pscan")]
    pub port_scan: bool,

    /// Initial port to scan. Default 1.
    #[clap(long = "iport")]
    pub initial_port: Option<u16>,

    /// Last port to scan. Default 1000.
    #[clap(long = "lport")]
    pub last_port: Option<u16>,

    /// Enable verbose mode (useful to debug problems).
    #[clap(short = 'v', long = "verbose", conflicts_with = "quiet")]
    pub verbose: bool,

    /// Allow Findomain to insert data in the database when the webhook returns a timeout error.
    #[clap(long = "mtimeout", requires = "monitoring_flag")]
    pub dbpush_if_timeout: bool,

    /// Disable monitoring mode while saving data to database.
    #[clap(long = "no-monitor", conflicts_with = "monitoring_flag")]
    pub no_monitor: bool,

    /// Path to save the screenshots of the HTTP(S) website for subdomains with active ones.
    #[clap(short = 's', long = "screenshots")]
    pub screenshots_path: Option<String>,

    /// Enable Chrome/Chromium sandbox. It is disabled by default because a big number of users run the tool using the root user by default. Make sure you are not running the program as root user before using this option.
    #[clap(long = "sandbox", requires = "screenshots_path")]
    pub sandbox: bool,

    /// Use an database identifier for jobs. It is useful when you want to relate different targets into a same job name. To extract the data by job name identifier, use the query-jobname option.
    #[clap(short = 'j', long = "jobname")]
    pub jobname: Option<String>,

    /// Extract all the subdomains from the database where the job name is the specified using the jobname option.
    #[clap(
        long = "query-jobname",
        requires = "jobname",
        conflicts_with = "query_database"
    )]
    pub query_jobname: bool,

    /// Value in seconds for the HTTP Status check of subdomains. Default 5.
    #[clap(long = "http-timeout")]
    pub http_timeout: Option<u64>,

    /// Read from stdin instead of files or aguments.
    #[clap(long = "stdin", conflicts_with_all = &["files", "target"])]
    pub stdin: bool,

    /// Path to file containing user agents strings.
    #[clap(long = "ua")]
    pub user_agents_file: Option<String>,

    /// Enable randomization when reading targets from files.
    #[clap(long = "randomize", conflicts_with = "target")]
    pub randomize: bool,

    /// Disable pre-screenshotting jobs (http check and ip discover) when used as resolver to take screenshots.
    #[clap(long = "no-resolve", requires_all = &["as_resolver", "screenshots_path"])]
    pub no_resolve: bool,

    /// Validate all the subdomains from the specified file.
    #[clap(long = "validate", requires = "files", conflicts_with_all = &["target", "stdin"])]
    pub validate_subdomains: bool,

    /// Timeout in seconds for the resolver. Default 3.
    #[clap(long = "resolver-timeout")]
    pub resolver_timeout: Option<u64>,

    /// Number of retries for the HTTP Status check of subdomains. Default 2.
    #[clap(long = "http-retries")]
    pub http_retries: Option<usize>,

    /// Enable double DNS check. This means that the subdomains that report an IP address are checked again using a list of trustable resolvers to avoid false-positives. Only applies when using custom resolvers.
    #[clap(long = "double-dns-check", requires = "custom_resolvers")]
    pub enable_double_dns_check: bool,

    /// Prevent findomain from searching subdomains itself. Useful when you are importing subdomains from other tools.
    #[clap(short = 'n', long = "no-discover")]
    pub no_discover: bool,

    /// Maximum number of HTTP redirects to follow. Default 0.
    #[clap(long = "max-http-redirects")]
    pub max_http_redirects: Option<usize>,

    /// Reset the database. It will delete all the data from the database.
    #[clap(long = "reset-database")]
    pub reset_database: bool,

    /// SQLite file to store results in. Defaults to findomain.db; naming any PostgreSQL option uses PostgreSQL instead.
    #[clap(long = "sqlite", value_name = "FILE")]
    pub sqlite: Option<String>,

    /// Run nmap with service detection and NSE scripts instead of a plain port sweep.
    #[clap(long = "nmap-full")]
    pub nmap_full: bool,

    /// Use a SYN scan. Needs root privileges.
    #[clap(long = "nmap-syn")]
    pub nmap_syn: bool,

    /// nmap --min-rate, the packets per second floor.
    #[clap(long = "min-rate")]
    pub min_rate: Option<usize>,

    /// Seconds nmap may spend on a single host. Default 900.
    #[clap(long = "nmap-host-timeout")]
    pub nmap_host_timeout: Option<u64>,

    /// Run nuclei against the subdomains with an active HTTP server.
    #[clap(long = "nuclei")]
    pub nuclei: bool,

    /// Path to the nuclei templates to run.
    #[clap(long = "nuclei-templates")]
    pub nuclei_templates: Option<String>,

    /// Severities to report, comma separated.
    #[clap(long = "nuclei-severity")]
    pub nuclei_severity: Option<String>,

    /// Template tags to run, comma separated.
    #[clap(long = "nuclei-tags")]
    pub nuclei_tags: Option<String>,

    /// Templates to skip, comma separated.
    #[clap(long = "nuclei-exclude-templates")]
    pub nuclei_exclude_templates: Option<String>,

    /// Extra argument passed to nuclei verbatim. Repeat it once per argument.
    #[clap(long = "nuclei-arg", allow_hyphen_values = true)]
    pub nuclei_args: Vec<String>,

    /// nuclei rate limit in requests per second.
    #[clap(long = "nuclei-rate-limit")]
    pub nuclei_rate_limit: Option<usize>,

    /// Run ffuf against the subdomains with an active HTTP server.
    #[clap(long = "ffuf")]
    pub ffuf: bool,

    /// Path wordlist for ffuf. Implies --ffuf.
    #[clap(long = "ffuf-wordlist")]
    pub ffuf_wordlist: Option<String>,

    /// Extra argument passed to ffuf verbatim. Repeat it once per argument.
    #[clap(long = "ffuf-arg", allow_hyphen_values = true)]
    pub ffuf_args: Vec<String>,

    /// Concurrent ffuf requests. Default 40.
    #[clap(long = "ffuf-threads")]
    pub ffuf_threads: Option<usize>,

    /// Let ffuf recurse into the directories it finds.
    #[clap(long = "ffuf-recursion")]
    pub ffuf_recursion: bool,

    /// How deep ffuf may recurse. Default 2.
    #[clap(long = "ffuf-recursion-depth")]
    pub ffuf_recursion_depth: Option<usize>,

    /// SMTP server used to email the report.
    #[clap(long = "smtp-server")]
    pub smtp_server: Option<String>,

    /// SMTP port. Default 587.
    #[clap(long = "smtp-port")]
    pub smtp_port: Option<u16>,

    /// SMTP username, also used as the sender address.
    #[clap(long = "smtp-user")]
    pub smtp_user: Option<String>,

    /// SMTP password.
    #[clap(long = "smtp-password")]
    pub smtp_password: Option<String>,

    /// Address to email the report to. Repeat for several recipients.
    #[clap(long = "email-to")]
    pub email_to: Vec<String>,

    /// Track the CNAME each resolved subdomain points at.
    #[clap(long = "cname")]
    pub cname: bool,

    /// Derive extra candidate subdomains from the ones discovered and resolve them.
    #[clap(long = "permutations")]
    pub permutations: bool,

    /// Wordlist used to build permutations. Implies --permutations.
    #[clap(long = "permutations-wordlist")]
    pub permutations_wordlist: Vec<String>,
}
