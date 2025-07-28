use {
    crate::{
        logic::{eval_resolved_or_ip_present, validate_target},
        misc::sanitize_target_string,
        resolvers,
        structs::Args,
    },
    clap::Parser,
    std::{
        collections::{HashMap, HashSet},
        fs::File,
        io::{BufRead, BufReader},
        path::Path,
        time::Instant,
    },
};

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
    #[clap(long = "import-subdomains")]
    pub import_subdomains: Vec<String>,

    /// Enable DNS over TLS for resolving subdomains IPs.
    #[clap(long = "enable-dot")]
    pub enable_dot: bool,

    /// Perform a IPv6 lookup only.
    #[clap(long = "ipv6-only", conflicts_with_all = &["ip", "resolved"])]
    pub ipv6_only: bool,

    /// Number of threads to use for lightweight tasks such as IP discovery and HTTP checks. Deprecated option, use --lighweight-threads instead. This would be removed in the future.
    #[clap(long = "threads")]
    pub threads: Option<usize>,

    /// Number of threads to use for lightweight tasks such as IP discovery and HTTP checks. Default is 50.
    #[clap(long = "lightweight-threads")]
    pub lightweight_threads: Option<usize>,

    /// Number of threads to use to use for taking screenshots. Default is 10.
    #[clap(long = "screenshots-threads")]
    pub screenshots_threads: Option<usize>,

    /// Number of IPs that will be port-scanned at the same time. Default is 10.
    #[clap(long = "parallel-ip-ports-scan")]
    pub parallel_ip_ports_scan: Option<usize>,

    /// Number of threads to use for TCP connections - It's the equivalent of Nmap's --min-rate. Default is 500.
    #[clap(long = "tcp-connect-threads")]
    pub tcp_connect_threads: Option<usize>,

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
    #[clap(use_value_delimiter = true, value_delimiter = ',', long = "exclude-sources", value_parser = ["certspotter", "crtsh", "sublist3r", "facebook", "spyse", "threatcrowd", "virustotalapikey", "anubis", "urlscan", "securitytrails", "threatminer", "c99", "bufferover_free", "bufferover_paid"])]
    pub exclude_sources: Vec<String>,

    /// Check the HTTP status of subdomains.
    #[clap(long = "http-status")]
    pub http_status: bool,

    /// Use a configuration file. The default configuration file is findomain and the format can be toml, json, hjson, ini or yml.
    #[clap(short = 'c', long = "config")]
    pub config_file: Option<String>,

    /// Set the rate limit in seconds for each target during enumeration.
    #[clap(long = "rate-limit")]
    pub rate_limit: Option<u64>,

    /// Enable port scanner.
    #[clap(long = "pscan")]
    pub port_scan: bool,

    /// Initial port to scan. Default 0.
    #[clap(long = "iport")]
    pub initial_port: Option<u16>,

    /// Last port to scan. Default 1000.
    #[clap(long = "lport")]
    pub last_port: Option<u16>,

    /// Enable verbose mode (useful to debug problems).
    #[clap(short = 'v', long = "verbose", conflicts_with_all = &["quiet", "ipv6_only"])]
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
    #[clap(long = "http-timeout", requires = "http_status")]
    pub http_timeout: Option<u64>,

    /// Value in milliseconds to wait for the TCP connection (ip:port) in the ports scanning function. Default 2000.
    #[clap(long = "tcp-connect-timeout")]
    pub tcp_connect_timeout: Option<u64>,

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

    /// Get external subdomains with amass and subfinder.
    #[clap(long = "external-subdomains")]
    pub external_subdomains: bool,

    /// Validate all the subdomains from the specified file.
    #[clap(long = "validate", requires = "files")]
    pub validate_subdomains: bool,

    /// Timeout in seconds for the resolver. Default 1.
    #[clap(long = "resolver-timeout")]
    pub resolver_timeout: Option<u64>,

    /// Number of retries for the HTTP Status check of subdomains. Default 1.
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
}

#[allow(clippy::cognitive_complexity)]
#[must_use]
pub fn get_args() -> Args {
    let cli = Cli::parse();

    let mut settings = config::Config::default();
    let settings: HashMap<String, String> = return_settings(&cli, &mut settings);

    // Extract values that will be moved
    let target_value = cli.target.clone();
    let unique_output_value = cli.unique_output.clone();
    let screenshots_path_value = cli.screenshots_path.clone();

    Args {
        target: {
            let target = sanitize_target_string(&cli.target.unwrap_or_default());
            if validate_target(&target) {
                target
            } else {
                String::new()
            }
        },
        file_name: if cli.output && target_value.is_some() {
            format!(
                "{}.txt",
                sanitize_target_string(target_value.as_ref().unwrap())
            )
        } else if let Some(ref unique_output) = unique_output_value {
            unique_output.clone()
        } else {
            String::new()
        },
        postgres_connection: {
            let database_connection = format!(
                "postgresql://{}:{}@{}:{}/{}",
                cli.postgres_user.unwrap_or_else(|| "postgres".to_string()),
                cli.postgres_password
                    .unwrap_or_else(|| "postgres".to_string()),
                cli.postgres_host.unwrap_or_else(|| "localhost".to_string()),
                cli.postgres_port.unwrap_or(5432),
                cli.postgres_database.unwrap_or_else(String::new),
            );
            return_value_or_default(&settings, "postgres_connection", database_connection)
        },
        discord_webhook: return_value_or_default(&settings, "discord_webhook", String::new()),
        slack_webhook: return_value_or_default(&settings, "slack_webhook", String::new()),
        telegram_bot_token: return_value_or_default(&settings, "telegrambot_token", String::new()),
        telegram_webhook: String::new(),
        telegram_chat_id: return_value_or_default(&settings, "telegram_chat_id", String::new()),
        facebook_access_token: return_value_or_default(&settings, "fb_token", String::new())
            .split_terminator(',')
            .map(str::to_owned)
            .collect(),
        virustotal_access_token: return_value_or_default(
            &settings,
            "virustotal_token",
            String::new(),
        )
        .split_terminator(',')
        .map(str::to_owned)
        .collect(),
        securitytrails_access_token: return_value_or_default(
            &settings,
            "securitytrails_token",
            String::new(),
        )
        .split_terminator(',')
        .map(str::to_owned)
        .collect(),
        certspotter_access_token: return_value_or_default(
            &settings,
            "certspotter_token",
            String::new(),
        )
        .split_terminator(',')
        .map(str::to_owned)
        .collect(),
        user_agent: String::new(),
        c99_api_key: return_value_or_default(&settings, "c99_api_key", String::new())
            .split_terminator(',')
            .map(str::to_owned)
            .collect(),
        bufferover_free_api_key: return_value_or_default(
            &settings,
            "bufferover_free_api_key",
            String::new(),
        )
        .split_terminator(',')
        .map(str::to_owned)
        .collect(),
        bufferover_paid_api_key: return_value_or_default(
            &settings,
            "bufferover_paid_api_key",
            String::new(),
        )
        .split_terminator(',')
        .map(str::to_owned)
        .collect(),
        fullhunt_api_key: return_value_or_default(&settings, "fullhunt_api_key", String::new())
            .split_terminator(',')
            .map(str::to_owned)
            .collect(),
        jobname: cli.jobname.unwrap_or_else(|| {
            return_value_or_default(&settings, "jobname", "findomain".to_string())
        }),
        screenshots_path: cli
            .screenshots_path
            .unwrap_or_else(|| "screenshots".to_string()),
        external_subdomains_dir_amass: String::from("external_subdomains/amass"),
        external_subdomains_dir_subfinder: String::from("external_subdomains/subfinder"),
        version: env!("CARGO_PKG_VERSION").to_string(),
        database_checker_counter: 0,
        commit_to_db_counter: 0,
        // let's keep compatibility with the deprecated --threads option, for now...
        lightweight_threads: cli.lightweight_threads.unwrap_or_else(|| {
            cli.threads.unwrap_or_else(|| {
                return_value_or_default(&settings, "lightweight_threads", "50".to_string())
                    .parse::<usize>()
                    .unwrap_or_else(|_| {
                        return_value_or_default(&settings, "threads", "50".to_string())
                            .parse::<usize>()
                            .unwrap_or(50)
                    })
            })
        }),
        screenshots_threads: cli.screenshots_threads.unwrap_or_else(|| {
            return_value_or_default(&settings, "screenshots_threads", "10".to_string())
                .parse::<usize>()
                .unwrap_or(10)
        }),
        parallel_ip_ports_scan: cli.parallel_ip_ports_scan.unwrap_or_else(|| {
            return_value_or_default(&settings, "parallel_ip_ports_scan", "10".to_string())
                .parse::<usize>()
                .unwrap_or(10)
        }),
        max_http_redirects: cli.max_http_redirects.unwrap_or_else(|| {
            return_value_or_default(&settings, "max_http_redirects", "0".to_string())
                .parse::<usize>()
                .unwrap_or(0)
        }),
        tcp_connect_threads: cli.tcp_connect_threads.unwrap_or_else(|| {
            return_value_or_default(&settings, "tcp_connect_threads", "500".to_string())
                .parse::<usize>()
                .unwrap_or(500)
        }),
        resolver_timeout: cli.resolver_timeout.unwrap_or_else(|| {
            return_value_or_default(&settings, "resolver_timeout", "3".to_string())
                .parse::<u64>()
                .unwrap_or(3)
        }),
        http_retries: cli.http_retries.unwrap_or_else(|| {
            return_value_or_default(&settings, "http_retries", "2".to_string())
                .parse::<usize>()
                .unwrap_or(2)
        }),
        rate_limit: cli.rate_limit.unwrap_or_else(|| {
            return_value_or_default(&settings, "rate_limit", "5".to_string())
                .parse::<u64>()
                .unwrap_or(5)
        }),
        http_timeout: cli.http_timeout.unwrap_or_else(|| {
            return_value_or_default(&settings, "http_timeout", "5".to_string())
                .parse::<u64>()
                .unwrap_or(5)
        }),
        tcp_connect_timeout: cli.tcp_connect_timeout.unwrap_or(2000),
        initial_port: cli.initial_port.unwrap_or(1),
        last_port: cli.last_port.unwrap_or(1000),
        only_resolved: cli.resolved,
        with_ip: cli.ip,
        with_output: cli.output || cli.unique_output.is_some(),
        unique_output_flag: cli.unique_output.is_some(),
        monitoring_flag: cli.monitoring_flag,
        from_file_flag: !cli.files.is_empty(),
        quiet_flag: cli.quiet,
        query_database: cli.query_database,
        enable_dot: eval_resolved_or_ip_present(
            cli.enable_dot,
            cli.ip || cli.ipv6_only,
            cli.resolved,
        ),
        ipv6_only: cli.ipv6_only,
        enable_empty_push: cli.enable_empty_push,
        as_resolver: cli.as_resolver,
        bruteforce: !cli.wordlists.is_empty(),
        disable_wildcard_check: cli.no_wildcards,
        http_status: cli.http_status || screenshots_path_value.is_some(),
        is_last_target: false,
        enable_port_scan: cli.port_scan || cli.initial_port.is_some() || cli.last_port.is_some(),
        custom_threads: cli.threads.is_some(),
        discover_ip: cli.ip || cli.resolved || cli.ipv6_only,
        verbose: cli.verbose,
        custom_resolvers: !cli.custom_resolvers.is_empty(),
        from_stdin: cli.stdin,
        dbpush_if_timeout: cli.dbpush_if_timeout || {
            return_value_or_default(&settings, "dbpush_if_timeout", "false".to_string())
                .parse::<bool>()
                .unwrap_or(false)
        },
        no_monitor: cli.no_monitor || {
            return_value_or_default(&settings, "no_monitor", "false".to_string())
                .parse::<bool>()
                .unwrap_or(false)
        },
        randomize: cli.randomize || {
            return_value_or_default(&settings, "randomize", "false".to_string())
                .parse::<bool>()
                .unwrap_or(false)
        },
        take_screenshots: screenshots_path_value.is_some(),
        chrome_sandbox: cli.sandbox,
        query_jobname: cli.query_jobname,
        no_resolve: cli.no_resolve,
        external_subdomains: cli.external_subdomains,
        validate_subdomains: cli.validate_subdomains,
        enable_double_dns_check: cli.enable_double_dns_check,
        reset_database: cli.reset_database,
        custom_ports_range: cli.initial_port.is_some() || cli.last_port.is_some(),
        no_discover: cli.no_discover,
        files: cli.files,
        import_subdomains_from: {
            let mut paths_from_config_file =
                return_value_or_default(&settings, "import_subdomains_from", String::new())
                    .split_terminator(',')
                    .map(str::to_owned)
                    .collect::<Vec<String>>();
            let mut import_subdomains_from = cli.import_subdomains;
            import_subdomains_from.append(&mut paths_from_config_file);
            import_subdomains_from
        },
        wordlists: cli.wordlists,
        resolvers: if cli.custom_resolvers.is_empty() {
            resolvers::return_ipv4_resolvers()
        } else {
            cli.custom_resolvers
        },
        user_agent_strings: {
            let file_name = cli.user_agents_file.unwrap_or_else(|| {
                return_value_or_default(&settings, "user_agents_file", String::new())
            });
            if !file_name.is_empty() && Path::new(&file_name).exists() {
                File::open(&file_name).map_or_else(|_| {
                    eprintln!("Error reading the user agents file, please make sure that the file format is correct.");
                    std::process::exit(1)
                }, |file| BufReader::new(file).lines().map_while(Result::ok).collect())
            } else if !file_name.is_empty() && !Path::new(&file_name).exists() {
                eprintln!("Error reading the user agents file, please make sure that the path is correct. Leaving");
                std::process::exit(1)
            } else {
                vec![
                    "APIs-Google (+https://developers.google.com/webmasters/APIs-Google.html)".to_string(),
                    "Mozilla/5.0 (Linux; Android 8.0.0; SM-G960F Build/R16NW) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.84 Mobile Safari/537.36".to_string(),
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36".to_string(),
                    "Mozilla/5.0 (X1s1; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2919.83 Safari/537.36".to_string(),
                    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2919.83 Safari/537.36".to_string()
                ]
            }
        },
        subdomains: HashSet::new(),
        wordlists_data: HashSet::new(),
        wilcard_ips: HashSet::new(),
        filter_by_string: cli.string_filter.into_iter().collect(),
        exclude_by_string: cli.string_exclude.into_iter().collect(),
        excluded_sources: if cli.exclude_sources.is_empty() {
            return_value_or_default(&settings, "exclude_sources", String::new())
                .split_terminator(',')
                .map(str::to_owned)
                .collect()
        } else {
            cli.exclude_sources.into_iter().collect()
        },
        time_wasted: Instant::now(),
    }
}

fn return_settings(cli: &Cli, _settings: &mut config::Config) -> HashMap<String, String> {
    let mut builder = config::Config::builder();

    if cli.config_file.is_some() || std::env::var("FINDOMAIN_CONFIG_FILE").is_ok() {
        let config_filename = std::env::var("FINDOMAIN_CONFIG_FILE")
            .unwrap_or_else(|_| cli.config_file.as_ref().unwrap().clone());
        builder = builder.add_source(config::File::with_name(&config_filename));
    } else if Path::new("findomain.toml").exists()
        || Path::new("findomain.json").exists()
        || Path::new("findomain.hjson").exists()
        || Path::new("findomain.ini").exists()
        || Path::new("findomain.yml").exists()
    {
        builder = builder.add_source(config::File::with_name("findomain"));
    }

    builder = builder.add_source(config::Environment::with_prefix("FINDOMAIN"));

    match builder.build() {
        Ok(settings) => match settings.try_deserialize::<HashMap<String, String>>() {
            Ok(settings) => settings,
            Err(e) => {
                eprintln!("Error parsing configuration: {e}");
                std::process::exit(1)
            }
        },
        Err(e) => {
            eprintln!("Error building configuration: {e}");
            std::process::exit(1)
        }
    }
}

fn return_value_or_default(
    settings: &HashMap<String, String>,
    value: &str,
    default_value: String,
) -> String {
    settings.get(value).unwrap_or(&default_value).to_string()
}
