use {
    crate::{
        logic::{eval_resolved_or_ip_present, validate_target},
        misc::{return_matches_hashset, return_matches_vec, sanitize_target_string},
        resolvers,
        structs::Args,
    },
    clap::{load_yaml, value_t, App},
    std::{
        collections::{HashMap, HashSet},
        fs::File,
        io::{BufRead, BufReader},
        path::Path,
        time::Instant,
    },
};

#[allow(clippy::cognitive_complexity)]
#[must_use]
pub fn get_args() -> Args {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml)
        .version(clap::crate_version!())
        .get_matches();
    let settings: HashMap<String, String> =
        return_settings(&matches, &mut config::Config::default());
    Args {
        target: {
            let target = sanitize_target_string(
                value_t!(matches, "target", String).unwrap_or_else(|_| String::new()),
            );
            if validate_target(&target) {
                target
            } else {
                String::new()
            }
        },
        file_name: if matches.is_present("output") && matches.is_present("target") {
            format!(
                "{}.txt",
                sanitize_target_string(matches.value_of("target").unwrap().to_string())
            )
        } else if matches.is_present("unique-output") {
            matches.value_of("unique-output").unwrap().to_string()
        } else {
            String::new()
        },
        postgres_connection: {
            let database_connection = format!(
                "postgresql://{}:{}@{}:{}/{}",
                value_t!(matches, "postgres-user", String)
                    .unwrap_or_else(|_| "postgres".to_string()),
                value_t!(matches, "postgres-password", String)
                    .unwrap_or_else(|_| "postgres".to_string()),
                value_t!(matches, "postgres-host", String)
                    .unwrap_or_else(|_| "localhost".to_string()),
                value_t!(matches, "postgres-port", usize).unwrap_or_else(|_| 5432),
                value_t!(matches, "postgres-database", String).unwrap_or_else(|_| String::new()),
            );
            return_value_or_default(&settings, "postgres_connection", database_connection)
        },
        discord_webhook: return_value_or_default(&settings, "discord_webhook", String::new()),
        slack_webhook: return_value_or_default(&settings, "slack_webhook", String::new()),
        telegram_bot_token: return_value_or_default(&settings, "telegrambot_token", String::new()),
        telegram_webhook: String::new(),
        telegram_chat_id: return_value_or_default(&settings, "telegram_chat_id", String::new()),
        spyse_access_token: return_value_or_default(&settings, "spyse_token", String::new())
            .split_terminator(',')
            .map(str::to_owned)
            .collect(),
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
        jobname: if matches.is_present("jobname") {
            value_t!(matches, "jobname", String).unwrap_or_else(|_| String::from("findomain"))
        } else {
            return_value_or_default(&settings, "jobname", String::from("findomain"))
        },
        screenshots_path: value_t!(matches, "screenshots-path", String)
            .unwrap_or_else(|_| String::from("screenshots")),
        external_subdomains_dir_amass: String::from("external_subdomains/amass"),
        external_subdomains_dir_subfinder: String::from("external_subdomains/subfinder"),
        version: clap::crate_version!().to_string(),
        database_checker_counter: 0,
        commit_to_db_counter: 0,
        // let's keep compatibility with the deprecated --threads option, for now...
        lightweight_threads: value_t!(matches, "lightweight-threads", usize).unwrap_or_else(|_| {
            value_t!(matches, "threads", usize).unwrap_or_else(|_| {
                return_value_or_default(&settings, "lightweight_threads", 50.to_string())
                    .parse::<usize>()
                    .unwrap_or_else(|_| {
                        return_value_or_default(&settings, "threads", 50.to_string())
                            .parse::<usize>()
                            .unwrap()
                    })
            })
        }),
        screenshots_threads: value_t!(matches, "screenshots-threads", usize).unwrap_or_else(|_| {
            return_value_or_default(&settings, "screenshots_threads", 10.to_string())
                .parse::<usize>()
                .unwrap()
        }),
        parallel_ip_ports_scan: value_t!(matches, "parallel-ip-ports-scan", usize).unwrap_or_else(
            |_| {
                return_value_or_default(&settings, "parallel_ip_ports_scan", 10.to_string())
                    .parse::<usize>()
                    .unwrap()
            },
        ),
        max_http_redirects: value_t!(matches, "max-http-redirects", usize).unwrap_or_else(|_| {
            return_value_or_default(&settings, "max_http_redirects", 0.to_string())
                .parse::<usize>()
                .unwrap()
        }),
        tcp_connect_threads: value_t!(matches, "tcp-connect-threads", usize).unwrap_or_else(|_| {
            return_value_or_default(&settings, "screenshots_threads", 500.to_string())
                .parse::<usize>()
                .unwrap()
        }),
        resolver_timeout: value_t!(matches, "resolver-timeout", u64).unwrap_or_else(|_| {
            return_value_or_default(&settings, "resolver_timeout", 3.to_string())
                .parse::<u64>()
                .unwrap()
        }),
        http_retries: value_t!(matches, "http-retries", usize).unwrap_or_else(|_| {
            return_value_or_default(&settings, "http_retries", 2.to_string())
                .parse::<usize>()
                .unwrap()
        }),
        rate_limit: if matches.is_present("rate-limit") {
            value_t!(matches, "rate-limit", u64).unwrap_or_else(|_| 5)
        } else {
            return_value_or_default(&settings, "rate_limit", 5.to_string())
                .parse::<u64>()
                .unwrap()
        },
        http_timeout: if matches.is_present("http-timeout") {
            value_t!(matches, "http-timeout", u64).unwrap_or_else(|_| 5)
        } else {
            return_value_or_default(&settings, "http_timeout", 5.to_string())
                .parse::<u64>()
                .unwrap()
        },
        tcp_connect_timeout: value_t!(matches, "tcp-connect-timeout", u64).unwrap_or_else(|_| 2000),
        initial_port: value_t!(matches, "initial-port", u16).unwrap_or_else(|_| 1),
        last_port: value_t!(matches, "last-port", u16).unwrap_or_else(|_| 1000),
        only_resolved: matches.is_present("resolved"),
        with_ip: matches.is_present("ip"),
        with_output: matches.is_present("output") || matches.is_present("unique-output"),
        unique_output_flag: matches.is_present("unique-output"),
        monitoring_flag: matches.is_present("monitoring-flag"),
        from_file_flag: matches.is_present("files"),
        quiet_flag: matches.is_present("quiet"),
        query_database: matches.is_present("query-database"),
        enable_dot: eval_resolved_or_ip_present(
            matches.is_present("enable-dot"),
            matches.is_present("ip") || matches.is_present("ipv6-only"),
            matches.is_present("resolved"),
        ),
        ipv6_only: matches.is_present("ipv6-only"),
        enable_empty_push: matches.is_present("enable-empty-push"),
        as_resolver: matches.is_present("as-resolver"),
        bruteforce: matches.is_present("wordlists"),
        disable_wildcard_check: matches.is_present("no-wildcards"),
        http_status: matches.is_present("http-status") || matches.is_present("screenshots-path"),
        is_last_target: false,
        enable_port_scan: matches.is_present("port-scan")
            || matches.is_present("initial-port")
            || matches.is_present("last-port"),
        custom_threads: matches.is_present("threads"),
        discover_ip: matches.is_present("ip")
            || matches.is_present("resolved")
            || matches.is_present("ipv6-only"),
        verbose: matches.is_present("verbose"),
        custom_resolvers: matches.is_present("custom-resolvers"),
        from_stdin: matches.is_present("stdin"),
        dbpush_if_timeout: if matches.is_present("dbpush-if-timeout") {
            matches.is_present("dbpush-if-timeout")
        } else {
            return_value_or_default(&settings, "dbpush_if_timeout", false.to_string())
                .parse::<bool>()
                .unwrap()
        },
        no_monitor: if matches.is_present("no-monitor") {
            matches.is_present("no-monitor")
        } else {
            return_value_or_default(&settings, "no_monitor", false.to_string())
                .parse::<bool>()
                .unwrap()
        },
        randomize: if matches.is_present("randomize") {
            true
        } else {
            return_value_or_default(&settings, "randomize", false.to_string())
                .parse::<bool>()
                .unwrap()
        },
        take_screenshots: matches.is_present("screenshots-path"),
        chrome_sandbox: matches.is_present("sandbox"),
        query_jobname: matches.is_present("query-jobname"),
        no_resolve: matches.is_present("no-resolve"),
        external_subdomains: matches.is_present("external-subdomains"),
        validate_subdomains: matches.is_present("validate-subdomains"),
        disable_double_dns_check: matches.is_present("no-double-dns-check")
            || !matches.is_present("custom-resolvers"),
        custom_ports_range: matches.is_present("initial-port") || matches.is_present("last-port"),
        no_discover: matches.is_present("no-discover"),
        files: return_matches_vec(&matches, "files"),
        import_subdomains_from: {
            let mut paths_from_config_file =
                return_value_or_default(&settings, "import_subdomains_from", String::new())
                    .split_terminator(',')
                    .map(str::to_owned)
                    .collect();
            let mut import_subdomains_from = return_matches_vec(&matches, "import-subdomains");
            import_subdomains_from.append(&mut paths_from_config_file);
            import_subdomains_from
        },
        wordlists: return_matches_vec(&matches, "wordlists"),
        resolvers: if matches.is_present("custom-resolvers") {
            return_matches_vec(&matches, "custom-resolvers")
        } else {
            resolvers::return_ipv4_resolvers()
        },
        user_agent_strings: {
            let file_name = if matches.is_present("user-agents-file") {
                value_t!(matches, "user-agents-file", String).unwrap_or_else(|_| String::new())
            } else {
                return_value_or_default(&settings, "user_agents_file", String::new())
                    .parse::<String>()
                    .unwrap()
            };
            if !file_name.is_empty() && Path::new(&file_name).exists() {
                match File::open(&file_name) {
                    Ok(file) => BufReader::new(file).lines().flatten().collect(),
                    Err(_) => {
                        eprintln!("Error reading the user agents file, please make sure that the file format is correct.");
                        std::process::exit(1)
                    }
                }
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
        filter_by_string: return_matches_hashset(&matches, "string-filter"),
        exclude_by_string: return_matches_hashset(&matches, "string-exclude"),
        excluded_sources: if matches.is_present("exclude-sources") {
            return_matches_hashset(&matches, "exclude-sources")
        } else {
            return_value_or_default(&settings, "exclude_sources", String::new())
                .split_terminator(',')
                .map(str::to_owned)
                .collect()
        },
        time_wasted: Instant::now(),
    }
}

fn return_settings(
    matches: &clap::ArgMatches,
    settings: &mut config::Config,
) -> HashMap<String, String> {
    if matches.is_present("config-file") || std::env::var("FINDOMAIN_CONFIG_FILE").is_ok() {
        let config_filename = match std::env::var("FINDOMAIN_CONFIG_FILE") {
            Ok(config) => config,
            Err(_) => value_t!(matches, "config-file", String).unwrap(),
        };
        match settings.merge(config::File::with_name(&config_filename)) {
            Ok(settings) => match settings.merge(config::Environment::with_prefix("FINDOMAIN")) {
                Ok(settings) => settings
                    .clone()
                    .try_into::<HashMap<String, String>>()
                    .unwrap(),
                Err(e) => {
                    eprintln!("Error merging environment variables into settings: {e}");
                    std::process::exit(1)
                }
            },
            Err(e) => {
                eprintln!("Error reading config file: {e}");
                std::process::exit(1)
            }
        }
    } else if Path::new("findomain.toml").exists()
        || Path::new("findomain.json").exists()
        || Path::new("findomain.hjson").exists()
        || Path::new("findomain.ini").exists()
        || Path::new("findomain.yml").exists()
    {
        match settings.merge(config::File::with_name("findomain")) {
            Ok(settings) => match settings.merge(config::Environment::with_prefix("FINDOMAIN")) {
                Ok(settings) => settings
                    .clone()
                    .try_into::<HashMap<String, String>>()
                    .unwrap(),
                Err(e) => {
                    eprintln!("Error merging environment variables into settings: {e}");
                    std::process::exit(1)
                }
            },
            Err(e) => {
                eprintln!("Error reading config file: {e}");
                std::process::exit(1)
            }
        }
    } else {
        match settings.merge(config::Environment::with_prefix("FINDOMAIN")) {
            Ok(settings) => settings
                .clone()
                .try_into::<HashMap<String, String>>()
                .unwrap(),
            Err(e) => {
                eprintln!("Error merging environment variables into settings: {e}");
                std::process::exit(1)
            }
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
