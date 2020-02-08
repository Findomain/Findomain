use {
    crate::{
        get_resolver,
        misc::{eval_resolved_or_ip_present, sanitize_target_string, validate_target},
    },
    clap::{load_yaml, value_t, App},
    std::{collections::HashSet, env::current_exe, time::Instant},
    trust_dns_resolver::Resolver,
};

pub struct Args {
    pub target: String,
    pub file_name: String,
    pub postgres_connection: String,
    pub discord_webhook: String,
    pub slack_webhook: String,
    pub telegram_bot_token: String,
    pub telegram_webhook: String,
    pub telegram_chat_id: String,
    pub resolver: String,
    pub version: String,
    pub current_executable_path: String,
    pub threads: usize,
    pub database_checker_counter: usize,
    pub commit_to_db_counter: usize,
    pub only_resolved: bool,
    pub with_ip: bool,
    pub with_output: bool,
    pub unique_output_flag: bool,
    pub monitoring_flag: bool,
    pub from_file_flag: bool,
    pub quiet_flag: bool,
    pub query_database: bool,
    pub with_imported_subdomains: bool,
    pub enable_dot: bool,
    pub ipv6_only: bool,
    pub enable_empty_push: bool,
    pub check_updates: bool,
    pub as_resolver: bool,
    pub bruteforce: bool,
    pub disable_wildcard_check: bool,
    pub files: Vec<String>,
    pub subdomains: HashSet<String>,
    pub wordlists_data: HashSet<String>,
    pub wilcard_ips: HashSet<String>,
    pub import_subdomains_from: Vec<String>,
    pub wordlists: Vec<String>,
    pub time_wasted: Instant,
    pub domain_resolver: Resolver,
}

pub fn get_args() -> Args {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml)
        .version(clap::crate_version!())
        .get_matches();
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
        files: if matches.is_present("files") {
            matches
                .values_of("files")
                .unwrap()
                .map(str::to_owned)
                .collect()
        } else {
            Vec::new()
        },
        postgres_connection: format!(
            "postgresql://{}:{}@{}:{}/{}",
            value_t!(matches, "postgres-user", String).unwrap_or_else(|_| "postgres".to_string()),
            value_t!(matches, "postgres-password", String)
                .unwrap_or_else(|_| "postgres".to_string()),
            value_t!(matches, "postgres-host", String).unwrap_or_else(|_| "localhost".to_string()),
            value_t!(matches, "postgres-port", usize).unwrap_or_else(|_| 5432),
            value_t!(matches, "postgres-database", String).unwrap_or_else(|_| String::new()),
        ),
        discord_webhook: String::new(),
        slack_webhook: String::new(),
        telegram_bot_token: String::new(),
        telegram_webhook: String::new(),
        telegram_chat_id: String::new(),
        resolver: value_t!(matches, "resolver", String)
            .unwrap_or_else(|_| "cloudflare".to_string()),
        threads: value_t!(matches, "threads", usize).unwrap_or_else(|_| 50),
        version: clap::crate_version!().to_string(),
        current_executable_path: current_exe().unwrap().display().to_string(),
        database_checker_counter: 0,
        commit_to_db_counter: 0,
        only_resolved: matches.is_present("resolved"),
        with_ip: matches.is_present("ip"),
        with_output: matches.is_present("output") || matches.is_present("unique-output"),
        unique_output_flag: matches.is_present("unique-output"),
        monitoring_flag: matches.is_present("monitoring-flag"),
        from_file_flag: matches.is_present("files"),
        quiet_flag: matches.is_present("quiet"),
        with_imported_subdomains: matches.is_present("import-subdomains"),
        query_database: matches.is_present("query-database"),
        enable_dot: eval_resolved_or_ip_present(
            matches.is_present("enable-dot"),
            matches.is_present("ip") || matches.is_present("ipv6-only"),
            matches.is_present("resolved"),
        ),
        ipv6_only: matches.is_present("ipv6-only"),
        enable_empty_push: matches.is_present("enable-empty-push"),
        check_updates: matches.is_present("check-updates"),
        as_resolver: matches.is_present("as-resolver"),
        bruteforce: matches.is_present("wordlists"),
        disable_wildcard_check: matches.is_present("no-wildcards"),
        subdomains: HashSet::new(),
        wordlists_data: HashSet::new(),
        wilcard_ips: HashSet::new(),
        import_subdomains_from: if matches.is_present("import-subdomains") {
            matches
                .values_of("import-subdomains")
                .unwrap()
                .map(str::to_owned)
                .collect()
        } else {
            Vec::new()
        },
        wordlists: if matches.is_present("wordlists") {
            matches
                .values_of("wordlists")
                .unwrap()
                .map(str::to_owned)
                .collect()
        } else {
            Vec::new()
        },
        time_wasted: Instant::now(),
        domain_resolver: {
            let resolver =
                value_t!(matches, "resolver", String).unwrap_or_else(|_| "cloudflare".to_string());
            let enable_dot = eval_resolved_or_ip_present(
                matches.is_present("enable-dot"),
                matches.is_present("ip") || matches.is_present("ipv6-only"),
                matches.is_present("resolved"),
            );
            get_resolver(enable_dot, resolver)
        },
    }
}
