use {
    crate::{
        get_resolver,
        misc::{eval_resolved_or_ip_present, sanitize_target_string, validate_target},
    },
    clap::{load_yaml, value_t, App},
    std::{
        collections::{HashMap, HashSet},
        env::current_exe,
        path::Path,
        time::Instant,
    },
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
    pub spyse_access_token: String,
    pub facebook_access_token: String,
    pub virustotal_access_token: String,
    pub securitytrails_access_token: String,
    pub c99_api_key: String,
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
        files: if matches.is_present("files") {
            matches
                .values_of("files")
                .unwrap()
                .map(str::to_owned)
                .collect()
        } else {
            Vec::new()
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
        spyse_access_token: return_value_or_default(&settings, "spyse_token", String::new()),
        facebook_access_token: return_value_or_default(&settings, "fb_token", String::new()),
        virustotal_access_token: return_value_or_default(
            &settings,
            "virustotal_token",
            String::new(),
        ),
        securitytrails_access_token: return_value_or_default(
            &settings,
            "securitytrails_token",
            String::new(),
        ),
        c99_api_key: return_value_or_default(&settings, "c99_api_key", String::new()),
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

fn return_settings(
    matches: &clap::ArgMatches,
    settings: &mut config::Config,
) -> HashMap<String, String> {
    if matches.is_present("config-file") {
        match settings.merge(config::File::with_name(
            &value_t!(matches, "config-file", String).unwrap(),
        )) {
            Ok(settings) => match settings.merge(config::Environment::with_prefix("FINDOMAIN")) {
                Ok(settings) => settings
                    .clone()
                    .try_into::<HashMap<String, String>>()
                    .unwrap(),
                Err(e) => {
                    eprintln!("Error merging environment variables into settings: {}\n", e);
                    std::process::exit(1)
                }
            },
            Err(e) => {
                eprintln!("Error reading config file: {}\n", e);
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
                    eprintln!("Error merging environment variables into settings: {}\n", e);
                    std::process::exit(1)
                }
            },
            Err(e) => {
                eprintln!("Error reading config file: {}\n", e);
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
                eprintln!("Error merging environment variables into settings: {}\n", e);
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
    settings
        .get(value)
        .unwrap_or_else(|| &default_value)
        .to_string()
}
