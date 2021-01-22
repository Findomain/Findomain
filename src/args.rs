use {
    crate::misc::{
        eval_resolved_or_ip_present, return_matches_hashset, return_matches_vec,
        sanitize_target_string, validate_target,
    },
    clap::{load_yaml, value_t, App},
    std::{
        collections::{HashMap, HashSet},
        path::Path,
        time::Instant,
    },
};

#[derive(Clone, Debug)]
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
    pub spyse_access_token: String,
    pub facebook_access_token: String,
    pub virustotal_access_token: String,
    pub securitytrails_access_token: String,
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
    pub http_status: bool,
    pub light_monitoring: bool,
    pub files: Vec<String>,
    pub import_subdomains_from: Vec<String>,
    pub wordlists: Vec<String>,
    pub subdomains: HashSet<String>,
    pub wordlists_data: HashSet<String>,
    pub wilcard_ips: HashSet<String>,
    pub filter_by_string: HashSet<String>,
    pub exclude_by_string: HashSet<String>,
    pub excluded_sources: HashSet<String>,
    pub time_wasted: Instant,
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
        resolver: value_t!(matches, "resolver", String)
            .unwrap_or_else(|_| "cloudflare".to_string()),
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
        threads: value_t!(matches, "threads", usize).unwrap_or_else(|_| 50),
        version: clap::crate_version!().to_string(),
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
        http_status: matches.is_present("http-status"),
        light_monitoring: matches.is_present("light-monitoring"),
        files: return_matches_vec(&matches, "files"),
        import_subdomains_from: return_matches_vec(&matches, "import-subdomains"),
        wordlists: return_matches_vec(&matches, "wordlists"),
        subdomains: HashSet::new(),
        wordlists_data: HashSet::new(),
        wilcard_ips: HashSet::new(),
        filter_by_string: return_matches_hashset(&matches, "string-filter"),
        exclude_by_string: return_matches_hashset(&matches, "string-exclude"),
        excluded_sources: return_matches_hashset(&matches, "exclude-sources"),
        time_wasted: Instant::now(),
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
                    eprintln!("Error merging environment variables into settings: {}", e);
                    std::process::exit(1)
                }
            },
            Err(e) => {
                eprintln!("Error reading config file: {}", e);
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
                    eprintln!("Error merging environment variables into settings: {}", e);
                    std::process::exit(1)
                }
            },
            Err(e) => {
                eprintln!("Error reading config file: {}", e);
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
                eprintln!("Error merging environment variables into settings: {}", e);
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
