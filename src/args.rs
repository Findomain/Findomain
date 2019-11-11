use crate::misc::{eval_resolved_or_ip_present, sanitize_target_string};
use clap::{load_yaml, value_t, App};
use std::collections::HashSet;

pub struct Args {
    pub target: String,
    pub file_name: String,
    pub file: String,
    pub postgres_connection: String,
    pub discord_webhook: String,
    pub slack_webhook: String,
    pub telegram_bot_token: String,
    pub telegram_webhook: String,
    pub telegram_chat_id: String,
    pub resolver: String,
    pub threads: usize,
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
    pub ipv4_only: bool,
    pub ipv6_only: bool,
    pub subdomains: HashSet<String>,
    pub import_subdomains_from: Vec<String>,
}

pub fn get_args() -> Args {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    Args {
        target: sanitize_target_string(
            value_t!(matches, "target", String).unwrap_or_else(|_| String::new()),
        ),
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
        file: if matches.is_present("file") {
            matches.value_of("file").unwrap().to_string()
        } else {
            String::new()
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
        only_resolved: matches.is_present("resolved"),
        with_ip: matches.is_present("ip"),
        with_output: matches.is_present("output") || matches.is_present("unique-output"),
        unique_output_flag: matches.is_present("unique-output"),
        monitoring_flag: matches.is_present("monitoring-flag"),
        from_file_flag: matches.is_present("file"),
        quiet_flag: matches.is_present("quiet"),
        with_imported_subdomains: matches.is_present("import-subdomains"),
        query_database: matches.is_present("query-database"),
        enable_dot: eval_resolved_or_ip_present(
            matches.is_present("enable-dot"),
            matches.is_present("ip")
                || matches.is_present("ipv4-only")
                || matches.is_present("ipv6-only"),
            matches.is_present("resolved"),
        ),
        ipv4_only: matches.is_present("ipv4-only"),
        ipv6_only: matches.is_present("ipv6-only"),
        subdomains: HashSet::new(),
        import_subdomains_from: if matches.is_present("import-subdomains") {
            matches
                .values_of("import-subdomains")
                .unwrap()
                .map(str::to_owned)
                .collect()
        } else {
            Vec::new()
        },
    }
}
