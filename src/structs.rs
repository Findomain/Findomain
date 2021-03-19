use std::{collections::HashSet, time::Instant};

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
    pub version: String,
    pub spyse_access_token: String,
    pub facebook_access_token: String,
    pub virustotal_access_token: String,
    pub securitytrails_access_token: String,
    pub user_agent: String,
    pub c99_api_key: String,
    pub jobname: String,
    pub screenshots_path: String,
    pub threads: usize,
    pub database_checker_counter: usize,
    pub commit_to_db_counter: usize,
    pub rate_limit: u64,
    pub http_timeout: u64,
    pub initial_port: u16,
    pub last_port: u16,
    pub only_resolved: bool,
    pub with_ip: bool,
    pub with_output: bool,
    pub unique_output_flag: bool,
    pub monitoring_flag: bool,
    pub from_file_flag: bool,
    pub quiet_flag: bool,
    pub query_database: bool,
    pub query_jobname: bool,
    pub with_imported_subdomains: bool,
    pub enable_dot: bool,
    pub ipv6_only: bool,
    pub enable_empty_push: bool,
    pub as_resolver: bool,
    pub bruteforce: bool,
    pub disable_wildcard_check: bool,
    pub http_status: bool,
    pub is_last_target: bool,
    pub enable_port_scan: bool,
    pub custom_threads: bool,
    pub discover_ip: bool,
    pub verbose: bool,
    pub unlock_threads: bool,
    pub dbpush_if_timeout: bool,
    pub no_monitor: bool,
    pub take_screenshots: bool,
    pub chrome_sandbox: bool,
    pub custom_resolvers: bool,
    pub from_stdin: bool,
    pub files: Vec<String>,
    pub import_subdomains_from: Vec<String>,
    pub wordlists: Vec<String>,
    pub resolvers: Vec<String>,
    pub user_agent_strings: Vec<String>,
    pub subdomains: HashSet<String>,
    pub wordlists_data: HashSet<String>,
    pub wilcard_ips: HashSet<String>,
    pub filter_by_string: HashSet<String>,
    pub exclude_by_string: HashSet<String>,
    pub excluded_sources: HashSet<String>,
    pub time_wasted: Instant,
}

pub struct Subdomain {
    pub name: String,
}

pub struct ResolvData {
    pub ip: String,
    pub http_status: HttpStatus,
    pub open_ports: Vec<i32>,
}

#[derive(Clone)]
pub struct HttpStatus {
    pub http_status: String,
    pub host_url: String,
}

pub struct ResolverEngineData {
    pub subdomain: String,
    pub resol_data: ResolvData,
    pub timeout: u64,
}
