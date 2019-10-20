#[macro_use]
extern crate serde_derive;
use serde::de::DeserializeOwned;

#[macro_use]
extern crate lazy_static;

pub mod args;
pub mod errors;
mod get_vars;
mod misc;

use crate::errors::*;
use postgres::{Connection, TlsMode};
use rand::Rng;
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    thread,
    time::Duration,
};
use trust_dns_resolver::{config::ResolverConfig, config::ResolverOpts, Resolver};

trait IntoSubdomains {
    fn into_subdomains(self) -> HashSet<String>;
}

impl IntoSubdomains for HashSet<String> {
    #[inline]
    fn into_subdomains(self) -> HashSet<String> {
        self
    }
}

#[derive(Deserialize, Eq, PartialEq, Hash)]
struct SubdomainsCertSpotter {
    dns_names: Vec<String>,
}

#[derive(Deserialize, Eq, PartialEq, Hash)]
struct SubdomainsCrtsh {
    name_value: String,
}

#[allow(non_snake_case)]
struct SubdomainsDBCrtsh {
    NAME_VALUE: String,
}

#[derive(Deserialize, Eq, PartialEq, Hash)]
struct SubdomainsVirustotal {
    id: String,
}

#[derive(Deserialize, Eq, PartialEq)]
struct ResponseDataVirusTotal {
    data: HashSet<SubdomainsVirustotal>,
}

impl IntoSubdomains for ResponseDataVirusTotal {
    fn into_subdomains(self) -> HashSet<String> {
        self.data.into_iter().map(|sub| sub.id).collect()
    }
}

#[derive(Deserialize, Eq, PartialEq, Hash)]
struct SubdomainsFacebook {
    domains: Vec<String>,
}

#[derive(Deserialize, Eq, PartialEq)]
struct ResponseDataFacebook {
    data: HashSet<SubdomainsFacebook>,
}

impl IntoSubdomains for ResponseDataFacebook {
    fn into_subdomains(self) -> HashSet<String> {
        self.data
            .into_iter()
            .flat_map(|sub| sub.domains.into_iter())
            .collect()
    }
}

#[derive(Deserialize, Eq, PartialEq, Hash)]
struct SubdomainsSpyse {
    domain: String,
}

#[derive(Deserialize, Eq, PartialEq)]
struct ResponseDataSpyse {
    records: HashSet<SubdomainsSpyse>,
}

impl IntoSubdomains for ResponseDataSpyse {
    fn into_subdomains(self) -> HashSet<String> {
        self.records.into_iter().map(|sub| sub.domain).collect()
    }
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct SubdomainsBufferover {
    FDNS_A: HashSet<String>,
}

impl IntoSubdomains for SubdomainsBufferover {
    fn into_subdomains(self) -> HashSet<String> {
        self.FDNS_A
            .iter()
            .map(|sub| sub.split(','))
            .flatten()
            .map(str::to_owned)
            .collect()
    }
}

#[derive(Deserialize)]
struct SubdomainsThreadcrowd {
    subdomains: HashSet<String>,
}

impl IntoSubdomains for SubdomainsThreadcrowd {
    fn into_subdomains(self) -> HashSet<String> {
        self.subdomains.into_iter().collect()
    }
}

#[derive(Deserialize)]
struct SubdomainsVirustotalApikey {
    subdomains: HashSet<String>,
}

impl IntoSubdomains for SubdomainsVirustotalApikey {
    fn into_subdomains(self) -> HashSet<String> {
        self.subdomains.into_iter().collect()
    }
}

struct Subdomain {
    name: String,
}

lazy_static! {
    static ref CLIENT: reqwest::Client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap();
}

pub fn get_subdomains(args: &mut args::Args) -> Result<()> {
    let file_name = &args.file_name;
    let postgres_connection = format!(
        "postgresql://{}:{}@{}:{}/{}",
        args.postgres_user,
        args.postgres_password,
        args.postgres_host,
        args.postgres_port,
        args.postgres_database
    );
    let quiet_flag = args.quiet_flag;
    let discord_webhook = get_vars::get_webhook("discord");
    let slack_webhook = get_vars::get_webhook("slack");
    let telegram_bot_token = get_vars::get_auth_token("telegram");
    let mut telegram_webhook = format!(
        "https://api.telegram.org/bot{}/sendMessage",
        telegram_bot_token
    );
    let telegram_chat_id = get_vars::get_chat_id("telegram");

    if args.monitoring_flag
        && discord_webhook.is_empty()
        && slack_webhook.is_empty()
        && telegram_bot_token.is_empty()
    {
        telegram_err1();
        std::process::exit(1)
    } else if !telegram_bot_token.is_empty() && telegram_chat_id.is_empty() {
        telegram_err2();
        std::process::exit(1)
    } else if telegram_bot_token.is_empty() && telegram_chat_id.is_empty() {
        telegram_webhook = String::from("")
    }

    let connection: Option<postgres::Connection> = if args.monitoring_flag {
        Some(Connection::connect(postgres_connection, TlsMode::None)?)
    } else {
        None
    };

    let target = args
        .target
        .replace("www.", "")
        .replace("https://", "")
        .replace("http://", "")
        .replace("/", "");

    if !quiet_flag {
        println!("\nTarget ==> {}\n", &target)
    }

    let spyse_access_token = get_vars::get_auth_token("spyse");
    let facebook_access_token = get_vars::get_auth_token("facebook");
    let virustotal_access_token = get_vars::get_auth_token("virustotal");

    let url_api_certspotter = format!(
        "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
        &target
    );
    let url_api_virustotal = format!(
        "https://www.virustotal.com/ui/domains/{}/subdomains?limit=40",
        &target
    );
    let url_api_crtsh = format!("https://crt.sh/?q=%.{}&output=json", &target);
    let crtsh_db_query = format!("SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%.{}'))", &target);
    let url_api_sublist3r = format!("https://api.sublist3r.com/search.php?domain={}", &target);
    let url_api_spyse = format!(
        "https://api.spyse.com/v1/subdomains?domain={}&api_token={}",
        &target, &spyse_access_token
    );
    let url_api_bufferover = format!("http://dns.bufferover.run/dns?q={}", &target);
    let url_api_threatcrowd = format!(
        "https://threatcrowd.org/searchApi/v2/domain/report/?domain={}",
        &target
    );
    let all_subdomains = vec![
        thread::spawn(move || get_certspotter_subdomains(&url_api_certspotter, quiet_flag)),
        thread::spawn(move || get_crtsh_db_subdomains(&crtsh_db_query, &url_api_crtsh, quiet_flag)),
        thread::spawn(move || get_virustotal_subdomains(&url_api_virustotal, quiet_flag)),
        thread::spawn(move || get_sublist3r_subdomains(&url_api_sublist3r, quiet_flag)),
        if facebook_access_token.is_empty() {
            let findomain_fb_tokens = [
                "688177841647920|RAeNYr8jwFXGH9v-IhGv4tfHMpU",
                "772592906530976|CNkO7OxM6ssQgOBLCraC_dhKE7M",
                "1004691886529013|iiUStPqcXCELcwv89-SZQSqqFNY",
                "2106186849683294|beVoPBtLp3IWjpLsnF6Mpzo1gVM",
                "2095886140707025|WkO8gTgPtwmnNZL3NQ74z92DA-k",
                "434231614102088|pLJSVc9iOqxrG6NO7DDPrlkQ1qE",
                "431009107520610|AX8VNunXMng-ainHO8Ke0sdeMJI",
                "893300687707948|KW_O07biKRaW5fpNqeAeSrMU1W8",
                "2477772448946546|BXn-h2zX6qb4WsFvtOywrNsDixo",
                "509488472952865|kONi75jYL_KQ_6J1CHPQ1MH4x_U",
            ];
            let url_api_fb = format!(
                "https://graph.facebook.com/certificates?query={}&fields=domains&limit=10000&access_token={}",
                &target,
                &findomain_fb_tokens[rand::thread_rng().gen_range(0, findomain_fb_tokens.len())]
            );
            thread::spawn(move || get_facebook_subdomains(&url_api_fb, quiet_flag))
        } else {
            let url_api_fb = format!(
                "https://graph.facebook.com/certificates?query={}&fields=domains&limit=10000&access_token={}",
                &target,
                &facebook_access_token);
            thread::spawn(move || get_facebook_subdomains(&url_api_fb, quiet_flag))
        },
        thread::spawn(move || get_spyse_subdomains(&url_api_spyse, quiet_flag)),
        thread::spawn(move || get_bufferover_subdomains(&url_api_bufferover, quiet_flag)),
        thread::spawn(move || get_threatcrowd_subdomains(&url_api_threatcrowd, quiet_flag)),
        if virustotal_access_token.is_empty() {
            thread::spawn(|| None)
        } else {
            let url_virustotal_apikey = format!(
                "https://www.virustotal.com/vtapi/v2/domain/report?apikey={}&domain={}",
                &virustotal_access_token, &target
            );
            thread::spawn(move || {
                get_virustotal_apikey_subdomains(&url_virustotal_apikey, quiet_flag)
            })
        },
    ];

    let subdomains: HashSet<String> = all_subdomains
        .into_iter()
        .map(|j| j.join().unwrap())
        .collect::<Vec<_>>()
        .into_iter()
        .flatten()
        .flat_map(|sub| sub)
        .collect();
    if subdomains.is_empty() {
        eprintln!(
            "\nNo subdomains were found for the target: {} ¡😭!\n",
            &target
        );
    } else {
        if args.unique_output_flag && !args.from_file_flag && !args.monitoring_flag {
            misc::check_output_file_exists(&file_name)?;
            manage_subdomains_data(
                subdomains,
                &target,
                args.only_resolved,
                args.with_ip,
                args.with_output,
                &file_name,
                args.quiet_flag,
            )?;
        } else if args.unique_output_flag && args.from_file_flag && !args.monitoring_flag {
            manage_subdomains_data(
                subdomains,
                &target,
                args.only_resolved,
                args.with_ip,
                args.with_output,
                &file_name,
                args.quiet_flag,
            )?;
        } else if args.monitoring_flag && !args.unique_output_flag {
            subdomains_alerts(
                connection.unwrap(),
                subdomains,
                &target,
                &discord_webhook,
                &slack_webhook,
                &telegram_webhook,
                telegram_chat_id,
                &args,
            )?;
        } else {
            misc::check_output_file_exists(&file_name)?;
            manage_subdomains_data(
                subdomains,
                &target,
                args.only_resolved,
                args.with_ip,
                args.with_output,
                &file_name,
                args.quiet_flag,
            )?;
        }
        if args.with_output && !args.quiet_flag && !args.monitoring_flag {
            misc::show_file_location(&target, &file_name)
        }
    }

    Ok(())
}

fn manage_subdomains_data(
    mut subdomains: HashSet<String>,
    target: &str,
    only_resolved: bool,
    with_ip: bool,
    with_output: bool,
    file_name: &str,
    quiet_flag: bool,
) -> Result<()> {
    let base_target = [".", &target].concat();
    let resolver = get_resolver();
    if !quiet_flag {
        println!()
    };
    subdomains
        .retain(|sub| !sub.contains('*') && !sub.starts_with('.') && sub.ends_with(&base_target));
    let mut subdomains_resolved = 0;
    if with_output && (only_resolved || with_ip) {
        if only_resolved {
            for subdomain in &subdomains {
                if resolver.lookup_ip(subdomain).is_ok() {
                    write_to_file(subdomain, file_name)?;
                    println!("{}", subdomain);
                    subdomains_resolved += 1
                }
            }
        } else if with_ip {
            for subdomain in &subdomains {
                let ip = get_ip(&resolver, subdomain);
                let data = format!("{},{}", subdomain, ip);
                if !ip.is_empty() {
                    write_to_file(&data, file_name)?;
                    println!("{}", data);
                    subdomains_resolved += 1
                }
            }
        }
        misc::show_subdomains_found(subdomains_resolved, target, quiet_flag)
    } else if !with_output && (only_resolved || with_ip) {
        if only_resolved {
            for subdomain in &subdomains {
                if resolver.lookup_ip(subdomain).is_ok() {
                    println!("{}", subdomain);
                    subdomains_resolved += 1
                }
            }
        } else if with_ip {
            for subdomain in &subdomains {
                let ip = get_ip(&resolver, subdomain);
                if !ip.is_empty() {
                    println!("{}", &format!("{},{}", subdomain, ip));
                    subdomains_resolved += 1
                }
            }
        }
        misc::show_subdomains_found(subdomains_resolved, target, quiet_flag)
    } else if !only_resolved && !with_ip && with_output {
        for subdomain in &subdomains {
            write_to_file(subdomain, file_name)?;
            println!("{}", subdomain);
        }
        misc::show_subdomains_found(subdomains.len(), target, quiet_flag)
    } else {
        for subdomain in &subdomains {
            println!("{}", subdomain);
        }
        misc::show_subdomains_found(subdomains.len(), target, quiet_flag)
    }

    if !quiet_flag {
        println!("\nGood luck Hax0r 💀!\n");
    }

    Ok(())
}

fn get_certspotter_subdomains(
    url_api_certspotter: &str,
    quiet_flag: bool,
) -> Option<HashSet<String>> {
    if !quiet_flag {
        misc::show_searching_msg("CertSpotter")
    }
    match CLIENT.get(url_api_certspotter).send() {
        Ok(mut data_certspotter) => match data_certspotter.json::<HashSet<SubdomainsCertSpotter>>()
        {
            Ok(domains_certspotter) => Some(
                domains_certspotter
                    .into_iter()
                    .flat_map(|sub| sub.dns_names.into_iter())
                    .collect(),
            ),
            Err(e) => {
                check_json_errors(e, "CertSpotter", quiet_flag);
                None
            }
        },
        Err(e) => {
            check_request_errors(e, "CertSpotter", quiet_flag);
            None
        }
    }
}

fn get_crtsh_subdomains(url_api_crtsh: &str, quiet_flag: bool) -> Option<HashSet<String>> {
    if !quiet_flag {
        misc::show_searching_msg("Crtsh")
    }
    match CLIENT.get(url_api_crtsh).send() {
        Ok(mut data_crtsh) => match data_crtsh.json::<HashSet<SubdomainsCrtsh>>() {
            Ok(domains_crtsh) => Some(
                domains_crtsh
                    .into_iter()
                    .map(|sub| sub.name_value)
                    .collect(),
            ),
            Err(e) => {
                check_json_errors(e, "Crtsh", quiet_flag);
                None
            }
        },
        Err(e) => {
            check_request_errors(e, "Crtsh", quiet_flag);
            None
        }
    }
}

fn get_crtsh_db_subdomains(
    crtsh_db_query: &str,
    url_api_crtsh: &str,
    quiet_flag: bool,
) -> Option<HashSet<String>> {
    if !quiet_flag {
        misc::show_searching_msg("Crtsh database")
    }
    match Connection::connect("postgres://guest@crt.sh:5432/certwatch", TlsMode::None) {
        Ok(crtsh_db_client) => match crtsh_db_client.query(&crtsh_db_query, &[]) {
            Ok(crtsh_db_subdomains) => Some(
                crtsh_db_subdomains
                    .iter()
                    .map(|row| {
                        let subdomain = SubdomainsDBCrtsh {
                            NAME_VALUE: row.get("NAME_VALUE"),
                        };
                        subdomain.NAME_VALUE
                    })
                    .collect(),
            ),
            Err(e) => {
                if !quiet_flag {
                    println!(
                    "❌ A error has occurred while querying the Crtsh database. Error: {}. Trying the API method...",
                    e.description()
                );
                }
                get_crtsh_subdomains(&url_api_crtsh, quiet_flag)
            }
        },
        Err(e) => {
            if !quiet_flag {
                println!(
                "❌ A error has occurred while connecting to the Crtsh database. Error: {}. Trying the API method...",
                e.description()
            );
            }
            get_crtsh_subdomains(&url_api_crtsh, quiet_flag)
        }
    }
}

fn get_from_http_api<T: DeserializeOwned + IntoSubdomains>(
    url: &str,
    name: &str,
    quiet_flag: bool,
) -> Option<HashSet<String>> {
    match CLIENT.get(url).send() {
        Ok(mut data) => match data.json::<T>() {
            Ok(json) => Some(json.into_subdomains()),
            Err(e) => {
                check_json_errors(e, name, quiet_flag);
                None
            }
        },
        Err(e) => {
            check_request_errors(e, name, quiet_flag);
            None
        }
    }
}

fn get_virustotal_subdomains(
    url_api_virustotal: &str,
    quiet_flag: bool,
) -> Option<HashSet<String>> {
    if !quiet_flag {
        misc::show_searching_msg("Virustotal")
    }
    get_from_http_api::<ResponseDataVirusTotal>(url_api_virustotal, "Virustotal", quiet_flag)
}

fn get_sublist3r_subdomains(url_api_sublist3r: &str, quiet_flag: bool) -> Option<HashSet<String>> {
    if !quiet_flag {
        misc::show_searching_msg("Sublist3r")
    }
    get_from_http_api::<HashSet<String>>(url_api_sublist3r, "Sublist3r", quiet_flag)
}

fn get_facebook_subdomains(url_api_fb: &str, quiet_flag: bool) -> Option<HashSet<String>> {
    if !quiet_flag {
        misc::show_searching_msg("Facebook")
    }
    get_from_http_api::<ResponseDataFacebook>(url_api_fb, "Facebook", quiet_flag)
}

fn get_spyse_subdomains(url_api_spyse: &str, quiet_flag: bool) -> Option<HashSet<String>> {
    if !quiet_flag {
        misc::show_searching_msg("Spyse")
    }
    get_from_http_api::<ResponseDataSpyse>(url_api_spyse, "Spyse", quiet_flag)
}

fn get_bufferover_subdomains(
    url_api_bufferover: &str,
    quiet_flag: bool,
) -> Option<HashSet<String>> {
    if !quiet_flag {
        misc::show_searching_msg("Bufferover")
    }
    get_from_http_api::<SubdomainsBufferover>(url_api_bufferover, "Bufferover", quiet_flag)
}

fn get_threatcrowd_subdomains(
    url_api_threatcrowd: &str,
    quiet_flag: bool,
) -> Option<HashSet<String>> {
    if !quiet_flag {
        misc::show_searching_msg("Threadcrowd")
    }
    get_from_http_api::<SubdomainsThreadcrowd>(url_api_threatcrowd, "Threadcrowd", quiet_flag)
}

fn get_virustotal_apikey_subdomains(
    url_virustotal_apikey: &str,
    quiet_flag: bool,
) -> Option<HashSet<String>> {
    if !quiet_flag {
        println!("Searching in the Virustotal API using apikey... 🔍");
    }
    get_from_http_api::<SubdomainsVirustotalApikey>(
        url_virustotal_apikey,
        "Virustotal API using apikey",
        quiet_flag,
    )
}

pub fn read_from_file(args: &mut args::Args) -> Result<()> {
    let file_name = args.file_name.clone();
    if args.unique_output_flag {
        misc::check_output_file_exists(&args.file_name)?;
    }
    let f =
        File::open(&args.file).with_context(|_| format!("Can't open file 📁 {}", &args.file))?;
    let f = BufReader::new(f);
    for domain in f.lines() {
        args.target = domain?.to_string();
        args.file_name = if file_name.is_empty() && !args.with_ip {
            [&args.target, ".txt"].concat()
        } else if file_name.is_empty() && args.with_ip {
            [&args.target, "-ip", ".txt"].concat()
        } else {
            file_name.to_string()
        };
        get_subdomains(args)?;
    }

    Ok(())
}

fn write_to_file(data: &str, file_name: &str) -> Result<()> {
    let mut output_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&file_name)
        .with_context(|_| format!("Can't create file 📁 {}", &file_name))?;
    output_file.write_all(&[data, "\n"].concat().as_bytes())?;
    Ok(())
}

fn get_ip(resolver: &Resolver, domain: &str) -> String {
    match resolver.lookup_ip(&domain) {
        Ok(ip_address) => ip_address
            .iter()
            .next()
            .expect("An error as ocurred getting the IP address.")
            .to_string(),
        Err(_) => String::from(""),
    }
}

fn get_resolver() -> Resolver {
    if let Ok(system_resolver) = Resolver::from_system_conf() {
        system_resolver
    } else if let Ok(quad9_resolver) =
        Resolver::new(ResolverConfig::quad9(), ResolverOpts::default())
    {
        quad9_resolver
    } else if let Ok(cloudflare_resolver) =
        Resolver::new(ResolverConfig::cloudflare(), ResolverOpts::default())
    {
        cloudflare_resolver
    } else {
        Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap()
    }
}

fn subdomains_alerts(
    connection: postgres::Connection,
    mut current_subdomains: HashSet<String>,
    target: &str,
    discord_webhook: &str,
    slack_webhook: &str,
    telegram_webhook: &str,
    telegram_chat_id: String,
    args: &&mut args::Args,
) -> Result<()> {
    let mut discord_parameters = HashMap::new();
    let mut slack_parameters = HashMap::new();
    let mut telegram_parameters = HashMap::new();
    let mut webhooks_data = HashMap::new();
    let base_target = [".", &target].concat();
    connection.execute(
        "CREATE TABLE IF NOT EXISTS subdomains (
                   id              SERIAL PRIMARY KEY,
                   name            VARCHAR NOT NULL UNIQUE
              )",
        &[],
    )?;

    let existing_subdomains = connection.query(
        &format!("SELECT name FROM subdomains WHERE name LIKE '%{}'", &target),
        &[],
    )?;

    let existing_subdomains: HashSet<String> = existing_subdomains
        .iter()
        .map(|row| {
            let subdomain = Subdomain {
                name: row.get("name"),
            };
            subdomain.name
        })
        .collect();

    current_subdomains
        .retain(|sub| !sub.contains('*') && !sub.starts_with('.') && sub.ends_with(&base_target));

    let new_subdomains: HashSet<String> = current_subdomains
        .difference(&existing_subdomains)
        .map(|sub| sub.to_string())
        .collect();

    if args.with_output && !new_subdomains.is_empty() {
        let file_name = args.file_name.replace(
            &args.file_name.split('.').last().unwrap(),
            "new_subdomains.txt",
        );
        misc::check_output_file_exists(&file_name)?;
        for subdomain in &new_subdomains {
            write_to_file(subdomain, &file_name)?;
        }
        if !args.quiet_flag {
            misc::show_file_location(&target, &file_name)
        }
    }

    if !discord_webhook.is_empty() {
        discord_parameters.insert(
            "content",
            misc::return_webhook_payload(&new_subdomains, "discord", &target),
        );
        webhooks_data.insert(discord_webhook, discord_parameters);
    }

    if !slack_webhook.is_empty() {
        slack_parameters.insert(
            "text",
            misc::return_webhook_payload(&new_subdomains, "slack", &target),
        );
        webhooks_data.insert(slack_webhook, slack_parameters);
    }

    if !telegram_webhook.is_empty() {
        telegram_parameters.insert(
            "text",
            misc::return_webhook_payload(&new_subdomains, "telegram", &target),
        );
        telegram_parameters.insert("chat_id", telegram_chat_id);
        telegram_parameters.insert("parse_mode", "HTML".to_string());
        webhooks_data.insert(telegram_webhook, telegram_parameters);
    }

    let mut commit_to_db_counter = 0;

    for (webhook, webhooks_payload) in webhooks_data {
        if !webhook.is_empty() {
            let response = CLIENT.post(webhook).json(&webhooks_payload).send()?;
            if response.status().is_success()
                || response.status() == 204
                    && !new_subdomains.is_empty()
                    && commit_to_db_counter == 0
            {
                if commit_to_db(&connection, &new_subdomains).is_ok() {
                    commit_to_db_counter += 1
                }
            } else if response.status().is_success()
                || response.status() == 204 && new_subdomains.is_empty()
            {
            } else if !args.quiet_flag {
                eprintln!(
                    "\nAn error occurred when Findomain tried to publish the data to the following webhook {}. \nError description: {}",
                    webhook, response.status()
                )
            }
        }
    }
    Ok(())
}

fn commit_to_db(conn: &postgres::Connection, new_subdomains: &HashSet<String>) -> Result<()> {
    let prepared_transaction = conn.transaction()?;
    for subdomain in new_subdomains {
        prepared_transaction.execute("INSERT INTO subdomains (name) VALUES ($1)", &[&subdomain])?;
    }
    prepared_transaction.commit()?;
    Ok(())
}
