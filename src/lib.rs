#[macro_use]
extern crate serde_derive;
use serde::de::DeserializeOwned;

#[macro_use]
extern crate lazy_static;

use postgres::{Connection, TlsMode};
use rand::Rng;
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::Path,
    thread,
    time::Duration,
};
use trust_dns_resolver::{config::ResolverConfig, config::ResolverOpts, Resolver};

pub mod errors;
mod get_vars;
use crate::errors::*;

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

pub fn get_subdomains(
    target: &str,
    only_resolved: &str,
    with_output: &str,
    file_name: &str,
    unique_output_flag: &str,
    monitoring_flag: &str,
    from_file_flag: &str,
    postgres_connection: &str,
) -> Result<()> {
    let discord_webhook = get_vars::get_webhook("discord");
    let slack_webhook = get_vars::get_webhook("slack");
    let telegram_bot_token = get_vars::get_auth_token("telegram");
    let mut telegram_webhook = format!(
        "{}{}{}",
        "https://api.telegram.org/bot", telegram_bot_token, "/sendMessage"
    );
    let telegram_chat_id = get_vars::get_chat_id("telegram");

    if monitoring_flag == "y"
        && discord_webhook.is_empty()
        && slack_webhook.is_empty()
        && telegram_bot_token.is_empty()
    {
        eprintln!("You need to configure at least one webhook variable in your system. For Discord set the findomain_discord_webhook system variable, for Slack set the findomain_slack_webhook variable, for Telegram set the findomain_telegrambot_token and findomain_telegrambot_chat_id valriables. See https://git.io/JeZQW for more information, exiting.");
        std::process::exit(1)
    } else if !telegram_bot_token.is_empty() && telegram_chat_id.is_empty() {
        eprintln!("You have configured the findomain_telegrambot_token variable but not the findomain_telegrambot_chat_id variable, it's required. See https://git.io/JeZQW for more information, exiting.");
        std::process::exit(1)
    } else if telegram_bot_token.is_empty() && telegram_chat_id.is_empty() {
        telegram_webhook = String::from("")
    }

    let connection: Option<postgres::Connection> = if monitoring_flag == "y" {
        Some(Connection::connect(postgres_connection, TlsMode::None)?)
    } else {
        None
    };

    let target = target
        .replace("www.", "")
        .replace("https://", "")
        .replace("http://", "")
        .replace("/", "");

    println!("\nTarget ==> {}\n", &target);

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
        thread::spawn(move || get_certspotter_subdomains(&url_api_certspotter)),
        thread::spawn(move || get_crtsh_db_subdomains(&crtsh_db_query, &url_api_crtsh)),
        thread::spawn(move || get_virustotal_subdomains(&url_api_virustotal)),
        thread::spawn(move || get_sublist3r_subdomains(&url_api_sublist3r)),
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
            thread::spawn(move || get_facebook_subdomains(&url_api_fb))
        } else {
            let url_api_fb = format!(
                "https://graph.facebook.com/certificates?query={}&fields=domains&limit=10000&access_token={}",
                &target,
                &facebook_access_token);
            thread::spawn(move || get_facebook_subdomains(&url_api_fb))
        },
        thread::spawn(move || get_spyse_subdomains(&url_api_spyse)),
        thread::spawn(move || get_bufferover_subdomains(&url_api_bufferover)),
        thread::spawn(move || get_threatcrowd_subdomains(&url_api_threatcrowd)),
        if virustotal_access_token.is_empty() {
            thread::spawn(|| None)
        } else {
            let url_virustotal_apikey = format!(
                "https://www.virustotal.com/vtapi/v2/domain/report?apikey={}&domain={}",
                &virustotal_access_token, &target
            );
            thread::spawn(move || get_virustotal_apikey_subdomains(&url_virustotal_apikey))
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
        println!(
            "\nNo subdomains were found for the target: {} ¡😭!\n",
            &target
        );
    } else {
        if unique_output_flag == "y" && from_file_flag.is_empty() && monitoring_flag.is_empty() {
            check_output_file_exists(file_name)?;
            manage_subdomains_data(
                subdomains,
                &target,
                &only_resolved,
                &with_output,
                &file_name,
            )?;
        } else if unique_output_flag == "y"
            && !from_file_flag.is_empty()
            && monitoring_flag.is_empty()
        {
            manage_subdomains_data(
                subdomains,
                &target,
                &only_resolved,
                &with_output,
                &file_name,
            )?;
        } else if monitoring_flag == "y" && unique_output_flag.is_empty() {
            subdomains_alerts(
                connection.unwrap(),
                subdomains,
                &target,
                &discord_webhook,
                &slack_webhook,
                &telegram_webhook,
                telegram_chat_id,
            )?;
        } else {
            check_output_file_exists(&file_name)?;
            manage_subdomains_data(
                subdomains,
                &target,
                &only_resolved,
                &with_output,
                &file_name,
            )?;
        }
        if with_output == "y" {
            println!(
                ">> 📁 Filename for the target {} was saved in: ./{} 😀",
                &target, &file_name
            )
        }
    }

    Ok(())
}

fn manage_subdomains_data(
    mut subdomains: HashSet<String>,
    target: &str,
    only_resolved: &str,
    with_output: &str,
    file_name: &str,
) -> Result<()> {
    let base_target = [".", &target].concat();
    println!();
    subdomains
        .retain(|sub| !sub.contains('*') && !sub.starts_with('.') && sub.ends_with(&base_target));
    let mut subdomains_resolved = 0;
    if only_resolved == "y" && with_output == "y" {
        for subdomain in &subdomains {
            if get_ip(subdomain) {
                write_to_file(subdomain, file_name)?;
                println!("{}", subdomain);
                subdomains_resolved += 1
            }
        }
        show_subdomains_found(subdomains_resolved, target)
    } else if only_resolved == "y" && with_output != "y" {
        for subdomain in &subdomains {
            if get_ip(subdomain) {
                println!("{}", subdomain);
                subdomains_resolved += 1
            }
        }
        show_subdomains_found(subdomains_resolved, target)
    } else if only_resolved != "y" && with_output == "y" {
        for subdomain in &subdomains {
            write_to_file(subdomain, file_name)?;
            println!("{}", subdomain);
        }
        show_subdomains_found(subdomains.len(), target)
    } else {
        for subdomain in &subdomains {
            println!("{}", subdomain);
        }
        show_subdomains_found(subdomains.len(), target)
    }
    println!("\nGood luck Hax0r 💀!\n");

    Ok(())
}

fn show_subdomains_found(subdomains_found: usize, target: &str) {
    println!(
        "\nA total of {} subdomains were found for ==>  {} 👽",
        subdomains_found, target
    )
}

fn get_certspotter_subdomains(url_api_certspotter: &str) -> Option<HashSet<String>> {
    println!("Searching in the CertSpotter API... 🔍");
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
                check_json_errors(e, "CertSpotter");
                None
            }
        },
        Err(e) => {
            check_request_errors(e, "CertSpotter");
            None
        }
    }
}

fn get_crtsh_subdomains(url_api_crtsh: &str) -> Option<HashSet<String>> {
    println!("Searching in the Crtsh API... 🔍");
    match CLIENT.get(url_api_crtsh).send() {
        Ok(mut data_crtsh) => match data_crtsh.json::<HashSet<SubdomainsCrtsh>>() {
            Ok(domains_crtsh) => Some(
                domains_crtsh
                    .into_iter()
                    .map(|sub| sub.name_value)
                    .collect(),
            ),
            Err(e) => {
                check_json_errors(e, "Crtsh");
                None
            }
        },
        Err(e) => {
            check_request_errors(e, "Crtsh");
            None
        }
    }
}

fn get_crtsh_db_subdomains(crtsh_db_query: &str, url_api_crtsh: &str) -> Option<HashSet<String>> {
    println!("Searching in the Crtsh database... 🔍");
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
                println!(
                    "❌ A error has occurred while querying the Crtsh database. Error: {}. Trying the API method...",
                    e.description()
                );
                get_crtsh_subdomains(&url_api_crtsh)
            }
        },
        Err(e) => {
            println!(
                "❌ A error has occurred while connecting to the Crtsh database. Error: {}. Trying the API method...",
                e.description()
            );
            get_crtsh_subdomains(&url_api_crtsh)
        }
    }
}

fn get_from_http_api<T: DeserializeOwned + IntoSubdomains>(
    url: &str,
    name: &str,
) -> Option<HashSet<String>> {
    match CLIENT.get(url).send() {
        Ok(mut data) => match data.json::<T>() {
            Ok(json) => Some(json.into_subdomains()),
            Err(e) => {
                check_json_errors(e, name);
                None
            }
        },
        Err(e) => {
            check_request_errors(e, name);
            None
        }
    }
}

fn get_virustotal_subdomains(url_api_virustotal: &str) -> Option<HashSet<String>> {
    println!("Searching in the Virustotal API... 🔍");
    get_from_http_api::<ResponseDataVirusTotal>(url_api_virustotal, "Virustotal")
}

fn get_sublist3r_subdomains(url_api_sublist3r: &str) -> Option<HashSet<String>> {
    println!("Searching in the Sublist3r API... 🔍");
    get_from_http_api::<HashSet<String>>(url_api_sublist3r, "Sublist3r")
}

fn get_facebook_subdomains(url_api_fb: &str) -> Option<HashSet<String>> {
    println!("Searching in the Facebook API... 🔍");
    get_from_http_api::<ResponseDataFacebook>(url_api_fb, "Facebook")
}

fn get_spyse_subdomains(url_api_spyse: &str) -> Option<HashSet<String>> {
    println!("Searching in the Spyse API... 🔍");
    get_from_http_api::<ResponseDataSpyse>(url_api_spyse, "Spyse")
}

fn get_bufferover_subdomains(url_api_bufferover: &str) -> Option<HashSet<String>> {
    println!("Searching in the Bufferover API... 🔍");
    get_from_http_api::<SubdomainsBufferover>(url_api_bufferover, "Bufferover")
}

fn get_threatcrowd_subdomains(url_api_threatcrowd: &str) -> Option<HashSet<String>> {
    println!("Searching in the Threadcrowd API... 🔍");
    get_from_http_api::<SubdomainsThreadcrowd>(url_api_threatcrowd, "Threadcrowd")
}

fn get_virustotal_apikey_subdomains(url_virustotal_apikey: &str) -> Option<HashSet<String>> {
    println!("Searching in the Virustotal API using apikey... 🔍");
    get_from_http_api::<SubdomainsVirustotalApikey>(
        url_virustotal_apikey,
        "Virustotal API using apikey",
    )
}

fn check_request_errors(error: reqwest::Error, api: &str) {
    if error.is_timeout() {
        println!(
            "⏳ A timeout error has occurred while processing the request in the {} API. Error description: {}",
            &api, &error.description())
    } else if error.is_redirect() {
        println!(
            "❌ A redirect was found while processing the {} API. Error description: {}",
            &api,
            &error.description()
        )
    } else if error.is_client_error() {
        println!(
            "❌ A client error has occurred sending the request to the {} API. Error description: {}",
            &api,
            &error.description()
        )
    } else if error.is_server_error() {
        println!(
            "❌ A server error has occurred sending the request to the {} API. Error description: {}",
            &api,
            &error.description()
        )
    } else {
        println!(
            "❌ An error has occurred while procesing the request in the {} API. Error description: {}",
            &api,
            &error.description()
        )
    }
}

fn check_json_errors(error: reqwest::Error, api: &str) {
    println!("❌ An error occurred while parsing the JSON obtained from the {} API. Error description: {}.", &api, error.description())
}

pub fn read_from_file(
    file: &str,
    only_resolved: &str,
    with_output: &str,
    file_name: &str,
    unique_output_flag: &str,
    monitoring_flag: &str,
    from_file_flag: &str,
    postgres_connection: &str,
) -> Result<()> {
    if unique_output_flag == "y" {
        check_output_file_exists(file_name)?;
    }
    let f = File::open(&file).with_context(|_| format!("Can't open file 📁 {}", &file))?;
    let f = BufReader::new(f);
    for domain in f.lines() {
        let domain = domain?.to_string();
        let file_name = if file_name.is_empty() {
            [&domain, ".txt"].concat()
        } else {
            file_name.to_string()
        };
        get_subdomains(
            &domain,
            &only_resolved,
            &with_output,
            &file_name,
            &unique_output_flag,
            &monitoring_flag,
            &from_file_flag,
            &postgres_connection,
        )?;
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

fn get_ip(domain: &str) -> bool {
    let resolver = get_resolver();
    resolver.lookup_ip(&domain).is_ok()
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

pub fn check_output_file_exists(file_name: &str) -> Result<()> {
    if Path::new(&file_name).exists() && Path::new(&file_name).is_file() {
        let backup_file_name = file_name.replace(&file_name.split('.').last().unwrap(), "old.txt");
        fs::rename(&file_name, &backup_file_name).with_context(|_| {
            format!(
                "The file {} already exists but Findomain can't backup the file to {}. Please run the tool with a more privileged user or try in a different directory.",
                &file_name, &backup_file_name,
            )
        })?;
    }
    Ok(())
}

fn subdomains_alerts(
    connection: postgres::Connection,
    mut current_subdomains: HashSet<String>,
    target: &str,
    discord_webhook: &str,
    slack_webhook: &str,
    telegram_webhook: &str,
    telegram_chat_id: String,
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

    if !discord_webhook.is_empty() {
        discord_parameters.insert(
            "content",
            return_webhook_payload(&new_subdomains, "discord", &target),
        );
        webhooks_data.insert(discord_webhook, discord_parameters);
    }

    if !slack_webhook.is_empty() {
        slack_parameters.insert(
            "text",
            return_webhook_payload(&new_subdomains, "slack", &target),
        );
        webhooks_data.insert(slack_webhook, slack_parameters);
    }

    if !telegram_webhook.is_empty() {
        telegram_parameters.insert(
            "text",
            return_webhook_payload(&new_subdomains, "telegram", &target),
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
            } else {
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

fn return_webhook_payload(
    new_subdomains: &HashSet<String>,
    webhook_name: &str,
    target: &str,
) -> String {
    if new_subdomains.is_empty() && webhook_name == "discord" {
        format!(
            "**Findomain alert:** No new subdomains found for {}",
            &target
        )
    } else if new_subdomains.is_empty() && webhook_name == "slack" {
        format!("*Findomain alert:* No new subdomains found for {}", &target)
    } else if new_subdomains.is_empty() && webhook_name == "telegram" {
        format!(
            "<b>Findomain alert:</b> No new subdomains found for {}",
            &target
        )
    } else {
        let webhooks_payload = new_subdomains
            .clone()
            .into_iter()
            .collect::<Vec<_>>()
            .join("\n");
        if webhook_name == "discord" {
            if webhooks_payload.len() > 1900 {
                format!(
                    "**Findomain alert:** {} new subdomains found for {}\n```{}```",
                    &new_subdomains.len(),
                    &target,
                    webhooks_payload.split_at(1900).0.to_string()
                )
            } else {
                format!(
                    "**Findomain alert:** {} new subdomains found for {}\n```{}```",
                    &new_subdomains.len(),
                    &target,
                    webhooks_payload.to_string()
                )
            }
        } else if webhook_name == "slack" {
            if webhooks_payload.len() > 15000 {
                format!(
                    "*Findomain alert:* {} new subdomains found for {}\n```{}```",
                    &new_subdomains.len(),
                    &target,
                    webhooks_payload.split_at(15000).0.to_string()
                )
            } else {
                format!(
                    "*Findomain alert:* {} new subdomains found for {}\n```{}```",
                    &new_subdomains.len(),
                    &target,
                    webhooks_payload.to_string()
                )
            }
        } else if webhook_name == "telegram" {
            if webhooks_payload.len() > 4000 {
                format!(
                    "<b>Findomain alert:</b> {} new subdomains found for {}\n\n<code>{}</code>",
                    &new_subdomains.len(),
                    &target,
                    webhooks_payload.split_at(4000).0.to_string()
                )
            } else {
                format!(
                    "<b>Findomain alert:</b> {} new subdomains found for {}\n\n<code>{}</code>",
                    &new_subdomains.len(),
                    &target,
                    webhooks_payload.to_string()
                )
            }
        } else {
            String::from("")
        }
    }
}
