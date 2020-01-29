#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate lazy_static;

pub mod args;
pub mod errors;
mod get_vars;
mod misc;
pub mod sources;

use {
    crate::errors::*,
    postgres::{Client, NoTls},
    rayon::prelude::*,
    std::{
        collections::{HashMap, HashSet},
        fs::{File, OpenOptions},
        io::{BufRead, BufReader, Write},
        thread,
        time::{Duration, Instant},
    },
    trust_dns_resolver::{config::ResolverConfig, config::ResolverOpts, Resolver},
};

struct Subdomain {
    name: String,
}

pub fn get_subdomains(args: &mut args::Args) -> Result<()> {
    if args.monitoring_flag && args.database_checker_counter == 0 {
        misc::test_database_connection(args);
        args.database_checker_counter += 1
    }
    if !args.quiet_flag {
        println!("\nTarget ==> {}\n", &args.target)
    }
    if args.query_database {
        query_findomain_database(args)?
    } else {
        if args.monitoring_flag {
            args.discord_webhook = get_vars::get_webhook("discord");
            args.slack_webhook = get_vars::get_webhook("slack");
            args.telegram_bot_token = get_vars::get_auth_token("telegram");
            args.telegram_chat_id = get_vars::get_chat_id("telegram");
            check_monitoring_parameters(args)?;
        }
        args.subdomains = search_subdomains(args);
        if args.subdomains.is_empty() {
            eprintln!(
                "\nNo subdomains were found for the target: {} ¡😭!\n",
                &args.target
            );
        } else {
            misc::works_with_data(args)?
        }
    }
    Ok(())
}

fn search_subdomains(args: &mut args::Args) -> HashSet<String> {
    let quiet_flag = args.quiet_flag;
    let base_target = &format!(".{}", args.target);
    let spyse_access_token = get_vars::get_auth_token("spyse");
    let facebook_access_token = get_vars::get_auth_token("facebook");
    let virustotal_access_token = get_vars::get_auth_token("virustotal");
    let securitytrails_access_token = get_vars::get_auth_token("securitytrails");

    let url_api_certspotter = format!(
        "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
        &args.target
    );
    let url_api_virustotal = format!(
        "https://www.virustotal.com/ui/domains/{}/subdomains?limit=40",
        &args.target
    );
    let url_api_crtsh = format!("https://crt.sh/?q=%.{}&output=json", &args.target);
    let crtsh_db_query = format!("SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%.{}'))", &args.target);
    let url_api_sublist3r = format!(
        "https://api.sublist3r.com/search.php?domain={}",
        &args.target
    );
    let url_api_spyse = format!(
        "https://api.spyse.com/v1/subdomains?domain={}&api_token={}",
        &args.target, &spyse_access_token
    );
    let url_api_bufferover = format!("http://dns.bufferover.run/dns?q={}", &args.target);
    let url_api_threatcrowd = format!(
        "https://threatcrowd.org/searchApi/v2/domain/report/?domain={}",
        &args.target
    );
    let url_api_anubisdb = format!("https://jonlu.ca/anubis/subdomains/{}", &args.target);
    let url_api_urlscan = format!(
        "https://urlscan.io/api/v1/search/?q=domain:{}",
        &args.target
    );
    let url_api_threatminer = format!(
        "https://api.threatminer.org/v2/domain.php?q={}&api=True&rt=5",
        &args.target
    );
    let mut all_subdomains: HashSet<String> = vec![
        thread::spawn(move || sources::get_certspotter_subdomains(&url_api_certspotter, quiet_flag)),
        thread::spawn(move || sources::get_crtsh_db_subdomains(&crtsh_db_query, &url_api_crtsh, quiet_flag)),
        thread::spawn(move || sources::get_virustotal_subdomains(&url_api_virustotal, quiet_flag)),
        thread::spawn(move || sources::get_sublist3r_subdomains(&url_api_sublist3r, quiet_flag)),
        if facebook_access_token.is_empty() {
            let url_api_fb = format!(
                "https://graph.facebook.com/certificates?query={}&fields=domains&limit=10000&access_token={}",
                &args.target,
                &misc::return_facebook_token()
            );
            thread::spawn(move || sources::get_facebook_subdomains(&url_api_fb, quiet_flag))
        } else {
            let url_api_fb = format!(
                "https://graph.facebook.com/certificates?query={}&fields=domains&limit=10000&access_token={}",
                &args.target,
                &facebook_access_token);
            thread::spawn(move || sources::get_facebook_subdomains(&url_api_fb, quiet_flag))
        },
        thread::spawn(move || sources::get_spyse_subdomains(&url_api_spyse, quiet_flag)),
        thread::spawn(move || sources::get_bufferover_subdomains(&url_api_bufferover, quiet_flag)),
        thread::spawn(move || sources::get_threatcrowd_subdomains(&url_api_threatcrowd, quiet_flag)),
        if virustotal_access_token.is_empty() {
            thread::spawn(|| None)
        } else {
            let url_virustotal_apikey = format!(
                "https://www.virustotal.com/vtapi/v2/domain/report?apikey={}&domain={}",
                &virustotal_access_token, &args.target
            );
            thread::spawn(move || {
                sources::get_virustotal_apikey_subdomains(&url_virustotal_apikey, quiet_flag)
            })
        },
        thread::spawn(move || sources::get_anubisdb_subdomains(&url_api_anubisdb, quiet_flag)),
        thread::spawn(move || sources::get_urlscan_subdomains(&url_api_urlscan, quiet_flag)),
        if securitytrails_access_token.is_empty() {
            thread::spawn(|| None)
        } else {
            let url_api_securitytrails = format!(
                "https://api.securitytrails.com/v1/domain/{}/subdomains?apikey={}",
                &args.target, &securitytrails_access_token
            );
            let target = args.target.clone();
            thread::spawn(move || sources::get_securitytrails_subdomains(&url_api_securitytrails, &target, quiet_flag))
        },
        thread::spawn(move || sources::get_threatminer_subdomains(&url_api_threatminer, quiet_flag)),
    ].into_iter().map(|j| j.join().unwrap()).collect::<Vec<_>>().into_iter().flatten().flatten().collect();

    all_subdomains.retain(|sub| misc::sanitize_subdomain(&base_target, &sub));
    all_subdomains
}

fn manage_subdomains_data(args: &mut args::Args) -> Result<()> {
    let file_name = args.file_name.clone();
    if !args.quiet_flag {
        println!()
    };
    let mut subdomains_resolved = 0;
    if args.with_output && (args.only_resolved || args.with_ip || args.ipv6_only) {
        if args.only_resolved && !args.with_ip && !args.ipv6_only {
            for (subdomain, _) in async_resolver(args) {
                write_to_file(subdomain, &file_name)?;
                subdomains_resolved += 1
            }
        } else if (args.with_ip || args.ipv6_only) && !args.only_resolved {
            for (subdomain, ip) in async_resolver(args) {
                write_to_file(&format!("{},{}", subdomain, ip), &file_name)?;
                subdomains_resolved += 1
            }
        }
        misc::show_subdomains_found(subdomains_resolved, args)
    } else if !args.with_output && (args.only_resolved || args.with_ip || args.ipv6_only) {
        misc::show_subdomains_found(async_resolver(args).len(), args)
    } else if !args.only_resolved && !args.with_ip && args.with_output {
        for subdomain in &args.subdomains {
            println!("{}", subdomain);
            write_to_file(subdomain, &file_name)?
        }
        misc::show_subdomains_found(args.subdomains.len(), args)
    } else {
        for subdomain in &args.subdomains {
            println!("{}", subdomain);
        }
        misc::show_subdomains_found(args.subdomains.len(), args)
    }
    args.time_wasted = Instant::now();
    Ok(())
}

pub fn read_from_file(args: &mut args::Args) -> Result<()> {
    let file_name = args.file_name.clone();
    if args.unique_output_flag {
        misc::check_output_file_exists(&args.file_name)?
    }
    let file =
        File::open(&args.file).with_context(|_| format!("Can't open file 📁 {}", &args.file))?;
    for domain in BufReader::new(file).lines().flatten() {
        if !domain.is_empty() {
            args.target = misc::sanitize_target_string(domain);
            if misc::validate_target(&args.target) {
                args.file_name = if file_name.is_empty() && !args.with_ip {
                    format!("{}.txt", &args.target)
                } else if file_name.is_empty() && args.with_ip {
                    format!("{}-ip.txt", &args.target)
                } else {
                    file_name.to_string()
                };
                get_subdomains(args)?
            }
        }
    }
    Ok(())
}

fn write_to_file(data: &str, file_name: &str) -> Result<()> {
    let mut output_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&file_name)
        .with_context(|_| format!("Can't create file 📁 {}", &file_name))?;
    output_file.write_all(&format!("{}\n", &data).as_bytes())?;
    Ok(())
}

fn async_resolver(args: &mut args::Args) -> HashMap<&String, String> {
    if !args.quiet_flag {
        println!(
            "Performing asynchronous resolution for {} subdomains with {} threads, it will take a while. 🧐\n",
            args.subdomains.len(), args.threads
        )
    }
    let mut data = HashMap::new();
    data.par_extend(args.subdomains.par_iter().map(|sub| {
        let ip = get_ip(&args.domain_resolver, &format!("{}.", sub), args.ipv6_only);
        if !ip.is_empty() {
            if args.only_resolved {
                println!("{}", sub)
            } else {
                println!("{},{}", sub, ip)
            }
        }
        (sub, ip)
    }));
    data.retain(|_, ip| !ip.is_empty());
    data
}

fn get_ip(resolver: &Resolver, domain: &str, ipv6_only: bool) -> String {
    if ipv6_only {
        if let Ok(ip_address) = resolver.ipv6_lookup(&domain) {
            ip_address
                .iter()
                .next()
                .expect("An error as ocurred getting the IP address.")
                .to_string()
        } else {
            String::new()
        }
    } else if let Ok(ip_address) = resolver.ipv4_lookup(&domain) {
        ip_address
            .iter()
            .next()
            .expect("An error as ocurred getting the IP address.")
            .to_string()
    } else {
        String::new()
    }
}

pub fn get_resolver(enable_dot: bool, resolver: String) -> Resolver {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(2);
    if !enable_dot {
        if resolver == "cloudflare" {
            Resolver::new(ResolverConfig::cloudflare(), opts).unwrap()
        } else if resolver == "system" {
            Resolver::from_system_conf().unwrap()
        } else {
            Resolver::new(ResolverConfig::quad9(), opts).unwrap()
        }
    } else if resolver == "cloudflare" {
        Resolver::new(ResolverConfig::cloudflare_tls(), opts).unwrap()
    } else if resolver == "system" {
        Resolver::from_system_conf().unwrap()
    } else {
        Resolver::new(ResolverConfig::quad9_tls(), opts).unwrap()
    }
}

fn commit_to_db(mut conn: postgres::Client, new_subdomains: &HashSet<String>) -> Result<()> {
    let mut prepared_transaction = conn.transaction()?;
    for subdomain in new_subdomains {
        prepared_transaction.execute("INSERT INTO subdomains (name) VALUES ($1)", &[&subdomain])?;
    }
    prepared_transaction.commit()?;
    Ok(())
}

fn push_data_to_webhooks(args: &mut args::Args, new_subdomains: &HashSet<String>) -> Result<()> {
    let mut discord_parameters = HashMap::new();
    let mut slack_parameters = HashMap::new();
    let mut telegram_parameters = HashMap::new();
    let mut webhooks_data = HashMap::new();

    if !args.discord_webhook.is_empty() {
        discord_parameters.insert(
            "content",
            misc::return_webhook_payload(&new_subdomains, "discord", &args.target),
        );
        webhooks_data.insert(&args.discord_webhook, discord_parameters);
    }

    if !args.slack_webhook.is_empty() {
        slack_parameters.insert(
            "text",
            misc::return_webhook_payload(&new_subdomains, "slack", &args.target),
        );
        webhooks_data.insert(&args.slack_webhook, slack_parameters);
    }

    if !args.telegram_webhook.is_empty() {
        telegram_parameters.insert(
            "text",
            misc::return_webhook_payload(&new_subdomains, "telegram", &args.target),
        );
        telegram_parameters.insert("chat_id", args.telegram_chat_id.clone());
        telegram_parameters.insert("parse_mode", "HTML".to_string());
        webhooks_data.insert(&args.telegram_webhook, telegram_parameters);
    }

    for (webhook, webhooks_payload) in webhooks_data {
        if !webhook.is_empty() {
            let response = misc::return_reqwest_client()
                .post(webhook)
                .json(&webhooks_payload)
                .send()?;
            if response.status() == 200 || response.status() == 204 {
                if args.commit_to_db_counter == 0
                    && !new_subdomains.is_empty()
                    && commit_to_db(
                        Client::connect(&args.postgres_connection, NoTls)?,
                        &new_subdomains,
                    )
                    .is_ok()
                {
                    args.commit_to_db_counter += 1
                }
            } else if !args.quiet_flag {
                eprintln!(
                    "\nAn error occurred when Findomain tried to publish the data to the following webhook {}. \nError description: {}",
                    webhook, response.status()
                )
            }
        }
    }
    args.commit_to_db_counter = 0;
    Ok(())
}

fn subdomains_alerts(args: &mut args::Args) -> Result<()> {
    if args.with_imported_subdomains {
        let imported_subdomains = import_subdomains_from_file(args)?;
        for subdomain in imported_subdomains {
            args.subdomains.insert(subdomain);
        }
    }
    let mut connection: postgres::Client = Client::connect(&args.postgres_connection, NoTls)?;
    connection.execute(
        "CREATE TABLE IF NOT EXISTS subdomains (
                   id              SERIAL PRIMARY KEY,
                   name            TEXT NOT NULL UNIQUE,
                   timestamp       TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
              )",
        &[],
    )?;

    // Update existing/old PostgreSQL table schema to match new scheme, will be removed later.
    if connection
        .execute(
            "ALTER TABLE subdomains ADD COLUMN timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP",
            &[],
        )
        .is_ok()
    {
        connection.execute("UPDATE subdomains SET timestamp = CURRENT_TIMESTAMP", &[])?;
    }

    let statement: &str = &format!(
        "SELECT name FROM subdomains WHERE name LIKE '%{}'",
        &args.target
    );
    let existing_subdomains = connection.query(statement, &[])?;

    let existing_subdomains: HashSet<String> = existing_subdomains
        .iter()
        .map(|row| {
            let subdomain = Subdomain {
                name: row.get("name"),
            };
            subdomain.name
        })
        .collect();

    let new_subdomains: HashSet<String> = args
        .subdomains
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
            write_to_file(subdomain, &file_name)?
        }
        if !args.quiet_flag {
            misc::show_file_location(&args.target, &file_name)
        }
    }

    if !args.enable_empty_push {
        if !new_subdomains.is_empty() {
            push_data_to_webhooks(args, &new_subdomains)?
        }
    } else {
        push_data_to_webhooks(args, &new_subdomains)?
    }

    Ok(())
}

fn query_findomain_database(args: &mut args::Args) -> Result<()> {
    if !args.quiet_flag {
        println!(
            "Searching subdomains in the Findomain database for the target {} 🔍",
            args.target
        )
    }
    let mut connection: postgres::Client = Client::connect(&args.postgres_connection, NoTls)?;
    connection.execute(
        "CREATE TABLE IF NOT EXISTS subdomains (
                   id              SERIAL PRIMARY KEY,
                   name            TEXT NOT NULL UNIQUE,
                   timestamp       TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
              )",
        &[],
    )?;

    // Update existing/old PostgreSQL table schema to match new scheme, will be removed later.
    if connection
        .execute(
            "ALTER TABLE subdomains ADD COLUMN timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP",
            &[],
        )
        .is_ok()
    {
        connection.execute("UPDATE subdomains SET timestamp = CURRENT_TIMESTAMP", &[])?;
    }

    let statement: &str = &format!(
        "SELECT name FROM subdomains WHERE name LIKE '%{}'",
        &args.target
    );
    let existing_subdomains = connection.query(statement, &[])?;
    args.subdomains = existing_subdomains
        .iter()
        .map(|row| {
            let subdomain = Subdomain {
                name: row.get("name"),
            };
            subdomain.name
        })
        .collect();
    misc::works_with_data(args)?;
    Ok(())
}

fn import_subdomains_from_file(args: &mut args::Args) -> Result<HashSet<String>> {
    let base_target = &format!(".{}", args.target);
    let mut subdomains_from_file: HashSet<String> = HashSet::new();
    if !args.import_subdomains_from.is_empty() {
        for file in &args.import_subdomains_from {
            let file =
                File::open(&file).with_context(|_| format!("Can't open file 📁 {}", &file))?;
            for subdomain in BufReader::new(file).lines().flatten() {
                if misc::sanitize_subdomain(&base_target, &subdomain) {
                    subdomains_from_file.insert(subdomain);
                }
            }
        }
    }
    Ok(subdomains_from_file)
}
