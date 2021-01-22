#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate lazy_static;

pub mod args;
pub mod errors;
pub mod misc;
pub mod resolvers;
pub mod sources;
pub mod update_checker;

use {
    crate::errors::*,
    postgres::{Client, NoTls},
    rand::{distributions::Alphanumeric, thread_rng as rng, Rng},
    rayon::prelude::*,
    std::{
        collections::{HashMap, HashSet},
        fs::{File, OpenOptions},
        io::{BufRead, BufReader, Write},
        iter::FromIterator,
        net::{IpAddr, Ipv4Addr},
        thread,
        time::{Duration, Instant},
    },
    trust_dns_resolver::{
        config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
        proto::rr::RecordType,
        Resolver,
    },
};

struct Subdomain {
    name: String,
}

lazy_static! {
    static ref RESOLVERS: Vec<Ipv4Addr> = {
        let args = args::get_args();
        let mut resolver_ips = Vec::new();
        if args.custom_resolvers {
            for r in &return_file_targets(&args, args.resolvers.clone()) {
                match r.parse::<Ipv4Addr>() {
                    Ok(ip) => resolver_ips.push(ip),
                    Err(e) => {
                        eprintln!("Error parsing the {} IP from resolvers file to IP address. Please check and try again. Error: {}\n", r, e);
                        std::process::exit(1)
                    }
                }
            }
        } else {
            for r in args.resolvers {
                match r.parse::<Ipv4Addr>() {
                    Ok(ip) => resolver_ips.push(ip),
                    Err(e) => {
                        eprintln!("Error parsing the {} IP from resolvers file to IP address. Please check and try again. Error: {}\n", r, e);
                        std::process::exit(1)
                    }
                }
            }
        }
        resolver_ips
    };
    static ref OPTS: ResolverOpts = {
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(3);
        opts
    };
}

pub fn get_subdomains(args: &mut args::Args) -> Result<()> {
    if args.monitoring_flag && args.database_checker_counter == 0 {
        misc::test_database_connection(args);
        args.database_checker_counter += 1
    }
    if !args.quiet_flag {
        println!("\nTarget ==> {}\n", &args.target)
    }

    // Test for new or modified sources.
    // let subdomains = sources::get_spyse_subdomains(
    //     &format!(
    //         "https://api.spyse.com/v3/data/domain/subdomain?limit=100&domain={}",
    //         &args.target
    //     ),
    //     "",
    //     false,
    // )
    // .unwrap();
    // for sub in subdomains {
    //     println!("{}", sub)
    // }
    // std::process::exit(1);

    if args.query_database {
        query_findomain_database(args)?
    } else if args.bruteforce {
        args.subdomains = args
            .wordlists_data
            .iter()
            .map(|target| format!("{}.{}", target, &args.target))
            .collect();
        manage_subdomains_data(args)?
    } else {
        if args.monitoring_flag {
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
    if !args.quiet_flag
        && args.rate_limit != 0
        && args.from_file_flag
        && !args.is_last_target
        && !args.monitoring_flag
    {
        println!(
            "Rate limit set to {} seconds, waiting to start next enumeration.",
            args.rate_limit
        );
        thread::sleep(Duration::from_secs(args.rate_limit))
    }
    Ok(())
}

fn search_subdomains(args: &mut args::Args) -> HashSet<String> {
    let quiet_flag = args.quiet_flag;
    let base_target = &format!(".{}", args.target);

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
        "https://api.spyse.com/v3/data/domain/subdomain?limit=100&domain={}",
        &args.target
    );
    let url_api_bufferover = format!("http://dns.bufferover.run/dns?q={}", &args.target);
    let url_api_threatcrowd = format!(
        "https://threatcrowd.org/searchApi/v2/domain/report/?domain={}",
        &args.target
    );
    let url_api_anubisdb = format!("https://jldc.me/anubis/subdomains/{}", &args.target);
    let url_api_urlscan = format!(
        "https://urlscan.io/api/v1/search/?q=domain:{}",
        &args.target
    );
    let url_api_threatminer = format!(
        "https://api.threatminer.org/v2/domain.php?q={}&api=True&rt=5",
        &args.target
    );
    let url_api_archiveorg = format!("https://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&fl=original&collapse=urlkey&limit=100000&_=1547318148315", &args.target);
    let mut all_subdomains: HashSet<String> = vec![
        if args.excluded_sources.contains("certspotter") { thread::spawn(|| None) }
        else { thread::spawn(move || sources::get_certspotter_subdomains(&url_api_certspotter, quiet_flag)) },
        if args.excluded_sources.contains("crtsh") { thread::spawn(|| None) }
        else { thread::spawn(move || sources::get_crtsh_db_subdomains(&crtsh_db_query, &url_api_crtsh, quiet_flag)) },
        if args.excluded_sources.contains("virustotal") { thread::spawn(|| None) }
        else { thread::spawn(move || sources::get_virustotal_subdomains(&url_api_virustotal, quiet_flag)) },
        if args.excluded_sources.contains("sublist3r") { thread::spawn(|| None) }
        else { thread::spawn(move || sources::get_sublist3r_subdomains(&url_api_sublist3r, quiet_flag)) },
        if args.excluded_sources.contains("facebook") { thread::spawn(|| None) }
        else if args.facebook_access_token.is_empty() {
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
                &args.facebook_access_token);
            thread::spawn(move || sources::get_facebook_subdomains(&url_api_fb, quiet_flag))
        },
        if args.excluded_sources.contains("spyse") || args.spyse_access_token.is_empty() { thread::spawn(|| None) }
        else { let spyse_api_token = args.spyse_access_token.clone(); thread::spawn(move || sources::get_spyse_subdomains(&url_api_spyse, &spyse_api_token, quiet_flag)) },
        if args.excluded_sources.contains("bufferover") { thread::spawn(|| None) }
        else { thread::spawn(move || sources::get_bufferover_subdomains(&url_api_bufferover, quiet_flag)) },
        if args.excluded_sources.contains("threatcrowd") { thread::spawn(|| None) }
        else { thread::spawn(move || sources::get_threatcrowd_subdomains(&url_api_threatcrowd, quiet_flag)) },
        if args.excluded_sources.contains("virustotalapikey") || args.virustotal_access_token.is_empty() {
            thread::spawn(|| None)
        } else {
            let url_virustotal_apikey = format!(
                "https://www.virustotal.com/vtapi/v2/domain/report?apikey={}&domain={}",
                &args.virustotal_access_token, &args.target
            );
            thread::spawn(move || {
                sources::get_virustotal_apikey_subdomains(&url_virustotal_apikey, quiet_flag)
            })
        },
        if args.excluded_sources.contains("anubis") { thread::spawn(|| None) }
        else { thread::spawn(move || sources::get_anubisdb_subdomains(&url_api_anubisdb, quiet_flag)) },
        if args.excluded_sources.contains("urlscan") { thread::spawn(|| None) }
        else { thread::spawn(move || sources::get_urlscan_subdomains(&url_api_urlscan, quiet_flag)) },
        if args.excluded_sources.contains("securitytrails") || args.securitytrails_access_token.is_empty() {
            thread::spawn(|| None)
        } else {
            let url_api_securitytrails = format!(
                "https://api.securitytrails.com/v1/domain/{}/subdomains?apikey={}",
                &args.target, &args.securitytrails_access_token
            );
            let target = args.target.clone();
            thread::spawn(move || sources::get_securitytrails_subdomains(&url_api_securitytrails, &target, quiet_flag))
        },
        if args.excluded_sources.contains("threatminer") { thread::spawn(|| None) }
        else { thread::spawn(move || sources::get_threatminer_subdomains(&url_api_threatminer, quiet_flag))},
        if args.excluded_sources.contains("archiveorg") { thread::spawn(|| None) }
        else { thread::spawn(move || sources::get_archiveorg_subdomains(&url_api_archiveorg, quiet_flag))},
        if args.excluded_sources.contains("c99") || args.c99_api_key.is_empty() { thread::spawn(|| None) }
        else {
            let url_api_c99 = format!(
                "https://api.c99.nl/subdomainfinder?key={}&domain={}&json",
                &args.c99_api_key, &args.target
                );
            thread::spawn(move || {
                sources::get_c99_subdomains(&url_api_c99, quiet_flag)
            })
        }
    ].into_iter().map(|j| j.join().unwrap()).collect::<Vec<_>>().into_iter().flatten().flatten().map(|sub| misc::sanitize_subdomains(&sub)).collect();

    all_subdomains.retain(|sub| misc::validate_subdomain(&base_target, &sub, args));
    all_subdomains
}

fn manage_subdomains_data(args: &mut args::Args) -> Result<()> {
    let file_name = args.file_name.clone();
    if !args.quiet_flag {
        println!()
    };
    if (args.only_resolved || args.with_ip || args.ipv6_only)
        && !args.disable_wildcard_check
        && !args.as_resolver
    {
        args.wilcard_ips = detect_wildcard(args);
    }
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

pub fn return_file_targets(args: &args::Args, mut files: Vec<String>) -> Vec<String> {
    let mut targets: Vec<String> = Vec::new();
    files.sort();
    files.dedup();
    for f in files {
        match File::open(&f) {
            Ok(file) => {
                for target in BufReader::new(file).lines().flatten() {
                    targets.push(target);
                }
            }
            Err(e) => {
                if args.files.len() == 1 {
                    println!("Can not open file {}. Error: {}", f, e);
                    std::process::exit(1)
                } else if !args.quiet_flag {
                    println!(
                        "Can not open file {}, working with next file. Error: {}",
                        f, e
                    );
                }
            }
        }
    }
    targets.sort();
    targets.dedup();
    targets.retain(|target| !target.is_empty());
    targets.iter().map(|t| t.to_lowercase()).collect()
}

pub fn read_from_file(args: &mut args::Args) -> Result<()> {
    let file_name = args.file_name.clone();
    if args.unique_output_flag {
        misc::check_output_file_exists(&args.file_name)?
    }
    if args.as_resolver {
        if !args.only_resolved && !args.with_ip && !args.ipv6_only {
            println!("To use Findomain as resolver, use one of the --resolved/-r, --ip/-i or --ipv6-only options.");
            std::process::exit(1)
        } else {
            args.subdomains = HashSet::from_iter(return_file_targets(args, args.files.clone()));
            manage_subdomains_data(args)?
        }
    } else {
        let file_targets = return_file_targets(args, args.files.clone());
        let last_target = file_targets.last().unwrap().to_string();
        for domain in file_targets {
            if domain == last_target {
                args.is_last_target = true
            }
            args.target = domain;
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
        let ip = get_records(
            &get_resolver(&RESOLVERS, &OPTS),
            &format!("{}.", sub),
            if args.ipv6_only {
                RecordType::AAAA
            } else {
                RecordType::A
            },
        );
        if !ip.is_empty() && !args.wilcard_ips.contains(&ip) {
            if args.only_resolved {
                println!("{}", sub)
            } else {
                println!("{},{}", sub, ip)
            }
        }
        (sub, ip)
    }));
    data.retain(|_, ip| !ip.is_empty() && !args.wilcard_ips.contains(ip));
    data
}

pub fn get_resolver(resolvers_ips: &[Ipv4Addr], opts: &ResolverOpts) -> Resolver {
    match Resolver::new(
        ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from_ips_clear(
                &[IpAddr::V4(
                    resolvers_ips[rand::thread_rng().gen_range(0, resolvers_ips.len())],
                )],
                53,
            ),
        ),
        *opts,
    ) {
        Ok(resolver) => resolver,

        Err(e) => {
            eprintln!("Failed to create the resolver. Error: {}\n", e);
            std::process::exit(1)
        }
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
        let mut imported_subdomains =
            return_file_targets(args, args.import_subdomains_from.clone());
        let base_target = &format!(".{}", args.target);
        imported_subdomains.retain(|target| {
            !target.is_empty() && misc::validate_subdomain(&base_target, &target, args)
        });
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

    if !args.quiet_flag && args.rate_limit != 0 && args.from_file_flag && !args.is_last_target {
        println!(
            "Rate limit set to {} seconds, waiting to start next enumeration.",
            args.rate_limit
        );
        thread::sleep(Duration::from_secs(args.rate_limit))
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

fn detect_wildcard(args: &mut args::Args) -> HashSet<String> {
    if !args.quiet_flag {
        println!("Running wildcards detection for {}...", &args.target)
    }
    let mut generated_wilcards: HashSet<String> = HashSet::new();
    for _ in 1..10 {
        generated_wilcards.insert(format!(
            "{}.{}",
            rng().sample_iter(Alphanumeric).take(15).collect::<String>(),
            &args.target
        ));
    }
    generated_wilcards = generated_wilcards
        .par_iter()
        .map(|sub| {
            get_records(
                &get_resolver(&RESOLVERS, &OPTS),
                &format!("{}.", sub),
                if args.ipv6_only {
                    RecordType::AAAA
                } else {
                    RecordType::A
                },
            )
        })
        .collect();
    generated_wilcards.retain(|ip| !ip.is_empty());
    if !generated_wilcards.is_empty() && !args.quiet_flag {
        println!(
            "Wilcards detected for {} and wildcard's IP saved for furter work.",
            &args.target
        );
        println!("Wilcard IPs: {:?}\n", generated_wilcards)
    } else if !args.quiet_flag {
        println!("No wilcards detected for {}, nice!\n", &args.target)
    }
    generated_wilcards
}

fn get_records(resolver: &Resolver, domain: &str, record_type: RecordType) -> String {
    if let Ok(rdata) = resolver.lookup(&domain, record_type) {
        let mut record_data: Vec<String> = Vec::new();
        if record_type == RecordType::AAAA {
            record_data = rdata
                .iter()
                .filter_map(|rdata| rdata.as_aaaa())
                .map(|ipv6| ipv6.to_string())
                .collect();
        } else if record_type == RecordType::A {
            record_data = rdata
                .iter()
                .filter_map(|rdata| rdata.as_a())
                .map(|ipv4| ipv4.to_string())
                .collect();
        }
        // else if record_type == RecordType::CNAME {
        //     record_data = rdata
        //         .iter()
        //         .filter_map(|rdata| rdata.as_cname())
        //         .map(|name| {
        //             let name = name.to_string();
        //             name[..name.len() - 1].to_owned()
        //         })
        //         .collect();
        // }
        record_data
            .iter()
            .next()
            .expect("Failed retrieving records data.")
            .to_owned()
    } else {
        String::new()
    }
}
