use {
    crate::{
        args, external_subs, files, logic, resolvers, screenshots, sources,
        structs::{Args, HttpStatus, ResolvData},
        utils,
    },
    crossbeam::channel,
    fhc::structs::HttpData,
    rand::{distributions::Alphanumeric, thread_rng as rng, Rng},
    rayon::prelude::*,
    rusolver::{
        dnslib::{return_hosts_data, return_tokio_asyncresolver},
        structs::DomainData,
    },
    std::{
        collections::{HashMap, HashSet},
        fs, thread,
        time::Duration,
    },
    trust_dns_resolver::config::{LookupIpStrategy, ResolverOpts},
};

lazy_static! {
    pub static ref RESOLVERS: Vec<String> = {
        let args = args::get_args();
        let mut resolver_ips = Vec::new();
        if args.custom_resolvers {
            for r in files::return_file_targets(&args, args.resolvers.clone()) {
                resolver_ips.push(r.to_string() + ":53");
            }
        } else {
            for r in args.resolvers {
                resolver_ips.push(r.to_string() + ":53");
            }
        }
        resolver_ips
    };
}

lazy_static! {
    pub static ref TRUSTABLE_RESOLVERS: Vec<String> = {
        let mut resolver_ips = Vec::new();
        for r in resolvers::return_ipv4_resolvers() {
            resolver_ips.push(r.to_string() + ":53");
        }
        resolver_ips
    };
}

pub fn search_subdomains(args: &mut Args) -> HashSet<String> {
    let quiet_flag = args.quiet_flag;
    let base_target = format!(".{}", args.target);

    let url_api_certspotter = format!(
        "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
        &args.target
    );
    let certspotter_token = args.certspotter_access_token.clone();
    let url_api_crtsh = format!("https://crt.sh/?q=%.{}&output=json", &args.target);
    let crtsh_db_query = format!("SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%.{}'))", &args.target);
    let url_api_sublist3r = format!(
        "https://api.sublist3r.com/search.php?domain={}",
        &args.target
    );
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
    let url_api_fullhunt = format!(
        "https://fullhunt.io/api/v1/domain/{}/subdomains",
        &args.target
    );
    let amass_target = args.target.clone();
    let subfinder_target = args.target.clone();
    let external_subdomains_dir_amass = args.external_subdomains_dir_amass.clone();
    let external_subdomains_dir_subfinder = args.external_subdomains_dir_subfinder.clone();

    if args.external_subdomains {
        fs::create_dir_all(&args.external_subdomains_dir_amass)
            .expect("Failed to create amass output directory.");
        fs::create_dir_all(&args.external_subdomains_dir_subfinder)
            .expect("Failed to create subfinder output directory.");
    }

    let mut all_subdomains: HashSet<String> = vec![
        if args.external_subdomains {
            thread::spawn(move || external_subs::get_amass_subdomains(&amass_target, external_subdomains_dir_amass, quiet_flag))
        } else { thread::spawn(|| None) },
        if args.external_subdomains {
            thread::spawn(move || external_subs::get_subfinder_subdomains(&subfinder_target, external_subdomains_dir_subfinder, quiet_flag))
        }  else { thread::spawn(|| None) },
        if args.excluded_sources.contains("certspotter") { thread::spawn(|| None) }
        else { thread::spawn(move || sources::get_certspotter_subdomains(&url_api_certspotter, &utils::return_random_string(certspotter_token), quiet_flag)) },
        if args.excluded_sources.contains("crtsh") { thread::spawn(|| None) }
        else { thread::spawn(move || sources::get_crtsh_db_subdomains(&crtsh_db_query, &url_api_crtsh, quiet_flag)) },
        if args.excluded_sources.contains("sublist3r") { thread::spawn(|| None) }
        else { thread::spawn(move || sources::get_sublist3r_subdomains(&url_api_sublist3r, quiet_flag)) },
        if args.facebook_access_token.is_empty() || args.excluded_sources.contains("facebook") { thread::spawn(|| None) 
        } else {
            let url_api_fb = format!(
                "https://graph.facebook.com/certificates?query={}&fields=domains&limit=10000&access_token={}",
                &args.target,
                &utils::return_random_string(args.facebook_access_token.clone()));
            thread::spawn(move || sources::get_facebook_subdomains(&url_api_fb, quiet_flag))
        },
        if args.excluded_sources.contains("spyse") || args.spyse_access_token.is_empty() { thread::spawn(|| None) }
        else {
            let target = base_target.clone();
            let spyse_api_key = utils::return_random_string(args.spyse_access_token.clone());
            thread::spawn(move || sources::get_spyse_subdomains(&target, "Spyse", &spyse_api_key, quiet_flag))
        },
        if args.excluded_sources.contains("bufferover_free") || args.bufferover_free_api_key.is_empty() { thread::spawn(|| None) }
        else {
            let url_api_bufferover = format!("https://tls.bufferover.run/dns?q={}", &args.target);
            let bufferover_free_api_key = utils::return_random_string(args.bufferover_free_api_key.clone());
            thread::spawn(move || sources::get_bufferover_subdomains(&url_api_bufferover, "Bufferover Free", &bufferover_free_api_key, quiet_flag))
        },
        if args.excluded_sources.contains("bufferover_paid")  || args.bufferover_paid_api_key.is_empty() {  thread::spawn(|| None) }
        else {
            let url_api_bufferover = format!("https://bufferover-run-tls.p.rapidapi.com/ipv4/dns?q={}", &args.target);
            let bufferover_paid_api_key = utils::return_random_string(args.bufferover_paid_api_key.clone());
            thread::spawn(move || sources::get_bufferover_subdomains(&url_api_bufferover, "Bufferover Paid", &bufferover_paid_api_key, quiet_flag))
        },
        if args.excluded_sources.contains("threatcrowd") { thread::spawn(|| None) }
        else { thread::spawn(move || sources::get_threatcrowd_subdomains(&url_api_threatcrowd, quiet_flag)) },
        if args.excluded_sources.contains("virustotalapikey") || args.virustotal_access_token.is_empty() {
            thread::spawn(|| None)
        } else {
            let url_virustotal_apikey = format!(
                "https://www.virustotal.com/vtapi/v2/domain/report?apikey={}&domain={}",
                &utils::return_random_string(args.virustotal_access_token.clone()), &args.target
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
                &args.target, &utils::return_random_string(args.securitytrails_access_token.clone())
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
                &utils::return_random_string(args.c99_api_key.clone()), &args.target
                );
            thread::spawn(move || {
                sources::get_c99_subdomains(&url_api_c99, quiet_flag)
            })
        },
        // Seems that FullHunt can work for a few requests without API Key
        // but they are like 5 requests ¿? so I decided to exclude it if no API key is present
        if args.excluded_sources.contains("fullhunt") || args.fullhunt_api_key.is_empty() { thread::spawn(|| None) }
        else {
            let fullhunt_api_key = utils::return_random_string(args.fullhunt_api_key.clone());
            thread::spawn(move || sources::get_fullhunt_subdomains(&url_api_fullhunt, &fullhunt_api_key, quiet_flag))
        },
    ].into_iter().map(|j| j.join().unwrap()).collect::<Vec<_>>().into_iter().flatten().flatten().map(|sub| sub.to_lowercase()).collect();
    all_subdomains.retain(|sub| logic::validate_subdomain(&base_target, sub, args));
    if !args.import_subdomains_from.is_empty() {
        let mut imported_subdomains =
            files::return_file_targets(args, args.import_subdomains_from.clone());
        imported_subdomains.retain(|target| !target.is_empty() && logic::validate_target(target));
        imported_subdomains.retain(|target| {
            !target.is_empty() && logic::validate_subdomain(&base_target, target, args)
        });
        for subdomain in imported_subdomains {
            all_subdomains.insert(subdomain);
        }
    }
    all_subdomains
}

pub fn async_resolver_all(args: &Args) -> HashMap<String, ResolvData> {
    // let mut data = HashMap::new();
    //  let mut scannet_hosts: HashMap<String, Vec<i32>> = HashMap::new();
    let file_name = files::return_output_file(args);

    if !args.quiet_flag && (args.discover_ip || args.http_status || args.enable_port_scan) {
        let message = if args.as_resolver {
            format!(
                "Performing asynchronous resolution for {} subdomains, it will take a while...\n",
                args.subdomains.len()
            )
        } else {
            format!("Performing asynchronous resolution for {} subdomains for the target {}, it will take a while...\n",
            args.subdomains.len(), args.target)
        };
        println!("{message}")
    }
    if (args.monitoring_flag || args.no_monitor) && !args.quiet_flag {
        println!()
    }

    async_resolver_engine(args, args.subdomains.clone(), &file_name)
    // if !args.enable_port_scan {
    //     data.par_extend(args.subdomains.par_iter().map(|sub| {
    //         async_resolver_engine(
    //             args,
    //             sub.to_owned(),
    //             &resolver,
    //             &client,
    //             //    &scannet_hosts,
    //             &file_name,
    //         )
    //     }));
    // } else {
    //     data.extend(args.subdomains.iter().map(|sub| {
    //         //  scannet_hosts.insert(resolv_data.1.ip.clone(), resolv_data.1.open_ports.clone());
    //         async_resolver_engine(
    //             args,
    //             sub.to_owned(),
    //             &resolver,
    //             &client,
    //             //       &scannet_hosts,
    //             &file_name,
    //         )
    //     }))
    // }
}

#[allow(clippy::cognitive_complexity)]
fn async_resolver_engine(
    args: &Args,
    subdomains: HashSet<String>,
    // resolved_hosts: &HashMap<String, Vec<i32>>,
    file_name: &Option<std::fs::File>,
) -> HashMap<String, ResolvData> {
    let ip_http_ports = args.discover_ip && args.http_status && args.enable_port_scan;
    let http_with_ip = args.discover_ip && args.http_status && !args.enable_port_scan;
    let only_resolved_or_ip = args.discover_ip && !args.http_status && !args.enable_port_scan;
    let http_without_ip_with_ports = args.http_status && !args.discover_ip && args.enable_port_scan;
    let only_http = args.http_status && !args.discover_ip && !args.enable_port_scan;
    let ports_with_ip = args.enable_port_scan && args.discover_ip && !args.http_status;
    let only_ports = args.enable_port_scan && !args.discover_ip && !args.http_status;
    let mut ports: Vec<u16> = vec![];
    if args.enable_port_scan {
        ports.extend(args.initial_port..=args.last_port)
    }
    #[allow(unused_assignments)]
    let mut data_to_write = String::new();
    // let mut timeout: u64 = 0;
    //

    let mut resolv_data: HashMap<String, ResolvData> = HashMap::new();

    let wildcard_ips = args.wilcard_ips.clone();

    let async_threads = if args.lightweight_threads > args.subdomains.len() {
        args.subdomains.len()
    } else {
        args.lightweight_threads
    };

    if !args.no_resolve {
        let options = ResolverOpts {
            attempts: 0,
            timeout: Duration::from_secs(args.resolver_timeout),
            ip_strategy: LookupIpStrategy::Ipv4Only,
            num_concurrent_reqs: 1,
            ..Default::default()
        };

        let resolvers =
            return_tokio_asyncresolver(RESOLVERS.iter().map(|x| x.to_owned()).collect(), options);
        let trustable_resolver = return_tokio_asyncresolver(
            TRUSTABLE_RESOLVERS.iter().map(|x| x.to_owned()).collect(),
            options,
        );

        let rt = tokio::runtime::Runtime::new().unwrap();
        let handle = rt.handle().to_owned();
        let (tx, rx) = channel::bounded(1);

        let subdomains_for_async_resolver = subdomains.clone();
        let empty_domain_data = DomainData::default();

        handle.spawn(async move {
            let data = return_hosts_data(
                subdomains_for_async_resolver,
                resolvers,
                trustable_resolver,
                wildcard_ips,
                false,
                async_threads,
                false,
                true,
            )
            .await;

            let _ = tx.send(data);
        });

        let hosts_data = match rx.recv() {
            Ok(data) => data,
            Err(e) => {
                println!("Error in the resolution process: {}", e);
                std::process::exit(1);
            }
        };

        resolv_data = subdomains
            .par_iter()
            .map(|sub| {
                let resolv_data = ResolvData {
                    ip: if args.enable_port_scan || args.discover_ip {
                        // let rtimeout = if args.enable_port_scan {
                        //     Some(std::time::Instant::now())
                        // } else {
                        //     None
                        // };

                        return_ip(&hosts_data, sub, &empty_domain_data)

                        // if args.enable_port_scan && !args.no_resolve {
                        //     timeout = utils::calculate_timeout(
                        //         args.threads,
                        //         rtimeout.unwrap().elapsed().as_millis() as u64,
                        //     );
                        // }
                    } else {
                        String::from("NOT CHECKED")
                    },
                    http_status: HttpStatus::default(),
                    open_ports: Vec::new(),
                };
                (sub.to_owned(), resolv_data)
            })
            .collect();
    };

    if args.http_status {
        let mut http_hosts = HashSet::new();
        let empty_http_data = HttpData::default();

        for (sub, resolv_data) in &resolv_data {
            if resolv_data.ip != "NOT CHECKED" && !resolv_data.ip.is_empty() {
                http_hosts.insert(sub.to_owned());
            }
        }

        let rt = tokio::runtime::Runtime::new().unwrap();
        let handle = rt.handle().to_owned();

        let (tx, rx) = channel::bounded(1);

        let client = fhc::httplib::return_http_client(args.http_timeout);
        let user_agents_list = args.user_agent_strings.clone();
        let http_retries = args.http_retries;

        handle.spawn(async move {
            let http_data = fhc::httplib::return_http_data(
                http_hosts,
                client,
                user_agents_list,
                http_retries,
                async_threads,
                0,
                false,
                true,
            )
            .await;

            let _ = tx.send(http_data);
        });

        let http_data = match rx.recv() {
            Ok(data) => data,
            Err(e) => {
                println!("Error in the resolution process: {}", e);
                std::process::exit(1);
            }
        };

        resolv_data = resolv_data
            .par_iter()
            .map(|(host, host_resolv_data)| {
                let local_http_data = http_data.get(host).unwrap_or(&empty_http_data);
                let mut local_resolv_data = host_resolv_data.clone();

                if args.http_status && !local_resolv_data.ip.is_empty() && !args.no_resolve {
                    local_resolv_data.http_status = HttpStatus {
                        http_status: local_http_data.http_status.clone(),
                        host_url: local_http_data.host_url.clone(),
                    };
                } else if args.http_status && local_resolv_data.ip.is_empty() && !args.no_resolve {
                    local_resolv_data.http_status.http_status = String::from("INACTIVE")
                } else {
                    local_resolv_data.http_status.http_status = String::from("NOT CHECKED")
                }

                if args.no_resolve {
                    local_resolv_data.http_status.host_url = host.clone()
                };

                (host.to_owned(), local_resolv_data)
            })
            .collect();
    };

    if args.take_screenshots {
        let screenshots_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(args.screenshots_threads)
            .build()
            .unwrap();
        screenshots_pool.install(|| { resolv_data.par_iter().map(|(sub, resolv_data)| {
        if !resolv_data.http_status.host_url.is_empty() || args.no_resolve {
            match screenshots::take_screenshot(
                utils::return_headless_browser(args.chrome_sandbox),
                &resolv_data.http_status.host_url,
                &args.screenshots_path,
                &args.target,
                sub,
            ) {
                Ok(_) => {
                    if args.no_resolve {
                        println!("{}", resolv_data.http_status.host_url)
                    }
                }
                Err(_) => {
                    let mut counter = 0;
                    while counter <= 2 {
                        match screenshots::take_screenshot(
                            utils::return_headless_browser(args.chrome_sandbox),
                            &resolv_data.http_status.host_url,
                            &args.screenshots_path,
                            &args.target,
                            sub,
                        ) {
                            Ok(_) => {
                                if args.no_resolve {
                                    println!("{}", resolv_data.http_status.host_url)
                                };
                                break;
                            }
                            Err(e) => {
                                if counter == 3 {
                                    eprintln!("The subdomain {} has an active HTTP server running at {} but the screenshot was not taken. Error description: {}", sub, resolv_data.http_status.host_url, e)
                                }
                                counter += 1
                            }
                        }
                    }
                }
            }
        }
        })
        }).collect::<()>();
        drop(screenshots_pool);
    }

    // if args.enable_port_scan && !resolv_data.ip.is_empty() {
    //     if !resolved_hosts.contains_key(&resolv_data.ip) {
    //         resolv_data.open_ports = port_scanner::return_open_ports(
    //             &ports,
    //             resolv_data
    //                 .ip
    //                 .parse::<Ipv4Addr>()
    //                 .expect("Error parsing IP address, please report the issue."),
    //             timeout,
    //         )
    //     } else {
    //         resolv_data.open_ports = resolved_hosts.get(&resolv_data.ip).unwrap().to_owned()
    //     }
    // };

    for (sub, resolv_data) in &resolv_data {
        if ip_http_ports {
            if (args.disable_wildcard_check && !resolv_data.ip.is_empty())
                || (!resolv_data.ip.is_empty() && !args.wilcard_ips.contains(&resolv_data.ip))
            {
                data_to_write = format!(
                    "{},{},{},{}",
                    sub,
                    &resolv_data.ip,
                    &logic::eval_http(&resolv_data.http_status),
                    logic::return_ports_string(&resolv_data.open_ports, args)
                );
                logic::print_and_write(data_to_write, args.with_output, file_name)
            }
        } else if http_with_ip {
            if (args.disable_wildcard_check && !resolv_data.ip.is_empty())
                || (!resolv_data.ip.is_empty() && !args.wilcard_ips.contains(&resolv_data.ip))
            {
                data_to_write = format!(
                    "{},{},{}",
                    sub,
                    &resolv_data.ip,
                    &logic::eval_http(&resolv_data.http_status)
                );
                logic::print_and_write(data_to_write, args.with_output, file_name)
            }
        } else if only_resolved_or_ip {
            if (args.disable_wildcard_check && !resolv_data.ip.is_empty())
                || (!resolv_data.ip.is_empty() && !args.wilcard_ips.contains(&resolv_data.ip))
            {
                if args.only_resolved {
                    data_to_write = sub.to_string();
                } else {
                    data_to_write = format!("{},{}", sub, resolv_data.ip);
                }
                logic::print_and_write(data_to_write, args.with_output, file_name)
            }
        } else if http_without_ip_with_ports {
            if resolv_data.http_status.http_status == "ACTIVE" {
                data_to_write = format!(
                    "{},{},{}",
                    sub,
                    &logic::eval_http(&resolv_data.http_status),
                    logic::return_ports_string(&resolv_data.open_ports, args)
                );
                logic::print_and_write(data_to_write, args.with_output, file_name)
            }
        } else if only_http {
            if resolv_data.http_status.http_status == "ACTIVE" {
                data_to_write = logic::eval_http(&resolv_data.http_status);
                logic::print_and_write(data_to_write, args.with_output, file_name)
            }
        } else if ports_with_ip {
            if (args.disable_wildcard_check && !resolv_data.ip.is_empty())
                || (!resolv_data.ip.is_empty() && !args.wilcard_ips.contains(&resolv_data.ip))
            {
                data_to_write = format!(
                    "{},{},{}",
                    sub,
                    resolv_data.ip,
                    logic::return_ports_string(&resolv_data.open_ports, args)
                );
                logic::print_and_write(data_to_write, args.with_output, file_name)
            }
        } else if only_ports && !resolv_data.open_ports.is_empty() {
            data_to_write = format!(
                "{},{}",
                sub,
                logic::return_ports_string(&resolv_data.open_ports, args)
            );
            logic::print_and_write(data_to_write, args.with_output, file_name)
        } else if (args.monitoring_flag || args.no_monitor) && !args.quiet_flag {
            logic::print_and_write(sub.to_string(), args.with_output, file_name)
        }
    }
    resolv_data
}

fn return_ip(
    hosts_data: &HashMap<String, DomainData>,
    sub: &str,
    empty_domain_data: &DomainData,
) -> String {
    hosts_data
        .get(sub)
        .unwrap_or(empty_domain_data)
        .ipv4_addresses
        .iter()
        .next()
        .unwrap_or(&String::new())
        .to_string()
}

pub fn detect_wildcard(args: &mut Args) -> HashSet<String> {
    if !args.quiet_flag {
        println!("Running wildcards detection for {}...", &args.target)
    }
    let mut generated_wildcards: HashSet<String> = HashSet::new();
    for _ in 1..20 {
        generated_wildcards.insert(format!(
            "{}.{}",
            rng()
                .sample_iter(Alphanumeric)
                .take(15)
                .map(char::from)
                .collect::<String>(),
            &args.target
        ));
    }

    let options = ResolverOpts {
        attempts: 0,
        timeout: Duration::from_secs(args.resolver_timeout),
        ip_strategy: LookupIpStrategy::Ipv4Only,
        num_concurrent_reqs: 1,
        ..Default::default()
    };

    let trustable_resolver = return_tokio_asyncresolver(
        TRUSTABLE_RESOLVERS.iter().map(|x| x.to_owned()).collect(),
        options,
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let handle = rt.handle().to_owned();

    let (tx, rx) = channel::bounded(1);

    handle.spawn(async move {
        let data = return_hosts_data(
            generated_wildcards,
            trustable_resolver.clone(),
            trustable_resolver,
            HashSet::new(),
            true,
            20,
            false,
            true,
        )
        .await;

        let _ = tx.send(data);
    });

    let wildcards_data = match rx.recv() {
        Ok(data) => data,
        Err(e) => {
            println!("Error in the resolution process: {}", e);
            std::process::exit(1);
        }
    };

    let mut wildcards = HashSet::new();

    for (_, wildcard_data) in wildcards_data {
        for ip in wildcard_data.ipv4_addresses {
            wildcards.insert(ip);
        }
    }

    wildcards.retain(|ip| !ip.is_empty());
    if !wildcards.is_empty() && !args.quiet_flag {
        println!(
            "Wilcards detected for {} and wildcard's IP saved for furter work.",
            &args.target
        );
        println!("Wilcard IPs: {:?}\n", wildcards)
    } else if !args.quiet_flag {
        println!("No wilcards detected for {}, nice!\n", &args.target)
    }
    wildcards
}

pub fn check_http_response_code(api_name: &str, response: &reqwest::blocking::Response) -> bool {
    let args = args::get_args();
    if response.status() == 200 {
        true
    } else {
        if !args.quiet_flag && args.verbose {
            println!(
                "The {} API has failed returning the following HTTP status: {}",
                api_name,
                response.status(),
            )
        };
        false
    }
}
