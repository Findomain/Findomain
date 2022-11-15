use {
    crate::{
        args, external_subs, files, logic, port_scanner, resolvers, screenshots, sources,
        structs::{self, Args, ResolvData},
        utils,
    },
    crossbeam::channel,
    fhc::structs::{HttpData, LibOptions as FhcLibOptions},
    rand::{distributions::Alphanumeric, thread_rng as rng, Rng},
    rayon::prelude::*,
    rusolver::{
        dnslib::{return_hosts_data, return_tokio_asyncresolver},
        structs::{DomainData, LibOptions as RusolverLibOptions},
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

    println!();

    all_subdomains
}

pub fn async_resolver_all(args: &Args) -> HashMap<String, ResolvData> {
    let file_name = files::return_output_file(args);

    if !args.quiet_flag
        && !args.subdomains.is_empty()
        && (args.discover_ip || args.http_status || args.enable_port_scan)
    {
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
    if !args.subdomains.is_empty() && (args.monitoring_flag || args.no_monitor) && !args.quiet_flag
    {
        println!()
    }

    if !args.subdomains.is_empty() {
        async_resolver_engine(args, args.subdomains.clone(), &file_name)
    } else {
        HashMap::new()
    }
}

#[allow(clippy::cognitive_complexity)]
fn async_resolver_engine(
    args: &Args,
    subdomains: HashSet<String>,
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
    if args.enable_port_scan && args.custom_ports_range {
        ports.extend(args.initial_port..=args.last_port)
    } else if args.enable_port_scan {
        ports = structs::top_1000_ports();
    }
    #[allow(unused_assignments)]
    let mut data_to_write = String::new();

    let wildcard_ips = args.wilcard_ips.clone();

    let async_threads = if args.lightweight_threads > args.subdomains.len() {
        args.subdomains.len()
    } else {
        args.lightweight_threads
    };

    let hosts_data = if !args.no_resolve && (args.enable_port_scan || args.discover_ip) {
        let options = ResolverOpts {
            attempts: 0,
            timeout: Duration::from_secs(args.resolver_timeout),
            ip_strategy: LookupIpStrategy::Ipv4Only,
            num_concurrent_reqs: 1,
            shuffle_dns_servers: true,
            ..Default::default()
        };

        let resolvers = return_tokio_asyncresolver(
            RESOLVERS.iter().map(std::clone::Clone::clone).collect(),
            options,
        );
        let trustable_resolver = return_tokio_asyncresolver(
            TRUSTABLE_RESOLVERS
                .iter()
                .map(std::clone::Clone::clone)
                .collect(),
            options,
        );

        let rt = tokio::runtime::Runtime::new().unwrap();
        let handle = rt.handle().clone();
        let (tx, rx) = channel::bounded(1);

        let subdomains_for_async_resolver = subdomains.clone();
        let disable_double_check = args.disable_double_dns_check;

        let rusolver_liboptions = RusolverLibOptions {
            hosts: subdomains_for_async_resolver,
            resolvers,
            trustable_resolver,
            wildcard_ips,
            disable_double_check,
            threads: async_threads,
            show_ip_address: false,
            quiet_flag: true,
        };

        handle.spawn(async move {
            let data = return_hosts_data(&rusolver_liboptions).await;

            let _ = tx.send(data);
        });

        match rx.recv() {
            Ok(data) => data,
            Err(e) => {
                println!("Error in the resolution process: {e}");
                std::process::exit(1);
            }
        }
    } else {
        subdomains
            .par_iter()
            .map(|sub| (sub.clone(), DomainData::default()))
            .collect()
    };

    let mut resolv_data: HashMap<String, ResolvData> = hosts_data
        .par_iter()
        .map(|(sub, hosts_data)| {
            let local_resolv_data = ResolvData {
                ip: if !args.no_resolve && (args.enable_port_scan || args.discover_ip) {
                    return_ip(hosts_data)
                } else {
                    String::from("NOT CHECKED")
                },
                http_data: HttpData::default(),
                open_ports: Vec::new(),
            };
            (sub.clone(), local_resolv_data)
        })
        .collect();

    let http_data = if args.http_status && !args.no_resolve {
        let mut http_hosts = HashSet::new();

        for (sub, host_resolv_data) in &resolv_data {
            if args.discover_ip {
                if host_resolv_data.ip != "NOT CHECKED" && !host_resolv_data.ip.is_empty() {
                    http_hosts.insert(sub.clone());
                }
            } else {
                http_hosts.insert(sub.clone());
            }
        }

        let rt = tokio::runtime::Runtime::new().unwrap();
        let handle = rt.handle().clone();

        let (tx, rx) = channel::bounded(1);

        let client = fhc::httplib::return_http_client(args.http_timeout, args.max_http_redirects);

        let lib_options = FhcLibOptions {
            hosts: http_hosts.clone(),
            client,
            user_agents: args.user_agent_strings.clone(),
            retries: args.http_retries,
            threads: async_threads,
            assign_response_data: true,
            quiet_flag: true,
            ..Default::default()
        };

        handle.spawn(async move {
            let http_data = fhc::httplib::return_http_data(&lib_options).await;

            let _ = tx.send(http_data);
        });

        match rx.recv() {
            Ok(data) => data,
            Err(e) => {
                println!("Error in the resolution process: {e}");
                std::process::exit(1);
            }
        }
    } else {
        subdomains
            .par_iter()
            .map(|sub| (sub.clone(), HttpData::default()))
            .collect()
    };

    let empty_http_data = HttpData::default();

    resolv_data = resolv_data
        .par_iter()
        .map(|(host, host_resolv_data)| {
            let local_fhc_data = http_data.get(host).unwrap_or(&empty_http_data).clone();
            let mut local_resolv_data = host_resolv_data.clone();

            if args.http_status
                && !local_resolv_data.ip.is_empty()
                && !local_fhc_data.host_url.is_empty()
                && !args.no_resolve
            {
                local_resolv_data.http_data = local_fhc_data;
            } else if (args.http_status && local_resolv_data.ip.is_empty()
                || local_fhc_data.host_url.is_empty())
                && !args.no_resolve
            {
                local_resolv_data.http_data.http_status = String::from("INACTIVE")
            } else {
                local_resolv_data.http_data.http_status = String::from("NOT CHECKED")
            }

            if args.no_resolve {
                local_resolv_data.http_data.host_url = host.clone()
            };

            (host.clone(), local_resolv_data)
        })
        .collect();

    if args.take_screenshots {
        let screenshots_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(args.screenshots_threads)
            .build()
            .unwrap();
        screenshots_pool.install(|| { resolv_data.par_iter().map(|(sub, host_resolv_data)| {
        if !host_resolv_data.http_data.host_url.is_empty() || args.no_resolve {
            match screenshots::take_screenshot(
                utils::return_headless_browser(args.chrome_sandbox),
                &host_resolv_data.http_data.host_url,
                &args.screenshots_path,
                &args.target,
                sub,
            ) {
                Ok(_) => {
                    if args.no_resolve {
                        println!("{}", host_resolv_data.http_data.host_url)
                    }
                }
                Err(_) => {
                    let mut counter = 0;
                    while counter <= 2 {
                        match screenshots::take_screenshot(
                            utils::return_headless_browser(args.chrome_sandbox),
                            &host_resolv_data.http_data.host_url,
                            &args.screenshots_path,
                            &args.target,
                            sub,
                        ) {
                            Ok(_) => {
                                if args.no_resolve {
                                    println!("{}", host_resolv_data.http_data.host_url)
                                };
                                break;
                            }
                            Err(e) => {
                                if counter == 3 {
                                    eprintln!("The subdomain {sub} has an active HTTP server running at {} but the screenshot was not taken. Error description: {e}", host_resolv_data.http_data.host_url)
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

    if args.enable_port_scan {
        let ips_to_scan = resolv_data
            .par_iter()
            .filter(|(_, host_resolv_data)| {
                host_resolv_data.ip != "NOT CHECKED" && !host_resolv_data.ip.is_empty()
            })
            .map(|(_, host_resolv_data)| host_resolv_data.ip.clone())
            .collect::<HashSet<String>>();

        if !ips_to_scan.is_empty() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let handle = rt.handle().clone();

            let tcp_connect_threads = args.tcp_connect_threads;
            let parallel_ip_ports_scan = if ips_to_scan.len() < args.parallel_ip_ports_scan {
                ips_to_scan.len()
            } else {
                args.parallel_ip_ports_scan
            };
            let tcp_connect_timeout = args.tcp_connect_timeout;

            let (tx, rx) = channel::bounded(1);

            handle.spawn(async move {
                let ips_ports_data = port_scanner::return_open_ports_from_ips(
                    ports,
                    ips_to_scan,
                    parallel_ip_ports_scan,
                    tcp_connect_timeout,
                    tcp_connect_threads,
                )
                .await;

                let _ = tx.send(ips_ports_data);
            });

            if let Ok(ips_ports_data) = rx.recv() {
                let empty_ports_data = vec![];

                resolv_data = resolv_data
                    .par_iter()
                    .map(|(host, host_resolv_data)| {
                        let local_ports_data = ips_ports_data
                            .get(&host_resolv_data.ip)
                            .unwrap_or(&empty_ports_data);
                        let mut local_resolv_data = host_resolv_data.clone();

                        local_resolv_data.open_ports = local_ports_data.clone();

                        (host.clone(), local_resolv_data)
                    })
                    .collect();
            }
        }
    };

    for (sub, host_resolv_data) in &resolv_data {
        if ip_http_ports {
            if (args.disable_wildcard_check && !host_resolv_data.ip.is_empty())
                || (!host_resolv_data.ip.is_empty()
                    && !args.wilcard_ips.contains(&host_resolv_data.ip))
            {
                data_to_write = format!(
                    "{},{},{},{}",
                    sub,
                    &host_resolv_data.ip,
                    &logic::eval_http(&host_resolv_data.http_data),
                    logic::return_ports_string(&host_resolv_data.open_ports, args)
                );
                logic::print_and_write(data_to_write, args.with_output, file_name)
            }
        } else if http_with_ip {
            if (args.disable_wildcard_check && !host_resolv_data.ip.is_empty())
                || (!host_resolv_data.ip.is_empty()
                    && !args.wilcard_ips.contains(&host_resolv_data.ip))
            {
                data_to_write = format!(
                    "{},{},{}",
                    sub,
                    &host_resolv_data.ip,
                    &logic::eval_http(&host_resolv_data.http_data)
                );
                logic::print_and_write(data_to_write, args.with_output, file_name)
            }
        } else if only_resolved_or_ip {
            if (args.disable_wildcard_check && !host_resolv_data.ip.is_empty())
                || (!host_resolv_data.ip.is_empty()
                    && !args.wilcard_ips.contains(&host_resolv_data.ip))
            {
                if args.only_resolved {
                    data_to_write = sub.to_string();
                } else {
                    data_to_write = format!("{sub},{}", host_resolv_data.ip);
                }
                logic::print_and_write(data_to_write, args.with_output, file_name)
            }
        } else if http_without_ip_with_ports {
            if host_resolv_data.http_data.http_status == "ACTIVE" {
                data_to_write = format!(
                    "{},{},{}",
                    sub,
                    &logic::eval_http(&host_resolv_data.http_data),
                    logic::return_ports_string(&host_resolv_data.open_ports, args)
                );
                logic::print_and_write(data_to_write, args.with_output, file_name)
            }
        } else if only_http {
            if host_resolv_data.http_data.http_status == "ACTIVE" {
                data_to_write = logic::eval_http(&host_resolv_data.http_data);
                logic::print_and_write(data_to_write, args.with_output, file_name)
            }
        } else if ports_with_ip {
            if (args.disable_wildcard_check && !host_resolv_data.ip.is_empty())
                || (!host_resolv_data.ip.is_empty()
                    && !args.wilcard_ips.contains(&host_resolv_data.ip))
            {
                data_to_write = format!(
                    "{},{},{}",
                    sub,
                    host_resolv_data.ip,
                    logic::return_ports_string(&host_resolv_data.open_ports, args)
                );
                logic::print_and_write(data_to_write, args.with_output, file_name)
            }
        } else if only_ports && !host_resolv_data.open_ports.is_empty() {
            data_to_write = format!(
                "{},{}",
                sub,
                logic::return_ports_string(&host_resolv_data.open_ports, args)
            );
            logic::print_and_write(data_to_write, args.with_output, file_name)
        } else if (args.monitoring_flag || args.no_monitor) && !args.quiet_flag {
            logic::print_and_write(sub.to_string(), args.with_output, file_name)
        }
    }
    resolv_data
}

fn return_ip(host_data: &DomainData) -> String {
    host_data
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
        shuffle_dns_servers: true,
        ..Default::default()
    };

    let trustable_resolver = return_tokio_asyncresolver(
        TRUSTABLE_RESOLVERS
            .iter()
            .map(std::clone::Clone::clone)
            .collect(),
        options,
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let handle = rt.handle().clone();

    let (tx, rx) = channel::bounded(1);

    let rusolver_liboptions = RusolverLibOptions {
        hosts: generated_wildcards,
        resolvers: trustable_resolver.clone(),
        trustable_resolver,
        wildcard_ips: HashSet::new(),
        disable_double_check: true,
        threads: 10,
        show_ip_address: false,
        quiet_flag: true,
    };

    handle.spawn(async move {
        let data = return_hosts_data(&rusolver_liboptions).await;

        let _ = tx.send(data);
    });

    let wildcards_data = match rx.recv() {
        Ok(data) => data,
        Err(e) => {
            println!("Error in the resolution process: {e}");
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
        println!("Wilcard IPs: {wildcards:?}\n")
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
