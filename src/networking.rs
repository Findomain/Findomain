use {
    crate::{
        args, external_subs, files, logic, port_scanner, screenshots, sources,
        structs::{Args, HttpStatus, ResolvData},
        utils,
    },
    rand::{distributions::Alphanumeric, thread_rng as rng, Rng},
    rayon::prelude::*,
    std::{
        collections::{HashMap, HashSet},
        fs,
        net::{Ipv4Addr, SocketAddr},
        thread,
    },
    trust_dns_resolver::{
        config::{NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts},
        Resolver,
    },
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

pub fn search_subdomains(args: &mut Args) -> HashSet<String> {
    let quiet_flag = args.quiet_flag;
    let base_target = &format!(".{}", args.target);

    let url_api_certspotter = format!(
        "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
        &args.target
    );
    let certspotter_token = args.certspotter_access_token.clone();
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
        &args.target,
        &utils::return_random_string(args.spyse_access_token.clone())
    );
    //  let url_api_bufferover = format!("http://dns.bufferover.run/dns?q={}", &args.target);
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
    let url_api_ctsearch = format!("https://ctsearch.entrust.com/api/v1/certificates?fields=subjectDN&domain={}&includeExpired=true&exactMatch=false&limit=5000", &args.target);
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
        if args.excluded_sources.contains("virustotal") { thread::spawn(|| None) }
        else { thread::spawn(move || sources::get_virustotal_subdomains(&url_api_virustotal, quiet_flag)) },
        if args.excluded_sources.contains("sublist3r") { thread::spawn(|| None) }
        else { thread::spawn(move || sources::get_sublist3r_subdomains(&url_api_sublist3r, quiet_flag)) },
        if args.excluded_sources.contains("facebook") || args.facebook_access_token.is_empty() { thread::spawn(|| None)
        } else {
            let url_api_fb = format!(
                "https://graph.facebook.com/certificates?query={}&fields=domains&limit=10000&access_token={}",
                &args.target,
                &utils::return_random_string(args.facebook_access_token.clone()));
            thread::spawn(move || sources::get_facebook_subdomains(&url_api_fb, quiet_flag))
        },
        if args.excluded_sources.contains("spyse") { thread::spawn(|| None) }
        else { thread::spawn(move || sources::get_spyse_subdomains(&url_api_spyse, quiet_flag)) },
        // if args.excluded_sources.contains("bufferover") { thread::spawn(|| None) }
        // else { thread::spawn(move || sources::get_bufferover_subdomains(&url_api_bufferover, quiet_flag)) },
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
        if args.excluded_sources.contains("ctsearch") { thread::spawn(|| None) }
        else { thread::spawn(move || sources::get_ctsearch_subdomains(&url_api_ctsearch, quiet_flag)) },
    ].into_iter().map(|j| j.join().unwrap()).collect::<Vec<_>>().into_iter().flatten().flatten().map(|sub| sub.to_lowercase()).collect();
    all_subdomains.retain(|sub| logic::validate_subdomain(base_target, sub, args));
    all_subdomains
}

pub fn async_resolver_all(args: &Args, resolver: Resolver) -> HashMap<String, ResolvData> {
    let client = utils::return_reqwest_client(args.http_timeout);
    let mut data = HashMap::new();
    let mut scannet_hosts: HashMap<String, Vec<i32>> = HashMap::new();
    let file_name = files::return_output_file(args);

    if !args.quiet_flag && (args.discover_ip || args.http_status || args.enable_port_scan) {
        println!(
            "Performing asynchronous resolution for {} subdomains for the target {}, it will take a while. 🧐\n",
            args.subdomains.len(), args.target
        )
    }
    if (args.monitoring_flag || args.no_monitor) && !args.quiet_flag {
        println!()
    }
    if !args.enable_port_scan {
        data.par_extend(args.subdomains.par_iter().map(|sub| {
            async_resolver_engine(
                args,
                sub.to_owned(),
                &resolver,
                &client,
                &scannet_hosts,
                &file_name,
            )
        }));
    } else {
        data.extend(args.subdomains.iter().map(|sub| {
            let resolv_data = async_resolver_engine(
                args,
                sub.to_owned(),
                &resolver,
                &client,
                &scannet_hosts,
                &file_name,
            );
            scannet_hosts.insert(resolv_data.1.ip.clone(), resolv_data.1.open_ports.clone());
            resolv_data
        }))
    }
    data
}

#[allow(clippy::cognitive_complexity)]
fn async_resolver_engine(
    args: &Args,
    sub: String,
    domain_resolver: &trust_dns_resolver::Resolver,
    client: &reqwest::blocking::Client,
    resolved_hosts: &HashMap<String, Vec<i32>>,
    file_name: &Option<std::fs::File>,
) -> (String, ResolvData) {
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
    let mut timeout: u64 = 0;

    let mut resolv_data = {
        ResolvData {
            ip: if !args.no_resolve && (args.enable_port_scan || args.discover_ip) {
                let rtimeout = if args.enable_port_scan {
                    Some(std::time::Instant::now())
                } else {
                    None
                };
                let ip = if args.no_resolve {
                    String::new()
                } else {
                    get_ip(domain_resolver, &format!("{}.", sub), args.ipv6_only)
                };
                if args.enable_port_scan && !args.no_resolve {
                    timeout = utils::calculate_timeout(
                        args.threads,
                        rtimeout.unwrap().elapsed().as_millis() as u64,
                    );
                }
                ip
            } else {
                String::from("NOT CHECKED")
            },
            http_status: HttpStatus {
                http_status: String::new(),
                host_url: String::new(),
            },
            open_ports: Vec::new(),
        }
    };

    if args.http_status && !resolv_data.ip.is_empty() && !args.no_resolve {
        resolv_data.http_status = check_http_status(client, &sub)
    } else if args.http_status && resolv_data.ip.is_empty() && !args.no_resolve {
        resolv_data.http_status.http_status = String::from("INACTIVE")
    } else {
        resolv_data.http_status.http_status = String::from("NOT CHECKED")
    }

    if args.no_resolve {
        resolv_data.http_status.host_url = sub.clone()
    }

    if args.take_screenshots && !resolv_data.http_status.host_url.is_empty() || args.no_resolve {
        match screenshots::take_screenshot(
            utils::return_headless_browser(args.chrome_sandbox),
            &resolv_data.http_status.host_url,
            &args.screenshots_path,
            &args.target,
            &sub,
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
                        &sub,
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

    if args.enable_port_scan && !resolv_data.ip.is_empty() {
        if !resolved_hosts.contains_key(&resolv_data.ip) {
            resolv_data.open_ports = port_scanner::return_open_ports(
                &ports,
                resolv_data
                    .ip
                    .parse::<Ipv4Addr>()
                    .expect("Error parsing IP address, please report the issue."),
                timeout,
            )
        } else {
            resolv_data.open_ports = resolved_hosts.get(&resolv_data.ip).unwrap().to_owned()
        }
    };

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
    (sub, resolv_data)
}

fn check_http_status(client: &reqwest::blocking::Client, target: &str) -> HttpStatus {
    let http_url = if target.starts_with("http://") {
        target.to_string()
    } else {
        format!("http://{}", target)
    };
    let https_url = if target.starts_with("https://") {
        target.to_string()
    } else {
        format!("https://{}", target)
    };
    if client.get(&https_url).send().is_ok() {
        HttpStatus {
            http_status: String::from("ACTIVE"),
            host_url: https_url,
        }
    } else if client.get(&http_url).send().is_ok() {
        HttpStatus {
            http_status: String::from("ACTIVE"),
            host_url: http_url,
        }
    } else {
        HttpStatus {
            http_status: String::from("INACTIVE"),
            host_url: String::new(),
        }
    }
}

fn get_ip(resolver: &Resolver, domain: &str, ipv6_only: bool) -> String {
    if ipv6_only {
        if let Ok(ip_address) = resolver.ipv6_lookup(domain.to_string()) {
            ip_address
                .iter()
                .next()
                .expect("An error as ocurred getting the IP address.")
                .to_string()
        } else {
            String::new()
        }
    } else if let Ok(ip_address) = resolver.ipv4_lookup(domain.to_string()) {
        ip_address
            .iter()
            .next()
            .expect("An error as ocurred getting the IP address.")
            .to_string()
    } else {
        String::new()
    }
}

pub fn get_resolver(nameserver_ips: &[String], opts: &ResolverOpts) -> Resolver {
    let mut name_servers = NameServerConfigGroup::with_capacity(nameserver_ips.len() * 2);
    name_servers.extend(nameserver_ips.iter().flat_map(|server| {
        let socket_addr = SocketAddr::V4(match server.parse() {
            Ok(a) => a,
            Err(e) => unreachable!(
                "Error parsing the server {}, only IPv4 are allowed. Error: {}",
                server, e
            ),
        });
        std::iter::once(NameServerConfig {
            socket_addr,
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_nx_responses: false,
        })
        .chain(std::iter::once(NameServerConfig {
            socket_addr,
            protocol: Protocol::Tcp,
            tls_dns_name: None,
            trust_nx_responses: false,
        }))
    }));

    match Resolver::new(
        ResolverConfig::from_parts(None, vec![], name_servers),
        *opts,
    ) {
        Ok(resolver) => resolver,

        Err(e) => {
            eprintln!("Failed to create the resolver. Error: {}\n", e);
            std::process::exit(1)
        }
    }
}

pub fn detect_wildcard(args: &mut Args, resolver: &Resolver) -> HashSet<String> {
    if !args.quiet_flag {
        println!("Running wildcards detection for {}...", &args.target)
    }
    let mut generated_wilcards: HashSet<String> = HashSet::new();
    for _ in 1..20 {
        generated_wilcards.insert(format!(
            "{}.{}",
            rng()
                .sample_iter(Alphanumeric)
                .take(15)
                .map(char::from)
                .collect::<String>(),
            &args.target
        ));
    }
    generated_wilcards = generated_wilcards
        .par_iter()
        .map(|sub| get_ip(resolver, &format!("{}.", sub), args.ipv6_only))
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
