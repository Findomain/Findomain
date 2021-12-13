use {
    crate::{
        alerts,
        errors::*,
        files, logic, misc, networking,
        structs::{Args, HttpStatus},
        utils,
    },
    addr::parse_domain_name,
    postgres::{Client, NoTls},
    std::time::{Duration, Instant},
    trust_dns_resolver::config::{LookupIpStrategy, ResolverOpts},
};

lazy_static! {
    static ref SPECIAL_CHARS: Vec<char> = vec![
        '[', ']', '{', '}', '(', ')', '*', '|', ':', '<', '>', '/', '\\', '%', '&', '¿', '?', '¡',
        '!', '#', '\'', ' ', ','
    ];
}

pub fn manage_subdomains_data(args: &mut Args) -> Result<()> {
    let file_name = files::return_output_file(args);
    if !args.quiet_flag {
        println!()
    };
    let opts = ResolverOpts {
        timeout: Duration::from_secs(5),
        ip_strategy: LookupIpStrategy::Ipv4Only,
        num_concurrent_reqs: 1,
        ..Default::default()
    };

    let resolver = networking::get_resolver(networking::return_socket_address(args), opts);

    if (args.only_resolved || args.with_ip || args.ipv6_only)
        && !args.disable_wildcard_check
        && !args.as_resolver
    {
        args.wilcard_ips = networking::detect_wildcard(args, &resolver);
    }

    if args.discover_ip || args.http_status || args.enable_port_scan {
        networking::async_resolver_all(args, resolver);
    } else if !args.discover_ip && !args.http_status && !args.enable_port_scan && args.with_output {
        for subdomain in &args.subdomains {
            println!("{}", subdomain);
            files::write_to_file(subdomain, &file_name)?
        }
    } else {
        for subdomain in &args.subdomains {
            println!("{}", subdomain);
        }
    }
    if !args.quiet_flag {
        println!(
            "\nJob finished in {} seconds.",
            args.time_wasted.elapsed().as_secs()
        )
    }
    args.time_wasted = Instant::now();
    Ok(())
}

pub fn works_with_data(args: &mut Args) -> Result<()> {
    let opts = ResolverOpts {
        timeout: Duration::from_secs(5),
        ip_strategy: LookupIpStrategy::Ipv4Only,
        num_concurrent_reqs: 1,
        ..Default::default()
    };

    let resolver = networking::get_resolver(networking::return_socket_address(args), opts);

    if !(!args.unique_output_flag
        || args.from_file_flag
        || args.from_stdin
        || args.monitoring_flag
        || args.no_monitor)
    {
        files::check_output_file_exists(&args.file_name)?;
        logic::manage_subdomains_data(args)?;
    } else if args.unique_output_flag
        && (args.from_file_flag || args.from_stdin)
        && !args.monitoring_flag
        && !args.no_monitor
    {
        logic::manage_subdomains_data(args)?;
    } else if (args.monitoring_flag || args.no_monitor)
        && !(args.from_file_flag || args.from_stdin)
        && args.unique_output_flag
    {
        files::check_output_file_exists(&args.file_name)?;
        alerts::subdomains_alerts(args, resolver)?
    } else if args.monitoring_flag || args.no_monitor {
        alerts::subdomains_alerts(args, resolver)?
    } else {
        files::check_output_file_exists(&args.file_name)?;
        logic::manage_subdomains_data(args)?;
    }
    if args.with_output && !args.quiet_flag && !args.monitoring_flag && !args.no_monitor {
        misc::show_file_location(&args.target, &args.file_name)
    }
    if !args.quiet_flag {
        println!("\nGood luck Hax0r 💀!\n");
    }
    Ok(())
}

pub fn validate_target(target: &str) -> bool {
    !target.starts_with('.')
        && target.contains('.')
        && parse_domain_name(target).is_ok()
        && !target.contains(&SPECIAL_CHARS[..])
        && target.chars().all(|c| c.is_ascii())
}

pub fn eval_resolved_or_ip_present(value: bool, with_ip: bool, resolved: bool) -> bool {
    if value && (with_ip || resolved) {
        true
    } else if !value {
        false
    } else {
        eprintln!("Error: --enable-dot flag needs -i/--ip or -r/--resolved");
        std::process::exit(1)
    }
}

pub fn validate_subdomain(base_target: &str, subdomain: &str, args: &mut Args) -> bool {
    !subdomain.is_empty()
        && !subdomain.starts_with('.')
        && (subdomain.ends_with(base_target) || subdomain == args.target)
        && !subdomain.contains(&SPECIAL_CHARS[..])
        && subdomain.chars().all(|c| c.is_ascii())
        && parse_domain_name(subdomain).is_ok()
        && if args.filter_by_string.is_empty() && args.exclude_by_string.is_empty() {
            true
        } else if !args.filter_by_string.is_empty() {
            args.filter_by_string
                .iter()
                .any(|key| subdomain.contains(key))
        } else if !args.exclude_by_string.is_empty() {
            !args
                .exclude_by_string
                .iter()
                .any(|key| subdomain.contains(key))
        } else {
            false
        }
}

pub fn test_database_connection(args: &mut Args) {
    if !args.quiet_flag {
        println!("Testing connection to database server...")
    }
    match Client::connect(&args.postgres_connection, NoTls) {
        Ok(_) => {
            if !args.quiet_flag {
                println!("Connected, performing enumeration!")
            }
        }
        Err(e) => {
            println!(
                "The following error happened while connecting to the database: {}",
                e
            );
            std::process::exit(1)
        }
    }
}

pub fn test_chrome_availability(args: &mut Args) {
    if !args.quiet_flag {
        println!("Testing Chromium/Chrome availability...")
    }
    utils::return_headless_browser(args.chrome_sandbox);
    println!("Chromium/Chrome is correctly installed, performing enumeration!")
}

pub fn null_ip_checker(ip: &str) -> String {
    if ip.is_empty() {
        String::from("NULL")
    } else {
        ip.to_string()
    }
}

pub fn return_ports_string(ports: &[i32], args: &Args) -> String {
    if ports.is_empty() && args.enable_port_scan {
        String::from("NULL")
    } else if ports.is_empty() && !args.enable_port_scan {
        String::from("NOT CHECKED")
    } else {
        format!("{:?}", ports)
    }
}

pub fn print_and_write(
    data_to_write: String,
    with_output: bool,
    file_name: &Option<std::fs::File>,
) {
    println!("{}", data_to_write);
    if with_output {
        files::write_to_file(&data_to_write, file_name).unwrap()
    }
}

pub fn eval_http(http_status: &HttpStatus) -> String {
    if !http_status.host_url.is_empty() {
        http_status.host_url.clone()
    } else {
        http_status.http_status.clone()
    }
}
