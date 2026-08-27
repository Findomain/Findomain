//! Per-subdomain network checks: DNS resolution, HTTP probing, screenshots
//! and port scanning.
//!
//! The stages run in that order because each one narrows the input of the
//! next: only resolved hosts are probed over HTTP, only hosts with a public
//! address are port scanned.

use {
    crate::{
        config::Config,
        errors::{fatal, Result},
        output::{self, INACTIVE, NOT_CHECKED},
        screenshots::{self, ScreenshotOutcome},
        session::Session,
        tools::nmap,
    },
    fhc::structs::{HttpData, LibOptions as FhcOptions},
    hickory_resolver::{config::ResolverOpts, TokioResolver},
    rand::distr::{Alphanumeric, SampleString},
    rayon::prelude::*,
    rusolver::{
        dnslib::{return_cname_data, return_hosts_data, return_tokio_asyncresolver},
        structs::{DomainData, IpVersion, LibOptions as ResolverOptions},
    },
    std::{
        collections::{HashMap, HashSet},
        fs::File,
        net::IpAddr,
    },
    tokio::runtime::Runtime,
};

/// Number of random hostnames generated to detect a wildcard DNS record.
const WILDCARD_PROBES: usize = 19;
/// Length of each generated wildcard probe label.
const WILDCARD_LABEL_LEN: usize = 15;
/// Concurrency used while probing for wildcards.
const WILDCARD_THREADS: usize = 10;
const RESOLVER_RETRIES: usize = 2;

/// Everything learned about a single subdomain.
#[derive(Clone, Debug, Default)]
pub struct ResolvData {
    /// First IPv4 address, empty when the name does not resolve.
    pub ip: String,
    /// HTTP probe result, or a placeholder status when it did not run.
    pub http_data: HttpData,
    /// Open TCP ports found on [`Self::ip`].
    pub open_ports: Vec<i32>,
    /// Name this subdomain is an alias of, when `--cname` is in use.
    pub cname: String,
}

/// Runs the requested checks over every subdomain of the session.
///
/// Results are printed, and written to `output_file` when one is open, as they
/// are formatted; the map is returned for the database and alerting stages.
///
/// # Errors
///
/// Fails when a result line cannot be written to the output file.
pub fn resolve_all(
    config: &Config,
    session: &Session,
    output_file: Option<&File>,
) -> Result<HashMap<String, ResolvData>> {
    announce(config, session);

    if session.subdomains.is_empty() {
        return Ok(HashMap::new());
    }

    // One thread is enough: everything inside is network bound and already
    // paced by rusolver and fhc, so the worker per core a multi threaded
    // runtime starts would only add context switches. Measured identical.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    // Never zero: `buffer_unordered(0)` polls nothing and hangs the stage.
    let threads = config
        .general
        .lightweight_threads
        .min(session.subdomains.len())
        .max(1);

    let mut resolv_data = initial_data(&runtime, config, session, threads);

    if config.resolution.track_cname {
        attach_cnames(&runtime, config, &mut resolv_data, threads);
    }

    let http_data = http_probe(&runtime, config, &resolv_data, threads);
    merge_http_data(config, &mut resolv_data, http_data);

    if config.screenshots.enabled {
        capture_screenshots(config, &session.target, &resolv_data);
    }
    if config.ports.enabled {
        let ports_by_ip = scan_ports(config, &resolv_data);
        merge_open_ports(&mut resolv_data, &ports_by_ip);
    }

    let mut sink = output::Sink::new(output_file);
    for (subdomain, data) in &resolv_data {
        if let Some(line) = output::result_line(config, &session.wildcard_ips, subdomain, data) {
            sink.write_line(&line)?;
        }
    }
    sink.flush()?;

    Ok(resolv_data)
}

/// Tells the user what is about to happen, unless running quietly.
fn announce(config: &Config, session: &Session) {
    if config.general.quiet || session.subdomains.is_empty() {
        return;
    }

    if config.needs_network_checks() {
        let count = session.subdomains.len();
        if config.input.as_resolver {
            println!("Performing asynchronous resolution for {count} subdomains, it will take a while...\n");
        } else {
            println!(
                "Performing asynchronous resolution for {count} subdomains for the target {}, it will take a while...\n",
                session.target
            );
        }
    }
    if config.monitoring.uses_database() {
        println!();
    }
}

/// Resolves the session subdomains and seeds one [`ResolvData`] per host.
fn initial_data(
    runtime: &Runtime,
    config: &Config,
    session: &Session,
    threads: usize,
) -> HashMap<String, ResolvData> {
    let resolving = config.resolution.is_enabled(config.ports.enabled);

    let hosts_data: HashMap<String, DomainData> = if resolving {
        runtime.block_on(lookup(
            config,
            session.subdomains.clone(),
            session.wildcard_ips.clone(),
            config.resolution.double_check,
            threads,
        ))
    } else {
        session
            .subdomains
            .iter()
            .map(|subdomain| (subdomain.clone(), DomainData::default()))
            .collect()
    };

    hosts_data
        .into_iter()
        .map(|(subdomain, domain_data)| {
            let data = ResolvData {
                ip: if resolving {
                    reported_address(config, &domain_data)
                } else {
                    NOT_CHECKED.to_owned()
                },
                ..ResolvData::default()
            };
            (subdomain, data)
        })
        .collect()
}

/// The address family the run asked for.
const fn ip_version(config: &Config) -> IpVersion {
    if config.resolution.ipv6_only {
        IpVersion::V6
    } else {
        IpVersion::V4
    }
}

/// Builds a resolver, ending the run when an address cannot be understood.
///
/// The addresses come from `--resolvers` or the configuration file, so a typo
/// has to be reported as the configuration mistake it is.
fn resolver(addresses: &[String], options: ResolverOpts) -> TokioResolver {
    match return_tokio_asyncresolver(&as_set(addresses), options) {
        Ok(resolver) => resolver,
        Err(e) => fatal(&format!("Error: {e}")),
    }
}

/// Parses the wildcard addresses into the form rusolver compares against.
fn wildcard_addresses(wildcard_ips: &HashSet<String>) -> HashSet<IpAddr> {
    wildcard_ips
        .iter()
        .filter_map(|ip| ip.parse().ok())
        .collect()
}

/// Runs the DNS lookups through rusolver.
async fn lookup(
    config: &Config,
    hosts: HashSet<String>,
    wildcard_ips: HashSet<String>,
    enable_double_check: bool,
    threads: usize,
) -> HashMap<String, DomainData> {
    let options = rusolver::utils::return_resolver_opts(
        config.resolution.timeout,
        RESOLVER_RETRIES,
        ip_version(config),
    );

    return_hosts_data(&ResolverOptions {
        hosts,
        resolvers: resolver(&config.resolution.resolvers, options.clone()),
        trustable_resolvers: resolver(&config.resolution.trustable_resolvers, options),
        wildcard_ips: wildcard_addresses(&wildcard_ips),
        enable_double_check,
        threads,
        ip_version: ip_version(config),
        show_ip_address: false,
        print_results: false,
        quiet_flag: true,
    })
    .await
}

/// Looks up the CNAME of every host and records it.
///
/// `return_hosts_data` only reports addresses, so the alias needs its own
/// query round; it is skipped entirely unless `--cname` asked for it.
fn attach_cnames(
    runtime: &Runtime,
    config: &Config,
    resolv_data: &mut HashMap<String, ResolvData>,
    threads: usize,
) {
    if resolv_data.is_empty() {
        return;
    }

    let hosts: HashSet<String> = resolv_data.keys().cloned().collect();
    let options = rusolver::utils::return_resolver_opts(
        config.resolution.timeout,
        RESOLVER_RETRIES,
        ip_version(config),
    );
    let resolvers = resolver(&config.resolution.resolvers, options.clone());
    let trustable = resolver(&config.resolution.trustable_resolvers, options);

    let aliases = runtime.block_on(return_cname_data(
        &hosts,
        &resolvers,
        &trustable,
        config.resolution.double_check,
        threads,
    ));

    for (host, cname) in aliases {
        if let Some(entry) = resolv_data.get_mut(&host) {
            cname.trim_end_matches('.').clone_into(&mut entry.cname);
        }
    }
}

/// Probes the hosts over HTTP, skipping the ones that did not resolve.
fn http_probe(
    runtime: &Runtime,
    config: &Config,
    resolv_data: &HashMap<String, ResolvData>,
    threads: usize,
) -> HashMap<String, HttpData> {
    if !config.http.enabled || config.resolution.skip {
        return HashMap::new();
    }

    let hosts: HashSet<String> = resolv_data
        .iter()
        .filter(|(_, data)| {
            !config.resolution.discover_ip || (data.ip != NOT_CHECKED && !data.ip.is_empty())
        })
        .map(|(subdomain, _)| subdomain.clone())
        .collect();

    let options = FhcOptions {
        hosts,
        client: fhc::httplib::return_http_client(config.http.timeout, config.http.max_redirects),
        user_agents: config.http.user_agents.clone(),
        retries: config.http.retries,
        threads,
        // Only the status and the final URL are read back, and the body is
        // the most expensive part of a check: a megabyte per host, parsed as
        // HTML.
        collect_body: false,
        print_results: false,
        quiet_flag: true,
        ..FhcOptions::default()
    };

    runtime.block_on(fhc::httplib::return_http_data(&options))
}

/// Folds the HTTP probe results back into the per-subdomain data.
///
/// Hosts that were probed but never answered are marked `INACTIVE`; hosts that
/// were never probed are marked `NOT CHECKED`. The probe results are consumed
/// rather than cloned: an `HttpData` carries the response body and headers.
fn merge_http_data(
    config: &Config,
    resolv_data: &mut HashMap<String, ResolvData>,
    mut http_data: HashMap<String, HttpData>,
) {
    let checking_http = config.http.enabled;
    let skipping = config.resolution.skip;

    for (host, data) in resolv_data.iter_mut() {
        let probed = http_data.remove(host);
        let answered = probed
            .as_ref()
            .is_some_and(|probed| !probed.final_url.is_empty());

        if checking_http && !data.ip.is_empty() && answered && !skipping {
            data.http_data = probed.unwrap_or_default();
        } else if ((checking_http && data.ip.is_empty()) || !answered) && !skipping {
            INACTIVE.clone_into(&mut data.http_data.http_status);
        } else {
            NOT_CHECKED.clone_into(&mut data.http_data.http_status);
        }

        if skipping {
            data.http_data.final_url.clone_from(host);
        }
    }
}

/// Scans the public IPv4 addresses found so far.
///
/// Addresses that are not reachable from here are skipped; scanning them only
/// wastes the run's time.
fn scan_ports(
    config: &Config,
    resolv_data: &HashMap<String, ResolvData>,
) -> HashMap<String, Vec<i32>> {
    let ips: HashSet<String> = resolv_data
        .iter()
        .filter(|(_, data)| data.ip.parse().is_ok_and(is_scannable))
        .map(|(_, data)| data.ip.clone())
        .collect();

    if ips.is_empty() {
        return HashMap::new();
    }

    match nmap::scan(config, &ips) {
        Ok(found) => found
            .into_iter()
            .map(|(ip, ports)| (ip, ports.into_iter().map(|port| port.port).collect()))
            .collect(),
        Err(e) => {
            eprintln!("Port scan skipped: {e}");
            HashMap::new()
        }
    }
}

/// Reports whether `ip` is worth sending a scanner at.
///
/// The IPv6 arm spells out unique local and link local by hand because the
/// standard library has no stable predicate for either.
fn is_scannable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => !ip.is_private() && !ip.is_loopback() && !ip.is_link_local(),
        IpAddr::V6(ip) => {
            let leading = ip.octets()[0];
            let unique_local = leading & 0xfe == 0xfc;
            let link_local = leading == 0xfe && ip.octets()[1] & 0xc0 == 0x80;
            !ip.is_loopback() && !ip.is_unspecified() && !unique_local && !link_local
        }
    }
}

/// Attaches the open ports found for each address to its subdomains.
fn merge_open_ports(
    resolv_data: &mut HashMap<String, ResolvData>,
    ports_by_ip: &HashMap<String, Vec<i32>>,
) {
    if ports_by_ip.is_empty() {
        return;
    }
    for data in resolv_data.values_mut() {
        if let Some(ports) = ports_by_ip.get(&data.ip) {
            data.open_ports.clone_from(ports);
        }
    }
}

/// Screenshots every host with a reachable HTTP server.
fn capture_screenshots(config: &Config, target: &str, resolv_data: &HashMap<String, ResolvData>) {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.screenshots.threads)
        .build()
        .expect("build the screenshots thread pool");

    pool.install(|| {
        resolv_data.par_iter().for_each(|(subdomain, data)| {
            let url = &data.http_data.final_url;
            if url.is_empty() && !config.resolution.skip {
                return;
            }
            match screenshots::capture(config, url, target, subdomain) {
                ScreenshotOutcome::Captured => {
                    if config.resolution.skip {
                        println!("{url}");
                    }
                }
                ScreenshotOutcome::Failed(e) => eprintln!(
                    "The subdomain {subdomain} has an active HTTP server running at {url} but the screenshot was not taken. Error description: {e}",
                ),
            }
        });
    });
}

/// Detects whether the target answers every name with the same addresses.
///
/// Those addresses are then excluded from the results, because a wildcard
/// record would otherwise turn every guess into a false positive.
#[must_use]
pub fn detect_wildcards(config: &Config, target: &str) -> HashSet<String> {
    if !config.general.quiet {
        println!("Running wildcards detection for {target}...");
    }

    let probes: HashSet<String> = (0..WILDCARD_PROBES)
        .map(|_| {
            let label = Alphanumeric.sample_string(&mut rand::rng(), WILDCARD_LABEL_LEN);
            format!("{label}.{target}")
        })
        .collect();

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("Error in the resolution process: {e}");
            return HashSet::new();
        }
    };

    // Wildcard probing deliberately uses the configured resolvers on both
    // sides: a wildcard is a property of the zone, not of the resolver.
    let wildcards_data = runtime.block_on(lookup(
        config,
        probes,
        HashSet::new(),
        false,
        WILDCARD_THREADS,
    ));

    let wildcards: HashSet<String> = wildcards_data
        .into_values()
        .flat_map(|data| {
            data.ipv4_addresses
                .into_iter()
                .map(|ip| ip.to_string())
                .chain(data.ipv6_addresses.into_iter().map(|ip| ip.to_string()))
        })
        .collect();

    if !config.general.quiet {
        if wildcards.is_empty() {
            println!("No wilcards detected for {target}, nice!\n");
        } else {
            println!("Wilcards detected for {target} and wildcard's IP saved for furter work.");
            println!("Wilcard IPs: {wildcards:?}\n");
        }
    }

    wildcards
}

/// Returns the address to report for `host_data`, or an empty string.
///
/// Reports the family the run asked for, and always the same one of several
/// records, so that two runs of the same target can be diffed.
fn reported_address(config: &Config, host_data: &DomainData) -> String {
    if config.resolution.ipv6_only {
        host_data.primary_ipv6().map(|ip| ip.to_string())
    } else {
        host_data.primary_ipv4().map(|ip| ip.to_string())
    }
    .unwrap_or_default()
}

/// Copies resolver addresses into the set shape rusolver expects.
fn as_set(resolvers: &[String]) -> HashSet<String> {
    resolvers.iter().cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(ip: &str) -> ResolvData {
        ResolvData {
            ip: ip.to_owned(),
            ..ResolvData::default()
        }
    }

    fn map(entries: &[(&str, ResolvData)]) -> HashMap<String, ResolvData> {
        entries
            .iter()
            .map(|(host, data)| ((*host).to_owned(), data.clone()))
            .collect()
    }

    #[test]
    fn an_address_is_reported_when_there_is_one() {
        let config = Config::default();
        let mut domain = DomainData::default();
        assert_eq!(reported_address(&config, &domain), "");
        domain.ipv4_addresses = HashSet::from(["1.2.3.4".parse().expect("valid")]);
        assert_eq!(reported_address(&config, &domain), "1.2.3.4");
    }

    #[test]
    fn the_reported_address_is_the_family_that_was_asked_for() {
        // `--ipv6-only` used to reach rusolver as an A lookup, so it answered
        // with IPv4 addresses and the flag did nothing at all.
        let domain = DomainData {
            ipv4_addresses: HashSet::from(["1.2.3.4".parse().expect("valid")]),
            ipv6_addresses: HashSet::from(["2001:db8::1".parse().expect("valid")]),
            ..DomainData::default()
        };

        let v4 = Config::default();
        assert_eq!(reported_address(&v4, &domain), "1.2.3.4");

        let v6 = Config {
            resolution: crate::config::Resolution {
                ipv6_only: true,
                ..crate::config::Resolution::default()
            },
            ..Config::default()
        };
        assert_eq!(reported_address(&v6, &domain), "2001:db8::1");
        assert_eq!(ip_version(&v6), IpVersion::V6);
        assert_eq!(ip_version(&v4), IpVersion::V4);
    }

    #[test]
    fn only_reachable_addresses_are_worth_scanning() {
        for reachable in ["1.2.3.4", "2606:4700::1111"] {
            assert!(
                is_scannable(reachable.parse().expect("valid")),
                "{reachable} is reachable"
            );
        }
        for skipped in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "::1",
            "::",
            "fd00::1",
            "fe80::1",
        ] {
            assert!(
                !is_scannable(skipped.parse().expect("valid")),
                "{skipped} is not reachable from here"
            );
        }
    }

    #[test]
    fn only_parseable_wildcard_addresses_reach_the_resolver() {
        let given = HashSet::from([
            "1.2.3.4".to_owned(),
            "2001:db8::1".to_owned(),
            String::new(),
            "not-an-address".to_owned(),
        ]);
        let parsed = wildcard_addresses(&given);
        assert_eq!(parsed.len(), 2);
        assert!(parsed.contains(&"1.2.3.4".parse::<IpAddr>().expect("valid")));
    }

    #[test]
    fn probed_hosts_that_answered_keep_their_data() {
        let mut config = Config::default();
        config.http.enabled = true;

        let mut resolv_data = map(&[("a.example.com", data("1.2.3.4"))]);
        let probed = HashMap::from([(
            "a.example.com".to_owned(),
            HttpData {
                http_status: "ACTIVE".to_owned(),
                final_url: "https://a.example.com".to_owned(),
                ..HttpData::default()
            },
        )]);

        merge_http_data(&config, &mut resolv_data, probed);
        let entry = &resolv_data["a.example.com"];
        assert_eq!(entry.http_data.http_status, "ACTIVE");
        assert_eq!(entry.http_data.final_url, "https://a.example.com");
    }

    #[test]
    fn probed_hosts_that_did_not_answer_are_inactive() {
        let mut config = Config::default();
        config.http.enabled = true;

        let mut resolv_data = map(&[("a.example.com", data("1.2.3.4"))]);
        merge_http_data(&config, &mut resolv_data, HashMap::new());
        assert_eq!(resolv_data["a.example.com"].http_data.http_status, INACTIVE);
    }

    #[test]
    fn skipping_resolution_reports_the_host_as_its_own_url() {
        let mut config = Config::default();
        config.http.enabled = true;
        config.resolution.skip = true;

        let mut resolv_data = map(&[("https://a.example.com", data(""))]);
        merge_http_data(&config, &mut resolv_data, HashMap::new());
        let entry = &resolv_data["https://a.example.com"];
        assert_eq!(entry.http_data.http_status, NOT_CHECKED);
        assert_eq!(entry.http_data.final_url, "https://a.example.com");
    }

    #[test]
    fn open_ports_are_attached_to_every_host_sharing_the_address() {
        let mut resolv_data = map(&[
            ("a.example.com", data("1.2.3.4")),
            ("b.example.com", data("1.2.3.4")),
            ("c.example.com", data("5.6.7.8")),
        ]);
        let ports = HashMap::from([("1.2.3.4".to_owned(), vec![80, 443])]);

        merge_open_ports(&mut resolv_data, &ports);
        assert_eq!(resolv_data["a.example.com"].open_ports, vec![80, 443]);
        assert_eq!(resolv_data["b.example.com"].open_ports, vec![80, 443]);
        assert!(resolv_data["c.example.com"].open_ports.is_empty());
    }

    #[test]
    fn as_set_deduplicates_resolvers() {
        let resolvers = vec!["1.1.1.1:53".to_owned(), "1.1.1.1:53".to_owned()];
        assert_eq!(as_set(&resolvers).len(), 1);
    }
}
