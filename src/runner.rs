//! Top level orchestration: what runs, in which order, for which targets.

use {
    crate::{
        alerts,
        config::Config,
        database, discovery,
        errors::{fatal, Result},
        files::{self, LineKind},
        filters::{validate_subdomain, validate_target},
        output, permutations, resolve, screenshots,
        session::Session,
        tools, utils,
    },
    rand::seq::SliceRandom,
    std::{collections::HashSet, thread, time::Duration},
};

/// Runs Findomain according to `config`.
///
/// # Errors
///
/// Fails when a stage cannot complete, for instance because the output file
/// cannot be written or the database is unreachable.
pub fn run(config: &Config) -> Result<()> {
    if config.database.reset {
        database::reset(config)?;
        println!("Database was reset successfully!");
        std::process::exit(0)
    }

    if config.filters.are_contradictory() {
        fatal(&format!(
            "Wait, you are filtering and excluding exactly the same keywords? Please check and try again. \nFiltering keywords: {:?} \nExcluding keywords: {:?}",
            config.filters.include, config.filters.exclude
        ));
    }

    if config.input.validate_only {
        return validate_files(config);
    }

    if !config.input.target.is_empty() || config.database.query_by_jobname {
        let mut session =
            Session::new(config.input.target.clone(), config.output.file_name.clone());
        enumerate_target(config, &mut session)
    } else if config.input.from_target_list() {
        run_target_list(config)
    } else {
        fatal("Error: Target is empty or invalid!")
    }
}

/// Prints the valid subdomains of the input files and exits.
fn validate_files(config: &Config) -> Result<()> {
    let subdomains: HashSet<String> =
        files::read_lines(&config.input.files, LineKind::Target, config.general.quiet)
            .into_iter()
            .filter(|subdomain| validate_target(subdomain))
            .collect();

    for subdomain in &subdomains {
        println!("{subdomain}");
    }

    if config.output.unique {
        let file = files::open_output_file(&config.output.file_name, true)?;
        if let Some(file) = file {
            let listing = subdomains.into_iter().collect::<Vec<_>>().join("\n");
            files::append_string(&listing, &file)?;
            println!(
                "\nValidated subdomains were written to {}. Good luck!",
                config.output.file_name
            );
        }
    }

    std::process::exit(0)
}

/// Walks a list of targets read from files or stdin.
fn run_target_list(config: &Config) -> Result<()> {
    if config.output.unique {
        files::backup_existing(&config.output.file_name)?;
    }

    if config.input.as_resolver {
        return resolve_given_hosts(config);
    }

    let mut targets = read_input(config, LineKind::Target);
    targets.retain(|target| !target.is_empty() && validate_target(target));

    if targets.is_empty() {
        fatal("Could not find any valid target, please check that the file is not empty and the targets are in the format domain.tld");
    }
    if config.input.randomize {
        targets.shuffle(&mut rand::rng());
    }

    let mut session = Session::default();
    let mut targets = targets.into_iter().peekable();
    while let Some(target) = targets.next() {
        let file_name = target_file_name(config, &target);
        session.start_target(target, file_name, targets.peek().is_none());
        enumerate_target(config, &mut session)?;
    }

    Ok(())
}

/// Uses Findomain purely as a resolver for a list of hosts.
fn resolve_given_hosts(config: &Config) -> Result<()> {
    if !config.needs_network_checks() {
        fatal("To use Findomain as resolver, use one or more of the --resolved/-r, --ip/-i, --ipv6-only, --http-status or --pscan/--iport/--lport options.");
    }

    let mut hosts: HashSet<String> = read_input(config, LineKind::Raw)
        .into_iter()
        .filter(|host| !host.is_empty())
        .collect();

    if config.resolution.skip {
        hosts.retain(|host| host.starts_with("https://") || host.starts_with("http://"));
        if hosts.is_empty() {
            fatal("You have used the --no-resolve flag but targets doesn't contains a valid URL schema. Please make sure that they starts with https:// or http://, leaving.");
        }
    }
    if hosts.is_empty() {
        fatal("Could not find any valid target, please check that the file is not empty.");
    }

    let mut session = Session::new(String::new(), config.output.file_name.clone());
    session.subdomains = hosts;
    manage_subdomains_data(config, &mut session)
}

/// Reads the input list from the configured files, or from stdin.
fn read_input(config: &Config, kind: LineKind) -> Vec<String> {
    if config.input.files.is_empty() {
        utils::read_stdin()
    } else {
        files::read_lines(&config.input.files, kind, config.general.quiet)
    }
}

/// Picks the output file for `target` when walking a list.
fn target_file_name(config: &Config, target: &str) -> String {
    if !config.output.file_name.is_empty() {
        return config.output.file_name.clone();
    }
    if config.resolution.with_ip {
        format!("{target}-ip.txt")
    } else {
        format!("{target}.txt")
    }
}

/// Gathers and reports every subdomain of the session target.
fn enumerate_target(config: &Config, session: &mut Session) -> Result<()> {
    session.target = session.target.to_lowercase();

    if config.screenshots.enabled {
        screenshots::check_availability(config);
    }
    if config.monitoring.uses_database() && !session.database_checked {
        database::test_connection(config);
        session.database_checked = true;
    }
    if !config.general.quiet && !config.database.is_query() {
        println!("\nTarget ==> {}\n", session.target);
    }
    if config.database.is_query() {
        return report_stored_subdomains(config, session);
    }

    if config.input.bruteforce() {
        session.subdomains.extend(
            config
                .input
                .wordlist_words
                .iter()
                .map(|word| format!("{word}.{}", session.target)),
        );
    }

    if config.monitoring.enabled
        && !config.monitoring.no_monitor
        && !config.monitoring.has_webhooks()
    {
        fatal("You must provide a webhook to use the monitoring API.");
    }

    if !config.input.no_discover {
        session
            .subdomains
            .extend(discovery::search(config, &session.target));
    }
    if !config.input.import_from.is_empty() {
        import_subdomains(config, session);
    }
    if config.input.permutations {
        add_permutations(config, session);
    }

    if session.subdomains.is_empty() {
        if !config.general.quiet {
            eprintln!(
                "\nNo subdomains were found for the target: {} ¡😭!\n",
                session.target
            );
        }
    } else {
        works_with_data(config, session)?;
    }

    if !config.monitoring.uses_database() {
        pause_between_targets(config, session.is_last_target, false);
    }
    session.subdomains.clear();

    Ok(())
}

/// Merges the subdomains listed in the `--import-subdomains` files.
fn import_subdomains(config: &Config, session: &mut Session) {
    let base_target = session.base_target();
    let imported = files::read_lines(
        &config.input.import_from,
        LineKind::Subdomain,
        config.general.quiet,
    );

    session.subdomains.extend(
        imported
            .into_iter()
            .map(|subdomain| subdomain.to_lowercase())
            .filter(|subdomain| {
                validate_target(subdomain)
                    && validate_subdomain(&base_target, &session.target, subdomain, &config.filters)
            }),
    );
}

/// Adds guessed hostnames derived from the ones already found.
///
/// Permutations are only useful when the run resolves them; printing unproven
/// guesses would bury the real results.
fn add_permutations(config: &Config, session: &mut Session) {
    if !config.needs_network_checks() {
        if !config.general.quiet {
            eprintln!(
                "Permutations need a resolution mode: use -r/--resolved, -i/--ip, --ipv6-only, --http-status or --pscan."
            );
        }
        return;
    }

    if !config.general.quiet {
        // The count grows as subdomains times words times six, which neither
        // flag hints at, so it is worth saying before the wait starts.
        println!(
            "Permuting {} subdomains against {} words for {}, about {} candidates...",
            session.subdomains.len(),
            config.input.permutation_words.len(),
            session.target,
            permutations::projected(
                session.subdomains.len(),
                config.input.permutation_words.len()
            ),
        );
    }

    let generated = permutations::generate(
        &session.subdomains,
        &session.target,
        &config.input.permutation_words,
    );
    if !config.general.quiet {
        println!(
            "Permutations generated {} candidate subdomains for {}.",
            generated.len(),
            session.target
        );
    }
    session.subdomains.extend(generated);
}

/// Prints what the database already knows and exits.
fn report_stored_subdomains(config: &Config, session: &mut Session) -> Result<()> {
    if !config.general.quiet {
        if config.database.query_by_jobname {
            println!(
                "Searching subdomains in the Findomain database for the job name {} 🔍",
                config.database.jobname
            );
        } else {
            println!(
                "Searching subdomains in the Findomain database for the target {} 🔍",
                session.target
            );
        }
    }

    session.subdomains = database::stored_subdomains(config, &session.target)?;
    works_with_data(config, session)?;
    std::process::exit(0)
}

/// Routes the collected subdomains to the reporting or the monitoring path.
///
/// # Errors
///
/// Fails when results cannot be written or the monitoring stage fails.
pub fn works_with_data(config: &Config, session: &mut Session) -> Result<()> {
    let monitoring = config.monitoring.uses_database();
    let from_list = config.input.from_target_list();

    // A shared `--unique-output` is rotated once before the target loop, and
    // monitoring appends across runs; rotating here would discard both.
    let rotate_output = if config.output.unique {
        !from_list
    } else {
        !monitoring
    };
    if rotate_output {
        files::backup_existing(&session.file_name)?;
    }

    if monitoring {
        alerts::subdomains_alerts(config, session)?;
    } else {
        manage_subdomains_data(config, session)?;
    }

    if config.output.enabled && !config.general.quiet && !monitoring {
        output::show_file_location(&session.target, &session.file_name);
    }
    if !config.general.quiet {
        println!("\nGood luck Hax0r 💀!\n");
    }

    Ok(())
}

/// Reports the collected subdomains, running the network checks if requested.
///
/// # Errors
///
/// Fails when results cannot be written.
pub fn manage_subdomains_data(config: &Config, session: &mut Session) -> Result<()> {
    let output_file = files::open_output_file(&session.file_name, config.output.enabled)?;

    if !config.general.quiet {
        println!();
    }

    if wildcard_detection_applies(config) {
        session.wildcard_ips = resolve::detect_wildcards(config, &session.target);
    }

    if config.needs_network_checks() {
        let resolv_data = resolve::resolve_all(config, session, output_file.as_ref())?;
        report_findings(&tools::scan_live_hosts(config, &resolv_data));
    } else {
        let mut sink = output::Sink::new(output_file.as_ref());
        for subdomain in &session.subdomains {
            sink.write_line(subdomain)?;
        }
        sink.flush()?;
    }

    if !config.general.quiet {
        println!("\nJob finished in {} seconds.", session.elapsed_secs());
    }
    session.restart_clock();

    Ok(())
}

/// Waits out the configured rate limit before moving on to the next target.
///
/// Only meaningful while walking a list, and skipped after the last target.
pub fn pause_between_targets(config: &Config, is_last_target: bool, leading_blank_line: bool) {
    if config.general.quiet
        || config.general.rate_limit == 0
        || !config.input.from_target_list()
        || is_last_target
    {
        return;
    }

    let prefix = if leading_blank_line { "\n" } else { "" };
    println!(
        "{prefix}Rate limit set to {} seconds, waiting to start next enumeration.",
        config.general.rate_limit
    );
    thread::sleep(Duration::from_secs(config.general.rate_limit));
}

/// Prints what the optional scanners found, if anything.
pub fn report_findings(findings: &tools::Findings) {
    for vulnerability in &findings.vulnerabilities {
        println!("{vulnerability}");
    }
    for path in &findings.paths {
        println!("{path}");
    }
}

/// Wildcards only matter when addresses decide what gets reported.
fn wildcard_detection_applies(config: &Config) -> bool {
    (config.resolution.only_resolved || config.resolution.with_ip || config.resolution.ipv6_only)
        && config.resolution.wildcard_check
        && !config.input.as_resolver
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_file_names_follow_the_output_flags() {
        let mut config = Config::default();
        assert_eq!(target_file_name(&config, "example.com"), "example.com.txt");

        config.resolution.with_ip = true;
        assert_eq!(
            target_file_name(&config, "example.com"),
            "example.com-ip.txt"
        );

        config.output.file_name = "all.txt".to_owned();
        assert_eq!(target_file_name(&config, "example.com"), "all.txt");
    }

    #[test]
    fn wildcard_detection_needs_an_address_based_mode() {
        let mut config = Config::default();
        assert!(!wildcard_detection_applies(&config));

        config.resolution.with_ip = true;
        assert!(wildcard_detection_applies(&config));

        config.resolution.wildcard_check = false;
        assert!(!wildcard_detection_applies(&config));

        config.resolution.wildcard_check = true;
        config.input.as_resolver = true;
        assert!(!wildcard_detection_applies(&config));
    }
}
