//! Monitoring mode: diff against the database and alert on what is new.

use {
    crate::{
        config::Config,
        database, email,
        errors::Result,
        files,
        output::{eval_http, null_ip_checker, ports_string},
        resolve::{self, ResolvData},
        runner,
        session::Session,
        tools,
        utils::random_from,
        webhooks::{self, Message},
    },
    reqwest::{blocking::Client, header::USER_AGENT, StatusCode},
    std::{
        collections::{HashMap, HashSet},
        net::IpAddr,
        time::Duration,
    },
};

const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(30);

/// Statuses that mean the webhook took too long rather than that the data was
/// rejected, so `--mtimeout` can still commit the results.
///
/// 408 and 504 are the standard ones; 598 is a proxy convention that never made
/// it into a spec, 524 is Cloudflare and 460 is an AWS load balancer. The chat
/// services this posts to sit behind exactly those two.
const TIMEOUT_STATUSES: [u16; 5] = [408, 504, 598, 524, 460];

/// Resolves the subdomains not seen before and alerts or stores them.
///
/// # Errors
///
/// Fails when the database is unreachable or a webhook cannot be posted to.
pub fn subdomains_alerts(config: &Config, session: &mut Session) -> Result<()> {
    let existing = database::existing_subdomains(config, &session.target)?;
    session.subdomains = session.subdomains.difference(&existing).cloned().collect();

    let output_file = files::open_output_file(&session.file_name, config.output.enabled)?;
    let resolv_data = resolve::resolve_all(config, session, output_file.as_ref())?;
    let new_subdomains = summarize(config, &resolv_data);

    let findings = tools::scan_live_hosts(config, &resolv_data);
    runner::report_findings(&findings);

    if config.output.enabled && !new_subdomains.is_empty() {
        write_new_subdomains(config, session, &new_subdomains)?;
    }

    let monitoring = &config.monitoring;
    let store_silently = monitoring.no_monitor && !monitoring.enabled;
    let nothing_new =
        new_subdomains.is_empty() && !resolv_data.is_empty() && !monitoring.push_when_empty;

    if store_silently || nothing_new {
        database::commit(config, &session.target, &resolv_data)?;
    } else if monitoring.push_when_empty || !new_subdomains.is_empty() {
        push_to_webhooks(config, session, &new_subdomains, &resolv_data)?;
    }

    // Last and never fatal: the results are already persisted and pushed.
    email_report(config, session, &new_subdomains, findings);

    runner::pause_between_targets(config, session.is_last_target, true);
    Ok(())
}

/// Emails the run's findings, when SMTP was configured.
///
/// Failures are logged rather than propagated: a notification that could not
/// be sent must not undo results that are already stored.
fn email_report(
    config: &Config,
    session: &Session,
    new_subdomains: &HashSet<String>,
    findings: tools::Findings,
) {
    if !config.email.is_configured() {
        return;
    }

    let mut subdomains: Vec<String> = new_subdomains.iter().cloned().collect();
    subdomains.sort_unstable();

    let report = email::Report {
        new_subdomains: subdomains,
        vulnerabilities: findings.vulnerabilities,
        paths: findings.paths,
    };
    if let Err(e) = email::send(config, &session.target, &report) {
        eprintln!("Could not email the report for {}: {e}", session.target);
    }
}

/// Renders one summary line per resolved subdomain.
///
/// When any check ran, hosts without a usable address are left out; with no
/// checks at all every host is reported with placeholder values. The address
/// is parsed as either family, because `--ipv6-only` stores an IPv6 one.
fn summarize(config: &Config, resolv_data: &HashMap<String, ResolvData>) -> HashSet<String> {
    let checked = config.needs_network_checks();

    resolv_data
        .iter()
        .filter(|(_, data)| !checked || data.ip.parse::<IpAddr>().is_ok())
        .map(|(subdomain, data)| {
            format!(
                "HOST: {subdomain},IP: {},HTTP/S: {},OPEN PORTS: {}",
                null_ip_checker(&data.ip),
                eval_http(&data.http_data),
                ports_string(&data.open_ports, config.ports.enabled),
            )
        })
        .collect()
}

/// Writes the new subdomains to their own file next to the main output.
fn write_new_subdomains(
    config: &Config,
    session: &Session,
    new_subdomains: &HashSet<String>,
) -> Result<()> {
    let file_name = files::derived_name(&session.file_name, "new_subdomains.txt");
    files::backup_existing(&file_name)?;

    let file = files::open_output_file(&file_name, true)?;
    for subdomain in new_subdomains {
        files::write_line(subdomain, file.as_ref())?;
    }

    if !config.general.quiet {
        println!(
            ">> 📁 Subdomains for {} were saved in: ./{file_name} 😀",
            session.target
        );
    }
    Ok(())
}

/// Posts every alert and stores the results once the first one goes through.
fn push_to_webhooks(
    config: &Config,
    session: &Session,
    new_subdomains: &HashSet<String>,
    resolv_data: &HashMap<String, ResolvData>,
) -> Result<()> {
    let client = Client::builder()
        .timeout(WEBHOOK_TIMEOUT)
        .build()
        .expect("build the webhook HTTP client");
    let mut stored = false;

    for message in webhooks::messages(config, new_subdomains, &session.target) {
        if !post(config, &client, &message)? {
            continue;
        }
        if !stored && !new_subdomains.is_empty() {
            stored = database::commit(config, &session.target, resolv_data).is_ok();
        }
    }

    Ok(())
}

/// Posts a single alert, reporting whether the service accepted it.
///
/// # Errors
///
/// Fails when the request itself could not be made.
fn post(config: &Config, client: &Client, message: &Message) -> Result<bool> {
    let response = client
        .post(&message.url)
        .header(USER_AGENT, random_from(&config.http.user_agents))
        .json(&message.body)
        .send()?;

    if accepted(response.status(), config.monitoring.push_on_timeout) {
        return Ok(true);
    }

    eprintln!(
        "\nAn error occurred when Findomain tried to publish the data to the following webhook {}. \nError description: {}",
        message.url,
        response.status()
    );
    Ok(false)
}

/// Reports whether `status` means the alert can be considered delivered.
fn accepted(status: StatusCode, push_on_timeout: bool) -> bool {
    status == StatusCode::OK
        || status == StatusCode::NO_CONTENT
        || (push_on_timeout && TIMEOUT_STATUSES.contains(&status.as_u16()))
}

#[cfg(test)]
mod tests {
    use {super::*, fhc::structs::HttpData};

    fn data(ip: &str, http_status: &str, ports: &[i32]) -> ResolvData {
        ResolvData {
            ip: ip.to_owned(),
            http_data: HttpData {
                http_status: http_status.to_owned(),
                ..HttpData::default()
            },
            open_ports: ports.to_vec(),
            ..ResolvData::default()
        }
    }

    #[test]
    fn accepted_covers_success_and_opt_in_timeouts() {
        assert!(accepted(StatusCode::OK, false));
        assert!(accepted(StatusCode::NO_CONTENT, false));
        assert!(!accepted(StatusCode::REQUEST_TIMEOUT, false));
        assert!(accepted(StatusCode::REQUEST_TIMEOUT, true));
        assert!(accepted(StatusCode::GATEWAY_TIMEOUT, true));
        assert!(!accepted(StatusCode::INTERNAL_SERVER_ERROR, true));
        assert!(!accepted(StatusCode::FORBIDDEN, true));
    }

    #[test]
    fn summarize_drops_unresolved_hosts_when_checks_ran() {
        let mut config = Config::default();
        config.resolution.discover_ip = true;

        let resolv_data = HashMap::from([
            ("a.example.com".to_owned(), data("1.2.3.4", "ACTIVE", &[80])),
            ("b.example.com".to_owned(), data("", "INACTIVE", &[])),
        ]);

        let summary = summarize(&config, &resolv_data);
        assert_eq!(
            summary.into_iter().collect::<Vec<_>>(),
            ["HOST: a.example.com,IP: 1.2.3.4,HTTP/S: ACTIVE,OPEN PORTS: [80]"]
        );
    }

    #[test]
    fn summarize_keeps_ipv6_hosts() {
        // --ipv6-only stores an IPv6 address; filtering on IPv4 alone would
        // leave the monitoring report empty on every run.
        let mut config = Config::default();
        config.resolution.discover_ip = true;
        config.resolution.ipv6_only = true;

        let resolv_data = HashMap::from([(
            "a.example.com".to_owned(),
            data("2606:4700::6810:2ca3", "ACTIVE", &[]),
        )]);

        let summary = summarize(&config, &resolv_data);
        assert_eq!(summary.len(), 1);
        assert!(summary
            .into_iter()
            .next()
            .is_some_and(|line| line.contains("IP: 2606:4700::6810:2ca3")));
    }

    #[test]
    fn summarize_keeps_every_host_when_nothing_was_checked() {
        let config = Config::default();
        let resolv_data = HashMap::from([
            ("a.example.com".to_owned(), data("", "NOT CHECKED", &[])),
            ("b.example.com".to_owned(), data("", "NOT CHECKED", &[])),
        ]);

        let summary = summarize(&config, &resolv_data);
        assert_eq!(summary.len(), 2);
        assert!(summary.iter().all(|line| line.contains("IP: NULL")));
    }

    #[test]
    fn summarize_reports_open_ports_when_scanning() {
        let mut config = Config::default();
        config.resolution.discover_ip = true;
        config.ports.enabled = true;

        let resolv_data = HashMap::from([(
            "a.example.com".to_owned(),
            data("1.2.3.4", "NOT CHECKED", &[80, 443]),
        )]);

        let summary = summarize(&config, &resolv_data);
        assert!(summary
            .iter()
            .next()
            .unwrap()
            .ends_with("OPEN PORTS: [80, 443]"));
    }
}
