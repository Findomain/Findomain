//! Formatting and emission of results.

use {
    crate::{config::Config, errors::Result, resolve::ResolvData},
    fhc::structs::HttpData,
    std::{
        collections::HashSet,
        fs::File,
        io::{BufWriter, Stdout, Write},
    },
};

/// Bytes buffered before a write reaches the terminal or the output file.
const WRITE_BUFFER: usize = 64 * 1024;

/// Placeholder written when a stage did not run.
pub const NOT_CHECKED: &str = "NOT CHECKED";
/// Placeholder written when a stage ran and found nothing.
pub const NULL: &str = "NULL";
/// Value fhc reports for a host answering HTTP requests.
pub const ACTIVE: &str = "ACTIVE";
/// Value written for a host that did not answer.
pub const INACTIVE: &str = "INACTIVE";

/// Renders the IP for the database, which distinguishes "no IP" from "unknown".
#[must_use]
pub fn null_ip_checker(ip: &str) -> String {
    if ip.is_empty() {
        NULL.to_owned()
    } else {
        ip.to_owned()
    }
}

/// Renders the open ports, distinguishing "none found" from "not scanned".
#[must_use]
pub fn ports_string(ports: &[i32], port_scan_enabled: bool) -> String {
    if !ports.is_empty() {
        return format!("{ports:?}");
    }
    if port_scan_enabled {
        NULL.to_owned()
    } else {
        NOT_CHECKED.to_owned()
    }
}

/// Renders the HTTP result: the final URL when there is one, else the status.
#[must_use]
pub fn eval_http(http_data: &HttpData) -> &str {
    if http_data.final_url.is_empty() {
        &http_data.http_status
    } else {
        &http_data.final_url
    }
}

/// Buffered destination for result lines.
///
/// Results arrive one host at a time and there can be hundreds of thousands of
/// them, so both the terminal and the output file are written through a buffer
/// rather than paying a lock and a syscall per line.
pub struct Sink<'a> {
    stdout: BufWriter<Stdout>,
    file: Option<BufWriter<&'a File>>,
}

impl<'a> Sink<'a> {
    #[must_use]
    pub fn new(file: Option<&'a File>) -> Self {
        Self {
            stdout: BufWriter::with_capacity(WRITE_BUFFER, std::io::stdout()),
            file: file.map(|file| BufWriter::with_capacity(WRITE_BUFFER, file)),
        }
    }

    /// Writes `line` and a newline to every configured destination.
    ///
    /// # Errors
    ///
    /// Fails when a destination cannot be written to.
    pub fn write_line(&mut self, line: &str) -> Result<()> {
        self.stdout.write_all(line.as_bytes())?;
        self.stdout.write_all(b"\n")?;
        if let Some(file) = &mut self.file {
            file.write_all(line.as_bytes())?;
            file.write_all(b"\n")?;
        }
        Ok(())
    }

    /// Pushes everything still buffered to its destination.
    ///
    /// # Errors
    ///
    /// Fails when a destination cannot be written to.
    pub fn flush(&mut self) -> Result<()> {
        self.stdout.flush()?;
        if let Some(file) = &mut self.file {
            file.flush()?;
        }
        Ok(())
    }
}

impl Drop for Sink<'_> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

pub fn show_file_location(target: &str, file_name: &str) {
    println!(">> 📁 Subdomains for {target} were saved in: ./{file_name} 😀");
}

/// Renders the trailing CNAME column, empty unless `--cname` was given.
fn cname_suffix(config: &Config, data: &ResolvData) -> String {
    if !config.resolution.track_cname {
        return String::new();
    }
    if data.cname.is_empty() {
        format!(",{NULL}")
    } else {
        format!(",{}", data.cname)
    }
}

/// Builds the result line for `subdomain`, or `None` when it must be hidden.
///
/// The shape of the line is decided by which checks were requested; a host is
/// dropped when the check that gates it produced nothing usable, for instance
/// an unresolved name in IP mode or a wildcard address.
#[must_use]
pub fn result_line(
    config: &Config,
    wildcard_ips: &HashSet<String>,
    subdomain: &str,
    data: &ResolvData,
) -> Option<String> {
    let ip = &data.ip;
    let has_usable_ip =
        !ip.is_empty() && (!config.resolution.wildcard_check || !wildcard_ips.contains(ip));
    let http = eval_http(&data.http_data);
    let http_is_active = data.http_data.http_status == ACTIVE;
    // Only the port-scanning arms read this, and without a scan it is always
    // the same placeholder, so the common path does not pay for it.
    let ports = if config.ports.enabled {
        ports_string(&data.open_ports, true)
    } else {
        String::new()
    };
    let cname = cname_suffix(config, data);

    match (
        config.resolution.discover_ip,
        config.http.enabled,
        config.ports.enabled,
    ) {
        (true, true, true) => {
            has_usable_ip.then(|| format!("{subdomain},{ip},{http},{ports}{cname}"))
        }
        (true, true, false) => has_usable_ip.then(|| format!("{subdomain},{ip},{http}{cname}")),
        (true, false, true) => has_usable_ip.then(|| format!("{subdomain},{ip},{ports}{cname}")),
        (true, false, false) => has_usable_ip.then(|| {
            if config.resolution.only_resolved {
                format!("{subdomain}{cname}")
            } else {
                format!("{subdomain},{ip}{cname}")
            }
        }),
        (false, true, true) => http_is_active.then(|| format!("{subdomain},{http},{ports}{cname}")),
        (false, true, false) => http_is_active.then(|| http.to_owned()),
        (false, false, true) => {
            (!data.open_ports.is_empty()).then(|| format!("{subdomain},{ports}{cname}"))
        }
        // Nothing was checked: only monitoring mode still echoes the host.
        (false, false, false) => (config.monitoring.uses_database() && !config.general.quiet)
            .then(|| subdomain.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolv_data(ip: &str, http_status: &str, final_url: &str, ports: &[i32]) -> ResolvData {
        ResolvData {
            ip: ip.to_owned(),
            http_data: HttpData {
                http_status: http_status.to_owned(),
                final_url: final_url.to_owned(),
                ..HttpData::default()
            },
            open_ports: ports.to_vec(),
            ..ResolvData::default()
        }
    }

    fn config(discover_ip: bool, http: bool, ports: bool) -> Config {
        let mut config = Config::default();
        config.resolution.discover_ip = discover_ip;
        config.http.enabled = http;
        config.ports.enabled = ports;
        config
    }

    fn line(config: &Config, data: &ResolvData) -> Option<String> {
        result_line(config, &HashSet::new(), "a.example.com", data)
    }

    #[test]
    fn null_ip_checker_marks_the_absence_of_an_address() {
        assert_eq!(null_ip_checker(""), "NULL");
        assert_eq!(null_ip_checker("1.2.3.4"), "1.2.3.4");
    }

    #[test]
    fn ports_string_separates_empty_from_unscanned() {
        assert_eq!(ports_string(&[], false), "NOT CHECKED");
        assert_eq!(ports_string(&[], true), "NULL");
        assert_eq!(ports_string(&[80, 443], true), "[80, 443]");
    }

    #[test]
    fn a_run_without_a_port_scan_never_shows_a_port_column() {
        // The placeholder is only meaningful to the arms that scan, so the
        // formatter skips building it entirely when no scan ran.
        let mut config = Config::default();
        config.resolution.discover_ip = true;
        let data = ResolvData {
            ip: "1.2.3.4".to_owned(),
            ..ResolvData::default()
        };
        let line = result_line(&config, &HashSet::new(), "a.example.com", &data)
            .expect("a resolved host is reported");
        assert_eq!(line, "a.example.com,1.2.3.4");
        assert!(!line.contains("NOT CHECKED"));
    }

    #[test]
    fn eval_http_prefers_the_final_url() {
        let mut data = HttpData {
            http_status: "ACTIVE".to_owned(),
            ..HttpData::default()
        };
        assert_eq!(eval_http(&data), "ACTIVE");
        data.final_url = "https://a.example.com".to_owned();
        assert_eq!(eval_http(&data), "https://a.example.com");
    }

    #[test]
    fn ip_mode_prints_the_address() {
        let config = config(true, false, false);
        let data = resolv_data("1.2.3.4", NOT_CHECKED, "", &[]);
        assert_eq!(
            line(&config, &data).as_deref(),
            Some("a.example.com,1.2.3.4")
        );
    }

    #[test]
    fn resolved_mode_prints_only_the_host() {
        let mut config = config(true, false, false);
        config.resolution.only_resolved = true;
        let data = resolv_data("1.2.3.4", NOT_CHECKED, "", &[]);
        assert_eq!(line(&config, &data).as_deref(), Some("a.example.com"));
    }

    #[test]
    fn hosts_without_an_ip_are_dropped_in_ip_mode() {
        let config = config(true, false, false);
        assert!(line(&config, &resolv_data("", NOT_CHECKED, "", &[])).is_none());
    }

    #[test]
    fn wildcard_addresses_are_dropped_unless_the_check_is_disabled() {
        let config = config(true, false, false);
        let data = resolv_data("1.2.3.4", NOT_CHECKED, "", &[]);
        let wildcards = HashSet::from(["1.2.3.4".to_owned()]);

        assert!(result_line(&config, &wildcards, "a.example.com", &data).is_none());

        let mut allowed = config;
        allowed.resolution.wildcard_check = false;
        assert_eq!(
            result_line(&allowed, &wildcards, "a.example.com", &data).as_deref(),
            Some("a.example.com,1.2.3.4")
        );
    }

    #[test]
    fn every_check_combination_has_its_own_shape() {
        let full = resolv_data("1.2.3.4", ACTIVE, "https://a.example.com", &[80]);

        assert_eq!(
            line(&config(true, true, true), &full).as_deref(),
            Some("a.example.com,1.2.3.4,https://a.example.com,[80]")
        );
        assert_eq!(
            line(&config(true, true, false), &full).as_deref(),
            Some("a.example.com,1.2.3.4,https://a.example.com")
        );
        assert_eq!(
            line(&config(true, false, true), &full).as_deref(),
            Some("a.example.com,1.2.3.4,[80]")
        );
        assert_eq!(
            line(&config(false, true, true), &full).as_deref(),
            Some("a.example.com,https://a.example.com,[80]")
        );
        // HTTP only reports the URL, which already carries the hostname.
        assert_eq!(
            line(&config(false, true, false), &full).as_deref(),
            Some("https://a.example.com")
        );
        assert_eq!(
            line(&config(false, false, true), &full).as_deref(),
            Some("a.example.com,[80]")
        );
    }

    #[test]
    fn inactive_hosts_are_dropped_in_http_mode() {
        let inactive = resolv_data("1.2.3.4", INACTIVE, "", &[80]);
        assert!(line(&config(false, true, false), &inactive).is_none());
        assert!(line(&config(false, true, true), &inactive).is_none());
    }

    #[test]
    fn port_only_mode_hides_hosts_without_open_ports() {
        let config = config(false, false, true);
        assert!(line(&config, &resolv_data("1.2.3.4", NOT_CHECKED, "", &[])).is_none());
    }

    #[test]
    fn with_no_checks_only_monitoring_echoes_the_host() {
        let data = resolv_data("", NOT_CHECKED, "", &[]);

        let plain = config(false, false, false);
        assert!(line(&plain, &data).is_none());

        let mut monitoring = config(false, false, false);
        monitoring.monitoring.enabled = true;
        assert_eq!(line(&monitoring, &data).as_deref(), Some("a.example.com"));

        monitoring.general.quiet = true;
        assert!(line(&monitoring, &data).is_none());
    }
}
