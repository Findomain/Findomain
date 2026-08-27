//! Port scanning delegated to nmap.
//!
//! nmap replaces the connect scanner Findomain used to carry: it already knows
//! about timing, retransmission and service detection, and its results are the
//! ones people expect to compare against.
//!
//! The scan runs unprivileged by default (`-sT`), because requiring root just
//! to list open ports is a bad trade. `--nmap-syn` opts into `-sS` for users
//! who do run as root.

use {
    super::{run, ToolError},
    crate::config::Config,
    serde::Deserialize,
    std::{
        collections::{HashMap, HashSet},
        net::Ipv6Addr,
    },
};

/// Scripts run when a thorough scan was asked for.
///
/// Everything here reports banners, headers or exposed metadata; nothing in
/// the list changes state on the target.
const SERVICE_SCRIPTS: [&str; 12] = [
    "banner",
    "http-headers",
    "http-cors",
    "http-cross-domain-policy",
    "http-vhosts",
    "http-git",
    "http-php-version",
    "http-apache-server-status",
    "http-webdav-scan",
    "http-aspnet-debug",
    "http-bigip-cookie",
    "ftp-anon",
];

/// One open port, with whatever nmap could tell about the service on it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenPort {
    pub port: i32,
    pub protocol: String,
    pub service: String,
    pub product: String,
}

#[derive(Debug, Default, Deserialize)]
struct NmapRun {
    #[serde(default, rename = "host")]
    hosts: Vec<XmlHost>,
    #[serde(default)]
    runstats: Option<XmlRunStats>,
}

#[derive(Debug, Default, Deserialize)]
struct XmlRunStats {
    #[serde(default)]
    finished: Option<XmlFinished>,
}

#[derive(Debug, Default, Deserialize)]
struct XmlFinished {
    #[serde(default, rename = "@exit")]
    exit: String,
    #[serde(default, rename = "@errormsg")]
    errormsg: String,
}

#[derive(Debug, Default, Deserialize)]
struct XmlHost {
    #[serde(default, rename = "address")]
    addresses: Vec<XmlAddress>,
    #[serde(default)]
    ports: Option<XmlPorts>,
}

#[derive(Debug, Default, Deserialize)]
struct XmlAddress {
    #[serde(default, rename = "@addr")]
    addr: String,
    #[serde(default, rename = "@addrtype")]
    addrtype: String,
}

#[derive(Debug, Default, Deserialize)]
struct XmlPorts {
    #[serde(default, rename = "port")]
    ports: Vec<XmlPort>,
}

#[derive(Debug, Default, Deserialize)]
struct XmlPort {
    #[serde(default, rename = "@portid")]
    portid: String,
    #[serde(default, rename = "@protocol")]
    protocol: String,
    #[serde(default)]
    state: XmlState,
    #[serde(default)]
    service: Option<XmlService>,
}

#[derive(Debug, Default, Deserialize)]
struct XmlState {
    #[serde(default, rename = "@state")]
    state: String,
}

#[derive(Debug, Default, Deserialize)]
struct XmlService {
    #[serde(default, rename = "@name")]
    name: String,
    #[serde(default, rename = "@product")]
    product: String,
}

/// Scans `ips` and returns the open ports found on each.
///
/// # Errors
///
/// Fails when nmap is missing, cannot be executed, or produced output that is
/// not the XML report it was asked for.
pub fn scan(
    config: &Config,
    ips: &HashSet<String>,
) -> Result<HashMap<String, Vec<OpenPort>>, ToolError> {
    if ips.is_empty() {
        return Ok(HashMap::new());
    }

    let report = run("nmap", &arguments(config, ips), config.ports.scan_timeout)?;
    parse(&report)
}

/// Builds the nmap command line.
fn arguments(config: &Config, ips: &HashSet<String>) -> Vec<String> {
    let ports = &config.ports;
    let mut args: Vec<String> = vec![
        // Hosts reached this far already resolved.
        "-Pn".into(),
        "-n".into(),
        "--open".into(),
        "-T4".into(),
        "--max-retries".into(),
        "2".into(),
        if ports.syn_scan { "-sS" } else { "-sT" }.into(),
    ];

    // A run resolves one family, so the batch shares it; nmap refuses IPv6
    // targets without being told.
    if ips.iter().any(|ip| ip.parse::<Ipv6Addr>().is_ok()) {
        args.push("-6".into());
    }

    if let Some(range) = &ports.range {
        args.push("-p".into());
        args.push(format!("{}-{}", range.start(), range.end()));
    } else {
        args.push("--top-ports".into());
        args.push("1000".into());
    }

    if ports.min_rate > 0 {
        args.push("--min-rate".into());
        args.push(ports.min_rate.to_string());
    }

    if !ports.fast_scan {
        args.push("-sV".into());
        args.push("--script".into());
        args.push(SERVICE_SCRIPTS.join(","));
        args.push("--script-timeout".into());
        args.push("2m".into());
    }

    args.push("--host-timeout".into());
    args.push(format!("{}s", ports.host_timeout));

    args.extend(ports.extra_args.iter().cloned());
    // Last: nmap lets the final output flag win, so the report cannot be
    // redirected away from the pipe this parses.
    args.extend(["-oX".into(), "-".into()]);

    args.extend(ips.iter().cloned());
    args
}

/// Turns an nmap XML report into the open ports of each scanned address.
///
/// nmap reports a rejected command line inside a well formed report and still
/// exits zero, so the run status has to be read out of the XML; otherwise a
/// bad port range looks exactly like a host with nothing open.
fn parse(report: &str) -> Result<HashMap<String, Vec<OpenPort>>, ToolError> {
    let run: NmapRun = quick_xml::de::from_str(report)
        .map_err(|e| ToolError::Output("nmap".into(), e.to_string()))?;

    if let Some(finished) = run
        .runstats
        .as_ref()
        .and_then(|stats| stats.finished.as_ref())
    {
        if finished.exit == "error" {
            let reason = if finished.errormsg.is_empty() {
                "nmap reported an error".to_owned()
            } else {
                finished.errormsg.clone()
            };
            return Err(ToolError::Failed("nmap".into(), reason));
        }
    }

    let mut by_address = HashMap::new();
    for host in run.hosts {
        let Some(address) = host
            .addresses
            .iter()
            .find(|address| address.addrtype.starts_with("ipv"))
            .map(|address| address.addr.clone())
        else {
            continue;
        };

        let mut open: Vec<OpenPort> = host
            .ports
            .into_iter()
            .flat_map(|ports| ports.ports)
            .filter(|port| port.state.state == "open")
            .filter_map(|port| {
                let service = port.service.unwrap_or_default();
                Some(OpenPort {
                    port: port.portid.parse().ok()?,
                    protocol: port.protocol,
                    service: service.name,
                    product: service.product,
                })
            })
            .collect();
        open.sort_by_key(|port| port.port);

        if !address.is_empty() {
            by_address.insert(address, open);
        }
    }
    Ok(by_address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extra_arguments_reach_nmap_but_never_displace_the_report() {
        let config = Config {
            ports: crate::config::PortScan {
                extra_args: vec!["-sU".to_owned(), "-oX".to_owned(), "/tmp/stolen".to_owned()],
                ..crate::config::PortScan::default()
            },
            ..Config::default()
        };
        let args = arguments(&config, &HashSet::from(["1.2.3.4".to_owned()]));

        assert!(args.iter().any(|arg| arg == "-sU"), "user flags are passed");
        // nmap keeps the last output flag, so ours has to come after theirs.
        let ours = args
            .iter()
            .rposition(|arg| arg == "-oX")
            .expect("-oX is set");
        assert_eq!(args[ours + 1], "-");
        assert!(
            args.iter().position(|arg| arg == "/tmp/stolen").unwrap() < ours,
            "the report cannot be redirected away from the pipe: {args:?}"
        );
    }

    #[test]
    fn ipv6_targets_are_announced_to_nmap() {
        // nmap refuses IPv6 targets unless it is told, and would otherwise
        // report no open ports at all rather than an error.
        let config = Config::default();
        let v6 = arguments(&config, &HashSet::from(["2606:4700::1111".to_owned()]));
        assert!(v6.iter().any(|arg| arg == "-6"));
        assert!(v6.iter().any(|arg| arg == "2606:4700::1111"));

        let v4 = arguments(&config, &HashSet::from(["1.2.3.4".to_owned()]));
        assert!(!v4.iter().any(|arg| arg == "-6"));
    }

    const REPORT: &str = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="closed"/>
        <service name="http-proxy"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="5.6.7.8" addrtype="ipv4"/>
  </host>
</nmaprun>"#;

    fn config_with(range: Option<std::ops::RangeInclusive<u16>>, fast: bool) -> Config {
        let mut config = Config::default();
        config.ports.range = range;
        config.ports.fast_scan = fast;
        config
    }

    #[test]
    fn open_ports_are_read_and_sorted() {
        let parsed = parse(REPORT).expect("valid report");
        let ports = parsed.get("1.2.3.4").expect("the scanned host");

        assert_eq!(ports.len(), 2, "closed ports must be dropped");
        assert_eq!(ports[0].port, 80);
        assert_eq!(ports[1].port, 443);
        assert_eq!(ports[1].service, "https");
        assert_eq!(ports[1].product, "nginx");
        assert_eq!(ports[1].protocol, "tcp");
    }

    #[test]
    fn a_host_without_open_ports_is_still_reported() {
        let parsed = parse(REPORT).expect("valid report");
        assert_eq!(parsed.get("5.6.7.8").map(Vec::len), Some(0));
    }

    #[test]
    fn a_rejected_command_line_is_surfaced_not_swallowed() {
        // nmap answers a bad port range with a well formed report, exit code
        // zero, and the reason buried in runstats. Reporting "no open ports"
        // here would quietly hide a user error.
        let report = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <runstats>
    <finished exit="error" errormsg="Your port range 900-100 is backwards. Did you mean 100-900?"/>
    <hosts up="0" down="0" total="0"/>
  </runstats>
</nmaprun>"#;

        let error = parse(report).expect_err("an error report must not parse as success");
        assert!(
            error.to_string().contains("backwards"),
            "nmap's own explanation must reach the user: {error}"
        );
    }

    #[test]
    fn a_successful_report_with_runstats_still_parses() {
        let report = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>
  </host>
  <runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>"#;

        let parsed = parse(report).expect("a successful report");
        assert_eq!(parsed["1.2.3.4"].len(), 1);
    }

    #[test]
    fn an_empty_report_yields_nothing() {
        let parsed = parse(r#"<?xml version="1.0"?><nmaprun scanner="nmap"></nmaprun>"#)
            .expect("valid report");
        assert!(parsed.is_empty());
    }

    #[test]
    fn malformed_xml_is_an_error_not_a_panic() {
        assert!(parse("not xml at all").is_err());
    }

    #[test]
    fn the_default_scan_asks_for_the_top_ports() {
        let args = arguments(
            &config_with(None, true),
            &HashSet::from(["1.2.3.4".to_owned()]),
        );
        assert!(args.windows(2).any(|w| w == ["--top-ports", "1000"]));
        assert!(!args.iter().any(|a| a == "-p"));
    }

    #[test]
    fn an_explicit_range_is_passed_through() {
        let args = arguments(
            &config_with(Some(80..=443), true),
            &HashSet::from(["1.2.3.4".to_owned()]),
        );
        assert!(args.windows(2).any(|w| w == ["-p", "80-443"]));
    }

    #[test]
    fn a_fast_scan_skips_service_detection() {
        let fast = arguments(
            &config_with(None, true),
            &HashSet::from(["1.2.3.4".to_owned()]),
        );
        assert!(!fast.iter().any(|a| a == "-sV"));
        assert!(!fast.iter().any(|a| a == "--script"));

        let thorough = arguments(
            &config_with(None, false),
            &HashSet::from(["1.2.3.4".to_owned()]),
        );
        assert!(thorough.iter().any(|a| a == "-sV"));
        assert!(thorough.iter().any(|a| a == "--script"));
    }

    #[test]
    fn the_scan_is_unprivileged_unless_asked_otherwise() {
        let mut config = config_with(None, true);
        let plain = arguments(&config, &HashSet::from(["1.2.3.4".to_owned()]));
        assert!(plain.iter().any(|a| a == "-sT"));
        assert!(!plain.iter().any(|a| a == "-sS"));

        config.ports.syn_scan = true;
        let syn = arguments(&config, &HashSet::from(["1.2.3.4".to_owned()]));
        assert!(syn.iter().any(|a| a == "-sS"));
    }

    #[test]
    fn every_address_reaches_the_command_line() {
        let ips = HashSet::from(["1.2.3.4".to_owned(), "5.6.7.8".to_owned()]);
        let args = arguments(&config_with(None, true), &ips);
        for ip in &ips {
            assert!(args.contains(ip), "{ip} missing from the command line");
        }
    }

    #[test]
    fn a_minimum_rate_is_only_passed_when_set() {
        let mut config = config_with(None, true);
        let without = arguments(&config, &HashSet::from(["1.2.3.4".to_owned()]));
        assert!(!without.iter().any(|a| a == "--min-rate"));
        config.ports.min_rate = 500;
        let args = arguments(&config, &HashSet::from(["1.2.3.4".to_owned()]));
        assert!(args.windows(2).any(|w| w == ["--min-rate", "500"]));
    }

    #[test]
    fn scanning_nothing_does_not_run_the_tool() {
        let found = scan(&Config::default(), &HashSet::new()).expect("no work is not a failure");
        assert!(found.is_empty());
    }
}
