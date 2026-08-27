//! Vulnerability scanning delegated to nuclei.
//!
//! Findomain feeds nuclei the URLs the HTTP stage confirmed as live and reads
//! back its JSONL findings. Templates, severities and tags stay under the
//! user's control: this is a pipe, not a policy.

use {
    super::{run_with_stdin, ToolError},
    crate::config::Config,
    serde::Deserialize,
    std::fmt,
};

/// One finding as reported by nuclei.
#[derive(Clone, Debug, Deserialize)]
pub struct Finding {
    #[serde(default, rename = "template-id")]
    pub template_id: String,
    #[serde(default)]
    pub info: FindingInfo,
    #[serde(default)]
    pub host: String,
    #[serde(default, rename = "matched-at")]
    pub matched_at: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct FindingInfo {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub severity: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let where_ = if self.matched_at.is_empty() {
            &self.host
        } else {
            &self.matched_at
        };
        write!(
            formatter,
            "[{}] {} {} ({})",
            self.info.severity, where_, self.info.name, self.template_id
        )
    }
}

impl Finding {
    /// Reports whether the finding is worth alerting a human about.
    #[must_use]
    pub fn is_actionable(&self) -> bool {
        matches!(
            self.info.severity.as_str(),
            "low" | "medium" | "high" | "critical"
        )
    }
}

/// Runs nuclei against `targets` and returns everything it found.
///
/// # Errors
///
/// Fails when nuclei is missing or cannot be executed.
pub fn scan(config: &Config, targets: &[String]) -> Result<Vec<Finding>, ToolError> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }

    let output = run_with_stdin(
        "nuclei",
        &arguments(config),
        config.nuclei.timeout,
        Some(&targets.join("\n")),
    )?;
    Ok(parse(&output))
}

/// Builds the nuclei command line.
///
/// The flags this parses results with go last, after whatever the user added,
/// because nuclei lets the last occurrence win. Everything else can be
/// overridden; the shape of the output cannot.
fn arguments(config: &Config) -> Vec<String> {
    let nuclei = &config.nuclei;
    let mut args: Vec<String> = vec!["-no-interactsh".into(), "-duc".into()];

    if !nuclei.templates.is_empty() {
        args.push("-t".into());
        args.push(nuclei.templates.clone());
    }
    if !nuclei.severity.is_empty() {
        args.push("-severity".into());
        args.push(nuclei.severity.clone());
    }
    if !nuclei.tags.is_empty() {
        args.push("-tags".into());
        args.push(nuclei.tags.clone());
    }
    if !nuclei.exclude_templates.is_empty() {
        args.push("-exclude-templates".into());
        args.push(nuclei.exclude_templates.clone());
    }
    if nuclei.rate_limit > 0 {
        args.push("-rate-limit".into());
        args.push(nuclei.rate_limit.to_string());
    }

    args.extend(nuclei.extra_args.iter().cloned());
    args.extend(["-silent".into(), "-jsonl".into()]);
    args
}

/// Reads the JSONL nuclei writes, skipping lines it cannot understand.
fn parse(output: &str) -> Vec<Finding> {
    output
        .lines()
        .filter(|line| line.trim_start().starts_with('{'))
        .filter_map(|line| serde_json::from_str::<Finding>(line).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extra_arguments_reach_nuclei_but_never_displace_the_format() {
        let config = Config {
            nuclei: crate::config::Nuclei {
                extra_args: vec!["-proxy".to_owned(), "http://127.0.0.1:8080".to_owned()],
                ..crate::config::Nuclei::default()
            },
            ..Config::default()
        };
        let args = arguments(&config);

        let proxy = args
            .iter()
            .position(|arg| arg == "-proxy")
            .expect("passed through");
        let jsonl = args
            .iter()
            .position(|arg| arg == "-jsonl")
            .expect("still set");
        assert!(proxy < jsonl, "the parsed format is decided last: {args:?}");
        assert!(args.contains(&"-silent".to_owned()));
    }

    const OUTPUT: &str = concat!(
        r#"{"template-id":"tech-detect","info":{"name":"Nginx","severity":"info"},"#,
        r#""host":"https://a.example.com","matched-at":"https://a.example.com"}"#,
        "\n",
        "not json\n",
        r#"{"template-id":"CVE-2021-1","info":{"name":"RCE","severity":"critical"},"#,
        r#""host":"https://b.example.com","matched-at":"https://b.example.com/x"}"#,
    );

    #[test]
    fn findings_are_read_and_bad_lines_skipped() {
        let findings = parse(OUTPUT);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].template_id, "tech-detect");
        assert_eq!(findings[1].info.severity, "critical");
        assert_eq!(findings[1].matched_at, "https://b.example.com/x");
    }

    #[test]
    fn only_real_severities_are_actionable() {
        let findings = parse(OUTPUT);
        assert!(!findings[0].is_actionable(), "info is noise");
        assert!(findings[1].is_actionable());
    }

    #[test]
    fn a_finding_renders_as_one_readable_line() {
        let findings = parse(OUTPUT);
        assert_eq!(
            findings[1].to_string(),
            "[critical] https://b.example.com/x RCE (CVE-2021-1)"
        );
    }

    #[test]
    fn a_finding_without_a_match_location_falls_back_to_the_host() {
        let finding: Finding = serde_json::from_str(
            r#"{"template-id":"t","info":{"name":"n","severity":"low"},"host":"h"}"#,
        )
        .unwrap();
        assert_eq!(finding.to_string(), "[low] h n (t)");
    }

    #[test]
    fn empty_output_yields_no_findings() {
        assert!(parse("").is_empty());
        assert!(parse("\n\n").is_empty());
    }

    #[test]
    fn the_command_line_reflects_the_configuration() {
        let mut config = Config::default();
        let plain = arguments(&config);
        assert!(plain.contains(&"-jsonl".to_owned()));
        assert!(!plain.iter().any(|a| a == "-severity"));

        config.nuclei.templates = "/templates".into();
        config.nuclei.severity = "high,critical".into();
        config.nuclei.tags = "cve".into();
        config.nuclei.exclude_templates = "/templates/dos".into();
        config.nuclei.rate_limit = 50;

        let full = arguments(&config);
        for pair in [
            ["-t", "/templates"],
            ["-severity", "high,critical"],
            ["-tags", "cve"],
            ["-exclude-templates", "/templates/dos"],
            ["-rate-limit", "50"],
        ] {
            assert!(
                full.windows(2).any(|w| w == pair),
                "missing {pair:?} in {full:?}"
            );
        }
    }

    #[test]
    fn scanning_nothing_does_not_run_the_tool() {
        let findings = scan(&Config::default(), &[]).expect("no work is not a failure");
        assert!(findings.is_empty());
    }
}
