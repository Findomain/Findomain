//! Emailing the monitoring report over SMTP.

use {
    crate::{
        config::{Config, Email},
        errors::Result,
        tools::{ffuf, nuclei},
    },
    anyhow::Context,
    lettre::{
        message::header::ContentType, transport::smtp::authentication::Credentials, Message,
        SmtpTransport, Transport,
    },
    std::collections::HashSet,
};

/// Findings collected during a run, in the order a reader cares about.
#[derive(Debug, Default)]
pub struct Report {
    pub new_subdomains: Vec<String>,
    pub vulnerabilities: Vec<nuclei::Finding>,
    pub paths: Vec<ffuf::Hit>,
}

impl Report {
    /// Reports whether there is anything worth sending.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.new_subdomains.is_empty() && self.vulnerabilities.is_empty() && self.paths.is_empty()
    }

    /// Renders the report as plain text.
    #[must_use]
    pub fn render(&self, target: &str) -> String {
        let mut body = format!("Findomain report for {target}\n");

        section(&mut body, "New subdomains", &self.new_subdomains);
        section(
            &mut body,
            "Vulnerabilities found by nuclei",
            &self
                .vulnerabilities
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        );
        section(
            &mut body,
            "Paths found by ffuf",
            &self
                .paths
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        );

        body
    }

    /// One-line summary used as the mail subject.
    #[must_use]
    pub fn subject(&self, target: &str) -> String {
        let critical = self
            .vulnerabilities
            .iter()
            .filter(|finding| finding.is_actionable())
            .count();

        if critical > 0 {
            format!(
                "Findomain: {critical} finding(s) and {} new subdomain(s) for {target}",
                self.new_subdomains.len()
            )
        } else {
            format!(
                "Findomain: {} new subdomain(s) for {target}",
                self.new_subdomains.len()
            )
        }
    }
}

/// Appends a titled block, skipping it entirely when there is nothing to show.
fn section(body: &mut String, title: &str, entries: &[String]) {
    use std::fmt::Write;
    if entries.is_empty() {
        return;
    }
    let _ = write!(body, "\n{title} ({})\n", entries.len());
    for entry in entries {
        body.push_str("  ");
        body.push_str(entry);
        body.push('\n');
    }
}

/// Emails `report` to every configured recipient.
///
/// # Errors
///
/// Fails when the message cannot be built or the server refuses it.
pub fn send(config: &Config, target: &str, report: &Report) -> Result<()> {
    let settings = &config.email;
    if !settings.is_configured() || report.is_empty() {
        return Ok(());
    }

    let transport = transport(settings)?;
    let body = report.render(target);
    let subject = report.subject(target);

    let recipients = unique(&settings.recipients);
    for recipient in &recipients {
        let message = Message::builder()
            .from(
                sender(settings)
                    .parse()
                    .with_context(|| format!("Invalid sender address {}", sender(settings)))?,
            )
            .to(recipient
                .parse()
                .with_context(|| format!("Invalid recipient address {recipient}"))?)
            .subject(subject.clone())
            .header(ContentType::TEXT_PLAIN)
            .body(body.clone())?;

        transport
            .send(&message)
            .with_context(|| format!("Could not email the report to {recipient}"))?;
    }

    if !config.general.quiet {
        println!("Report emailed to {} recipient(s).", recipients.len());
    }
    Ok(())
}

/// Builds the SMTP transport, using STARTTLS unless the port says otherwise.
fn transport(settings: &Email) -> Result<SmtpTransport> {
    // 465 is implicit TLS; everything else negotiates with STARTTLS.
    let builder = if settings.port == 465 {
        SmtpTransport::relay(&settings.server)
    } else {
        SmtpTransport::starttls_relay(&settings.server)
    }
    .with_context(|| format!("Could not reach the SMTP server {}", settings.server))?;

    let builder = builder.port(settings.port);
    let builder = if settings.user.is_empty() {
        builder
    } else {
        builder.credentials(Credentials::new(
            settings.user.clone(),
            settings.password.clone(),
        ))
    };

    Ok(builder.build())
}

/// The address the report is sent from.
fn sender(settings: &Email) -> String {
    if settings.user.contains('@') {
        settings.user.clone()
    } else {
        format!("findomain@{}", settings.server)
    }
}

/// Removes repeated recipients while keeping the configured order.
fn unique(recipients: &[String]) -> Vec<&str> {
    let mut seen = HashSet::new();
    recipients
        .iter()
        .map(String::as_str)
        .filter(|address| !address.is_empty() && seen.insert(*address))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: &str) -> nuclei::Finding {
        serde_json::from_str(&format!(
            r#"{{"template-id":"t","info":{{"name":"n","severity":"{severity}"}},"host":"h"}}"#
        ))
        .unwrap()
    }

    fn settings(user: &str, recipients: &[&str]) -> Email {
        Email {
            server: "smtp.example.com".into(),
            port: 587,
            user: user.into(),
            password: "secret".into(),
            recipients: recipients.iter().map(|r| (*r).to_owned()).collect(),
        }
    }

    #[test]
    fn a_report_with_nothing_in_it_is_empty() {
        assert!(Report::default().is_empty());
        assert!(!Report {
            new_subdomains: vec!["a.example.com".into()],
            ..Report::default()
        }
        .is_empty());
    }

    #[test]
    fn the_body_only_lists_sections_that_have_content() {
        let report = Report {
            new_subdomains: vec!["a.example.com".into()],
            ..Report::default()
        };
        let body = report.render("example.com");

        assert!(body.contains("Findomain report for example.com"));
        assert!(body.contains("New subdomains (1)"));
        assert!(body.contains("  a.example.com"));
        assert!(!body.contains("nuclei"));
        assert!(!body.contains("ffuf"));
    }

    #[test]
    fn the_body_lists_every_kind_of_finding() {
        let report = Report {
            new_subdomains: vec!["a.example.com".into()],
            vulnerabilities: vec![finding("high")],
            paths: vec![ffuf::Hit {
                url: "https://a.example.com/admin".into(),
                status: 200,
                length: 1,
                words: 1,
                lines: 1,
            }],
        };
        let body = report.render("example.com");

        assert!(body.contains("New subdomains (1)"));
        assert!(body.contains("Vulnerabilities found by nuclei (1)"));
        assert!(body.contains("Paths found by ffuf (1)"));
    }

    #[test]
    fn the_subject_calls_out_actionable_findings() {
        let quiet = Report {
            new_subdomains: vec!["a.example.com".into()],
            vulnerabilities: vec![finding("info")],
            ..Report::default()
        };
        assert_eq!(
            quiet.subject("example.com"),
            "Findomain: 1 new subdomain(s) for example.com"
        );

        let loud = Report {
            new_subdomains: vec!["a.example.com".into()],
            vulnerabilities: vec![finding("critical"), finding("info")],
            ..Report::default()
        };
        assert_eq!(
            loud.subject("example.com"),
            "Findomain: 1 finding(s) and 1 new subdomain(s) for example.com"
        );
    }

    #[test]
    fn email_is_only_configured_with_a_server_and_a_recipient() {
        assert!(!Email::default().is_configured());
        assert!(!settings("me@example.com", &[]).is_configured());
        assert!(settings("me@example.com", &["you@example.com"]).is_configured());
    }

    #[test]
    fn the_sender_falls_back_to_the_server_when_the_user_is_not_an_address() {
        assert_eq!(sender(&settings("me@example.com", &[])), "me@example.com");
        assert_eq!(sender(&settings("bob", &[])), "findomain@smtp.example.com");
    }

    #[test]
    fn recipients_are_deduplicated_in_order() {
        let addresses = vec![
            "b@example.com".to_owned(),
            "a@example.com".to_owned(),
            "b@example.com".to_owned(),
            String::new(),
        ];
        assert_eq!(unique(&addresses), ["b@example.com", "a@example.com"]);
    }

    #[test]
    fn nothing_is_sent_when_there_is_nothing_to_say() {
        let config = Config {
            email: settings("me@example.com", &["you@example.com"]),
            ..Config::default()
        };
        // An empty report must not even try to reach the server.
        send(&config, "example.com", &Report::default()).expect("no work is not a failure");
    }

    #[test]
    fn nothing_is_sent_when_email_is_not_configured() {
        let report = Report {
            new_subdomains: vec!["a.example.com".into()],
            ..Report::default()
        };
        send(&Config::default(), "example.com", &report).expect("unconfigured is not a failure");
    }
}
