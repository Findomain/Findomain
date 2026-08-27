//! Content discovery delegated to ffuf.
//!
//! ffuf fuzzes a path wordlist against every host the HTTP stage confirmed as
//! live. It writes its report to a file rather than to stdout, so the run uses
//! a scratch file and removes it afterwards.

use {
    super::{run, ToolError},
    crate::config::Config,
    serde::Deserialize,
    std::{
        collections::hash_map::DefaultHasher,
        fmt, fs,
        hash::{Hash, Hasher},
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    },
};

/// Status codes never worth reporting: they mean "nothing here".
const FILTERED_STATUS: &str = "400,404,429,500,501,502,503";

/// Extensions tried for leftover files when recursion is on.
const BACKUP_EXTENSIONS: &str = ".bak,.old,.inc,.config,.sql,.zip";

/// One path ffuf found.
#[derive(Clone, Debug, Deserialize)]
pub struct Hit {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub status: u16,
    #[serde(default)]
    pub length: u64,
    #[serde(default)]
    pub words: u64,
    #[serde(default)]
    pub lines: u64,
}

impl fmt::Display for Hit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} [status {}, {} bytes, {} words, {} lines]",
            self.url, self.status, self.length, self.words, self.lines
        )
    }
}

#[derive(Debug, Default, Deserialize)]
struct Report {
    #[serde(default)]
    results: Vec<Hit>,
}

/// Fuzzes `urls` with the configured wordlist.
///
/// # Errors
///
/// Fails when ffuf is missing, when no wordlist was configured, or when its
/// report cannot be read.
pub fn scan(config: &Config, urls: &[String]) -> Result<Vec<Hit>, ToolError> {
    if urls.is_empty() {
        return Ok(Vec::new());
    }
    if config.ffuf.wordlist.is_empty() {
        return Err(ToolError::Failed(
            "ffuf".into(),
            "no wordlist configured, use --ffuf-wordlist".into(),
        ));
    }

    let hosts_file = scratch_path("ffuf-hosts");
    let report_file = scratch_path("ffuf-report");
    fs::write(&hosts_file, urls.join("\n"))
        .map_err(|e| ToolError::Failed("ffuf".into(), e.to_string()))?;

    let outcome = run(
        "ffuf",
        &arguments(config, &hosts_file, &report_file),
        config.ffuf.timeout,
    );

    let _ = fs::remove_file(&hosts_file);
    let findings = match outcome {
        Ok(_) => read_report(&report_file),
        Err(e) => {
            let _ = fs::remove_file(&report_file);
            return Err(e);
        }
    };
    let _ = fs::remove_file(&report_file);
    findings
}

/// Builds the ffuf command line.
fn arguments(config: &Config, hosts_file: &Path, report_file: &Path) -> Vec<String> {
    let ffuf = &config.ffuf;
    let mut args: Vec<String> = vec![
        "-u".into(),
        "DOM/FUZZ".into(),
        "-w".into(),
        format!("{}:DOM", hosts_file.display()),
        "-w".into(),
        format!("{}:FUZZ", ffuf.wordlist),
        "-t".into(),
        ffuf.threads.to_string(),
        "-timeout".into(),
        "5".into(),
        "-fc".into(),
        FILTERED_STATUS.into(),
        // ffuf drops responses that keep repeating the same size, which is
        // what a host answering everything with 200 produces.
        "-ac".into(),
    ];

    if ffuf.recursion {
        args.extend([
            "-recursion".into(),
            "-recursion-depth".into(),
            ffuf.recursion_depth.to_string(),
            "-e".into(),
            BACKUP_EXTENSIONS.into(),
        ]);
    }

    args.extend(ffuf.extra_args.iter().cloned());
    // Last, so that the report stays where and how this expects to read it.
    args.extend([
        "-of".into(),
        "json".into(),
        "-o".into(),
        report_file.display().to_string(),
        "-s".into(),
    ]);
    args
}

/// Reads the JSON report ffuf wrote.
fn read_report(path: &Path) -> Result<Vec<Hit>, ToolError> {
    let Ok(body) = fs::read_to_string(path) else {
        // ffuf writes nothing when it found nothing.
        return Ok(Vec::new());
    };
    if body.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str::<Report>(&body)
        .map(|report| report.results)
        .map_err(|e| ToolError::Output("ffuf".into(), e.to_string()))
}

/// Returns a unique path in the system temporary directory.
fn scratch_path(label: &str) -> PathBuf {
    let mut hasher = DefaultHasher::new();
    std::process::id().hash(&mut hasher);
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .hash(&mut hasher);
    std::env::temp_dir().join(format!("findomain-{label}-{:x}", hasher.finish()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hits_are_read_from_the_report() {
        let dir = crate::test_support::TempDir::new("ffuf_report");
        let path = PathBuf::from(dir.write(
            "report.json",
            r#"{"results":[
                {"url":"https://a.example.com/admin","status":200,"length":12,"words":3,"lines":1},
                {"url":"https://a.example.com/.git","status":403,"length":5,"words":1,"lines":1}]}"#,
        ));

        let hits = read_report(&path).expect("valid report");
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].url, "https://a.example.com/admin");
        assert_eq!(hits[1].status, 403);
    }

    #[test]
    fn a_missing_or_empty_report_means_no_hits() {
        let dir = crate::test_support::TempDir::new("ffuf_empty");
        assert!(read_report(&PathBuf::from(dir.path("absent.json")))
            .unwrap()
            .is_empty());
        assert!(read_report(&PathBuf::from(dir.write("empty.json", "  ")))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_corrupt_report_is_an_error() {
        let dir = crate::test_support::TempDir::new("ffuf_corrupt");
        let path = PathBuf::from(dir.write("bad.json", "{not json"));
        assert!(read_report(&path).is_err());
    }

    #[test]
    fn a_hit_renders_as_one_readable_line() {
        let hit = Hit {
            url: "https://a.example.com/admin".into(),
            status: 200,
            length: 12,
            words: 3,
            lines: 1,
        };
        assert_eq!(
            hit.to_string(),
            "https://a.example.com/admin [status 200, 12 bytes, 3 words, 1 lines]"
        );
    }

    #[test]
    fn the_command_line_wires_both_wordlists() {
        let mut config = Config::default();
        config.ffuf.wordlist = "/paths.txt".into();
        let args = arguments(&config, &PathBuf::from("/hosts"), &PathBuf::from("/out"));

        assert!(args.windows(2).any(|w| w == ["-u", "DOM/FUZZ"]));
        assert!(args.iter().any(|a| a == "/hosts:DOM"));
        assert!(args.iter().any(|a| a == "/paths.txt:FUZZ"));
        assert!(args.windows(2).any(|w| w == ["-of", "json"]));
        assert!(!args.iter().any(|a| a == "-recursion"));
    }

    #[test]
    fn recursion_is_opt_in() {
        let mut config = Config::default();
        config.ffuf.wordlist = "/paths.txt".into();
        config.ffuf.recursion = true;
        config.ffuf.recursion_depth = 2;

        let args = arguments(&config, &PathBuf::from("/hosts"), &PathBuf::from("/out"));
        assert!(args.iter().any(|a| a == "-recursion"));
        assert!(args.windows(2).any(|w| w == ["-recursion-depth", "2"]));
    }

    #[test]
    fn a_missing_wordlist_is_refused_before_running_anything() {
        let error = scan(&Config::default(), &["https://a.example.com".to_owned()])
            .expect_err("must refuse");
        assert!(error.to_string().contains("no wordlist"));
    }

    #[test]
    fn scanning_nothing_does_not_run_the_tool() {
        assert!(scan(&Config::default(), &[]).expect("no work").is_empty());
    }

    #[test]
    fn scratch_paths_do_not_collide() {
        assert_ne!(scratch_path("a"), scratch_path("a"));
    }
}
