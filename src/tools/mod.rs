//! Integration with the external scanners Findomain drives.
//!
//! Each tool is an optional stage: if the binary is missing the run says so
//! once and carries on, because a missing scanner must never cost the
//! enumeration that already succeeded.

pub mod ffuf;
pub mod nmap;
pub mod nuclei;

use crate::{config::Config, resolve::ResolvData};
use std::{
    collections::HashMap,
    fmt,
    io::{Read, Write},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

/// How often the wait loop checks whether the child has exited.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Why an external tool did not produce usable results.
#[derive(Debug)]
pub enum ToolError {
    /// The binary is not installed, or not on `PATH`.
    Missing(String),
    /// The binary ran but failed.
    Failed(String, String),
    /// The binary ran but its output could not be understood.
    Output(String, String),
}

impl fmt::Display for ToolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(tool) => write!(
                formatter,
                "{tool} is not installed or not in PATH, skipping that stage"
            ),
            Self::Failed(tool, reason) => write!(formatter, "{tool} failed: {reason}"),
            Self::Output(tool, reason) => {
                write!(formatter, "could not read the {tool} output: {reason}")
            }
        }
    }
}

impl std::error::Error for ToolError {}

/// Runs `tool` and returns its standard output.
///
/// # Errors
///
/// Fails when the binary is missing or exits without producing output.
pub fn run(tool: &str, args: &[String], timeout: u64) -> Result<String, ToolError> {
    run_with_stdin(tool, args, timeout, None)
}

/// Runs `tool`, optionally feeding it `stdin`, and returns its standard output.
///
/// # Errors
///
/// Fails when the binary is missing or exits without producing output.
pub fn run_with_stdin(
    tool: &str,
    args: &[String],
    timeout: u64,
    stdin: Option<&str>,
) -> Result<String, ToolError> {
    let mut child = Command::new(tool)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => ToolError::Missing(tool.to_owned()),
            _ => ToolError::Failed(tool.to_owned(), e.to_string()),
        })?;

    // Both pipes drained on their own threads, and stdin fed on another, so a
    // child that outgrows the OS pipe buffer cannot block against our wait.
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut stderr = child.stderr.take().expect("stderr is piped");
    let stdout_reader = thread::spawn(move || read_to_end(&mut stdout));
    let stderr_reader = thread::spawn(move || read_to_end(&mut stderr));

    if let (Some(mut pipe), Some(input)) = (child.stdin.take(), stdin) {
        let input = input.to_owned();
        thread::spawn(move || {
            let _ = pipe.write_all(input.as_bytes());
            // Dropping the pipe closes the child's stdin, signalling EOF.
        });
    }

    let status = wait_with_timeout(&mut child, tool, Duration::from_secs(timeout))?;

    let stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();

    if stdout.is_empty() && !status.success() {
        let reason = String::from_utf8_lossy(&stderr);
        return Err(ToolError::Failed(
            tool.to_owned(),
            reason.lines().next().unwrap_or("no output").to_owned(),
        ));
    }

    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

/// Reads a pipe to the end, returning whatever arrived before any error.
fn read_to_end<R: Read>(pipe: &mut R) -> Vec<u8> {
    let mut buffer = Vec::new();
    let _ = pipe.read_to_end(&mut buffer);
    buffer
}

/// Waits for `child`, killing it once `timeout` has passed.
///
/// A scan that never returns would otherwise hold the whole run hostage. The
/// caller drains the output pipes concurrently, so the child cannot deadlock
/// against a full pipe while this polls.
fn wait_with_timeout(
    child: &mut Child,
    tool: &str,
    timeout: Duration,
) -> Result<ExitStatus, ToolError> {
    let deadline = Instant::now() + timeout;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ToolError::Failed(
                    tool.to_owned(),
                    format!("timed out after {} seconds", timeout.as_secs()),
                ));
            }
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(e) => return Err(ToolError::Failed(tool.to_owned(), e.to_string())),
        }
    }
}

/// Findings produced by the optional scanners.
#[derive(Debug, Default)]
pub struct Findings {
    pub vulnerabilities: Vec<nuclei::Finding>,
    pub paths: Vec<ffuf::Hit>,
}

/// Runs the enabled scanners against every host with a live HTTP server.
///
/// A scanner that is missing or fails is reported once and skipped: it must
/// never cost the enumeration that already succeeded.
#[must_use]
pub fn scan_live_hosts(config: &Config, resolv_data: &HashMap<String, ResolvData>) -> Findings {
    let mut findings = Findings::default();
    if !config.nuclei.enabled && !config.ffuf.enabled {
        return findings;
    }

    let mut urls: Vec<String> = resolv_data
        .values()
        .filter(|data| !data.http_data.final_url.is_empty())
        .map(|data| data.http_data.final_url.clone())
        .collect();
    urls.sort_unstable();
    urls.dedup();

    if urls.is_empty() {
        return findings;
    }

    if config.nuclei.enabled {
        match nuclei::scan(config, &urls) {
            Ok(found) => findings.vulnerabilities = found,
            Err(e) => eprintln!("nuclei stage skipped: {e}"),
        }
    }
    if config.ffuf.enabled {
        match ffuf::scan(config, &urls) {
            Ok(found) => findings.paths = found,
            Err(e) => eprintln!("ffuf stage skipped: {e}"),
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_binary_is_reported_as_missing() {
        let error = run("findomain-no-such-tool-exists", &[], 5).expect_err("must fail");
        assert!(matches!(error, ToolError::Missing(_)));
        assert!(error.to_string().contains("not installed"));
    }

    #[test]
    fn standard_output_is_captured() {
        let out = run("echo", &["hello".to_owned()], 5).expect("echo exists");
        assert_eq!(out.trim(), "hello");
    }

    #[test]
    fn stdin_reaches_the_tool() {
        let out = run_with_stdin("cat", &[], 5, Some("piped input")).expect("cat exists");
        assert_eq!(out.trim(), "piped input");
    }

    #[test]
    fn a_hanging_tool_is_killed() {
        let error = run("sleep", &["30".to_owned()], 1).expect_err("must time out");
        assert!(error.to_string().contains("timed out"));
    }

    #[test]
    fn output_larger_than_the_pipe_buffer_does_not_deadlock() {
        // 1 MB dwarfs the ~64 KB OS pipe buffer; without concurrent draining
        // the child would block writing and the wait would time out.
        let out = run(
            "sh",
            &[
                "-c".to_owned(),
                "yes ABCDEFGHIJKLMNOP | head -c 1000000".to_owned(),
            ],
            10,
        )
        .expect("must complete well within the timeout");
        assert_eq!(out.len(), 1_000_000);
    }

    #[test]
    fn a_large_stdin_paired_with_large_stdout_does_not_deadlock() {
        // The child echoes a big stdin straight back to stdout; feeding stdin
        // and draining stdout must happen concurrently or both pipes wedge.
        let input = "x".repeat(500_000);
        let out = run_with_stdin("cat", &[], 10, Some(&input)).expect("must complete");
        assert_eq!(out.len(), input.len());
    }

    #[test]
    fn a_failing_tool_reports_its_first_error_line() {
        let error = run("ls", &["/definitely/not/here".to_owned()], 5).expect_err("must fail");
        assert!(matches!(error, ToolError::Failed(..)));
    }
}
