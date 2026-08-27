//! End to end tests driving the real binary.
//!
//! Everything here runs offline: `--no-discover` skips the passive sources and
//! no resolution flag is ever passed, so no DNS, HTTP or database access takes
//! place. Each test gets its own working directory because Findomain derives
//! output file names from the target and auto-detects `findomain.toml` in the
//! current directory.

use {
    findomain::test_support::TempDir,
    std::{
        io::Write,
        process::{Command, Stdio},
    },
};

/// Subdomains covering the interesting parsing cases.
const IMPORT_FILE: &str = "\
sub1.example.com
sub2.example.com
not-in-scope.other.com
SUB3.Example.com

invalid_$$$.example.com
example.com
https://sub4.example.com
www.sub5.example.com
";

const WORDLIST: &str = "www\nmail\ndev\n";

/// Result of one invocation.
struct Run {
    stdout: String,
    stderr: String,
    code: i32,
}

impl Run {
    /// Stdout lines, sorted so that `HashSet` iteration order does not matter.
    fn stdout_lines(&self) -> Vec<&str> {
        let mut lines: Vec<&str> = self
            .stdout
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        lines.sort_unstable();
        lines
    }

    /// Both streams joined, for asserting on a message without caring which
    /// one carried it.
    fn output(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

/// Runs the binary inside `dir`.
fn run_in(dir: &TempDir, args: &[&str]) -> Run {
    run_with_stdin(dir, args, None)
}

/// Runs the binary inside `dir`, optionally feeding it stdin.
fn run_with_stdin(dir: &TempDir, args: &[&str], stdin: Option<&str>) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_findomain"));
    command
        .args(args)
        .current_dir(dir.root())
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().expect("spawn findomain");
    if let Some(input) = stdin {
        child
            .stdin
            .as_mut()
            .expect("stdin is piped")
            .write_all(input.as_bytes())
            .expect("write stdin");
    }

    let output = child.wait_with_output().expect("wait for findomain");
    Run {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        code: output.status.code().unwrap_or(-1),
    }
}

/// A directory pre-populated with the shared fixtures.
fn fixtures(label: &str) -> TempDir {
    let dir = TempDir::new(label);
    dir.write("import.txt", IMPORT_FILE);
    dir.write("words.txt", WORDLIST);
    dir
}

/// Sorted, non-empty lines of a file inside `dir`.
fn file_lines(dir: &TempDir, name: &str) -> Vec<String> {
    let mut lines: Vec<String> = std::fs::read_to_string(dir.path(name))
        .unwrap_or_else(|e| panic!("read {name}: {e}"))
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_owned)
        .collect();
    lines.sort();
    lines
}

#[test]
fn help_exits_successfully_and_documents_the_flags() {
    let dir = TempDir::new("help");
    let run = run_in(&dir, &["--help"]);

    assert_eq!(run.code, 0);
    for flag in [
        "--target",
        "--file",
        "--output",
        "--unique-output",
        "--no-discover",
        "--import-subdomains",
        "--exclude-sources",
        "--validate",
        "--reset-database",
    ] {
        assert!(run.stdout.contains(flag), "{flag} missing from --help");
    }
}

#[test]
fn running_without_arguments_shows_the_usage() {
    let dir = TempDir::new("no-args");
    let run = run_in(&dir, &[]);

    assert_eq!(run.code, 2);
    assert!(run.output().contains("Usage: findomain"));
}

#[test]
fn an_invalid_target_is_rejected() {
    let dir = TempDir::new("invalid-target");
    let run = run_in(&dir, &["-t", "not_a_domain", "-n"]);

    assert_eq!(run.code, 1);
    assert!(run.output().contains("Error: Target is empty or invalid!"));
}

#[test]
fn filtering_and_excluding_the_same_keyword_is_rejected() {
    let dir = fixtures("contradictory-filters");
    let run = run_in(
        &dir,
        &[
            "-t",
            "example.com",
            "-n",
            "--filter",
            "dev",
            "--exclude",
            "dev",
        ],
    );

    assert_eq!(run.code, 1);
    assert!(run
        .output()
        .contains("you are filtering and excluding exactly the same keywords"));
}

#[test]
fn imported_subdomains_are_normalised_and_scoped_to_the_target() {
    let dir = fixtures("import");
    let run = run_in(
        &dir,
        &[
            "-t",
            "example.com",
            "-n",
            "-q",
            "--import-subdomains",
            "import.txt",
        ],
    );

    assert_eq!(run.code, 0);
    assert_eq!(
        run.stdout_lines(),
        [
            "example.com",
            "sub1.example.com",
            "sub2.example.com",
            // Case is normalised, as it already was for discovered subdomains.
            "sub3.example.com",
            // The scheme is stripped from an imported hostname...
            "sub4.example.com",
            // ...but every label is kept: www.x is a host of its own.
            "www.sub5.example.com",
        ],
        "out-of-scope and malformed entries must be dropped"
    );
}

#[test]
fn bruteforce_combines_the_wordlist_with_the_target() {
    let dir = fixtures("bruteforce");
    let run = run_in(&dir, &["-t", "example.com", "-n", "-q", "-w", "words.txt"]);

    assert_eq!(run.code, 0);
    assert_eq!(
        run.stdout_lines(),
        ["dev.example.com", "mail.example.com", "www.example.com"]
    );
}

#[test]
fn bruteforce_does_not_change_how_imported_files_are_parsed() {
    let dir = fixtures("bruteforce-import");
    let run = run_in(
        &dir,
        &[
            "-t",
            "example.com",
            "-n",
            "-q",
            "-w",
            "words.txt",
            "--import-subdomains",
            "import.txt",
        ],
    );

    assert_eq!(run.code, 0);
    assert_eq!(
        run.stdout_lines(),
        [
            "dev.example.com",
            "example.com",
            "mail.example.com",
            "sub1.example.com",
            "sub2.example.com",
            "sub3.example.com",
            "sub4.example.com",
            "www.example.com",
            "www.sub5.example.com",
        ],
        "the wordlist must not affect how --import-subdomains is read"
    );
}

#[test]
fn the_include_filter_keeps_only_matching_subdomains() {
    let dir = fixtures("filter");
    let run = run_in(
        &dir,
        &[
            "-t",
            "example.com",
            "-n",
            "-q",
            "--import-subdomains",
            "import.txt",
            "--filter",
            "sub1",
        ],
    );

    assert_eq!(run.stdout_lines(), ["sub1.example.com"]);
}

#[test]
fn the_exclude_filter_drops_matching_subdomains() {
    let dir = fixtures("exclude");
    let run = run_in(
        &dir,
        &[
            "-t",
            "example.com",
            "-n",
            "-q",
            "--import-subdomains",
            "import.txt",
            "--exclude",
            "sub1",
        ],
    );

    let lines = run.stdout_lines();
    assert!(!lines.contains(&"sub1.example.com"));
    assert!(lines.contains(&"sub2.example.com"));
}

#[test]
fn quiet_hides_the_banners_that_the_default_run_prints() {
    let dir = fixtures("quiet");
    let args = [
        "-t",
        "example.com",
        "-n",
        "--import-subdomains",
        "import.txt",
    ];

    let loud = run_in(&dir, &args);
    assert!(loud.stdout.contains("Target ==> example.com"));
    assert!(loud.stdout.contains("Job finished in"));
    assert!(loud.stdout.contains("Good luck Hax0r"));

    let quiet = run_in(&dir, &[args.as_slice(), &["-q"]].concat());
    assert!(!quiet.stdout.contains("Target ==>"));
    assert!(!quiet.stdout.contains("Job finished in"));
    assert!(!quiet.stdout.contains("Good luck Hax0r"));
}

#[test]
fn the_target_is_reduced_to_a_bare_hostname() {
    let dir = fixtures("sanitize-target");
    let run = run_in(
        &dir,
        &[
            "-t",
            "https://www.example.com/some/path",
            "-n",
            "--import-subdomains",
            "import.txt",
        ],
    );

    assert_eq!(run.code, 0);
    assert!(run.stdout.contains("Target ==> example.com"));
    assert!(run.stdout.contains("sub1.example.com"));
}

#[test]
fn an_uppercase_target_is_lowercased() {
    let dir = fixtures("uppercase-target");
    let run = run_in(
        &dir,
        &[
            "-t",
            "EXAMPLE.com",
            "-n",
            "--import-subdomains",
            "import.txt",
        ],
    );

    assert!(run.stdout.contains("Target ==> example.com"));
    assert!(run.stdout.contains("sub1.example.com"));
}

#[test]
fn a_target_without_results_says_so_without_failing() {
    let dir = TempDir::new("no-results");
    let run = run_in(&dir, &["-t", "nothing-here.com", "-n"]);

    assert_eq!(run.code, 0);
    assert!(run
        .output()
        .contains("No subdomains were found for the target: nothing-here.com"));
}

#[test]
fn unique_output_writes_every_result_to_the_named_file() {
    let dir = fixtures("unique-output");
    let run = run_in(
        &dir,
        &[
            "-t",
            "example.com",
            "-n",
            "--import-subdomains",
            "import.txt",
            "-u",
            "out.txt",
        ],
    );

    assert_eq!(run.code, 0);
    assert_eq!(
        file_lines(&dir, "out.txt"),
        [
            "example.com",
            "sub1.example.com",
            "sub2.example.com",
            "sub3.example.com",
            "sub4.example.com",
            "www.sub5.example.com",
        ]
    );
}

#[test]
fn automatic_output_derives_the_file_name_and_rotates_it() {
    let dir = fixtures("auto-output");
    let args = [
        "-t",
        "example.com",
        "-n",
        "--import-subdomains",
        "import.txt",
        "-o",
    ];

    assert_eq!(run_in(&dir, &args).code, 0);
    let first = file_lines(&dir, "example.com.txt");
    assert!(first.contains(&"sub1.example.com".to_owned()));

    // A second run moves the previous results aside instead of appending.
    assert_eq!(run_in(&dir, &args).code, 0);
    assert_eq!(file_lines(&dir, "example.com.old.txt"), first);
    assert_eq!(file_lines(&dir, "example.com.txt"), first);
}

#[test]
fn validate_prints_only_syntactically_valid_domains() {
    let dir = TempDir::new("validate");
    dir.write(
        "hosts.txt",
        "sub1.example.com\nbad domain\nexample.com\n.leadingdot.com\nnot_a_domain\n",
    );

    let run = run_in(&dir, &["-f", "hosts.txt", "--validate"]);

    assert_eq!(run.code, 0);
    assert_eq!(run.stdout_lines(), ["example.com", "sub1.example.com"]);
}

#[test]
fn validate_can_write_its_result_to_a_file() {
    let dir = TempDir::new("validate-output");
    dir.write("hosts.txt", "sub1.example.com\nbad domain\nexample.com\n");

    let run = run_in(&dir, &["-f", "hosts.txt", "--validate", "-u", "valid.txt"]);

    assert_eq!(run.code, 0);
    assert!(run.stdout.contains("Validated subdomains were written to"));
    assert_eq!(
        file_lines(&dir, "valid.txt"),
        ["example.com", "sub1.example.com"]
    );
}

#[test]
fn enable_dot_requires_a_resolution_mode() {
    let dir = TempDir::new("enable-dot");
    let run = run_in(&dir, &["-t", "example.com", "-n", "--enable-dot"]);

    assert_eq!(run.code, 1);
    assert!(run
        .output()
        .contains("--enable-dot flag needs -i/--ip or -r/--resolved"));
}

#[test]
fn the_resolver_mode_requires_something_to_check() {
    let dir = fixtures("as-resolver");
    let run = run_in(&dir, &["-x", "-f", "import.txt"]);

    assert_eq!(run.code, 1);
    assert!(run.output().contains("To use Findomain as resolver"));
}

#[test]
fn a_missing_input_file_is_fatal_when_it_is_the_only_one() {
    let dir = TempDir::new("missing-file");
    let run = run_in(&dir, &["-f", "does-not-exist.txt"]);

    assert_eq!(run.code, 1);
    assert!(run
        .output()
        .contains("Can not open file does-not-exist.txt"));
}

#[test]
fn conflicting_input_flags_are_reported_by_the_parser() {
    let dir = fixtures("conflicts");
    let run = run_in(&dir, &["-t", "example.com", "-f", "import.txt"]);

    assert_eq!(run.code, 2);
    assert!(run.output().contains("cannot be used with"));
}

#[test]
fn an_unknown_source_name_is_rejected() {
    let dir = TempDir::new("unknown-source");
    let run = run_in(
        &dir,
        &["-t", "example.com", "-n", "--exclude-sources", "notasource"],
    );

    assert_eq!(run.code, 2);
    assert!(run.output().contains("invalid value 'notasource'"));
}

#[test]
fn every_target_of_a_file_is_enumerated() {
    let dir = TempDir::new("target-file");
    dir.write("targets.txt", "example.com\ntest.org\n");

    let run = run_in(&dir, &["-f", "targets.txt", "-n", "--rate-limit", "0"]);

    assert_eq!(run.code, 0);
    assert!(run.stdout.contains("Target ==> example.com"));
    assert!(run.stdout.contains("Target ==> test.org"));
}

#[test]
fn targets_can_be_read_from_stdin() {
    let dir = TempDir::new("stdin");
    let run = run_with_stdin(
        &dir,
        &["--stdin", "-n", "--rate-limit", "0"],
        Some("example.com\nfoo.test\n"),
    );

    assert_eq!(run.code, 0);
    assert!(run.stdout.contains("Target ==> example.com"));
    assert!(run.stdout.contains("Target ==> foo.test"));
}

#[test]
fn a_configuration_file_in_the_working_directory_is_picked_up() {
    let dir = fixtures("config-autodetect");
    dir.write(
        "findomain.toml",
        "import_subdomains_from = \"import.txt\"\nrate_limit = \"0\"\n",
    );

    let run = run_in(&dir, &["-t", "example.com", "-n", "-q"]);

    assert_eq!(run.code, 0);
    assert!(
        run.stdout_lines().contains(&"sub1.example.com"),
        "the config file should have supplied the import list"
    );
}

#[test]
fn an_explicit_configuration_file_is_honoured() {
    let dir = fixtures("config-explicit");
    dir.write(
        "custom.toml",
        "import_subdomains_from = \"import.txt\"\nrate_limit = \"0\"\n",
    );

    let run = run_in(
        &dir,
        &["-t", "example.com", "-n", "-q", "-c", "custom.toml"],
    );

    assert_eq!(run.code, 0);
    assert!(run.stdout_lines().contains(&"sub1.example.com"));
}

#[test]
fn results_can_be_stored_in_and_read_back_from_sqlite() {
    let dir = fixtures("sqlite-roundtrip");
    let database = dir.path("findomain.db");

    let write = run_in(
        &dir,
        &[
            "-t",
            "example.com",
            "-n",
            "-q",
            "--import-subdomains",
            "import.txt",
            "--no-monitor",
            "--sqlite",
            &database,
        ],
    );
    assert_eq!(write.code, 0, "stderr: {}", write.stderr);

    let read = run_in(
        &dir,
        &[
            "-t",
            "example.com",
            "--query-database",
            "-q",
            "--sqlite",
            &database,
        ],
    );
    assert_eq!(read.code, 0);
    assert!(read.stdout_lines().contains(&"sub1.example.com"));
}

#[test]
fn storing_the_same_results_twice_is_idempotent() {
    let dir = fixtures("sqlite-idempotent");
    let database = dir.path("findomain.db");
    let args = [
        "-t",
        "example.com",
        "-n",
        "-q",
        "--import-subdomains",
        "import.txt",
        "--no-monitor",
        "--sqlite",
        &database,
    ];

    assert_eq!(run_in(&dir, &args).code, 0);
    let first = run_in(
        &dir,
        &[
            "-t",
            "example.com",
            "--query-database",
            "-q",
            "--sqlite",
            &database,
        ],
    )
    .stdout_lines()
    .len();

    assert_eq!(run_in(&dir, &args).code, 0, "a second run must not fail");
    let second = run_in(
        &dir,
        &[
            "-t",
            "example.com",
            "--query-database",
            "-q",
            "--sqlite",
            &database,
        ],
    )
    .stdout_lines()
    .len();

    assert_eq!(first, second, "re-running must not duplicate rows");
}

#[test]
fn the_database_can_be_reset() {
    let dir = fixtures("sqlite-reset");
    let database = dir.path("findomain.db");

    run_in(
        &dir,
        &[
            "-t",
            "example.com",
            "-n",
            "-q",
            "--import-subdomains",
            "import.txt",
            "--no-monitor",
            "--sqlite",
            &database,
        ],
    );
    let reset = run_in(&dir, &["--reset-database", "--sqlite", &database]);
    assert_eq!(reset.code, 0);
    assert!(reset.stdout.contains("Database was reset successfully"));

    let read = run_in(
        &dir,
        &[
            "-t",
            "example.com",
            "--query-database",
            "-q",
            "--sqlite",
            &database,
        ],
    );
    assert!(read.stdout_lines().is_empty());
}

#[test]
fn permutations_need_a_resolution_mode() {
    let dir = fixtures("permutations-guard");
    let run = run_in(
        &dir,
        &[
            "-t",
            "example.com",
            "-n",
            "--import-subdomains",
            "import.txt",
            "--permutations",
        ],
    );

    assert_eq!(run.code, 0);
    assert!(run.output().contains("Permutations need a resolution mode"));
    // The subdomains that were already known are still reported.
    assert!(run.stdout_lines().contains(&"sub1.example.com"));
}

#[test]
fn the_permutations_wordlist_implies_the_flag() {
    let dir = fixtures("permutations-wordlist");
    let run = run_in(
        &dir,
        &[
            "-t",
            "example.com",
            "-n",
            "--import-subdomains",
            "import.txt",
            "--permutations-wordlist",
            "words.txt",
        ],
    );

    assert_eq!(run.code, 0);
    assert!(run.output().contains("Permutations need a resolution mode"));
}

#[test]
fn every_source_can_be_excluded_at_once() {
    let dir = fixtures("exclude-all");
    let help = run_in(&dir, &["--help"]);
    let values = help
        .stdout
        .split("possible values: ")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .expect("the flag documents its values");
    let all: String = values
        .split(',')
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(",");

    let run = run_in(
        &dir,
        &[
            "-t",
            "example.com",
            "-q",
            "--import-subdomains",
            "import.txt",
            "--exclude-sources",
            &all,
        ],
    );

    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(run.stdout_lines().contains(&"sub1.example.com"));
}

#[test]
fn the_source_time_limits_are_accepted_and_validated() {
    let dir = fixtures("source-limits");

    let run = run_in(
        &dir,
        &[
            "-t",
            "example.com",
            "-q",
            "--no-discover",
            "--import-subdomains",
            "import.txt",
            "--source-timeout",
            "20",
            "--source-budget",
            "0",
        ],
    );
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(run.stdout_lines().contains(&"sub1.example.com"));

    let rejected = run_in(&dir, &["-t", "example.com", "--source-budget", "abc"]);
    assert_ne!(rejected.code, 0);
}

#[test]
fn the_mutually_exclusive_options_stay_exclusive() {
    let dir = fixtures("exclusive");

    for conflicting in [
        vec!["-t", "example.com", "-r", "-i"],
        vec!["-t", "example.com", "-i", "--ipv6-only"],
        vec!["-t", "example.com", "-r", "--ipv6-only"],
        vec!["-t", "example.com", "--stdin"],
        vec!["-t", "example.com", "-q", "--verbose"],
        vec!["-t", "example.com", "-o", "-u", "out.txt"],
        vec!["-t", "example.com", "--randomize"],
        vec!["-t", "example.com", "-m", "--no-monitor"],
    ] {
        let run = run_in(&dir, &conflicting);
        assert_ne!(run.code, 0, "{conflicting:?} must be rejected");
    }
}

#[test]
fn an_option_that_needs_another_says_so() {
    let dir = fixtures("requires");

    for incomplete in [
        vec!["-t", "example.com", "--sandbox"],
        vec!["-t", "example.com", "--mtimeout"],
        vec!["-t", "example.com", "--query-jobname"],
        vec!["-t", "example.com", "--validate"],
        vec!["-t", "example.com", "--double-dns-check"],
    ] {
        let run = run_in(&dir, &incomplete);
        assert_ne!(run.code, 0, "{incomplete:?} must be rejected");
    }
}

#[test]
fn debugging_and_tuning_are_not_arbitrarily_restricted() {
    let dir = fixtures("permitted");

    // Verbose used to be refused alongside --ipv6-only for no stated reason,
    // and --http-timeout demanded --http-status even though nuclei, ffuf and
    // screenshots all turn the same HTTP check on.
    for permitted in [
        vec![
            "-t",
            "example.com",
            "--verbose",
            "--ipv6-only",
            "--no-discover",
        ],
        vec![
            "-t",
            "example.com",
            "--nuclei",
            "--http-timeout",
            "10",
            "--no-discover",
            "-q",
        ],
        vec![
            "-t",
            "example.com",
            "--ffuf",
            "--http-retries",
            "1",
            "--no-discover",
            "-q",
        ],
    ] {
        let run = run_in(&dir, &permitted);
        assert_eq!(run.code, 0, "{permitted:?}: {}", run.stderr);
    }
}

#[test]
#[cfg(unix)]
fn a_closed_reader_ends_the_run_quietly() {
    use std::io::Read;

    // `findomain -t example.com | head` used to abort and dump core: Rust
    // ignores SIGPIPE, so the closed pipe became a write error that `println!`
    // panicked on. The run must end the way any other Unix filter does.
    let dir = fixtures("closed-pipe");
    let mut child = Command::new(env!("CARGO_BIN_EXE_findomain"))
        .args([
            "-t",
            "example.com",
            "--no-discover",
            "--import-subdomains",
            "import.txt",
        ])
        .current_dir(dir.root())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn findomain");

    // Read one byte, then drop the pipe so the next write hits EPIPE.
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut byte = [0_u8; 1];
    let _ = stdout.read(&mut byte);
    drop(stdout);

    let output = child.wait_with_output().expect("wait for findomain");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked"),
        "a closed pipe must not panic: {stderr}"
    );
    assert!(
        !stderr.contains("Broken pipe"),
        "a closed pipe must not be reported as an error: {stderr}"
    );
}

#[test]
fn several_files_can_be_imported_in_one_option_or_in_several() {
    // The documented form lists the files after one flag; the repeated form is
    // what clap accepts by default. Both have to work, and neither may swallow
    // the options that follow.
    let dir = fixtures("import-many");
    dir.write("more.txt", "extra.example.com\n");

    let together = run_in(
        &dir,
        &[
            "-t",
            "example.com",
            "-q",
            "--no-discover",
            "--import-subdomains",
            "import.txt",
            "more.txt",
        ],
    );
    assert_eq!(together.code, 0, "stderr: {}", together.stderr);
    assert!(together.stdout_lines().contains(&"extra.example.com"));
    assert!(together.stdout_lines().contains(&"sub1.example.com"));

    let repeated = run_in(
        &dir,
        &[
            "-t",
            "example.com",
            "-q",
            "--no-discover",
            "--import-subdomains",
            "import.txt",
            "--import-subdomains",
            "more.txt",
        ],
    );
    assert_eq!(repeated.stdout_lines(), together.stdout_lines());

    let followed_by_a_flag = run_in(
        &dir,
        &[
            "-t",
            "example.com",
            "-q",
            "--no-discover",
            "--import-subdomains",
            "import.txt",
            "more.txt",
            "--no-wildcards",
        ],
    );
    assert_eq!(
        followed_by_a_flag.code, 0,
        "stderr: {}",
        followed_by_a_flag.stderr
    );
}
