//! Reading input files and writing the results.

use {
    crate::{
        errors::{fatal, Context, Result},
        utils::{sanitize_host_string, sanitize_target_string},
    },
    std::{
        fs::{self, File, OpenOptions},
        io::{BufRead, BufReader, Write},
        path::{Path, PathBuf},
    },
};

/// How the lines of an input file should be interpreted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LineKind {
    /// Targets written by a human: strip the scheme, a leading `www.` and any
    /// path, because the enumeration wants the registrable domain.
    Target,
    /// Known hostnames: strip the scheme and any path but keep every label.
    /// `www.shop.example.com` is a subdomain in its own right.
    Subdomain,
    /// Verbatim values such as wordlist entries, resolver IPs or full URLs.
    Raw,
}

/// Reads every line of `paths`, sorted and deduplicated.
///
/// A file that cannot be opened is fatal when it is the only one given,
/// otherwise it is reported and skipped.
#[must_use]
pub fn read_lines(paths: &[String], kind: LineKind, quiet: bool) -> Vec<String> {
    let mut unique_paths = paths.to_vec();
    unique_paths.sort();
    unique_paths.dedup();

    let only_one = unique_paths.len() == 1;
    let mut lines = Vec::new();

    for path in unique_paths {
        match File::open(&path) {
            Ok(file) => lines.extend(BufReader::new(file).lines().map_while(Result::ok).map(
                |line| match kind {
                    LineKind::Target => sanitize_target_string(&line),
                    LineKind::Subdomain => sanitize_host_string(&line),
                    LineKind::Raw => line,
                },
            )),
            Err(e) if only_one => fatal(&format!("Can not open file {path}. Error: {e}")),
            Err(e) => {
                if !quiet {
                    eprintln!("Can not open file {path}, working with next file. Error: {e}");
                }
            }
        }
    }

    lines.sort();
    lines.dedup();
    lines
}

/// Appends `data` and a newline to `file`, doing nothing when there is none.
///
/// # Errors
///
/// Fails when the data cannot be written.
pub fn write_line(data: &str, file: Option<&File>) -> Result<()> {
    if let Some(mut file) = file {
        file.write_all(data.as_bytes())?;
        file.write_all(b"\n")?;
    }
    Ok(())
}

/// Appends `data` to `file`, making sure it ends with a newline.
///
/// # Errors
///
/// Fails when the data cannot be written.
pub fn append_string(data: &str, mut file: &File) -> Result<()> {
    file.write_all(data.as_bytes())?;
    if !data.ends_with('\n') {
        file.write_all(b"\n")?;
    }
    Ok(())
}

/// Opens `file_name` for appending, or returns `None` when output is disabled.
///
/// # Errors
///
/// Fails when the file exists but cannot be opened for appending.
pub fn open_output_file(file_name: &str, enabled: bool) -> Result<Option<File>> {
    if !enabled || file_name.is_empty() {
        return Ok(None);
    }
    OpenOptions::new()
        .append(true)
        .create(true)
        .open(file_name)
        .map(Some)
        .with_context(|| format!("Can't create file 📁 {file_name}"))
}

/// Renames an existing result file out of the way so the run starts clean.
///
/// `results.txt` is moved to `results.old.txt`.
///
/// # Errors
///
/// Fails when the file exists but cannot be renamed.
pub fn backup_existing(file_name: &str) -> Result<()> {
    let path = Path::new(file_name);
    if !path.is_file() {
        return Ok(());
    }
    let backup = derived_name(file_name, "old.txt");
    fs::rename(path, &backup).with_context(|| {
        format!(
            "The file {file_name} already exists but Findomain can't backup the file to {backup}. Please run the tool with a more privileged user or try in a different directory.",
        )
    })
}

/// Replaces the extension of `file_name` with `extension`.
///
/// `example.com.txt` plus `old.txt` gives `example.com.old.txt`.
#[must_use]
pub fn derived_name(file_name: &str, extension: &str) -> String {
    PathBuf::from(file_name)
        .with_extension(extension)
        .to_string_lossy()
        .into_owned()
}

/// Makes sure `<screenshots_dir>/<target>/` exists, reporting success.
#[must_use]
pub fn ensure_screenshot_dir(screenshots_dir: &str, target: &str) -> bool {
    let full_path = format!("{screenshots_dir}/{target}");
    Path::new(&full_path).is_dir() || fs::create_dir_all(&full_path).is_ok()
}

#[cfg(test)]
mod tests {
    use {super::*, crate::test_support::TempDir};

    #[test]
    fn derived_name_swaps_the_extension() {
        assert_eq!(
            derived_name("example.com.txt", "old.txt"),
            "example.com.old.txt"
        );
        assert_eq!(derived_name("out.txt", "old.txt"), "out.old.txt");
        assert_eq!(derived_name("results", "old.txt"), "results.old.txt");
        // The old implementation produced "old.txt.com.old.txt" here.
        assert_eq!(derived_name("txt.com.txt", "old.txt"), "txt.com.old.txt");
        assert_eq!(
            derived_name("example.com.txt", "new_subdomains.txt"),
            "example.com.new_subdomains.txt"
        );
    }

    #[test]
    fn read_lines_sorts_dedupes_and_sanitizes() {
        let dir = TempDir::new("read_lines");
        let first = dir.write("a.txt", "https://www.b.example.com/\nb.example.com\n");
        let second = dir.write("b.txt", "a.example.com\n");

        let targets = read_lines(&[first.clone(), second], LineKind::Target, true);
        assert_eq!(targets, vec!["a.example.com", "b.example.com"]);

        // Raw keeps the line untouched.
        let raw = read_lines(&[first], LineKind::Raw, true);
        assert_eq!(raw, vec!["b.example.com", "https://www.b.example.com/"]);
    }

    #[test]
    fn read_lines_dedupes_repeated_paths() {
        let dir = TempDir::new("read_lines_dupes");
        let path = dir.write("words.txt", "dev\nmail\n");
        assert_eq!(
            read_lines(&[path.clone(), path], LineKind::Raw, true),
            vec!["dev", "mail"]
        );
    }

    #[test]
    fn read_lines_skips_a_missing_file_when_others_are_given() {
        let dir = TempDir::new("read_lines_missing");
        let good = dir.write("good.txt", "a.example.com\n");
        let missing = dir.path("missing.txt");
        assert_eq!(
            read_lines(&[good, missing], LineKind::Target, true),
            vec!["a.example.com"]
        );
    }

    #[test]
    fn backup_existing_renames_and_tolerates_a_missing_file() {
        let dir = TempDir::new("backup");
        let target = dir.write("example.com.txt", "old results\n");
        backup_existing(&target).expect("rename succeeds");
        assert!(!Path::new(&target).exists());
        assert_eq!(
            fs::read_to_string(dir.path("example.com.old.txt")).unwrap(),
            "old results\n"
        );
        // A second call is a no-op rather than an error.
        backup_existing(&target).expect("missing file is fine");
    }

    #[test]
    fn open_output_file_honours_the_enabled_flag() {
        let dir = TempDir::new("open_output");
        let path = dir.path("out.txt");
        assert!(open_output_file(&path, false).unwrap().is_none());
        assert!(open_output_file("", true).unwrap().is_none());
        assert!(open_output_file(&path, true).unwrap().is_some());
    }

    #[test]
    fn write_line_appends_a_newline_and_skips_when_absent() {
        let dir = TempDir::new("write_line");
        let path = dir.path("out.txt");
        let file = open_output_file(&path, true).unwrap().unwrap();
        write_line("a.example.com", Some(&file)).unwrap();
        write_line("b.example.com", Some(&file)).unwrap();
        write_line("ignored", None).unwrap();
        drop(file);
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "a.example.com\nb.example.com\n"
        );
    }

    #[test]
    fn append_string_adds_a_trailing_newline_only_when_needed() {
        let dir = TempDir::new("append_string");
        let path = dir.path("out.txt");
        let file = open_output_file(&path, true).unwrap().unwrap();
        append_string("a\nb", &file).unwrap();
        append_string("c\n", &file).unwrap();
        drop(file);
        assert_eq!(fs::read_to_string(&path).unwrap(), "a\nb\nc\n");
    }

    #[test]
    fn ensure_screenshot_dir_creates_nested_directories() {
        let dir = TempDir::new("shots");
        let base = dir.path("shots");
        assert!(ensure_screenshot_dir(&base, "example.com"));
        assert!(Path::new(&format!("{base}/example.com")).is_dir());
        // Idempotent.
        assert!(ensure_screenshot_dir(&base, "example.com"));
    }
}
