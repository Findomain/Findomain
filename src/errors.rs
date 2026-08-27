//! Error plumbing shared by the whole crate.

pub use anyhow::{Context, Result};

/// Reports an unrecoverable problem on stderr and terminates with exit code 1.
///
/// Diagnostics deliberately go to stderr so that stdout stays a clean stream of
/// subdomains that can be piped into other tools.
pub fn fatal(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1)
}
