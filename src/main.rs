use {
    clap::Parser,
    findomain::{cli::Cli, config::Config, runner},
};

/// Dies quietly when the reader of our output goes away.
///
/// Rust ignores `SIGPIPE`, which turns a closed pipe into a write error that
/// `println!` panics on: `findomain -t example.com | head` aborted and dumped
/// core. Restoring the default makes it end the way every other Unix filter
/// does.
#[cfg(unix)]
fn restore_sigpipe() {
    // Safe: setting a signal disposition before any thread is spawned.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
const fn restore_sigpipe() {}

fn main() {
    restore_sigpipe();

    let config = Config::from_cli(&Cli::parse());

    if let Err(err) = runner::run(&config) {
        eprintln!("\nError: {err}");
        for cause in err.chain().skip(1) {
            eprintln!("Error description: {cause}");
        }
        std::process::exit(1);
    }
}
