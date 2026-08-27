//! Screenshots of the discovered HTTP servers, taken with headless Chrome.

use {
    crate::{config::Config, errors::Result, files},
    anyhow::anyhow,
    headless_chrome::{
        protocol::cdp::Page::CaptureScreenshotFormatOption, Browser, LaunchOptionsBuilder,
    },
    std::{ffi::OsStr, fs::write, path::Path, time::Duration},
};

/// Attempts made before giving up on a host.
const ATTEMPTS: usize = 4;
/// How long a page is given to load.
const NAVIGATION_TIMEOUT: Duration = Duration::from_secs(60);
const JPEG_QUALITY: u32 = 75;
/// Emulated viewport; tall on purpose so long pages are captured whole.
const WINDOW_SIZE: (u32, u32) = (1920, 2500);

/// Result of trying to screenshot a single host.
#[derive(Debug)]
pub enum ScreenshotOutcome {
    Captured,
    Failed(anyhow::Error),
}

/// Screenshots `url`, retrying a few times before reporting a failure.
///
/// Chrome is flaky under load, so a first failure says little; the browser is
/// relaunched from scratch on every attempt.
#[must_use]
pub fn capture(
    config: &Config,
    url: &str,
    root_domain: &str,
    output_image: &str,
) -> ScreenshotOutcome {
    let mut last_error = None;

    for _ in 0..ATTEMPTS {
        match take(config, url, root_domain, output_image) {
            Ok(()) => return ScreenshotOutcome::Captured,
            Err(e) => last_error = Some(e),
        }
    }

    ScreenshotOutcome::Failed(
        last_error.unwrap_or_else(|| anyhow!("no screenshot attempt was made")),
    )
}

/// Aborts early when Chrome is missing, rather than failing on every host.
pub fn check_availability(config: &Config) {
    if !config.general.quiet {
        println!("Testing Chromium/Chrome availability...");
    }
    if let Err(e) = launch(config.screenshots.sandbox) {
        eprintln!(
            "Error getting the Chrome/Chromium instance, make sure that it's properly installed.
Chromium/Chrome from Snap are known to cause problems, if you have installed it from there,
please uninstall it and reinstall without using Snap. Error: {e}"
        );
        std::process::exit(1)
    }
    println!("Chromium/Chrome is correctly installed, performing enumeration!");
}

/// Navigates to `url` once and writes the resulting JPEG.
fn take(config: &Config, url: &str, root_domain: &str, output_image: &str) -> Result<()> {
    let directory = &config.screenshots.path;
    if !files::ensure_screenshot_dir(directory, root_domain) {
        return Err(anyhow!(
            "can't create the screenshots directory {directory}/{root_domain}"
        ));
    }

    let browser = launch(config.screenshots.sandbox)?;
    let jpeg = browser
        .new_tab()?
        .set_default_timeout(NAVIGATION_TIMEOUT)
        .navigate_to(url)?
        .wait_until_navigated()?
        .capture_screenshot(
            CaptureScreenshotFormatOption::Jpeg,
            Some(JPEG_QUALITY),
            None,
            true,
        )?;

    write(
        Path::new(&image_path(directory, root_domain, output_image)),
        jpeg,
    )?;
    Ok(())
}

/// Builds the path an image is stored at.
fn image_path(directory: &str, root_domain: &str, output_image: &str) -> String {
    let name = output_image
        .replace("https://", "")
        .replace("http://", "")
        .replace(':', "_");
    format!("{directory}/{root_domain}/{name}.jpeg")
}

/// Starts a headless Chrome instance.
fn launch(sandbox: bool) -> Result<Browser> {
    let options = LaunchOptionsBuilder::default()
        .sandbox(sandbox)
        .window_size(Some(WINDOW_SIZE))
        .ignore_certificate_errors(true)
        .args(vec![OsStr::new("--disable-crash-reporter")])
        .build()
        .map_err(|e| anyhow!("Could not find appropriate Chrome binary. {e}"))?;

    Browser::new(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_paths_are_filesystem_safe() {
        assert_eq!(
            image_path("shots", "example.com", "https://a.example.com"),
            "shots/example.com/a.example.com.jpeg"
        );
        assert_eq!(
            image_path("shots", "example.com", "http://a.example.com:8080"),
            "shots/example.com/a.example.com_8080.jpeg"
        );
        assert_eq!(
            image_path("shots", "example.com", "a.example.com"),
            "shots/example.com/a.example.com.jpeg"
        );
    }
}
