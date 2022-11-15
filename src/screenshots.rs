use {
    crate::files,
    anyhow::Result,
    headless_chrome::{protocol::cdp::Page::CaptureScreenshotFormatOption, Browser},
    std::{fs::write, path::Path},
};

pub fn take_screenshot(
    browser: Browser,
    target: &str,
    screenshots_dir: &str,
    root_domain: &str,
    output_image: &str,
) -> Result<()> {
    if files::check_image_path(screenshots_dir, root_domain) {
        if let Ok(jpeg_data) = browser
            .wait_for_initial_tab()?
            .set_default_timeout(std::time::Duration::from_secs(60))
            .navigate_to(target)?
            .wait_until_navigated()?
            .capture_screenshot(CaptureScreenshotFormatOption::Jpeg, Some(75), None, true)
        {
            write(
                Path::new(&format!(
                    "{}/{}/{}.jpeg",
                    screenshots_dir,
                    root_domain,
                    output_image
                        .replace("https://", "")
                        .replace("http://", "")
                        .replace(':', "_")
                )),
                jpeg_data,
            )?
        }
    }
    drop(browser);
    Ok(())
}
