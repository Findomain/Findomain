use {
    crate::files,
    failure::Fallible,
    headless_chrome::{protocol::page::ScreenshotFormat, Browser},
    std::{fs::write, path::Path},
};

pub fn take_screenshot(
    browser: Browser,
    target: &str,
    screenshots_dir: &str,
    root_domain: &str,
    output_image: &str,
) -> Fallible<()> {
    if files::check_image_path(&screenshots_dir, &root_domain) {
        if let Ok(jpeg_data) = browser
            .wait_for_initial_tab()?
            .set_default_timeout(std::time::Duration::from_secs(60))
            .navigate_to(target)?
            .wait_until_navigated()?
            .capture_screenshot(ScreenshotFormat::JPEG(Some(75)), None, true)
        {
            write(
                Path::new(&format!(
                    "{}/{}/{}.jpeg",
                    screenshots_dir, root_domain, output_image
                )),
                &jpeg_data,
            )?
        }
    }
    drop(browser);
    Ok(())
}
