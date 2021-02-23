use {
    crate::structs::Args,
    headless_chrome::{Browser, LaunchOptionsBuilder},
    reqwest::blocking::Client,
};

pub fn return_reqwest_client(secs: u64, args: &Args) -> Client {
    Client::builder()
        .user_agent(&args.user_agent)
        .timeout(std::time::Duration::from_secs(secs))
        .build()
        .unwrap()
}

pub fn return_headless_browser(sandbox: bool) -> Browser {
    match Browser::new(
        LaunchOptionsBuilder::default()
            .sandbox(sandbox)
            .window_size(Some((1920, 2500)))
            .build()
            .expect("Could not find appropriate Chrome binary."),
    ) {
        Ok(browser) => browser,
        Err(e) => {
            eprintln!("Error getting the Chrome/Chromium instance, make sure that it's properly installed.
Chromium/Chrome from Snap are known to cause problems, if you have installed it from there,
please uninstall it and reinstall without using Snap. Error: {}", e);
            std::process::exit(1)
        }
    }
}

pub fn calculate_timeout(threads: usize, timeout: u64) -> u64 {
    if timeout <= 500 {
        if threads >= 50 {
            timeout + 200
        } else if threads >= 100 {
            timeout + 300
        } else if threads >= 200 {
            timeout + 400
        } else if threads >= 300 {
            timeout + 500
        } else {
            timeout + 100
        }
    } else {
        timeout
    }
}
