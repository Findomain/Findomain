use std::error::Error as stdError;

pub use failure::{Error, ResultExt};
pub type Result<T> = ::std::result::Result<T, Error>;

pub fn check_request_errors(error: reqwest::Error, api: &str, quiet_flag: bool) {
    if !quiet_flag {
        if error.is_timeout() {
            eprintln!(
            "⏳ A timeout error has occurred while processing the request in the {} API. Error description: {}",
            &api, &error.description())
        } else if error.is_redirect() {
            eprintln!(
                "❌ A redirect was found while processing the {} API. Error description: {}",
                &api,
                &error.description()
            )
        } else if error.is_client_error() {
            eprintln!(
            "❌ A client error has occurred sending the request to the {} API. Error description: {}",
            &api,
            &error.description()
        )
        } else if error.is_server_error() {
            eprintln!(
            "❌ A server error has occurred sending the request to the {} API. Error description: {}",
            &api,
            &error.description()
        )
        } else {
            eprintln!(
            "❌ An error has occurred while procesing the request in the {} API. Error description: {}",
            &api,
            &error.description()
        )
        }
    }
}

pub fn check_json_errors(error: reqwest::Error, api: &str, quiet_flag: bool) {
    if !quiet_flag {
        eprintln!("❌ An error occurred while parsing the JSON obtained from the {} API. Error description: {}.", &api, error.description())
    }
}

pub fn telegram_err1() {
    eprintln!("You need to configure at least one webhook variable in your system. For Discord set the findomain_discord_webhook system variable, for Slack set the findomain_slack_webhook variable, for Telegram set the findomain_telegrambot_token and findomain_telegrambot_chat_id valriables. See https://git.io/JeZQW for more information, exiting.");
}

pub fn telegram_err2() {
    eprintln!("You have configured the findomain_telegrambot_token variable but not the findomain_telegrambot_chat_id variable, it's required. See https://git.io/JeZQW for more information, exiting.");
}
