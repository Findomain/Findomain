use crate::args;
pub use failure::{Error, ResultExt};
pub type Result<T> = ::std::result::Result<T, Error>;

pub fn check_request_errors(error: reqwest::Error, api: &str, quiet_flag: bool) {
    if !quiet_flag {
        eprintln!("❌ Error in {} API. {} ", &api, &error)
    }
}

pub fn check_json_errors(error: reqwest::Error, api: &str, quiet_flag: bool) {
    if !quiet_flag {
        eprintln!("❌ An error occurred while parsing the JSON obtained from the {} API. Error description: {:?}.", &api, error)
    }
}

pub fn check_monitoring_parameters(args: &mut args::Args) -> Result<()> {
    if args.discord_webhook.is_empty()
        && args.slack_webhook.is_empty()
        && args.telegram_bot_token.is_empty()
        && args.telegram_chat_id.is_empty()
    {
        eprintln!("You need to configure at least one webhook variable in your system. For Discord set the findomain_discord_webhook system variable, for Slack set the findomain_slack_webhook variable, for Telegram set the findomain_telegrambot_token and findomain_telegrambot_chat_id valriables. See https://git.io/JeZQW for more information, exiting.");
        std::process::exit(1)
    } else if (args.telegram_bot_token.is_empty() && !args.telegram_chat_id.is_empty())
        || (!args.telegram_bot_token.is_empty() && args.telegram_chat_id.is_empty())
    {
        eprintln!("You need to set the findomain_telegrambot_chat_id an findomain_telegrambot_token variables if you want to use Telegram webhooks. See https://git.io/JeZQW for more information, exiting.");
        std::process::exit(1)
    } else if !args.telegram_bot_token.is_empty() && !args.telegram_chat_id.is_empty() {
        args.telegram_webhook = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            args.telegram_bot_token
        )
    }
    Ok(())
}
