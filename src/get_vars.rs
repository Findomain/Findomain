use std::env;

pub fn get_auth_token(api: &str) -> String {
    let empty_string = String::from("");
    if api == "facebook" {
        if let Ok(token) = env::var("findomain_fb_token") {
            token
        } else {
            empty_string
        }
    } else if api == "spyse" {
        if let Ok(token) = env::var("findomain_spyse_token") {
            token
        } else {
            empty_string
        }
    } else if api == "virustotal" {
        if let Ok(token) = env::var("findomain_virustotal_token") {
            token
        } else {
            empty_string
        }
    } else if api == "telegram" {
        if let Ok(webhook) = env::var("findomain_telegrambot_token") {
            webhook
        } else {
            empty_string
        }
    } else {
        empty_string
    }
}

pub fn get_webhook(webhook: &str) -> String {
    let empty_string = String::from("");
    if webhook == "discord" {
        if let Ok(webhook) = env::var("findomain_discord_webhook") {
            webhook
        } else {
            empty_string
        }
    } else if webhook == "slack" {
        if let Ok(webhook) = env::var("findomain_slack_webhook") {
            webhook
        } else {
            empty_string
        }
    } else {
        empty_string
    }
}

pub fn get_chat_id(chat: &str) -> String {
    let empty_string = String::from("");
    if chat == "telegram" {
        if let Ok(chat_id) = env::var("findomain_telegrambot_chat_id") {
            chat_id
        } else {
            empty_string
        }
    } else {
        empty_string
    }
}
