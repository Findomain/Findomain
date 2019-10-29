use std::env;

pub fn get_auth_token(api: &str) -> String {
    if api == "facebook" {
        if let Ok(token) = env::var("findomain_fb_token") {
            token
        } else {
            String::new()
        }
    } else if api == "spyce" {
        if let Ok(token) = env::var("findomain_spyse_token") {
            token
        } else {
            String::new()
        }
    } else if api == "virustotal" {
        if let Ok(token) = env::var("findomain_virustotal_token") {
            token
        } else {
            String::new()
        }
    } else if api == "telegram" {
        if let Ok(webhook) = env::var("findomain_telegrambot_token") {
            webhook
        } else {
            String::new()
        }
    } else {
        String::new()
    }
}

pub fn get_webhook(webhook: &str) -> String {
    if webhook == "discord" {
        if let Ok(webhook) = env::var("findomain_discord_webhook") {
            webhook
        } else {
            String::new()
        }
    } else if webhook == "slack" {
        if let Ok(webhook) = env::var("findomain_slack_webhook") {
            webhook
        } else {
            String::new()
        }
    } else {
        String::new()
    }
}

pub fn get_chat_id(chat: &str) -> String {
    if chat == "telegram" {
        if let Ok(chat_id) = env::var("findomain_telegrambot_chat_id") {
            chat_id
        } else {
            String::new()
        }
    } else {
        String::new()
    }
}
