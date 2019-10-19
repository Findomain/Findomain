use crate::errors::*;
use std::{
    collections::HashSet,
    fs::{self},
    path::Path,
};

pub fn show_searching_msg(api: &str) {
    println!("Searching in the {} API... 🔍", api)
}

pub fn show_subdomains_found(subdomains_found: usize, target: &str, quiet_flag: bool) {
    if !quiet_flag {
        println!(
            "\nA total of {} subdomains were found for ==>  {} 👽",
            subdomains_found, target
        )
    }
}

pub fn check_output_file_exists(file_name: &str) -> Result<()> {
    if Path::new(&file_name).exists() && Path::new(&file_name).is_file() {
        let backup_file_name = file_name.replace(&file_name.split('.').last().unwrap(), "old.txt");
        fs::rename(&file_name, &backup_file_name).with_context(|_| {
            format!(
                "The file {} already exists but Findomain can't backup the file to {}. Please run the tool with a more privileged user or try in a different directory.",
                &file_name, &backup_file_name,
            )
        })?;
    }
    Ok(())
}

pub fn return_webhook_payload(
    new_subdomains: &HashSet<String>,
    webhook_name: &str,
    target: &str,
) -> String {
    if new_subdomains.is_empty() && webhook_name == "discord" {
        format!(
            "**Findomain alert:** No new subdomains found for {}",
            &target
        )
    } else if new_subdomains.is_empty() && webhook_name == "slack" {
        format!("*Findomain alert:* No new subdomains found for {}", &target)
    } else if new_subdomains.is_empty() && webhook_name == "telegram" {
        format!(
            "<b>Findomain alert:</b> No new subdomains found for {}",
            &target
        )
    } else {
        let webhooks_payload = new_subdomains
            .clone()
            .into_iter()
            .collect::<Vec<_>>()
            .join("\n");
        if webhook_name == "discord" {
            if webhooks_payload.len() > 1900 {
                format!(
                    "**Findomain alert:** {} new subdomains found for {}\n```{}```",
                    &new_subdomains.len(),
                    &target,
                    webhooks_payload.split_at(1900).0.to_string()
                )
            } else {
                format!(
                    "**Findomain alert:** {} new subdomains found for {}\n```{}```",
                    &new_subdomains.len(),
                    &target,
                    webhooks_payload.to_string()
                )
            }
        } else if webhook_name == "slack" {
            if webhooks_payload.len() > 15000 {
                format!(
                    "*Findomain alert:* {} new subdomains found for {}\n```{}```",
                    &new_subdomains.len(),
                    &target,
                    webhooks_payload.split_at(15000).0.to_string()
                )
            } else {
                format!(
                    "*Findomain alert:* {} new subdomains found for {}\n```{}```",
                    &new_subdomains.len(),
                    &target,
                    webhooks_payload.to_string()
                )
            }
        } else if webhook_name == "telegram" {
            if webhooks_payload.len() > 4000 {
                format!(
                    "<b>Findomain alert:</b> {} new subdomains found for {}\n\n<code>{}</code>",
                    &new_subdomains.len(),
                    &target,
                    webhooks_payload.split_at(4000).0.to_string()
                )
            } else {
                format!(
                    "<b>Findomain alert:</b> {} new subdomains found for {}\n\n<code>{}</code>",
                    &new_subdomains.len(),
                    &target,
                    webhooks_payload.to_string()
                )
            }
        } else {
            String::from("")
        }
    }
}
