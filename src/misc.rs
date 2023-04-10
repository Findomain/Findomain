use {crate::utils::split_string_at_len, std::collections::HashSet};

pub fn show_searching_msg(api: &str) {
    println!("Searching in the {api} API... 🔍")
}

pub fn show_file_location(target: &str, file_name: &str) {
    println!(
        ">> 📁 Subdomains for {} were saved in: ./{} 😀",
        &target, &file_name
    )
}

pub fn return_webhook_payload(
    new_subdomains: &HashSet<String>,
    webhook_name: &str,
    target: &str,
) -> Vec<String> {
    if new_subdomains.is_empty() && webhook_name == "discord" {
        vec![format!(
            "**Findomain alert:** No new subdomains found for {}",
            &target
        )]
    } else if new_subdomains.is_empty() && webhook_name == "slack" {
        vec![format!(
            "*Findomain alert:* No new subdomains found for {}",
            &target
        )]
    } else if new_subdomains.is_empty() && webhook_name == "telegram" {
        vec![format!(
            "<b>Findomain alert:</b> No new subdomains found for {}",
            &target
        )]
    } else {
        let webhooks_payload = new_subdomains
            .clone()
            .into_iter()
            .collect::<Vec<_>>()
            .join("\n");
        if webhook_name == "discord" {
            let mut payloads = vec![format!(
                "**Findomain alert:** {} new subdomains found for {}\n",
                &new_subdomains.len(),
                &target,
            )];
            payloads.extend(split_string_at_len(&webhooks_payload, 1900));
            payloads
        } else if webhook_name == "slack" {
            let mut payloads = vec![format!(
                "*Findomain alert:* {} new subdomains found for {}\n",
                &new_subdomains.len(),
                &target,
            )];
            payloads.extend(split_string_at_len(&webhooks_payload, 15000));
            payloads
        } else if webhook_name == "telegram" {
            let mut payloads = vec![format!(
                "<b>Findomain alert:</b> {} new subdomains found for {}\n",
                &new_subdomains.len(),
                &target,
            )];
            payloads.extend(split_string_at_len(&webhooks_payload, 4000));
            payloads
        } else {
            vec![]
        }
    }
}

pub fn sanitize_target_string(target: String) -> String {
    target
        .replace("www.", "")
        .replace("https://", "")
        .replace("http://", "")
        .replace('/', "")
}

pub fn return_matches_vec(matches: &clap::ArgMatches, value: &str) -> Vec<String> {
    if matches.is_present(value) {
        matches
            .values_of(value)
            .unwrap()
            .map(str::to_owned)
            .collect()
    } else {
        Vec::new()
    }
}

pub fn return_matches_hashset(matches: &clap::ArgMatches, value: &str) -> HashSet<String> {
    if matches.is_present(value) {
        matches
            .values_of(value)
            .unwrap()
            .map(str::to_owned)
            .collect()
    } else {
        HashSet::new()
    }
}
