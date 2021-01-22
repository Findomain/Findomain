use {rand::Rng, std::collections::HashSet};

pub fn show_searching_msg(api: &str) {
    println!("Searching in the {} API... 🔍", api)
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
                    webhooks_payload
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
                    webhooks_payload
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
                    webhooks_payload
                )
            }
        } else {
            String::new()
        }
    }
}

pub fn sanitize_target_string(target: String) -> String {
    target
        .replace("www.", "")
        .replace("https://", "")
        .replace("http://", "")
        .replace("/", "")
}

pub fn return_facebook_token() -> String {
    let findomain_fb_tokens = vec![
        "688177841647920|RAeNYr8jwFXGH9v-IhGv4tfHMpU",
        "772592906530976|CNkO7OxM6ssQgOBLCraC_dhKE7M",
        "1004691886529013|iiUStPqcXCELcwv89-SZQSqqFNY",
        "2106186849683294|beVoPBtLp3IWjpLsnF6Mpzo1gVM",
        "2095886140707025|WkO8gTgPtwmnNZL3NQ74z92DA-k",
        "434231614102088|pLJSVc9iOqxrG6NO7DDPrlkQ1qE",
        "431009107520610|AX8VNunXMng-ainHO8Ke0sdeMJI",
        "893300687707948|KW_O07biKRaW5fpNqeAeSrMU1W8",
        "2477772448946546|BXn-h2zX6qb4WsFvtOywrNsDixo",
        "509488472952865|kONi75jYL_KQ_6J1CHPQ1MH4x_U",
    ];
    findomain_fb_tokens[rand::thread_rng().gen_range(0, findomain_fb_tokens.len())].to_string()
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
