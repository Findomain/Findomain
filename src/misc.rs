use {
    crate::{args, errors::*},
    lazy_static,
    postgres::{Client, NoTls},
    rand::Rng,
    std::{collections::HashSet, fs, path::Path},
};

lazy_static! {
    static ref SPECIAL_CHARS: Vec<char> = vec![
        '[', ']', '{', '}', '(', ')', '*', '|', ':', '<', '>', '/', '\\', '%', '&', '¿', '?', '¡',
        '!', '#', '\'', ' ', ','
    ];
}

pub fn show_searching_msg(api: &str) {
    println!("Searching in the {} API... 🔍", api)
}

pub fn show_subdomains_found(subdomains_found: usize, args: &mut args::Args) {
    if !args.quiet_flag && (args.only_resolved || args.with_ip || args.ipv6_only) {
        if args.as_resolver {
            println!(
                "\n{} of {} subdomains were resolved in {} seconds.⏲️",
                subdomains_found,
                args.subdomains.len(),
                args.time_wasted.elapsed().as_secs()
            );
        } else if args.bruteforce {
            println!(
                "\n{} of {} bruteforce combinations were resolved in {} seconds.⏲️",
                subdomains_found,
                args.subdomains.len(),
                args.time_wasted.elapsed().as_secs()
            );
        } else {
            println!(
                "\n{} of {} subdomains found were resolved for domain {} 👽 in {} seconds.⏲️",
                subdomains_found,
                args.subdomains.len(),
                args.target,
                args.time_wasted.elapsed().as_secs()
            );
        }
    } else if !args.quiet_flag {
        println!(
            "\nA total of {} subdomains were found for domain {} 👽 in {} seconds.⏲️",
            subdomains_found,
            args.target,
            args.time_wasted.elapsed().as_secs()
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

pub fn validate_target(target: &str) -> bool {
    !target.starts_with('.')
        && target.contains('.')
        && !target.contains(&SPECIAL_CHARS[..])
        && target.chars().all(|c| c.is_ascii())
}

pub fn works_with_data(args: &mut args::Args) -> Result<()> {
    if args.unique_output_flag && !args.from_file_flag && !args.monitoring_flag {
        check_output_file_exists(&args.file_name)?;
        crate::manage_subdomains_data(args)?;
    } else if args.unique_output_flag && args.from_file_flag && !args.monitoring_flag {
        crate::manage_subdomains_data(args)?;
    } else if args.monitoring_flag && !args.unique_output_flag {
        crate::subdomains_alerts(args)?;
    } else {
        check_output_file_exists(&args.file_name)?;
        crate::manage_subdomains_data(args)?;
    }
    if args.with_output && !args.quiet_flag && !args.monitoring_flag {
        show_file_location(&args.target, &args.file_name)
    }
    if !args.quiet_flag {
        println!("\nGood luck Hax0r 💀!\n");
    }
    Ok(())
}

pub fn eval_resolved_or_ip_present(value: bool, with_ip: bool, resolved: bool) -> bool {
    if value && (with_ip || resolved) {
        true
    } else if !value {
        false
    } else {
        eprintln!("Error: --enable-dot flag needs -i/--ip or -r/--resolved");
        std::process::exit(1)
    }
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

pub fn sanitize_subdomain(base_target: &str, subdomain: &str) -> bool {
    !subdomain.is_empty()
        && !subdomain.starts_with('.')
        && subdomain.ends_with(base_target)
        && !subdomain.contains(&SPECIAL_CHARS[..])
        && subdomain.chars().all(|c| c.is_ascii())
}

pub fn check_http_response_code(
    api_name: &str,
    response: &reqwest::blocking::Response,
    quiet_flag: bool,
) -> bool {
    if response.status() == 200 {
        true
    } else {
        if !quiet_flag {
            println!(
                "The {} API has failed returning the following HTTP status: {}",
                api_name,
                response.status(),
            )
        };
        false
    }
}

pub fn test_database_connection(args: &mut args::Args) {
    if !args.quiet_flag {
        println!("Monitoring flag enabled, testing connection to database server...")
    }
    match Client::connect(&args.postgres_connection, NoTls) {
        Ok(_) => {
            if !args.quiet_flag {
                println!("Connected, performing enumeration!")
            }
        }
        Err(e) => {
            println!(
                "The following error happened while connecting to the database: {}",
                e
            );
            std::process::exit(1)
        }
    }
}

pub fn return_reqwest_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3835.0 Safari/537.36")
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap()
}
