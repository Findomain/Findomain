use {
    crate::{
        database::{self, return_database_connection},
        errors::Result,
        files, logic, misc, networking,
        structs::{Args, ResolvData},
        utils,
    },
    std::{
        collections::{HashMap, HashSet},
        net::Ipv4Addr,
        thread,
        time::Duration,
    },
};

fn push_data_to_webhooks(
    args: &mut Args,
    new_subdomains: &HashSet<String>,
    subdomains_data: &HashMap<String, ResolvData>,
) -> Result<()> {
    let mut discord_parameters = HashMap::new();
    let mut slack_parameters = HashMap::new();
    let mut telegram_parameters = HashMap::new();
    let mut webhooks_data = HashMap::new();

    if !args.discord_webhook.is_empty() {
        webhooks_data.clear();
        for data in &misc::return_webhook_payload(new_subdomains, "discord", &args.target) {
            // Add formatting to the webhook payload
            let data = format!("```{data}```");
            discord_parameters.insert("content", data.to_string());
            webhooks_data.insert(args.discord_webhook.clone(), discord_parameters.clone());
            send_webhook_alert(&webhooks_data, args, new_subdomains, subdomains_data)?;
        }
    }

    if !args.slack_webhook.is_empty() {
        webhooks_data.clear();
        for data in &misc::return_webhook_payload(new_subdomains, "slack", &args.target) {
            // Add formatting to the webhook payload
            let data = format!("```{data}```");
            slack_parameters.insert("text", data.to_string());
            webhooks_data.insert(args.slack_webhook.clone(), slack_parameters.clone());
            send_webhook_alert(&webhooks_data, args, new_subdomains, subdomains_data)?;
        }
    }

    if !args.telegram_webhook.is_empty() {
        telegram_parameters.insert("chat_id", args.telegram_chat_id.clone());
        telegram_parameters.insert("parse_mode", "HTML".to_string());
        for data in &misc::return_webhook_payload(new_subdomains, "telegram", &args.target) {
            // Add formatting to the webhook payload
            let data = format!("<code>{data}</code>");
            telegram_parameters.insert("text", data.to_string());
            webhooks_data.insert(args.telegram_webhook.clone(), telegram_parameters.clone());
            send_webhook_alert(&webhooks_data, args, new_subdomains, subdomains_data)?;
        }
    }

    args.commit_to_db_counter = 0;
    Ok(())
}

pub fn subdomains_alerts(args: &mut Args) -> Result<()> {
    let mut new_subdomains = HashSet::new();

    let existing_subdomains = database::return_existing_subdomains(args)?;

    args.subdomains = args
        .subdomains
        .difference(&existing_subdomains)
        .map(ToString::to_string)
        .collect();

    let resolv_data = networking::async_resolver_all(args);

    for (sub, resolv_data) in &resolv_data {
        if args.enable_port_scan || args.discover_ip || args.http_status {
            if resolv_data.ip.parse::<Ipv4Addr>().is_ok() {
                new_subdomains.insert(format!(
                    "HOST: {},IP: {},HTTP/S: {},OPEN PORTS: {}",
                    sub,
                    &resolv_data.ip,
                    logic::eval_http(&resolv_data.http_data),
                    logic::return_ports_string(&resolv_data.open_ports, args)
                ));
            }
        } else {
            new_subdomains.insert(format!(
                "HOST: {},IP: {},HTTP/S: {},OPEN PORTS: {}",
                sub,
                logic::null_ip_checker(&resolv_data.ip),
                logic::eval_http(&resolv_data.http_data),
                logic::return_ports_string(&resolv_data.open_ports, args)
            ));
        }
    }

    if args.with_output && !new_subdomains.is_empty() {
        let filename = args.file_name.replace(
            args.file_name.split('.').next_back().unwrap(),
            "new_subdomains.txt",
        );
        let file_name = files::return_output_file(args);
        files::check_output_file_exists(&filename)?;
        for subdomain in &new_subdomains {
            files::write_to_file(subdomain, file_name.as_ref())?;
        }
        if !args.quiet_flag {
            misc::show_file_location(&args.target, &filename);
        }
    }

    if (args.no_monitor && !args.monitoring_flag)
        || (new_subdomains.is_empty() && !resolv_data.is_empty() && !args.enable_empty_push)
    {
        database::commit_to_db(
            return_database_connection(&args.postgres_connection),
            &resolv_data,
            &args.target,
            args,
        )?;
    } else if args.enable_empty_push || !new_subdomains.is_empty() {
        push_data_to_webhooks(args, &new_subdomains, &resolv_data)?;
    }

    if !args.quiet_flag
        && args.rate_limit != 0
        && (args.from_file_flag || args.from_stdin)
        && !args.is_last_target
    {
        println!(
            "\nRate limit set to {} seconds, waiting to start next enumeration.",
            args.rate_limit
        );
        thread::sleep(Duration::from_secs(args.rate_limit));
    }
    Ok(())
}

pub fn send_webhook_alert(
    webhooks_data: &HashMap<String, HashMap<&str, String>>,
    args: &mut Args,
    new_subdomains: &HashSet<String>,
    subdomains_data: &HashMap<String, ResolvData>,
) -> Result<()> {
    for (webhook, webhooks_payload) in webhooks_data {
        if !webhook.is_empty() {
            let response = utils::return_reqwest_client(30)
                .post(webhook)
                .json(&webhooks_payload)
                .send()?;
            if (response.status() == 200 || response.status() == 204)
                || (["408", "504", "598", "524", "460"].contains(&response.status().as_str())
                    && args.dbpush_if_timeout)
            {
                if args.commit_to_db_counter == 0
                    && !new_subdomains.is_empty()
                    && database::commit_to_db(
                        return_database_connection(&args.postgres_connection),
                        subdomains_data,
                        &args.target,
                        args,
                    )
                    .is_ok()
                {
                    args.commit_to_db_counter += 1;
                }
            } else {
                eprintln!(
                    "\nAn error occurred when Findomain tried to publish the data to the following webhook {}. \nError description: {}",
                    webhook, response.status()
                );
            }
        }
    }

    Ok(())
}
