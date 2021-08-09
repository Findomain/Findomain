use {
    crate::{
        database,
        errors::*,
        files, logic, misc, networking,
        structs::{Args, ResolvData, Subdomain},
        utils,
    },
    postgres::{Client, NoTls},
    std::{
        collections::{HashMap, HashSet},
        thread,
        time::Duration,
    },
    trust_dns_resolver::Resolver,
};

fn push_data_to_webhooks(
    args: &mut Args,
    new_subdomains: &HashSet<String>,
    subdomains_data: HashMap<String, ResolvData>,
) -> Result<()> {
    let mut discord_parameters = HashMap::new();
    let mut slack_parameters = HashMap::new();
    let mut telegram_parameters = HashMap::new();
    let mut webhooks_data = HashMap::new();

    if !args.discord_webhook.is_empty() {
        discord_parameters.insert(
            "content",
            misc::return_webhook_payload(new_subdomains, "discord", &args.target),
        );
        webhooks_data.insert(&args.discord_webhook, discord_parameters);
    }

    if !args.slack_webhook.is_empty() {
        slack_parameters.insert(
            "text",
            misc::return_webhook_payload(new_subdomains, "slack", &args.target),
        );
        webhooks_data.insert(&args.slack_webhook, slack_parameters);
    }

    if !args.telegram_webhook.is_empty() {
        telegram_parameters.insert(
            "text",
            misc::return_webhook_payload(new_subdomains, "telegram", &args.target),
        );
        telegram_parameters.insert("chat_id", args.telegram_chat_id.clone());
        telegram_parameters.insert("parse_mode", "HTML".to_string());
        webhooks_data.insert(&args.telegram_webhook, telegram_parameters);
    }
    for (webhook, webhooks_payload) in webhooks_data {
        if !webhook.is_empty() {
            let response = utils::return_reqwest_client(15)
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
                        Client::connect(&args.postgres_connection, NoTls)?,
                        &subdomains_data,
                        &args.target,
                        args,
                    )
                    .is_ok()
                {
                    args.commit_to_db_counter += 1
                }
            } else {
                eprintln!(
                    "\nAn error occurred when Findomain tried to publish the data to the following webhook {}. \nError description: {}",
                    webhook, response.status()
                )
            }
        }
    }
    args.commit_to_db_counter = 0;
    Ok(())
}

pub fn subdomains_alerts(args: &mut Args, resolver: Resolver) -> Result<()> {
    let mut new_subdomains = HashSet::new();
    if args.with_imported_subdomains {
        let mut imported_subdomains =
            files::return_file_targets(args, args.import_subdomains_from.clone());
        imported_subdomains.retain(|target| !target.is_empty() && logic::validate_target(target));
        let base_target = &format!(".{}", args.target);
        imported_subdomains.retain(|target| {
            !target.is_empty() && logic::validate_subdomain(base_target, target, args)
        });
        for subdomain in imported_subdomains {
            args.subdomains.insert(subdomain);
        }
    }
    let mut connection: postgres::Client = Client::connect(&args.postgres_connection, NoTls)?;
    database::prepare_database(&args.postgres_connection)?;

    let statement: &str = &format!(
        "SELECT name FROM subdomains WHERE name LIKE '%{}'",
        &args.target
    );
    let existing_subdomains = connection.query(statement, &[])?;

    let existing_subdomains: HashSet<String> = existing_subdomains
        .iter()
        .map(|row| {
            let subdomain = Subdomain {
                name: row.get("name"),
            };
            subdomain.name
        })
        .collect();

    args.subdomains = {
        let newsubs: HashSet<String> = args
            .subdomains
            .difference(&existing_subdomains)
            .map(|sub| sub.to_string())
            .collect();
        if !newsubs.is_empty() {
            newsubs
        } else {
            HashSet::new()
        }
    };

    let resolv_data = networking::async_resolver_all(args, resolver);

    for (sub, resolv_data) in &resolv_data {
        new_subdomains.insert(format!(
            "HOST: {},IP: {},HTTP/S: {},OPEN PORTS: {}",
            sub,
            logic::null_ip_checker(&resolv_data.ip),
            logic::eval_http(&resolv_data.http_status),
            logic::return_ports_string(&resolv_data.open_ports, args)
        ));
    }

    if args.with_output && !new_subdomains.is_empty() {
        let filename = args.file_name.replace(
            &args.file_name.split('.').last().unwrap(),
            "new_subdomains.txt",
        );
        let file_name = files::return_output_file(args);
        files::check_output_file_exists(&filename)?;
        for subdomain in &new_subdomains {
            files::write_to_file(subdomain, &file_name)?
        }
        if !args.quiet_flag {
            misc::show_file_location(&args.target, &filename)
        }
    }

    if args.no_monitor && !args.monitoring_flag {
        if !new_subdomains.is_empty() {
            database::commit_to_db(
                Client::connect(&args.postgres_connection, NoTls)?,
                &resolv_data,
                &args.target,
                args,
            )?
        }
    } else if args.enable_empty_push || !new_subdomains.is_empty() {
        push_data_to_webhooks(args, &new_subdomains, resolv_data)?
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
        thread::sleep(Duration::from_secs(args.rate_limit))
    }
    Ok(())
}
