#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate lazy_static;

pub mod args;
pub mod errors;
pub mod files;
pub mod logic;
pub mod structs;
pub mod utils;

mod alerts;
mod database;
mod external_subs;
mod misc;
mod networking;
mod port_scanner;
mod resolvers;
mod screenshots;
mod sources;

use {
    crate::{
        errors::{check_monitoring_parameters, Result},
        structs::Args,
    },
    std::{thread, time::Duration},
};

pub fn get_subdomains(args: &mut Args) -> Result<()> {
    args.target = args.target.to_lowercase();
    //    let subdomains = sources::get_c99_subdomains(
    //      &format!(
    //        "https://api.c99.nl/subdomainfinder?key=KEY&domain={}&json",
    //      &args.target
    //        ),
    //      false,
    //)
    //    .unwrap();
    //  for sub in subdomains {
    //    println!("{}", sub)
    //    }
    //  std::process::exit(1);
    if args.take_screenshots {
        logic::test_chrome_availability(args)
    }
    if (args.monitoring_flag || args.no_monitor) && args.database_checker_counter == 0 {
        logic::test_database_connection(args);
        args.database_checker_counter += 1
    }
    if !args.quiet_flag && !args.query_jobname && !args.query_database {
        println!("\nTarget ==> {}\n", &args.target)
    }
    if args.query_database || args.query_jobname {
        database::query_findomain_database(args)?
    }

    if args.bruteforce {
        args.subdomains.extend(
            args.wordlists_data
                .iter()
                .map(|target| format!("{target}.{}", &args.target)),
        );
    }

    if args.monitoring_flag && !args.no_monitor {
        check_monitoring_parameters(args)?
    }

    if !args.no_discover {
        let discovered_subdomains = networking::search_subdomains(args);
        args.subdomains.extend(discovered_subdomains);
    };

    if !args.import_subdomains_from.is_empty() {
        let base_target = format!(".{}", args.target);
        let mut imported_subdomains =
            files::return_file_targets(args, args.import_subdomains_from.clone());
        imported_subdomains.retain(|target| !target.is_empty() && logic::validate_target(target));
        imported_subdomains.retain(|target| {
            !target.is_empty() && logic::validate_subdomain(&base_target, target, args)
        });
        args.subdomains.extend(imported_subdomains);
    }

    if args.subdomains.is_empty() {
        eprintln!(
            "\nNo subdomains were found for the target: {} ¡😭!\n",
            &args.target
        );
    } else {
        logic::works_with_data(args)?
    }
    if !args.quiet_flag
        && args.rate_limit != 0
        && (args.from_file_flag || args.from_stdin)
        && !args.is_last_target
        && !args.monitoring_flag
        && !args.no_monitor
    {
        println!(
            "Rate limit set to {} seconds, waiting to start next enumeration.",
            args.rate_limit
        );
        thread::sleep(Duration::from_secs(args.rate_limit))
    }

    args.subdomains.clear();

    Ok(())
}
