#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate lazy_static;

pub mod args;
pub mod errors;
pub mod files;
pub mod structs;

mod alerts;
mod database;
mod logic;
mod misc;
mod networking;
mod port_scanner;
mod resolvers;
mod screenshots;
mod sources;
mod utils;

use {
    crate::{errors::*, structs::Args},
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
    } else if args.bruteforce {
        args.subdomains = args
            .wordlists_data
            .iter()
            .map(|target| format!("{}.{}", target, &args.target))
            .collect();
        logic::manage_subdomains_data(args)?
    } else {
        if args.monitoring_flag && !args.no_monitor {
            check_monitoring_parameters(args)?
        }
        args.subdomains = networking::search_subdomains(args);
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
    }
    Ok(())
}
