#[macro_use]
extern crate clap;
use clap::App;

use findomain::errors::*;
use findomain::{get_subdomains, read_from_file};

fn run() -> Result<()> {
    let empty_value = String::from("");

    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    let target = value_t!(matches, "target", String).unwrap_or_else(|_| empty_value.clone());

    let only_resolved = if matches.is_present("resolved") {
        "y"
    } else {
        ""
    };
    let with_output = if matches.is_present("output") || matches.is_present("unique-output") {
        "y"
    } else {
        "n"
    };
    let file_name = if matches.is_present("output") && matches.is_present("target") {
        format!("{}.txt", &target)
    } else if matches.is_present("unique-output") {
        matches.value_of("unique-output").unwrap().to_string()
    } else {
        empty_value.clone()
    };
    let unique_output_flag = if matches.is_present("unique-output") {
        "y"
    } else {
        ""
    };

    let monitoring_flag = if matches.is_present("monitoring-flag") {
        "y"
    } else {
        ""
    };
    let from_file_flag = if matches.is_present("file") { "y" } else { "" };
    let postgres_user =
        value_t!(matches, "postgres-user", String).unwrap_or_else(|_| "postgres".to_string());

    let postgres_password =
        value_t!(matches, "postgres-password", String).unwrap_or_else(|_| "postgres".to_string());

    let postgres_host =
        value_t!(matches, "postgres-host", String).unwrap_or_else(|_| "localhost".to_string());

    let postgres_port = value_t!(matches, "postgres-port", usize).unwrap_or_else(|_| 5432);

    let postgres_database =
        value_t!(matches, "postgres-database", String).unwrap_or_else(|_| empty_value.clone());

    let postgres_connection = if matches.is_present("monitoring-flag") {
        format!(
            "postgresql://{}:{}@{}:{}/{}",
            postgres_user, postgres_password, postgres_host, postgres_port, postgres_database
        )
    } else {
        empty_value.clone()
    };

    if matches.is_present("target") {
        get_subdomains(
            &target,
            &only_resolved,
            &with_output,
            &file_name,
            &unique_output_flag,
            &monitoring_flag,
            &from_file_flag,
            &postgres_connection,
        )
    } else if matches.is_present("file") {
        let file = matches.value_of("file").unwrap().to_string();
        read_from_file(
            &file,
            &only_resolved,
            &with_output,
            &file_name,
            &unique_output_flag,
            &monitoring_flag,
            &from_file_flag,
            &postgres_connection,
        )
    } else {
        Ok(())
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("\nError: {}", err);
        for cause in err.iter_chain().skip(1) {
            eprintln!("Error description: {}", cause);
        }
        std::process::exit(1);
    }
}
