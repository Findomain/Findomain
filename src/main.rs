#[macro_use]
extern crate clap;
use clap::App;

use findomain::errors::*;
use findomain::{get_subdomains, read_from_file};

fn run() -> Result<()> {
    let empty_value = String::from("");

    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    let target = if matches.is_present("target") {
        matches.value_of("target").unwrap().to_string()
    } else {
        empty_value.clone()
    };
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
        [&target, ".txt"].concat()
    } else if matches.is_present("unique-output") {
        matches.value_of("unique-output").unwrap().to_string()
    } else {
        empty_value
    };
    let unique_output_flag = if matches.is_present("unique-output") {
        "y"
    } else {
        ""
    };

    if matches.is_present("target") {
        get_subdomains(
            &target,
            &only_resolved,
            &with_output,
            &file_name,
            &unique_output_flag,
        )
    } else if matches.is_present("file") {
        let file = matches.value_of("file").unwrap().to_string();
        read_from_file(
            &file,
            &only_resolved,
            &with_output,
            &file_name,
            &unique_output_flag,
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
