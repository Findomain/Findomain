#[macro_use]
extern crate clap;
use clap::App;

use findomain::{check_output_file_exists, get_subdomains, read_from_file};

fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    if matches.is_present("target") && matches.is_present("output") {
        let target = matches.value_of("target").unwrap().to_string();
        let with_output = "y";
        let file_name = &target;
        check_output_file_exists(&file_name);
        if matches.is_present("ip") {
            let with_ip = "y";
            get_subdomains(&target, &with_ip, &with_output, &file_name)
        } else {
            let with_ip = "";
            get_subdomains(&target, &with_ip, &with_output, &file_name)
        }
    } else if matches.is_present("target") {
        let target = matches.value_of("target").unwrap().to_string();
        let with_output = "n";
        let file_name = "";
        if matches.is_present("ip") {
            let with_ip = "y";
            get_subdomains(&target, &with_ip, &with_output, &file_name)
        } else {
            let with_ip = "";
            get_subdomains(&target, &with_ip, &with_output, &file_name)
        }
    } else if matches.is_present("file") && matches.is_present("output") {
        let with_output = "y";
        let file = matches.value_of("file").unwrap().to_string();
        if matches.is_present("ip") {
            let with_ip = "y";
            read_from_file(&file, &with_ip, &with_output)
        } else {
            let with_ip = "";
            read_from_file(&file, &with_ip, &with_output)
        }
    } else if matches.is_present("file") {
        let with_output = "n";
        let file = matches.value_of("file").unwrap().to_string();
        if matches.is_present("ip") {
            let with_ip = "y";
            read_from_file(&file, &with_ip, &with_output)
        } else {
            let with_ip = "";
            read_from_file(&file, &with_ip, &with_output)
        }
    }
}
