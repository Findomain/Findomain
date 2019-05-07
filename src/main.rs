#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate serde_derive;
extern crate reqwest;

// Crate clap
#[macro_use]
extern crate clap;
use clap::App;

use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::path::Path;
use trust_dns_resolver::Resolver;

#[derive(Deserialize)]
struct Subdomains {
    dns_names: Vec<String>,
}

error_chain! {
    foreign_links {
        Reqwest(reqwest::Error);
    }
}

fn get_subdomains(target: &str, with_ip: &str, with_output: &str, file_format: &str) -> Result<()> {
    let target = target
        .replace("www.", "")
        .replace("https://", "")
        .replace("http://", "")
        .replace("/", "");
    let ct_api_url = [
        "https://api.certspotter.com/v1/issuances?domain=",
        &target,
        "&include_subdomains=true&expand=dns_names",
    ]
    .concat();
    let mut ct_data = reqwest::get(&ct_api_url)?;
    println!("\nTarget ==> {}", &target);
    if ct_data.status() == 200 {
        let domains: Vec<Subdomains> = ct_data.json()?;
        println!("\nThe following subdomains were found for ==>  {}", &target);
        for subdomain in concat_domains(&domains) {
            if with_ip == "y" && with_output == "y" {
                let ipadress = get_ip(&subdomain);
                write_to_file(&subdomain, &target, &ipadress, &file_format);
                println!(" --> {} : {}", &subdomain, &ipadress);
            } else if with_ip == "y" {
                let ipadress = get_ip(&subdomain);
                println!(" --> {} : {}", &subdomain, &ipadress);
            } else if with_output == "y" {
                let ipadress = "";
                write_to_file(&subdomain, &target, &ipadress, &file_format);
                println!(" --> {}", &subdomain);
            } else {
                println!(" --> {}", &subdomain);
            }
        }
        println!("\nGood luck Hax0r!\n")
    } else {
        println!(
            "An error as ocurred while procesing the request, the status code is: {}",
            ct_data.status()
        );
    }
    Ok(())
}

fn get_ip(domain: &str) -> String {
    let resolver =
        Resolver::from_system_conf().expect("Error reading system resolver configuration.");
    if let Ok(ip_address) = resolver.lookup_ip(&domain) {
        let address = ip_address.iter().next().expect("An error as ocurred.");
        address.to_string()
    } else {
        String::from("Domain not resolved")
    }
}

fn read_from_file(
    file: &str,
    with_ip: &str,
    with_output: &str,
    file_format: &str,
) -> io::Result<()> {
    if let Ok(f) = File::open(&file) {
        let f = BufReader::new(f);
        for line in f.lines() {
            get_subdomains(
                &line.unwrap().to_string(),
                &with_ip,
                &with_output,
                &file_format,
            )
            .unwrap();
        }
    } else {
        println!(
            "Error: can't open file {}, please check the filename and try again.",
            &file
        );
    }
    Ok(())
}

fn concat_domains(domains: &Vec<Subdomains>) -> std::collections::HashSet<&String> {
    domains
        .iter()
        .flat_map(|sub| sub.dns_names.iter())
        .collect()
}

fn write_to_file(data: &str, target: &str, subdomain_ip: &str, file_format: &str) {
    let data = &[data, ",", subdomain_ip, ",", "\n"].concat();
    let filename = &[target, ".", file_format].concat();
    if Path::new(&filename).exists() {
        let mut output_file = OpenOptions::new()
            .append(true)
            .open(&filename)
            .expect("Can't open file.");
        output_file
            .write_all(&data.as_bytes())
            .expect("Failed writing to file.");
    } else {
        File::create(&filename).expect("Failed to create file.");
        let mut output_file = OpenOptions::new()
            .append(true)
            .open(&filename)
            .expect("Can't open file.");
        output_file
            .write_all("domain,ip\n".as_bytes())
            .expect("Failed writing to file.");
        output_file
            .write_all(&data.as_bytes())
            .expect("Failed writing to file.");
    }
}

fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    if matches.is_present("target") && matches.is_present("output") {
        let target: String = matches.values_of("target").unwrap().collect();
        let with_output = "y";
        let file_format: String = matches.values_of("output").unwrap().collect();
        if matches.is_present("ip") {
            let with_ip = "y";
            get_subdomains(&target, &with_ip, &with_output, &file_format).unwrap();
        } else {
            let with_ip = "";
            get_subdomains(&target, &with_ip, &with_output, &file_format).unwrap();
        }
    } else if matches.is_present("target") {
        let target: String = matches.values_of("target").unwrap().collect();
        let with_output = "n";
        let file_format = "n";
        if matches.is_present("ip") {
            let with_ip = "y";
            get_subdomains(&target, &with_ip, &with_output, &file_format).unwrap();
        } else {
            let with_ip = "";
            get_subdomains(&target, &with_ip, &with_output, &file_format).unwrap();
        }
    } else if matches.is_present("file") && matches.is_present("output") {
        let with_output = "y";
        let file_format: String = matches.values_of("output").unwrap().collect();
        let file: String = matches.values_of("file").unwrap().collect();
        if matches.is_present("ip") {
            let with_ip = "y";
            read_from_file(&file, &with_ip, &with_output, &file_format).unwrap();
        } else {
            let with_ip = "";
            read_from_file(&file, &with_ip, &with_output, &file_format).unwrap();
        }
    } else if matches.is_present("file") {
        let with_output = "n";
        let file_format = "n";
        let file: String = matches.values_of("file").unwrap().collect();
        if matches.is_present("ip") {
            let with_ip = "y";
            read_from_file(&file, &with_ip, &with_output, &file_format).unwrap();
        } else {
            let with_ip = "";
            read_from_file(&file, &with_ip, &with_output, &file_format).unwrap();
        }
    }
}
