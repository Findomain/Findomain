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
use std::io;
use std::io::{BufRead, BufReader};
use trust_dns_resolver::Resolver;

#[derive(Deserialize, Debug)]
struct Subdomains {
    dns_names: Vec<String>,
}

error_chain! {
    foreign_links {
        Reqwest(reqwest::Error);
    }
}

fn get_subdomains(target: &str, with_ip: &str) -> Result<()> {
    let ct_api_url = [
        "https://api.certspotter.com/v1/issuances?domain=",
        &target,
        "&include_subdomains=true&expand=dns_names",
    ]
    .concat();
    let mut ct_data = reqwest::get(&ct_api_url)?;
    println!("\nTarget: ==> {}", &target);
    if ct_data.status() == 200 {
        //        fn foo(domains: &Vec<Vec<String>>) -> std::collections::HashSet<&String> {
        //            domains.iter().flat_map(|sub| sub.iter()).collect()
        //        }
        let domains: Vec<Subdomains> = ct_data.json()?;
        println!("\nThe following subdomains were found for ==>  {}", &target);
        for domain in &domains {
            for subdomain in domain.dns_names.iter() {
                if with_ip == "y" {
                    let ipadress = get_ip(&subdomain);
                    println!(" --> {} : {}", &subdomain, &ipadress);
                } else {
                    println!(" --> {}", &subdomain);
                }
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

fn read_from_file(file: &str, with_ip: &str) -> io::Result<()> {
    if let Ok(f) = File::open(&file) {
        let f = BufReader::new(f);
        for line in f.lines() {
            get_subdomains(
                &line
                    .unwrap()
                    .to_string()
                    .replace("www.", "")
                    .replace("https://", "")
                    .replace("http://", "")
                    .replace("/", ""),
                &with_ip,
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

fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    if matches.is_present("target") {
        let target: String = matches.values_of("target").unwrap().collect();
        if matches.is_present("ip") {
            let with_ip = "y";
            get_subdomains(
                &target
                    .replace("www.", "")
                    .replace("https://", "")
                    .replace("http://", "")
                    .replace("/", ""),
                &with_ip,
            )
            .unwrap();
        } else {
            let with_ip = "";
            get_subdomains(
                &target
                    .replace("www.", "")
                    .replace("https://", "")
                    .replace("http://", "")
                    .replace("/", ""),
                &with_ip,
            )
            .unwrap();
        }
    } else if matches.is_present("file") {
        let file: String = matches.values_of("file").unwrap().collect();
        if matches.is_present("ip") {
            let with_ip = "y";
            read_from_file(&file, &with_ip).unwrap();
        } else {
            let with_ip = "";
            read_from_file(&file, &with_ip).unwrap();
        }
    }
}
