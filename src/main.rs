#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate serde_derive;
extern crate reqwest;

use std::env;
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

fn banner() {
    println!(
        "
                                 --- Findomain ---
            A tool that use Certificates Transparency logs to find subdomains.
                          Autor: Eduard Tolosa - @edu4rdshl
                                   Version: 0.1.1

            Usage:

            findomain                Return the subdomain list without IP address.
            findomain -i             Return the subdomain list with IP address if resolved.
            findomain -f <file>      Return the subdomain list for host specified in a file.
            findomain -i -f <file>   Return the subdomain list for host specified in a file with IP address if resolved.
    "
    )
}

fn get_subdomains(target: String, with_ip: &str) -> Result<()> {
    let ct_api_url = [
        "https:api.certspotter.com/v1/issuances?domain=",
        &target,
        "&include_subdomains=true&expand=dns_names",
    ]
    .concat();
    let mut ct_data = reqwest::get(&ct_api_url)?;
    println!("\nTarget: ==> {}", &target);
    if ct_data.status() == 200 {
        let domains: Vec<Subdomains> = ct_data.json()?;
        println!("\nThe following hosts were found for ==>  {}", target);
        for domain in &domains {
            for subdomain in domain.dns_names.iter() {
                if with_ip.is_empty() || with_ip != "-i" {
                    println!(" --> {}", subdomain);
                } else {
                    let ipadress = get_ip(&subdomain);
                    println!(" --> {} : {}", subdomain, ipadress);
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

fn str_input() -> String {
    use std::io::Write;
    print!("Enter the target: ");
    io::stdout().flush().expect("Error reading input.");
    let mut val = String::new();

    io::stdin()
        .read_line(&mut val)
        .expect("Error getting target.");
    val.replace("www.", "")
        .replace("https://", "")
        .replace("http://", "")
        .replace("/", "")
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
            get_subdomains(line.unwrap(), with_ip);
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
    banner();
    let args: Vec<String> = env::args().collect();
    if args.len() <= 1 {
        let with_ip = "";
        let target = str_input();
        get_subdomains(target, with_ip);
    } else if args.len() >= 4 && &args[1] == "-i" && &args[2] == "-f" {
        let with_ip = &args[1];
        read_from_file(&args[3], with_ip);
    } else if args.len() >= 3 && &args[1] == "-f" {
        let with_ip = "";
        read_from_file(&args[2], with_ip);
    } else if &args[1] == "-i" {
        let target = str_input();
        get_subdomains(target, &args[1]);
    } else {
        let target = str_input();
        let with_ip = "";
        get_subdomains(target, with_ip);
    }
}
