#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate serde_derive;
extern crate reqwest;

use std::env;
use std::io;
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
                                   Version: 0.1.0

            Usage:

            findomain -i             Return the subdomain list with IP address if resolved.
            findomain                Return the subdomain list without IP address.
    "
    )
}

fn get_subdomains(with_ip: &str) -> Result<()> {
    let ct_api_url = format!("https:api.certspotter.com/v1/issuances?domain={target}&include_subdomains=true&expand=dns_names", target = str_input().replace("www.", "").replace("https://", "").replace("http://", "").replace("/", "")
    );
    let mut ct_data = reqwest::get(&ct_api_url)?;
    if ct_data.status() == 200 {
        let domains: Vec<Subdomains> = ct_data.json()?;
        println!("\nThe following hosts where found!\n");
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
    val
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

fn main() {
    banner();
    let args: Vec<String> = env::args().collect();
    if args.len() == 2 {
        let with_ip = &args[1];
        get_subdomains(with_ip);
    } else {
        let with_ip = "";
        get_subdomains(with_ip);
    }
}
