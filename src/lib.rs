#![allow(deprecated)] // In order to remove the warning for error_chain! when compiling.

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate serde_derive;

use trust_dns_resolver::Resolver;

use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Deserialize, PartialEq, PartialOrd, Ord, Eq)]
struct SubdomainsCertSpotter {
    dns_names: Vec<String>,
}

#[derive(Deserialize, PartialEq, PartialOrd, Ord, Eq)]
struct SubdomainsCrtsh {
    name_value: String,
}

#[derive(Deserialize, PartialEq, PartialOrd, Ord, Eq)]
struct SubdomainsVirustotal {
    id: String,
}

#[derive(Deserialize)]
struct ResponseDataVirusTotal {
    data: Vec<SubdomainsVirustotal>,
}

error_chain! {
    foreign_links {
        Reqwest(reqwest::Error);
    }
}

pub fn get_subdomains(
    target: &str,
    with_ip: &str,
    with_output: &str,
    file_format: &str,
) -> Result<()> {
    let target = target
        .replace("www.", "")
        .replace("https://", "")
        .replace("http://", "")
        .replace("/", "");
    let ct_api_url_certspotter = [
        "https://api.certspotter.com/v1/issuances?domain=",
        &target,
        "&include_subdomains=true&expand=dns_names",
    ]
    .concat();
    let ct_api_url_virustotal = [
        "https://www.virustotal.com/ui/domains/",
        &target,
        "/subdomains?limit=40",
    ]
    .concat();
    let ct_api_url_crtsh = ["https://crt.sh/?q=%", &target, "&output=json"].concat();
    let ct_api_url_sublist3r = ["https://api.sublist3r.com/search.php?domain=", &target].concat();

    println!("\nTarget ==> {}", &target);

    println!("\nSearching in the CertSpotter API...");
    match reqwest::get(&ct_api_url_certspotter) {
        Ok(mut ct_data_certspotter) => {
            let mut domains_certspotter: Vec<SubdomainsCertSpotter> = ct_data_certspotter.json()?;
            if domains_certspotter.is_empty() {
                println!(
                    "\nNo data was found for the target: {} in CertSpotter, ¡Sad 😭!",
                    &target
                );
            } else {
                println!(
                    "\nThe following subdomains were found for ==>  {} in CertSpotter.\n",
                    &target
                );
                domains_certspotter.sort();
                domains_certspotter.dedup();
                let fixed_subdomains: Vec<&String> = domains_certspotter
                    .iter()
                    .flat_map(|sub| sub.dns_names.iter())
                    .collect();
                for subdomain in &fixed_subdomains {
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
            }
        }
        Err(e) => check_errors(e, "CertSpotter"),
    }

    println!("\nSearching in the Crtsh API...");
    match reqwest::get(&ct_api_url_crtsh) {
        Ok(mut ct_data_crtsh) => {
            let mut domains_crtsh: Vec<SubdomainsCrtsh> = ct_data_crtsh.json()?;
            if domains_crtsh.is_empty() {
                println!(
                    "\nNo data was found for the target: {} in crt.sh, ¡Sad 😭!",
                    &target
                );
            } else {
                domains_crtsh.sort();
                domains_crtsh.dedup();
                println!(
                    "\nThe following subdomains were found for ==>  {} in crt.sh\n",
                    &target
                );
                for subdomain in &domains_crtsh {
                    let subdomain = &subdomain.name_value;
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
            }
        }
        Err(e) => check_errors(e, "Crtsh"),
    }

    println!("\nSearching in the Virustotal API...");
    match reqwest::get(&ct_api_url_virustotal) {
        Ok(mut ct_data_virustotal) => {
            let mut domains_virustotal = ct_data_virustotal.json::<ResponseDataVirusTotal>()?.data;
            if domains_virustotal.is_empty() {
                println!(
                    "\nNo data was found for the target: {} in Virustotal, ¡Sad 😭!",
                    &target
                );
            } else {
                domains_virustotal.sort();
                domains_virustotal.dedup();
                println!(
                    "\nThe following subdomains were found for ==>  {} in Virustotal\n",
                    &target
                );
                for subdomain in &domains_virustotal {
                    let subdomain = &subdomain.id;
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
            }
        }
        Err(e) => check_errors(e, "Virustotal"),
    }

    println!("\nSearching in the Sublist3r API...");
    match reqwest::get(&ct_api_url_sublist3r) {
        Ok(mut ct_data_sublist3r) => {
            let mut domains_sublist3r: Vec<String> = ct_data_sublist3r.json()?;
            if domains_sublist3r.is_empty() {
                println!(
                    "\nNo data was found for the target: {} in Sublist3r, ¡Sad 😭!",
                    &target
                );
            } else {
                domains_sublist3r.sort();
                domains_sublist3r.dedup();
                println!(
                    "\nThe following subdomains were found for ==>  {} in Sublist3r\n",
                    &target
                );
                for subdomain in &domains_sublist3r {
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
            }
        }
        Err(e) => check_errors(e, "Sublist3r"),
    }
    println!("\nGood luck Hax0r 💀!\n");
    Ok(())
}

pub fn get_ip(domain: &str) -> String {
    let resolver =
        Resolver::from_system_conf().expect("Error reading system resolver configuration.");
    if let Ok(ip_address) = resolver.lookup_ip(&domain) {
        let address = ip_address.iter().next().expect("An error as ocurred.");
        address.to_string()
    } else {
        String::from("Domain not resolved")
    }
}

pub fn read_from_file(
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

pub fn check_errors(error: reqwest::Error, api: &str) {
    use std::error::Error;
    if error.is_timeout() {
        println!(
            "\nA timeout error as occured while processing the request in the {} API. Error description: {}",
            &api, &error.description())
    } else if error.is_redirect() {
        println!(
            "\nA redirect was found while processing the {} API. Error description: {}",
            &api,
            &error.description()
        )
    } else if error.is_client_error() {
        println!(
            "\nA client error as occured sending the request to the {} API. Error description: {}",
            &api,
            &error.description()
        )
    } else if error.is_server_error() {
        println!(
            "\nA server error as occured sending the request to the {} API. Error description: {}",
            &api,
            &error.description()
        )
    } else {
        println!(
            "\nAn error as occured while procesing the request in the {} API. Error description: {}",
            &api,
            &error.description()
        )
    }
}

pub fn write_to_file(data: &str, target: &str, subdomain_ip: &str, file_format: &str) {
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
