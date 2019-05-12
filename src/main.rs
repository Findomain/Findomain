#![allow(deprecated)] // In order to remove the warning for error_chain! when compiling.

// Import of external crates: serde, reqwest, error_chain.
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate serde_derive;
extern crate reqwest;

// Specific imports of Crate clap.
#[macro_use]
extern crate clap;
use clap::App;

// Specific imports of Crate trust-dns-resolver.
use trust_dns_resolver::Resolver;

// Import of standar libraries.
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::path::Path;

// Needed Deserialize for the Subdomains structure.
#[derive(Deserialize)]
struct Subdomains {
    dns_names: Vec<String>,
}

// Error catch for reqwest crate.
error_chain! {
    foreign_links {
        Reqwest(reqwest::Error);
    }
}

// Function to get subdomains taking the needed parameters: target, with_ip, with_output,
// file_format.
fn get_subdomains(target: &str, with_ip: &str, with_output: &str, file_format: &str) -> Result<()> {
    // Define the target taking it from user aguments or file and remove unneeded strings in order
    // to get a clean domain in the format: domain.[ext]
    let target = target
        .replace("www.", "")
        .replace("https://", "")
        .replace("http://", "")
        .replace("/", "");
    // Define the API URL passing the target in the needed place in order to get a complete URL.
    let ct_api_url = [
        "https://api.certspotter.com/v1/issuances?domain=",
        &target,
        "&include_subdomains=true&expand=dns_names",
    ]
    .concat();
    // Get data from the API URL making the request using the get method of the reqwest crate.
    let mut ct_data = reqwest::get(&ct_api_url)?;
    println!("\nTarget ==> {}", &target);
    // Check the status of the API request.
    if ct_data.status() == 200 {
        // If the request was sucessful, then convert the data to JSON format.
        let domains: Vec<Subdomains> = ct_data.json()?;
        // Check if we contain or not data from the request.
        if domains.is_empty() {
            println!("No data was found for the target: {} :'(", &target);
        } else {
            println!("\nThe following subdomains were found for ==>  {}", &target);
            // Concat the domains vectors and iter over every subdomain, then print that.
            for subdomain in concat_domains(&domains) {
                // In there conditions we check the options given by the user in order to format
                // the output with the needed items.
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
        }
    } else {
        println!(
            "An error as ocurred while procesing the request, the status code is: {}",
            ct_data.status()
        );
    }
    Ok(())
}

// Function to get the IP for the subdomain passed as argument.
fn get_ip(domain: &str) -> String {
    let resolver =
        Resolver::from_system_conf().expect("Error reading system resolver configuration.");
    // Check if the resolv was sucessful or not, if yes then return the IP address, if not print
    // the message "Domain not resolved"
    if let Ok(ip_address) = resolver.lookup_ip(&domain) {
        let address = ip_address.iter().next().expect("An error as ocurred.");
        address.to_string()
    } else {
        String::from("Domain not resolved")
    }
}

// Function to read from file. It's done opening the file and itering over their lines (every line
// is a domain).
fn read_from_file(
    file: &str,
    with_ip: &str,
    with_output: &str,
    file_format: &str,
) -> io::Result<()> {
    // Check if the file was opened sucessfully, if yes iter over lines, if not print the error
    // message.
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

// Function to concat the domains vectors itering over their subdomains and collecting they.
fn concat_domains(domains: &Vec<Subdomains>) -> std::collections::HashSet<&String> {
    domains
        .iter()
        .flat_map(|sub| sub.dns_names.iter())
        .collect()
}

// Function to write output to file if specified by the user.
fn write_to_file(data: &str, target: &str, subdomain_ip: &str, file_format: &str) {
    // Define the data structure concatenating subdomain and ip separated by comma.
    let data = &[data, ",", subdomain_ip, ",", "\n"].concat();
    // Define file name for output, it's: domain.[file type]
    let filename = &[target, ".", file_format].concat();
    // Check if the path exists, if yes the append data to file, if not create the file and write
    // to it.
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

// Main function, here we catch the user input and based in the arguments perform the needed
// actions doing calls to the functions defined before.
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
