#[macro_use]
extern crate serde_derive;

use trust_dns_resolver::Resolver;

use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
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

#[derive(Deserialize, PartialEq, PartialOrd, Ord, Eq, Clone)]
struct SubdomainsFacebook {
    domains: Vec<String>,
}

#[derive(Deserialize)]
struct ResponseDataFacebook {
    data: Vec<SubdomainsFacebook>,
}

pub fn get_subdomains(
    target: &str,
    with_ip: &str,
    with_output: &str,
    file_format: &str,
    all_apis: &u32,
) {
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
    let ct_api_url_fb = [
        "https://graph.facebook.com/certificates?query=",
        &target,
        "&fields=domains&limit=10000&access_token=298348064419358|RrUIvPdydH023XhrMh1xBzv9dTM",
    ]
    .concat();

    println!("\nTarget ==> {}", &target);

    get_certspotter_subdomains(
        &ct_api_url_certspotter,
        &target,
        &with_ip,
        &with_output,
        &file_format,
        &all_apis,
    );

    if all_apis == &1 {
        get_crtsh_subdomains(
            &ct_api_url_crtsh,
            &target,
            &with_ip,
            &with_output,
            &file_format,
        );
        get_virustotal_subdomains(
            &ct_api_url_virustotal,
            &target,
            &with_ip,
            &with_output,
            &file_format,
        );
        get_sublist3r_subdomains(
            &ct_api_url_sublist3r,
            &target,
            &with_ip,
            &with_output,
            &file_format,
        );
        get_facebook_subdomains(
            &ct_api_url_fb,
            &target,
            &with_ip,
            &with_output,
            &file_format,
        );
        println!("\nGood luck Hax0r 💀!")
    }
    if with_ip == "y" && with_output == "y" {
        let with_ip = "-ip";
        let filename: String = [&target, with_ip, ".", file_format].concat();
        if Path::new(&filename).exists() {
            fix_duplicated(&filename);
            println!(
                "\n 📁 Filename for the target {} was saved in: ./{} 😀",
                &target, &filename
            )
        }
    } else if with_output == "y" {
        let filename: String = [&target, ".", file_format].concat();
        if Path::new(&filename).exists() {
            fix_duplicated(&filename);
            println!(
                "\n📁 Filename for the target {} was saved in: ./{} 😀",
                &target, &filename
            )
        }
    }
}

fn get_certspotter_subdomains(
    ct_api_url_certspotter: &str,
    target: &str,
    with_ip: &str,
    with_output: &str,
    file_format: &str,
    all_apis: &u32,
) {
    println!("\nSearching in the CertSpotter API... 🔍");
    match reqwest::get(ct_api_url_certspotter) {
        Ok(mut ct_data_certspotter) => {
            match ct_data_certspotter.json::<Vec<SubdomainsCertSpotter>>() {
                Ok(domains_certspotter) => {
                    if domains_certspotter.is_empty() {
                        println!(
                            "\nNo data was found for the target: {} in CertSpotter, ¡Sad 😭!",
                            &target
                        );
                    } else {
                        println!(
                            "\nThe following subdomains were found for ==>  {} in CertSpotter 👽\n",
                            &target
                        );
                        let mut fixed_certspotter_subdomains: Vec<&String> = domains_certspotter
                            .iter()
                            .flat_map(|sub| sub.dns_names.iter())
                            .collect();
                        fixed_certspotter_subdomains.sort();
                        fixed_certspotter_subdomains.dedup();
                        fixed_certspotter_subdomains.retain(|sub| !sub.contains("*."));
                        for subdomain in &fixed_certspotter_subdomains {
                            if with_ip == "y" && with_output == "y" {
                                let ipadress = get_ip(&subdomain);
                                write_to_file(
                                    &subdomain,
                                    &target,
                                    &ipadress,
                                    &file_format,
                                    &with_ip,
                                );
                                println!(" --> {} : {}", &subdomain, &ipadress);
                            } else if with_ip == "y" {
                                let ipadress = get_ip(&subdomain);
                                println!(" --> {} : {}", &subdomain, &ipadress);
                            } else if with_output == "y" {
                                let ipadress = "";
                                write_to_file(
                                    &subdomain,
                                    &target,
                                    &ipadress,
                                    &file_format,
                                    &with_ip,
                                );
                                println!(" --> {}", &subdomain);
                            } else {
                                println!(" --> {}", &subdomain);
                            }
                        }
                    }
                }
                Err(e) => check_json_errors(e, "CertSpotter"),
            }
            if all_apis != &1 {
                println!("\nGood luck Hax0r 💀! If you want more results, use the -a option to check in all APIs.\n");
            }
        }
        Err(e) => check_request_errors(e, "CertSpotter"),
    }
}

fn get_crtsh_subdomains(
    ct_api_url_crtsh: &str,
    target: &str,
    with_ip: &str,
    with_output: &str,
    file_format: &str,
) {
    println!("\nSearching in the Crtsh API... 🔍");
    match reqwest::get(ct_api_url_crtsh) {
        Ok(mut ct_data_crtsh) => match ct_data_crtsh.json::<Vec<SubdomainsCrtsh>>() {
            Ok(mut domains_crtsh) => {
                if domains_crtsh.is_empty() {
                    println!(
                        "\nNo data was found for the target: {} in crt.sh, ¡Sad 😭!",
                        &target
                    );
                } else {
                    domains_crtsh.sort();
                    domains_crtsh.dedup();
                    domains_crtsh.retain(|sub| !sub.name_value.contains("*."));
                    println!(
                        "\nThe following subdomains were found for ==>  {} in crt.sh 👽\n",
                        &target
                    );
                    for subdomain in &domains_crtsh {
                        let subdomain = &subdomain.name_value;
                        if with_ip == "y" && with_output == "y" {
                            let ipadress = get_ip(&subdomain);
                            write_to_file(&subdomain, &target, &ipadress, &file_format, &with_ip);
                            println!(" --> {} : {}", &subdomain, &ipadress);
                        } else if with_ip == "y" {
                            let ipadress = get_ip(&subdomain);
                            println!(" --> {} : {}", &subdomain, &ipadress);
                        } else if with_output == "y" {
                            let ipadress = "";
                            write_to_file(&subdomain, &target, &ipadress, &file_format, &with_ip);
                            println!(" --> {}", &subdomain);
                        } else {
                            println!(" --> {}", &subdomain);
                        }
                    }
                }
            }
            Err(e) => check_json_errors(e, "Crtsh"),
        },
        Err(e) => check_request_errors(e, "Crtsh"),
    }
}

fn get_virustotal_subdomains(
    ct_api_url_virustotal: &str,
    target: &str,
    with_ip: &str,
    with_output: &str,
    file_format: &str,
) {
    println!("\nSearching in the Virustotal API... 🔍");
    match reqwest::get(ct_api_url_virustotal) {
        Ok(mut ct_data_virustotal) => match ct_data_virustotal.json::<ResponseDataVirusTotal>() {
            Ok(virustotal_json) => {
                let mut domains_virustotal = virustotal_json.data;
                if domains_virustotal.is_empty() {
                    println!(
                        "\nNo data was found for the target: {} in Virustotal, ¡Sad 😭!",
                        &target
                    );
                } else {
                    domains_virustotal.sort();
                    domains_virustotal.dedup();
                    domains_virustotal.retain(|sub| !sub.id.contains("*."));
                    println!(
                        "\nThe following subdomains were found for ==>  {} in Virustotal 👽\n",
                        &target
                    );
                    for subdomain in &domains_virustotal {
                        let subdomain = &subdomain.id;
                        if with_ip == "y" && with_output == "y" {
                            let ipadress = get_ip(&subdomain);
                            write_to_file(&subdomain, &target, &ipadress, &file_format, &with_ip);
                            println!(" --> {} : {}", &subdomain, &ipadress);
                        } else if with_ip == "y" {
                            let ipadress = get_ip(&subdomain);
                            println!(" --> {} : {}", &subdomain, &ipadress);
                        } else if with_output == "y" {
                            let ipadress = "";
                            write_to_file(&subdomain, &target, &ipadress, &file_format, &with_ip);
                            println!(" --> {}", &subdomain);
                        } else {
                            println!(" --> {}", &subdomain);
                        }
                    }
                }
            }
            Err(e) => check_json_errors(e, "Virustotal"),
        },
        Err(e) => check_request_errors(e, "Virustotal"),
    }
}

fn get_sublist3r_subdomains(
    ct_api_url_sublist3r: &str,
    target: &str,
    with_ip: &str,
    with_output: &str,
    file_format: &str,
) {
    println!("\nSearching in the Sublist3r API... 🔍");
    match reqwest::get(ct_api_url_sublist3r) {
        Ok(mut ct_data_sublist3r) => match ct_data_sublist3r.json::<Vec<String>>() {
            Ok(mut domains_sublist3r) => {
                if domains_sublist3r.is_empty() {
                    println!(
                        "\nNo data was found for the target: {} in Sublist3r, ¡Sad 😭!",
                        &target
                    );
                } else {
                    domains_sublist3r.sort();
                    domains_sublist3r.dedup();
                    domains_sublist3r.retain(|sub| !sub.contains("*."));
                    println!(
                        "\nThe following subdomains were found for ==>  {} in Sublist3r 👽\n",
                        &target
                    );
                    for subdomain in &domains_sublist3r {
                        if with_ip == "y" && with_output == "y" {
                            let ipadress = get_ip(&subdomain);
                            write_to_file(&subdomain, &target, &ipadress, &file_format, &with_ip);
                            println!(" --> {} : {}", &subdomain, &ipadress);
                        } else if with_ip == "y" {
                            let ipadress = get_ip(&subdomain);
                            println!(" --> {} : {}", &subdomain, &ipadress);
                        } else if with_output == "y" {
                            let ipadress = "";
                            write_to_file(&subdomain, &target, &ipadress, &file_format, &with_ip);
                            println!(" --> {}", &subdomain);
                        } else {
                            println!(" --> {}", &subdomain);
                        }
                    }
                }
            }
            Err(e) => check_json_errors(e, "Sublist3r"),
        },
        Err(e) => check_request_errors(e, "Sublist3r"),
    }
}

fn get_facebook_subdomains(
    ct_api_url_fb: &str,
    target: &str,
    with_ip: &str,
    with_output: &str,
    file_format: &str,
) {
    println!("\nSearching in the Facebook API... 🔍");
    match reqwest::get(ct_api_url_fb) {
        Ok(mut ct_data_fb) => match ct_data_fb.json::<ResponseDataFacebook>() {
            Ok(fb_json) => {
                let fb_subdomains = fb_json.data;
                let mut fixed_fb_subdomains: Vec<&String> = fb_subdomains
                    .iter()
                    .flat_map(|sub| sub.domains.iter())
                    .collect();
                if fixed_fb_subdomains.is_empty() {
                    println!(
                        "\nNo data was found for the target: {} in Facebook, ¡Sad 😭!",
                        &target
                    );
                } else {
                    fixed_fb_subdomains.sort();
                    fixed_fb_subdomains.dedup();
                    fixed_fb_subdomains.retain(|sub| !sub.contains("*."));
                    println!(
                        "\nThe following subdomains were found for ==>  {} in Facebook 👽\n",
                        &target
                    );
                    for subdomain in &fixed_fb_subdomains {
                        if with_ip == "y" && with_output == "y" {
                            let ipadress = get_ip(&subdomain);
                            write_to_file(&subdomain, &target, &ipadress, &file_format, &with_ip);
                            println!(" --> {} : {}", &subdomain, &ipadress);
                        } else if with_ip == "y" {
                            let ipadress = get_ip(&subdomain);
                            println!(" --> {} : {}", &subdomain, &ipadress);
                        } else if with_output == "y" {
                            let ipadress = "";
                            write_to_file(&subdomain, &target, &ipadress, &file_format, &with_ip);
                            println!(" --> {}", &subdomain);
                        } else {
                            println!(" --> {}", &subdomain);
                        }
                    }
                }
            }
            Err(e) => check_json_errors(e, "Facebook"),
        },
        Err(e) => check_request_errors(e, "Facebook"),
    }
}

pub fn check_request_errors(error: reqwest::Error, api: &str) {
    use std::error::Error;
    if error.is_timeout() {
        println!(
            "\nA timeout ⏳ error as occured while processing the request in the {} API. Error description: {}",
            &api, &error.description())
    } else if error.is_redirect() {
        println!(
            "\nA redirect ↪️  was found while processing the {} API. Error description: {}",
            &api,
            &error.description()
        )
    } else if error.is_client_error() {
        println!(
            "\nA client error 🧑❌ as occured sending the request to the {} API. Error description: {}",
            &api,
            &error.description()
        )
    } else if error.is_server_error() {
        println!(
            "\nA server error 🖥️❌ as occured sending the request to the {} API. Error description: {}",
            &api,
            &error.description()
        )
    } else {
        println!(
            "\nAn error ❌ as occured while procesing the request in the {} API. Error description: {}",
            &api,
            &error.description()
        )
    }
}

pub fn check_json_errors(error: reqwest::Error, api: &str) {
    use std::error::Error;
    println!("\nAn error ❌ as ocurred while parsing the JSON obtained from the {} API. Error description: {}.", &api, error.description())
}

pub fn read_from_file(
    file: &str,
    with_ip: &str,
    with_output: &str,
    file_format: &str,
    all_apis: &u32,
) {
    if let Ok(f) = File::open(&file) {
        let f = BufReader::new(f);
        for line in f.lines() {
            get_subdomains(
                &line.unwrap().to_string(),
                &with_ip,
                &with_output,
                &file_format,
                &all_apis,
            )
        }
    } else {
        println!(
            "Error: can't open file 📁 {}, please check the filename and try again.",
            &file
        );
    }
}

pub fn write_to_file(
    data: &str,
    target: &str,
    subdomain_ip: &str,
    file_format: &str,
    with_ip: &str,
) {
    if with_ip == "y" {
        let data = &[data, ",", subdomain_ip, ",", "\n"].concat();
        let with_ip = "-ip";
        let filename = &[target, with_ip, ".", file_format].concat();
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
                .write_all(&data.as_bytes())
                .expect("Failed writing to file.");
        }
    } else {
        let data = &[data, ",", "\n"].concat();
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
                .write_all(&data.as_bytes())
                .expect("Failed writing to file.");
        }
    }
}

pub fn fix_duplicated(filename: &str) {
    let mut file = match File::open(filename) {
        Ok(file) => file,
        Err(_) => panic!("Error opening file!"),
    };
    let mut file_contents = String::new();
    file.read_to_string(&mut file_contents)
        .ok()
        .expect("Failed to read file!");
    let mut lines: Vec<String> = file_contents
        .split("\n")
        .map(|s: &str| s.to_string())
        .collect();
    fs::remove_file(&filename).unwrap();
    File::create(&filename).expect("Failed to create file.");
    let mut output_file = OpenOptions::new()
        .append(true)
        .open(&filename)
        .expect("Can't open file.");
    lines.sort();
    lines.dedup();
    for mut line in lines {
        line = [&line, "\n"].concat();
        output_file
            .write_all(&line.as_bytes())
            .expect("Failed writing to file.");
    }
}

pub fn get_ip(domain: &str) -> String {
    let resolver =
        Resolver::from_system_conf().expect("Error reading system resolver configuration.");
    match resolver.lookup_ip(&domain) {
        Ok(ip_address) => {
            let address = ip_address
                .iter()
                .next()
                .expect("An error as ocurred getting the IP address.");
            address.to_string()
        }
        Err(_) => String::from("No IP address found"),
    }
}
