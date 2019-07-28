#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate lazy_static;

use rand::Rng;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::Duration;
use trust_dns_resolver::{config::ResolverConfig, config::ResolverOpts, Resolver};
use url::Url;

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

#[derive(Deserialize, PartialEq, PartialOrd, Ord, Eq)]
struct SubdomainsFacebook {
    domains: Vec<String>,
}

#[derive(Deserialize)]
struct ResponseDataFacebook {
    data: Vec<SubdomainsFacebook>,
}

lazy_static! {
    static ref RNUM: String = rand::thread_rng().gen_range(0, 10000).to_string();
}

pub fn get_subdomains(
    target: &str,
    with_ip: &str,
    with_output: &str,
    file_format: &str,
    all_apis: &u32,
    with_proxy: &str,
    proxy: &str,
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

    println!("\nTarget ==> {}\n", &target);

    if all_apis == &1 {
        let all_subdomains = vec![
            get_certspotter_subdomains(&ct_api_url_certspotter, &with_proxy, &proxy),
            get_crtsh_subdomains(&ct_api_url_crtsh, &with_proxy, &proxy),
            get_virustotal_subdomains(&ct_api_url_virustotal, &with_proxy, &proxy),
            get_sublist3r_subdomains(&ct_api_url_sublist3r, &with_proxy, &proxy),
            get_facebook_subdomains(&ct_api_url_fb, &with_proxy, &proxy),
        ];

        let all_subdomains_vec = all_subdomains.into_iter().fold(None, concat_options);

        manage_subdomains_data(
            all_subdomains_vec,
            &target,
            &with_ip,
            &with_output,
            &file_format,
        );
        println!("\nGood luck Hax0r 💀!");
    } else {
        manage_subdomains_data(
            get_certspotter_subdomains(&ct_api_url_certspotter, &with_proxy, &proxy),
            &target,
            &with_ip,
            &with_output,
            &file_format,
        );
        println!("\nGood luck Hax0r 💀! If you want more results, use the -a option to check in all APIs.\n");
    }
    if with_ip == "y" && with_output == "y" {
        let with_ip = "-ip";
        let filename = [&target, "_", &RNUM.to_string(), with_ip, ".", file_format].concat();
        if Path::new(&filename).exists() {
            println!(
                ">> 📁 Filename for the target {} was saved in: ./{} 😀",
                &target, &filename
            )
        }
    } else if with_output == "y" {
        let filename = [&target, "_", &RNUM.to_string(), ".", file_format].concat();
        if Path::new(&filename).exists() {
            println!(
                ">> 📁 Filename for the target {} was saved in: ./{} 😀",
                &target, &filename
            )
        }
    }
}

fn concat_options<T>(l: Option<Vec<T>>, r: Option<Vec<T>>) -> Option<Vec<T>> {
    match (l, r) {
        (Some(mut l), Some(mut r)) => {
            l.append(&mut r);
            Some(l)
        }
        (x @ Some(_), None) => x,
        (None, x) => x,
    }
}

fn manage_subdomains_data(
    data: Option<Vec<String>>,
    target: &str,
    with_ip: &str,
    with_output: &str,
    file_format: &str,
) {
    let base_target = [".", &target].concat();
    for mut vec_subdomains in data {
        if vec_subdomains.is_empty() {
            println!(
                "\nNo subdomains were found for the target: {} ¡😭!\n",
                &target
            );
        } else {
            vec_subdomains.sort();
            vec_subdomains.dedup();
            vec_subdomains.retain(|sub| !sub.contains("*.") && sub.contains(&base_target));
            println!(
                "\nA total of {} subdomains were found for ==>  {} 👽\n",
                &vec_subdomains.len(),
                &target
            );
            for subdomain in vec_subdomains {
                if with_ip == "y" && with_output == "y" {
                    let ipadress = get_ip(&subdomain);
                    write_to_file(&subdomain, &target, &ipadress, &file_format, &with_ip);
                    println!(" >> {} => {}", &subdomain, &ipadress);
                } else if with_ip == "y" {
                    let ipadress = get_ip(&subdomain);
                    println!(" >> {} => {}", &subdomain, &ipadress);
                } else if with_output == "y" {
                    let ipadress = "";
                    write_to_file(&subdomain, &target, &ipadress, &file_format, &with_ip);
                    println!(" >> {}", &subdomain);
                } else {
                    println!(" >> {}", &subdomain);
                }
            }
        }
    }
}

fn get_certspotter_subdomains(
    ct_api_url_certspotter: &str,
    with_proxy: &str,
    proxy: &str,
) -> Option<Vec<String>> {
    let client = return_client(&with_proxy, &proxy).unwrap();
    println!("Searching in the CertSpotter API... 🔍");
    match client.get(ct_api_url_certspotter).send() {
        Ok(mut ct_data_certspotter) => {
            match ct_data_certspotter.json::<Vec<SubdomainsCertSpotter>>() {
                Ok(domains_certspotter) => Some(
                    domains_certspotter
                        .into_iter()
                        .flat_map(|sub| sub.dns_names.into_iter())
                        .collect(),
                ),
                Err(e) => {
                    check_json_errors(e, "CertSpotter");
                    None
                }
            }
        }
        Err(e) => {
            check_request_errors(e, "CertSpotter");
            None
        }
    }
}

fn get_crtsh_subdomains(
    ct_api_url_crtsh: &str,
    with_proxy: &str,
    proxy: &str,
) -> Option<Vec<String>> {
    let client = return_client(&with_proxy, &proxy).unwrap();
    println!("Searching in the Crtsh API... 🔍");
    match client.get(ct_api_url_crtsh).send() {
        Ok(mut ct_data_crtsh) => match ct_data_crtsh.json::<Vec<SubdomainsCrtsh>>() {
            Ok(domains_crtsh) => Some(
                domains_crtsh
                    .into_iter()
                    .map(|sub| sub.name_value)
                    .collect(),
            ),
            Err(e) => {
                check_json_errors(e, "Crtsh");
                None
            }
        },
        Err(e) => {
            check_request_errors(e, "Crtsh");
            None
        }
    }
}

fn get_virustotal_subdomains(
    ct_api_url_virustotal: &str,
    with_proxy: &str,
    proxy: &str,
) -> Option<Vec<String>> {
    let client = return_client(&with_proxy, &proxy).unwrap();
    println!("Searching in the Virustotal API... 🔍");
    match client.get(ct_api_url_virustotal).send() {
        Ok(mut ct_data_virustotal) => match ct_data_virustotal.json::<ResponseDataVirusTotal>() {
            Ok(virustotal_json) => {
                let domains_virustotal = virustotal_json.data;
                Some(domains_virustotal.into_iter().map(|sub| sub.id).collect())
            }
            Err(e) => {
                check_json_errors(e, "Virustotal");
                None
            }
        },
        Err(e) => {
            check_request_errors(e, "Virustotal");
            None
        }
    }
}

fn get_sublist3r_subdomains(
    ct_api_url_sublist3r: &str,
    with_proxy: &str,
    proxy: &str,
) -> Option<Vec<String>> {
    let client = return_client(&with_proxy, &proxy).unwrap();
    println!("Searching in the Sublist3r API... 🔍");
    match client.get(ct_api_url_sublist3r).send() {
        Ok(mut ct_data_sublist3r) => match ct_data_sublist3r.json::<Vec<String>>() {
            Ok(domains_sublist3r) => Some(domains_sublist3r),
            Err(e) => {
                check_json_errors(e, "Sublist3r");
                None
            }
        },
        Err(e) => {
            check_request_errors(e, "Sublist3r");
            None
        }
    }
}

fn get_facebook_subdomains(
    ct_api_url_fb: &str,
    with_proxy: &str,
    proxy: &str,
) -> Option<Vec<String>> {
    let client = return_client(&with_proxy, &proxy).unwrap();
    println!("Searching in the Facebook API... 🔍");
    match client.get(ct_api_url_fb).send() {
        Ok(mut ct_data_fb) => match ct_data_fb.json::<ResponseDataFacebook>() {
            Ok(fb_json) => Some(
                fb_json
                    .data
                    .into_iter()
                    .flat_map(|sub| sub.domains.into_iter())
                    .collect(),
            ),
            Err(e) => {
                check_json_errors(e, "Facebook");
                None
            }
        },
        Err(e) => {
            check_request_errors(e, "Facebook");
            None
        }
    }
}

pub fn check_request_errors(error: reqwest::Error, api: &str) {
    if error.is_timeout() {
        println!(
            "A timeout ⏳ error as occured while processing the request in the {} API. Error description: {}\n",
            &api, &error.description())
    } else if error.is_redirect() {
        println!(
            "A redirect ↪️  was found while processing the {} API. Error description: {}\n",
            &api,
            &error.description()
        )
    } else if error.is_client_error() {
        println!(
            "A client error 🧑❌ as occured sending the request to the {} API. Error description: {}\n",
            &api,
            &error.description()
        )
    } else if error.is_server_error() {
        println!(
            "A server error 🖥️❌ as occured sending the request to the {} API. Error description: {}\n",
            &api,
            &error.description()
        )
    } else {
        println!(
            "An error ❌ as occured while procesing the request in the {} API. Error description: {}\n",
            &api,
            &error.description()
        )
    }
}

pub fn check_json_errors(error: reqwest::Error, api: &str) {
    println!("An error ❌ as ocurred while parsing the JSON obtained from the {} API. Error description: {}.\n", &api, error.description())
}

pub fn read_from_file(
    file: &str,
    with_ip: &str,
    with_output: &str,
    file_format: &str,
    all_apis: &u32,
    with_proxy: &str,
    proxy: &str,
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
                &with_proxy,
                &proxy,
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
        let data = &[data, ",", subdomain_ip, "\n"].concat();
        let with_ip = "-ip";
        let filename = &[target, "_", &RNUM, with_ip, ".", file_format].concat();
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
                .write_all("subdomain,ip\n".as_bytes())
                .expect("Failed writing to file.");
            output_file
                .write_all(&data.as_bytes())
                .expect("Failed writing to file.");
        }
    } else {
        let data = &[data, "\n"].concat();
        let filename = &[target, "_", &RNUM, ".", file_format].concat();
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
                .write_all("subdomain\n".as_bytes())
                .expect("Failed writing to file.");
            output_file
                .write_all(&data.as_bytes())
                .expect("Failed writing to file.");
        }
    }
}

pub fn get_ip(domain: &str) -> String {
    let resolver = get_resolver();
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

pub fn get_resolver() -> Resolver {
    match Resolver::from_system_conf() {
        Ok(system_resolver) => system_resolver,
        Err(_) => match Resolver::new(ResolverConfig::quad9(), ResolverOpts::default()) {
            Ok(quad9_resolver) => quad9_resolver,
            Err(_) => match Resolver::new(ResolverConfig::cloudflare(), ResolverOpts::default()) {
                Ok(cloudflare_resolver) => cloudflare_resolver,
                Err(_) => {
                    let defaul_resolver =
                        Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
                    defaul_resolver
                }
            },
        },
    }
}

pub fn return_client(with_proxy: &str, proxy: &str) -> Option<reqwest::Client> {
    if with_proxy == "y" {
        match Url::parse(&proxy) {
            Ok(proxy) => {
                let proxy = proxy.as_str();
                Some(
                    reqwest::Client::builder()
                        .proxy(reqwest::Proxy::all(proxy).unwrap())
                        .timeout(Duration::from_secs(20))
                        .build()
                        .unwrap(),
                )
            }
            Err(e) => {
                println!(
                    "An error ❌ as occured while parsing the proxy URL, your proxy is {} and the generated error is: {}\nMake sure that your proxy URL follow the syntax: [http/https]://[host]:[port]. Example: http://127.0.0.1:8080",
                    &proxy, e.description()
                );
                std::process::exit(1)
            }
        }
    } else {
        Some(
            reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .build()
                .unwrap(),
        )
    }
}
