#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate lazy_static;

use postgres::{Connection, TlsMode};
use rand::Rng;
use std::{
    collections::HashSet,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::Path,
    thread,
    time::Duration,
};
use trust_dns_resolver::{config::ResolverConfig, config::ResolverOpts, Resolver};

mod auth;
pub mod errors;
use crate::errors::*;

#[derive(Deserialize, Eq, PartialEq, Hash)]
struct SubdomainsCertSpotter {
    dns_names: Vec<String>,
}

#[derive(Deserialize, Eq, PartialEq, Hash)]
struct SubdomainsCrtsh {
    name_value: String,
}

#[allow(non_snake_case)]
struct SubdomainsDBCrtsh {
    NAME_VALUE: String,
}

#[derive(Deserialize, Eq, PartialEq, Hash)]
struct SubdomainsVirustotal {
    id: String,
}

#[derive(Deserialize, Eq, PartialEq)]
struct ResponseDataVirusTotal {
    data: HashSet<SubdomainsVirustotal>,
}

#[derive(Deserialize, Eq, PartialEq, Hash)]
struct SubdomainsFacebook {
    domains: Vec<String>,
}

#[derive(Deserialize, Eq, PartialEq)]
struct ResponseDataFacebook {
    data: HashSet<SubdomainsFacebook>,
}

#[derive(Deserialize, Eq, PartialEq, Hash)]
struct SubdomainsSpyse {
    domain: String,
}

#[derive(Deserialize, Eq, PartialEq)]
struct ResponseDataSpyse {
    records: HashSet<SubdomainsSpyse>,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct SubdomainsBufferover {
    FDNS_A: HashSet<String>,
}

#[derive(Deserialize)]
struct SubdomainsThreadcrowd {
    subdomains: HashSet<String>,
}

#[derive(Deserialize)]
struct SubdomainsVirustotalApikey {
    subdomains: HashSet<String>,
}

lazy_static! {
    static ref CLIENT: reqwest::Client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap();
}

pub fn get_subdomains(target: &str, with_ip: &str, with_output: &str, file_name: &str) -> Result<()> {
    let target = target
        .replace("www.", "")
        .replace("https://", "")
        .replace("http://", "")
        .replace("/", "");

    println!("\nTarget ==> {}\n", &target);

    let spyse_access_token = auth::get_auth_token("spyse");
    let facebook_access_token = auth::get_auth_token("facebook");
    let virustotal_access_token = auth::get_auth_token("virustotal");

    let url_api_certspotter = [
        "https://api.certspotter.com/v1/issuances?domain=",
        &target,
        "&include_subdomains=true&expand=dns_names",
    ]
    .concat();
    let url_api_virustotal = [
        "https://www.virustotal.com/ui/domains/",
        &target,
        "/subdomains?limit=40",
    ]
    .concat();
    let url_api_crtsh = ["https://crt.sh/?q=%.", &target, "&output=json"].concat();
    let crtsh_db_query = ["SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%.", &target, "'))"].concat();
    let url_api_sublist3r = ["https://api.sublist3r.com/search.php?domain=", &target].concat();
    let url_api_spyse = [
        "https://api.spyse.com/v1/subdomains?domain=",
        &target,
        "&api_token=",
        &spyse_access_token,
    ]
    .concat();
    let url_api_bufferover = ["http://dns.bufferover.run/dns?q=", &target].concat();
    let url_api_threatcrowd = [
        "https://threatcrowd.org/searchApi/v2/domain/report/?domain=",
        &target,
    ]
    .concat();
    let all_subdomains = vec![
        thread::spawn(move || get_certspotter_subdomains(&url_api_certspotter)),
        thread::spawn(move || get_crtsh_db_subdomains(&crtsh_db_query, &url_api_crtsh)),
        thread::spawn(move || get_virustotal_subdomains(&url_api_virustotal)),
        thread::spawn(move || get_sublist3r_subdomains(&url_api_sublist3r)),
        if facebook_access_token.is_empty() {
            let findomain_fb_tokens = [
                "688177841647920|RAeNYr8jwFXGH9v-IhGv4tfHMpU",
                "772592906530976|CNkO7OxM6ssQgOBLCraC_dhKE7M",
                "1004691886529013|iiUStPqcXCELcwv89-SZQSqqFNY",
                "2106186849683294|beVoPBtLp3IWjpLsnF6Mpzo1gVM",
                "2095886140707025|WkO8gTgPtwmnNZL3NQ74z92DA-k",
                "434231614102088|pLJSVc9iOqxrG6NO7DDPrlkQ1qE",
                "431009107520610|AX8VNunXMng-ainHO8Ke0sdeMJI",
                "893300687707948|KW_O07biKRaW5fpNqeAeSrMU1W8",
                "2477772448946546|BXn-h2zX6qb4WsFvtOywrNsDixo",
                "509488472952865|kONi75jYL_KQ_6J1CHPQ1MH4x_U",
            ];
            let url_api_fb = [
                "https://graph.facebook.com/certificates?query=",
                &target,
                "&fields=domains&limit=10000&access_token=",
                &findomain_fb_tokens[rand::thread_rng().gen_range(0, findomain_fb_tokens.len())],
            ]
            .concat();
            thread::spawn(move || get_facebook_subdomains(&url_api_fb))
        } else {
            let url_api_fb = [
                "https://graph.facebook.com/certificates?query=",
                &target,
                "&fields=domains&limit=10000&access_token=",
                &facebook_access_token,
            ]
            .concat();
            thread::spawn(move || get_facebook_subdomains(&url_api_fb))
        },
        thread::spawn(move || get_spyse_subdomains(&url_api_spyse)),
        thread::spawn(move || get_bufferover_subdomains(&url_api_bufferover)),
        thread::spawn(move || get_threatcrowd_subdomains(&url_api_threatcrowd)),
        if virustotal_access_token.is_empty() {
            thread::spawn(|| None)
        } else {
            let url_virustotal_apikey = [
                "https://www.virustotal.com/vtapi/v2/domain/report?apikey=",
                &virustotal_access_token,
                "&domain=",
                &target,
            ]
            .concat();
            thread::spawn(move || get_virustotal_apikey_subdomains(&url_virustotal_apikey))
        },
    ];

    let subdomains = all_subdomains
        .into_iter()
        .map(|j| j.join().unwrap())
        .collect::<Vec<_>>();

    //    let current_subdomains: HashSet<String> = subdomains
    //       .iter()
    //       .flatten()
    //       .flat_map(|sub| sub)
    //       .cloned()
    //       .collect();

    //   let existing_subdomains: HashSet<String> = [
    //   database query here
    //   ]
    //   .into_iter()
    //   .cloned()
    //   .map(str::to_owned)
    //   .collect();

    //    let new_subdomains: HashSet<&String> = current_subdomains.difference(&existing_subdomains).into_iter().collect();
    //
    //    At it point we can push the new subdomains to slack hook.

    manage_subdomains_data(
        subdomains.iter().flatten().flat_map(|sub| sub).collect(),
        &target,
        &with_ip,
        &with_output,
        &file_name,
    )?;
    if with_ip == "y" && with_output == "y" {
        println!(
            ">> 📁 Filename for the target {} was saved in: ./{} 😀",
            &target, &file_name
        )
    } else if with_output == "y" {
        println!(
            ">> 📁 Filename for the target {} was saved in: ./{} 😀",
            &target, &file_name
        )
    }
    Ok(())
}

fn manage_subdomains_data(
    mut subdomains: HashSet<&String>,
    target: &str,
    with_ip: &str,
    with_output: &str,
    file_name: &str,
) -> Result<()> {
    let base_target = [".", &target].concat();
    if subdomains.is_empty() {
        println!(
            "\nNo subdomains were found for the target: {} ¡😭!\n",
            &target
        );
    } else {
        check_output_file_exists(&file_name)?;
        subdomains.retain(|sub| {
            !sub.contains("*") && !sub.starts_with(".") && sub.contains(&base_target)
        });
        if with_ip == "y" && with_output == "y" {
            for subdomain in &subdomains {
                let ipadress = get_ip(&subdomain);
                write_to_file(&subdomain, &ipadress, &file_name, &with_ip)?;
                println!("{},{}", &subdomain, &ipadress);
            }
        } else if with_ip == "y" && with_output != "y" {
            for subdomain in &subdomains {
                let ipadress = get_ip(&subdomain);
                println!("{},{}", &subdomain, &ipadress);
            }
        } else if with_ip != "y" && with_output == "y" {
            let ipadress = "";
            for subdomain in &subdomains {
                write_to_file(&subdomain, &ipadress, &file_name, &with_ip)?;
                println!("{}", &subdomain);
            }
        } else {
            for subdomain in &subdomains {
                println!("{}", &subdomain);
            }
        }
        println!(
            "\nA total of {} subdomains were found for ==>  {} 👽\n",
            &subdomains.len(),
            &target
        );
        println!("\nGood luck Hax0r 💀!\n");
    }

    Ok(())
}

fn get_certspotter_subdomains(url_api_certspotter: &str) -> Option<HashSet<String>> {
    println!("Searching in the CertSpotter API... 🔍");
    match CLIENT.get(url_api_certspotter).send() {
        Ok(mut data_certspotter) => match data_certspotter.json::<HashSet<SubdomainsCertSpotter>>()
        {
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
        },
        Err(e) => {
            check_request_errors(e, "CertSpotter");
            None
        }
    }
}

fn get_crtsh_subdomains(url_api_crtsh: &str) -> Option<HashSet<String>> {
    println!("Searching in the Crtsh API... 🔍");
    match CLIENT.get(url_api_crtsh).send() {
        Ok(mut data_crtsh) => match data_crtsh.json::<HashSet<SubdomainsCrtsh>>() {
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

fn get_crtsh_db_subdomains(crtsh_db_query: &str, url_api_crtsh: &str) -> Option<HashSet<String>> {
    println!("Searching in the Crtsh database... 🔍");
    match Connection::connect("postgres://guest@crt.sh:5432/certwatch", TlsMode::None) {
        Ok(crtsh_db_client) => match crtsh_db_client.query(&crtsh_db_query, &[]) {
            Ok(crtsh_db_subdomains) => Some(
                crtsh_db_subdomains
                    .iter()
                    .map(|row| {
                        let subdomain = SubdomainsDBCrtsh {
                            NAME_VALUE: row.get("NAME_VALUE"),
                        };
                        subdomain.NAME_VALUE
                    })
                    .collect(),
            ),
            Err(e) => {
                println!(
                    "A error ❌ has occurred while querying the Crtsh database. Error: {}. Trying the API method...",
                    e.description()
                );
                get_crtsh_subdomains(&url_api_crtsh)
            }
        },
        Err(e) => {
            println!(
                "A error ❌ has occurred while connecting to the Crtsh database. Error: {}. Trying the API method...",
                e.description()
            );
            get_crtsh_subdomains(&url_api_crtsh)
        }
    }
}

fn get_virustotal_subdomains(url_api_virustotal: &str) -> Option<HashSet<String>> {
    println!("Searching in the Virustotal API... 🔍");
    match CLIENT.get(url_api_virustotal).send() {
        Ok(mut data_virustotal) => match data_virustotal.json::<ResponseDataVirusTotal>() {
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

fn get_sublist3r_subdomains(url_api_sublist3r: &str) -> Option<HashSet<String>> {
    println!("Searching in the Sublist3r API... 🔍");
    match CLIENT.get(url_api_sublist3r).send() {
        Ok(mut data_sublist3r) => match data_sublist3r.json::<HashSet<String>>() {
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

fn get_facebook_subdomains(url_api_fb: &str) -> Option<HashSet<String>> {
    println!("Searching in the Facebook API... 🔍");
    match CLIENT.get(url_api_fb).send() {
        Ok(mut data_fb) => match data_fb.json::<ResponseDataFacebook>() {
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

fn get_spyse_subdomains(url_api_spyse: &str) -> Option<HashSet<String>> {
    println!("Searching in the Spyse API... 🔍");
    match CLIENT.get(url_api_spyse).send() {
        Ok(mut data_spyse) => match data_spyse.json::<ResponseDataSpyse>() {
            Ok(spyse_json) => {
                let domains_spyse = spyse_json.records;
                Some(domains_spyse.into_iter().map(|sub| sub.domain).collect())
            }
            Err(e) => {
                check_json_errors(e, "Spyse");
                None
            }
        },
        Err(e) => {
            check_request_errors(e, "Spyse");
            None
        }
    }
}

fn get_bufferover_subdomains(url_api_bufferover: &str) -> Option<HashSet<String>> {
    println!("Searching in the Bufferover API... 🔍");
    match CLIENT.get(url_api_bufferover).send() {
        Ok(mut data_bufferover) => match data_bufferover.json::<SubdomainsBufferover>() {
            Ok(bufferover_json) => Some(
                bufferover_json
                    .FDNS_A
                    .iter()
                    .map(|sub| sub.split(","))
                    .flatten()
                    .map(str::to_owned)
                    .collect(),
            ),
            Err(e) => {
                check_json_errors(e, "Bufferover");
                None
            }
        },
        Err(e) => {
            check_request_errors(e, "Bufferover");
            None
        }
    }
}

fn get_threatcrowd_subdomains(url_api_threatcrowd: &str) -> Option<HashSet<String>> {
    println!("Searching in the Threadcrowd API... 🔍");
    match CLIENT.get(url_api_threatcrowd).send() {
        Ok(mut data_threatcrowd) => match data_threatcrowd.json::<SubdomainsThreadcrowd>() {
            Ok(threatcrowd_json) => Some(
                threatcrowd_json
                    .subdomains
                    .into_iter()
                    .map(|sub| sub)
                    .collect(),
            ),
            Err(e) => {
                check_json_errors(e, "Threadcrowd");
                None
            }
        },
        Err(e) => {
            check_request_errors(e, "Threadcrowd");
            None
        }
    }
}

fn get_virustotal_apikey_subdomains(url_virustotal_apikey: &str) -> Option<HashSet<String>> {
    println!("Searching in the Virustotal API using apikey... 🔍");
    match CLIENT.get(url_virustotal_apikey).send() {
        Ok(mut data_virustotal_apikey) => {
            match data_virustotal_apikey.json::<SubdomainsVirustotalApikey>() {
                Ok(virustotal_apikey_json) => Some(
                    virustotal_apikey_json
                        .subdomains
                        .into_iter()
                        .map(|sub| sub)
                        .collect(),
                ),
                Err(e) => {
                    check_json_errors(e, "Virustotal API using apikey");
                    None
                }
            }
        }
        Err(e) => {
            check_request_errors(e, "Virustotal API using apikey");
            None
        }
    }
}

fn check_request_errors(error: reqwest::Error, api: &str) {
    if error.is_timeout() {
        println!(
            "A timeout ⏳ error has occurred while processing the request in the {} API. Error description: {}",
            &api, &error.description())
    } else if error.is_redirect() {
        println!(
            "A redirect ↪️  was found while processing the {} API. Error description: {}",
            &api,
            &error.description()
        )
    } else if error.is_client_error() {
        println!(
            "A client error 🧑❌ has occurred sending the request to the {} API. Error description: {}",
            &api,
            &error.description()
        )
    } else if error.is_server_error() {
        println!(
            "A server error ❌ has occurred sending the request to the {} API. Error description: {}",
            &api,
            &error.description()
        )
    } else {
        println!(
            "An error ❌ has occurred while procesing the request in the {} API. Error description: {}",
            &api,
            &error.description()
        )
    }
}

fn check_json_errors(error: reqwest::Error, api: &str) {
    println!("An error ❌ occurred while parsing the JSON obtained from the {} API. Error description: {}.", &api, error.description())
}

pub fn read_from_file(file: &str, with_ip: &str, with_output: &str) -> Result<()> {
    match File::open(&file) {
        Ok(f) => {
            let f = BufReader::new(f);
            for domain in f.lines() {
                let domain = domain.unwrap().to_string();
                let file_name = [&domain, ".txt"].concat();
                get_subdomains(&domain, &with_ip, &with_output, &file_name)?;
            }
        }
        Err(e) => {
            println!("Can't open file 📁 {}. Error: {}", &file, e.description());
        }
    }
    Ok(())
}

fn write_to_file(data: &str, subdomain_ip: &str, file_name: &str, with_ip: &str) -> Result<()> {
    let data = if with_ip == "y" {
        [data, ",", subdomain_ip, "\n"].concat()
    } else {
        [data, "\n"].concat()
    };
    let mut output_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&file_name)
        .context("Can't open file")?;
    output_file
        .write_all(&data.as_bytes())?;
    Ok(())
}

fn get_ip(domain: &str) -> String {
    let resolver = get_resolver();
    match resolver.lookup_ip(&domain) {
        Ok(ip_address) => ip_address
            .iter()
            .next()
            .expect("An error has occurred getting the IP address.")
            .to_string(),
        Err(_) => String::from("No IP address found"),
    }
}

fn get_resolver() -> Resolver {
    match Resolver::from_system_conf() {
        Ok(system_resolver) => system_resolver,
        Err(_) => match Resolver::new(ResolverConfig::quad9(), ResolverOpts::default()) {
            Ok(quad9_resolver) => quad9_resolver,
            Err(_) => match Resolver::new(ResolverConfig::cloudflare(), ResolverOpts::default()) {
                Ok(cloudflare_resolver) => cloudflare_resolver,
                Err(_) => {
                    Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap()
                }
            },
        },
    }
}

pub fn check_output_file_exists(file_name: &str) -> Result<()> {
    if Path::new(&file_name).exists() && Path::new(&file_name).is_file() {
        fs::rename(
            &file_name,
            &file_name.replace(&file_name.split(".").last().unwrap(), "old.txt"),
        ).with_context(|_| format!("An error occurred while backing up the file {:?}", &file_name))?;
    }
    Ok(())
}
