use {
    crate::files,
    std::{
        collections::HashSet,
        fs::File,
        io::{BufRead, BufReader},
        process::Command,
    },
};

pub fn get_amass_subdomains(
    target: &str,
    external_subdomains_dir: String,
    quiet_flag: bool,
) -> Option<HashSet<String>> {
    if !quiet_flag {
        println!("Getting amass subdomains for {}", target);
    }
    let output_filename = &format!(
        "{}/amass_subdomains_{}.txt",
        external_subdomains_dir, target
    );
    let mut subdomains = HashSet::new();
    if !(File::create(output_filename).is_ok()
        && Command::new("amass")
            .args(&mut vec![
                "enum",
                "--passive",
                "-d",
                target,
                "-o",
                output_filename,
            ])
            .output()
            .is_ok()
        && files::check_no_empty(output_filename))
    {
        eprintln!("Error getting amass subdomains for {}\n", target);
    }
    match File::open(output_filename) {
        Ok(file) => {
            for target in BufReader::new(file).lines().flatten() {
                subdomains.insert(target);
            }
            Some(subdomains)
        }
        Err(e) => {
            eprintln!("Can not open file {}. Error: {}\n", output_filename, e);
            None
        }
    }
}

pub fn get_subfinder_subdomains(
    target: &str,
    external_subdomains_dir: String,
    quiet_flag: bool,
) -> Option<HashSet<String>> {
    if !quiet_flag {
        println!("Getting subfinder subdomains for {}", target);
    }
    let output_filename = &format!(
        "{}/subfinder_subdomains_{}.txt",
        external_subdomains_dir, target
    );
    let mut subdomains = HashSet::new();
    if !(File::create(output_filename).is_ok()
        && Command::new("subfinder")
            .args(&mut vec!["-silent", "-d", target, "-o", output_filename])
            .output()
            .is_ok()
        && files::check_no_empty(output_filename))
    {
        eprintln!("Error getting subfinder subdomains for {}\n", target);
    }
    match File::open(output_filename) {
        Ok(file) => {
            for target in BufReader::new(file).lines().flatten() {
                subdomains.insert(target);
            }
            Some(subdomains)
        }
        Err(e) => {
            eprintln!("Can not open file {}. Error: {}\n", output_filename, e);
            None
        }
    }
}
