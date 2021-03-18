use {
    crate::{errors::*, logic, misc, structs::Args, utils},
    std::{
        collections::HashSet,
        fs::{self, File, OpenOptions},
        io::{BufRead, BufReader, Write},
        iter::FromIterator,
        path::Path,
    },
};

pub fn return_file_targets(args: &Args, files: Vec<String>) -> Vec<String> {
    let mut targets: Vec<String> = Vec::new();
    files.clone().dedup();
    for f in files {
        match File::open(&f) {
            Ok(file) => {
                for target in BufReader::new(file).lines().flatten() {
                    if args.bruteforce || args.as_resolver || args.custom_resolvers {
                        targets.push(target);
                    } else {
                        targets.push(misc::sanitize_target_string(target));
                    }
                }
            }
            Err(e) => {
                if args.files.len() == 1 {
                    println!("Can not open file {}. Error: {}", f, e);
                    std::process::exit(1)
                } else if !args.quiet_flag {
                    println!(
                        "Can not open file {}, working with next file. Error: {}",
                        f, e
                    );
                }
            }
        }
    }
    targets.sort();
    targets.dedup();
    targets
}

pub fn read_from_file(args: &mut Args) -> Result<()> {
    let file_name = args.file_name.clone();
    if args.unique_output_flag {
        check_output_file_exists(&args.file_name)?
    }
    if args.as_resolver {
        if !args.discover_ip && !args.http_status && !args.enable_port_scan {
            println!("To use Findomain as resolver, use one or more of the --resolved/-r, --ip/-i, --ipv6-only, --http-status or --pscan/--iport/--lport options.");
            std::process::exit(1)
        } else {
            args.subdomains = if !args.files.is_empty() {
                HashSet::from_iter(return_file_targets(args, args.files.clone()))
            } else {
                HashSet::from_iter(utils::read_stdin())
            };
            args.subdomains
                .retain(|target| !target.is_empty() && logic::validate_target(target));
            logic::manage_subdomains_data(args)?
        }
    } else {
        let mut file_targets = if !args.files.is_empty() {
            return_file_targets(args, args.files.clone())
        } else {
            utils::read_stdin()
        };
        file_targets.retain(|target| !target.is_empty() && logic::validate_target(target));
        let last_target = file_targets.last().unwrap().to_string();
        for domain in file_targets {
            if domain == last_target {
                args.is_last_target = true
            }
            args.target = domain;
            args.file_name = if file_name.is_empty() && !args.with_ip {
                format!("{}.txt", &args.target)
            } else if file_name.is_empty() && args.with_ip {
                format!("{}-ip.txt", &args.target)
            } else {
                file_name.to_string()
            };
            crate::get_subdomains(args)?
        }
    }
    Ok(())
}

pub fn write_to_file(data: &str, file_name: &Option<std::fs::File>) -> Result<()> {
    file_name.as_ref().unwrap().write_all(data.as_bytes())?;
    file_name.as_ref().unwrap().write_all(b"\n")?;
    Ok(())
}

pub fn return_output_file(args: &Args) -> Option<File> {
    if args.file_name.is_empty() || !args.with_output {
        None
    } else {
        Some(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(&args.file_name)
                .with_context(|_| format!("Can't create file 📁 {}", &args.file_name))
                .unwrap(),
        )
    }
}

pub fn check_output_file_exists(file_name: &str) -> Result<()> {
    if Path::new(&file_name).exists() && Path::new(&file_name).is_file() {
        let backup_file_name = file_name.replace(&file_name.split('.').last().unwrap(), "old.txt");
        fs::rename(&file_name, &backup_file_name).with_context(|_| {
            format!(
                "The file {} already exists but Findomain can't backup the file to {}. Please run the tool with a more privileged user or try in a different directory.",
                &file_name, &backup_file_name,
            )
        })?;
    }
    Ok(())
}

pub fn check_image_path(screenshots_dir: &str, target: &str) -> bool {
    let full_path = format!("{}/{}/", screenshots_dir, target);
    (Path::new(&full_path).exists() && Path::new(&full_path).is_dir())
        || fs::create_dir_all(&full_path).is_ok()
}
