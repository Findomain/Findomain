use crate::args;
use crate::misc;
use {
    crate::errors::*,
    serde::*,
    std::os::unix::fs::OpenOptionsExt,
    std::{
        fs::{self, OpenOptions},
        io,
    },
};

#[derive(Deserialize)]
struct GitVer {
    tag_name: String,
}

const BASE_URL: &str = "https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-";

fn return_git_version() -> Option<String> {
    println!("Checking for latest Github release... 🔍");
    match misc::return_reqwest_client()
        .get("https://api.github.com/repos/edu4rdshl/findomain/releases/latest")
        .send()
    {
        Ok(github_response) => match github_response.json::<GitVer>() {
            Ok(github_data) => Some(github_data.tag_name),
            Err(e) => {
                check_json_errors(e, "Github Releases", false);
                None
            }
        },
        Err(e) => {
            check_request_errors(e, "Github Releases", false);
            None
        }
    }
}

pub fn selfupdater(args: &mut args::Args) -> Result<()> {
    let download_url = format!(
        "{}{}",
        BASE_URL,
        match env!("TARGET") {
            "x86_64-unknown-linux-gnu" => "linux",
            "x86_64-pc-windows-gnu" => "windows.exe",
            "x86_64-apple-darwin" => "osx",
            "aarch64-unknown-linux-gnu" => "aarch64",
            _ => "UnknownPlatform",
        }
    );
    let latest_version = return_git_version().unwrap();
    println!(
        "Findomain local release: {}, Findomain latest release: {}",
        args.version, latest_version
    );
    if latest_version.replace(".", "").parse::<usize>().unwrap()
        > args.version.replace(".", "").parse::<usize>().unwrap()
    {
        if download_url.contains("UnknownPlatform") {
            eprintln!("Update is available but you are running a unsupported platform by Findomain self-updater. Please use cargo to update the tool instead. See https://git.io/Jv3v7 for more information.");
            std::process::exit(1)
        };
        println!("Update is available, trying to update Findomain now...");
        println!("Downloading latest release from: {}", download_url);
        update_file(latest_version, download_url, args)?;
    } else {
        println!("Findomain is up to date!");
        std::process::exit(0)
    }
    Ok(())
}

fn update_file(latest_version: String, download_url: String, args: &mut args::Args) -> Result<()> {
    println!("Removing the old version of Findomain...");
    match fs::remove_file(&args.current_executable_path) {
        Ok(_) => {
            match OpenOptions::new()
                .create(true)
                .write(true)
                .mode(0o755)
                .open(&args.current_executable_path)
            {
                Ok(mut out) => {
                    println!("Download started, wait...");
                    let mut response = misc::return_reqwest_client().get(&download_url).send()?;
                    io::copy(&mut response, &mut out)?;
                    println!(
                        "Findomain has been sucessfully updated to {} version.",
                        latest_version
                    );
                    std::process::exit(0)
                }
                Err(_) => {
                    let mut out = fs::OpenOptions::new()
                        .create(true)
                        .write(true)
                        .read(true)
                        .open(&args.current_executable_path)?;
                    println!("Download started, wait...");
                    let mut response = misc::return_reqwest_client().get(&download_url).send()?;
                    std::io::copy(&mut response, &mut out)?;
                    println!(
                        "Findomain has been sucessfully updated to {} version.",
                        latest_version
                    );
                    std::process::exit(0)
                }
            }
        }
        Err(e) => eprintln!(
            "An error has occurred deleting the file from {} : {}",
            &args.current_executable_path, e
        ),
    }
    Ok(())
}
