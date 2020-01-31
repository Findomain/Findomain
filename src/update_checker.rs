use {
    crate::{args, errors::*, misc},
    serde::*,
};

#[derive(Deserialize)]
struct GitVer {
    tag_name: String,
}

fn return_git_version() -> String {
    println!("Checking for latest Github release... 🔍");
    match misc::return_reqwest_client()
        .get("https://api.github.com/repos/edu4rdshl/findomain/releases/latest")
        .send()
    {
        Ok(github_response) => match github_response.json::<GitVer>() {
            Ok(github_data) => github_data.tag_name,
            Err(e) => {
                check_json_errors(e, "Github Releases", false);
                String::new()
            }
        },
        Err(e) => {
            check_request_errors(e, "Github Releases", false);
            String::new()
        }
    }
}

pub fn main(args: &mut args::Args) -> Result<()> {
    let latest_version = return_git_version();
    if latest_version.replace(".", "").parse::<usize>().unwrap()
        > args
            .version
            .replace(&['.', '-', 'c', 'r', 'v'][..], "")
            .parse::<usize>()
            .unwrap()
    {
        if !args.quiet_flag {
            println!(
                "Findomain local release: {}, Findomain latest stable release: {}",
                args.version, latest_version
            );
            println!("Update is available, please see https://git.io/Jv3v7 for more information.");
            std::process::exit(0)
        }
    } else if !args.quiet_flag {
        println!("Findomain is up to date.");
        std::process::exit(0)
    }
    Ok(())
}
