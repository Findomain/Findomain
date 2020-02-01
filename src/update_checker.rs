use {
    crate::{args, errors::*, misc},
    semver::Version,
    serde::*,
};

#[derive(Deserialize)]
struct GitVer {
    tag_name: String,
}

fn return_latest_release() -> String {
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
    let latest_version = return_latest_release();
    if Version::parse(&latest_version) > Version::parse(&args.version) {
        if !args.quiet_flag {
            println!(
                "Findomain local release: {}, Findomain latest stable release: {}",
                args.version, latest_version
            );
            println!("Update is available, please see https://git.io/Jv3v7 for more information.");
        }
    } else if !args.quiet_flag {
        println!("Findomain is up to date.");
    }
    Ok(())
}
