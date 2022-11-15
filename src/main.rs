use {
    findomain::{
        args,
        errors::Result,
        files::{read_from_file, return_file_targets, string_to_file},
        get_subdomains,
        logic::validate_target,
        utils,
    },
    std::{collections::HashSet, fs::OpenOptions, iter::FromIterator, path::Path},
};

fn run() -> Result<()> {
    let mut arguments = args::get_args();
    if !arguments.filter_by_string.is_empty()
        && !arguments.exclude_by_string.is_empty()
        && arguments
            .filter_by_string
            .difference(&arguments.exclude_by_string)
            .next()
            .is_none()
    {
        eprintln!("Wait, you are filtering and excluding exactly the same keywords? Please check and try again. \nFiltering keywords: {:?} \nExcluding keywords: {:?}", arguments.filter_by_string, arguments.exclude_by_string);
        std::process::exit(1)
    }

    if arguments.validate_subdomains {
        arguments.subdomains =
            HashSet::from_iter(return_file_targets(&arguments, arguments.files.clone()));
        arguments.subdomains.retain(|sub| validate_target(sub));
        for subdomain in &arguments.subdomains {
            println!("{subdomain}")
        }

        if arguments.unique_output_flag {
            let total_subs_file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(&arguments.file_name);

            let total_subs_file_exists =
                Path::new(&arguments.file_name).exists() && total_subs_file.is_ok();

            if total_subs_file_exists {
                string_to_file(
                    utils::hashset_to_string("\n", arguments.subdomains.clone()),
                    total_subs_file.unwrap(),
                )?;
                println!(
                    "\nValidated subdomains were written to {}. Good luck!",
                    arguments.file_name
                )
            }
        }
        std::process::exit(0)
    }

    if arguments.bruteforce {
        arguments.wordlists_data =
            HashSet::from_iter(return_file_targets(&arguments, arguments.wordlists.clone()))
    }
    if !arguments.target.is_empty() || arguments.query_jobname {
        get_subdomains(&mut arguments)
    } else if !arguments.files.is_empty() || arguments.from_stdin || arguments.query_jobname {
        read_from_file(&mut arguments)
    } else {
        eprintln!("Error: Target is empty or invalid!");
        std::process::exit(1)
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("\nError: {err}");
        for cause in err.chain().skip(1) {
            eprintln!("Error description: {cause}");
        }
        std::process::exit(1);
    }
}
