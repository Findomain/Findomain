use {
    findomain::{
        args, errors::*, files::read_from_file, files::return_file_targets, get_subdomains,
        structs::Args,
    },
    std::{collections::HashSet, iter::FromIterator},
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
    manage_threads(&mut arguments);
    if arguments.bruteforce {
        if !arguments.discover_ip && !arguments.http_status && !arguments.enable_port_scan {
            println!("To use Findomain bruteforce method, use one of the --resolved/-r, --ip/-i, --ipv6-only, --http-status or --pscan/--iport/--lport options.");
            std::process::exit(1)
        } else {
            let wordlists = arguments.wordlists.clone();
            arguments.wordlists_data =
                HashSet::from_iter(return_file_targets(&arguments, wordlists))
        }
    }
    if !arguments.target.is_empty() || arguments.query_jobname {
        get_subdomains(&mut arguments)
    } else if !arguments.files.is_empty() || arguments.query_jobname {
        read_from_file(&mut arguments)
    } else {
        eprintln!("Error: Target is empty or invalid!");
        std::process::exit(1)
    }
}

fn manage_threads(arguments: &mut Args) {
    if arguments.discover_ip
        || arguments.http_status
        || arguments.enable_port_scan
        || arguments.take_screenshots
    {
        if arguments.threads > 1000
            && !arguments.enable_port_scan
            && !arguments.unlock_threads
            && !arguments.take_screenshots
        {
            if !arguments.quiet_flag {
                println!("Number of threads too high, maximum allowed is 1000. Adjusting the number of threads from {} to 1000. Use the --unlock flag if you want to bypass this filter.", arguments.threads)
            }
            arguments.threads = 1000
        } else if arguments.threads > 300
            && arguments.enable_port_scan
            && !arguments.unlock_threads
            && !arguments.take_screenshots
        {
            if !arguments.quiet_flag {
                println!("The maximum recommended number of threads for a good port scan process is 300. Adjusting the number of threads from {} to 300. Use the --unlock flag if you want to bypass this filter.", arguments.threads)
            }
            arguments.threads = 300
        } else if arguments.threads > 5 && arguments.take_screenshots && !arguments.unlock_threads {
            if !arguments.quiet_flag {
                println!("The maximum recommended number of threads for a subdomains screenshots process is 5. Adjusting the number of threads from {} to 5. Use the --unlock flag if you want to bypass this filter.", arguments.threads)
            }
            arguments.threads = 5
        }
        rayon::ThreadPoolBuilder::new()
            .num_threads(arguments.threads)
            .build_global()
            .unwrap()
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("\nError: {}", err);
        for cause in err.iter_chain().skip(1) {
            eprintln!("Error description: {}", cause);
        }
        std::process::exit(1);
    }
}
