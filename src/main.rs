use findomain::{
    args, errors::*, get_subdomains, read_from_file, return_file_targets, update_checker,
};

fn run() -> Result<()> {
    let mut arguments = args::get_args();
    if arguments.check_updates {
        update_checker::main(&mut arguments)?
    }
    if arguments.threads > 500 {
        arguments.threads = 500
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(arguments.threads)
        .build_global()
        .unwrap();
    if arguments.bruteforce {
        if !arguments.only_resolved && !arguments.with_ip && !arguments.ipv6_only {
            println!("To use Findomain bruteforce method, use one of the --resolved/-r, --ip/-i or --ipv6-only options.");
            std::process::exit(1)
        } else {
            let wordlists = arguments.wordlists.clone();
            arguments.wordlists_data = return_file_targets(&mut arguments, wordlists)
        }
    }
    if !arguments.target.is_empty() {
        get_subdomains(&mut arguments)
    } else if !arguments.files.is_empty() {
        read_from_file(&mut arguments)
    } else {
        eprintln!("Error: Target is empty or invalid!");
        std::process::exit(1)
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
