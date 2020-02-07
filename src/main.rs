use findomain::{args, errors::*, get_subdomains, read_from_file, update_checker};

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
