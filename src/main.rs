use findomain::errors::*;
use findomain::{args, get_subdomains, read_from_file};

fn run() -> Result<()> {
    let mut arguments = args::get_args();
    if !arguments.target.is_empty() {
        get_subdomains(&mut arguments)
    } else if !arguments.file.is_empty() {
        read_from_file(&mut arguments)
    } else {
        eprintln!("Error: Target is empty and not input file was supplied!");
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
