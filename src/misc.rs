pub fn show_searching_msg(api: &str) {
    println!("Searching in the {} API... 🔍", api)
}

pub fn show_subdomains_found(subdomains_found: usize, target: &str, quiet_flag: bool) {
    if !quiet_flag {
        println!(
            "\nA total of {} subdomains were found for ==>  {} 👽",
            subdomains_found, target
        )
    }
}
