pub fn return_ipv4_resolvers() -> Vec<String> {
    vec![
        // Cloudflare
        "1.1.1.1",
        "1.0.0.1",
        // Google
        "8.8.8.8",
        "8.8.4.4",
        // Quad9
        "9.9.9.9",
        "149.112.112.112",
        // OpenDNS
        "208.67.222.222",
        "208.67.220.220",
        // Verisign
        "64.6.64.6",
        "64.6.65.6",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
