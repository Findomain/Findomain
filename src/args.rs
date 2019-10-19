use clap::{load_yaml, value_t, App};

pub struct Args {
    pub target: String,
    pub file_name: String,
    pub file: String,
    pub postgres_user: String,
    pub postgres_password: String,
    pub postgres_host: String,
    pub postgres_port: usize,
    pub postgres_database: String,
    pub only_resolved: bool,
    pub with_ip: bool,
    pub with_output: bool,
    pub unique_output_flag: bool,
    pub monitoring_flag: bool,
    pub from_file_flag: bool,
    pub quiet_flag: bool,
}

pub fn get_args() -> Args {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    Args {
        target: value_t!(matches, "target", String).unwrap_or_else(|_| String::from("")),
        file_name: if matches.is_present("output") && matches.is_present("target") {
            format!("{}.txt", matches.value_of("target").unwrap().to_string())
        } else if matches.is_present("unique-output") {
            matches.value_of("unique-output").unwrap().to_string()
        } else {
            String::from("")
        },
        file: if matches.is_present("file") {
            matches.value_of("file").unwrap().to_string()
        } else {
            String::from("")
        },
        postgres_user: value_t!(matches, "postgres-user", String)
            .unwrap_or_else(|_| "postgres".to_string()),

        postgres_password: value_t!(matches, "postgres-password", String)
            .unwrap_or_else(|_| "postgres".to_string()),

        postgres_host: value_t!(matches, "postgres-host", String)
            .unwrap_or_else(|_| "localhost".to_string()),

        postgres_port: value_t!(matches, "postgres-port", usize).unwrap_or_else(|_| 5432),

        postgres_database: value_t!(matches, "postgres-database", String)
            .unwrap_or_else(|_| String::from("")),

        only_resolved: matches.is_present("resolved"),
        with_ip: matches.is_present("ip"),
        with_output: matches.is_present("output") || matches.is_present("unique-output"),
        unique_output_flag: matches.is_present("unique-output"),
        monitoring_flag: matches.is_present("monitoring-flag"),
        from_file_flag: matches.is_present("file"),
        quiet_flag: matches.is_present("quiet"),
    }
}
