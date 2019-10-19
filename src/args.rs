use clap::{load_yaml, value_t, App};

pub struct Args {
    pub target: String,
    pub only_resolved: String,
    pub with_output: String,
    pub file_name: String,
    pub file: String,
    pub unique_output_flag: String,
    pub monitoring_flag: String,
    pub from_file_flag: String,
    pub postgres_user: String,
    pub postgres_password: String,
    pub postgres_host: String,
    pub postgres_port: usize,
    pub postgres_database: String,
}

pub fn get_args() -> Args {
    let empty_value = String::from("");
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    let yes = String::from("y");
    let not = String::from("n");

    Args {
        target: value_t!(matches, "target", String).unwrap_or_else(|_| empty_value.clone()),
        only_resolved: if matches.is_present("resolved") {
            yes.clone()
        } else {
            empty_value.clone()
        },
        with_output: if matches.is_present("output") || matches.is_present("unique-output") {
            yes.clone()
        } else {
            not
        },
        file_name: if matches.is_present("output") && matches.is_present("target") {
            format!("{}.txt", matches.value_of("target").unwrap().to_string())
        } else if matches.is_present("unique-output") {
            matches.value_of("unique-output").unwrap().to_string()
        } else {
            empty_value.clone()
        },
        file: if matches.is_present("file") {
            matches.value_of("file").unwrap().to_string()
        } else {
            empty_value.clone()
        },
        unique_output_flag: if matches.is_present("unique-output") {
            yes.clone()
        } else {
            empty_value.clone()
        },

        monitoring_flag: if matches.is_present("monitoring-flag") {
            yes.clone()
        } else {
            empty_value.clone()
        },
        from_file_flag: if matches.is_present("file") {
            yes
        } else {
            empty_value.clone()
        },
        postgres_user: value_t!(matches, "postgres-user", String)
            .unwrap_or_else(|_| "postgres".to_string()),

        postgres_password: value_t!(matches, "postgres-password", String)
            .unwrap_or_else(|_| "postgres".to_string()),

        postgres_host: value_t!(matches, "postgres-host", String)
            .unwrap_or_else(|_| "localhost".to_string()),

        postgres_port: value_t!(matches, "postgres-port", usize).unwrap_or_else(|_| 5432),

        postgres_database: value_t!(matches, "postgres-database", String)
            .unwrap_or_else(|_| empty_value.clone()),
    }
}
