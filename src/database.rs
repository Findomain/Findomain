use {
    crate::{
        errors::Result,
        logic,
        structs::{Args, ResolvData, Subdomain},
    },
    native_tls::TlsConnector,
    postgres::Client,
    postgres_native_tls::MakeTlsConnector,
    std::collections::{HashMap, HashSet},
};

pub fn return_database_connection(postgres_connection: &str) -> Client {
    // Lets accept self signed certificates
    let connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let tls_connector = MakeTlsConnector::new(connector);

    match Client::connect(postgres_connection, tls_connector) {
        Ok(client) => client,
        Err(e) => {
            println!(
                "The following error happened while connecting to the database: {}",
                e
            );
            std::process::exit(1)
        }
    }
}

pub fn prepare_database(postgres_connection: &str) -> Result<()> {
    let mut connection: postgres::Client = return_database_connection(postgres_connection);
    connection.execute(
        "CREATE TABLE IF NOT EXISTS subdomains (
                   id              SERIAL PRIMARY KEY,
                   name            TEXT NOT NULL UNIQUE,
                   ip              TEXT,
                   http_status     TEXT,
                   open_ports      TEXT,
                   root_domain     TEXT,
                   jobname         TEXT,
                   timestamp       TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
              )",
        &[],
    )?;
    update_database_schema(connection);
    Ok(())
}

fn update_database_schema(mut connection: postgres::Client) {
    let database_columns = vec!["ip", "http_status", "open_ports", "root_domain", "jobname"];
    for column in database_columns {
        let _ = connection
            .execute(
                format!("ALTER TABLE subdomains ADD COLUMN {column} TEXT").as_str(),
                &[],
            )
            .is_ok();
    }
    let _ = connection.close().is_ok();
}

pub fn commit_to_db<S: ::std::hash::BuildHasher>(
    mut conn: postgres::Client,
    subdomains_data: &HashMap<String, ResolvData, S>,
    root_domain: &str,
    args: &Args,
) -> Result<()> {
    let mut prepared_transaction = conn.transaction()?;
    for (subdomain, resolv_data) in subdomains_data {
        prepared_transaction.execute(
            "INSERT INTO subdomains (name, ip, http_status, open_ports, root_domain, jobname) VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &subdomain,
                &logic::null_ip_checker(&resolv_data.ip),
                &resolv_data.http_data.http_status,
                &logic::return_ports_string(&resolv_data.open_ports, args),
                &root_domain,
                &args.jobname,
            ],
        )?;
    }

    prepared_transaction.commit()?;

    let _ = conn.close().is_ok();
    Ok(())
}

pub fn query_findomain_database(args: &mut Args) -> Result<()> {
    if !args.quiet_flag && args.query_database {
        println!(
            "Searching subdomains in the Findomain database for the target {} 🔍",
            args.target
        )
    } else if !args.quiet_flag && args.query_jobname {
        println!(
            "Searching subdomains in the Findomain database for the job name {} 🔍",
            args.jobname
        )
    };

    let mut connection: postgres::Client = return_database_connection(&args.postgres_connection);

    prepare_database(&args.postgres_connection)?;

    if args.query_database {
        let statement: &str = &format!(
            "SELECT name FROM subdomains WHERE name LIKE '%{}'",
            &args.target
        );
        let existing_subdomains = connection.query(statement, &[])?;
        args.subdomains = existing_subdomains
            .iter()
            .map(|row| {
                let subdomain = Subdomain {
                    name: row.get("name"),
                };
                subdomain.name
            })
            .collect();
    } else if args.query_jobname {
        let statement: &str = &format!(
            "SELECT name FROM subdomains WHERE jobname = '{}'",
            &args.jobname
        );
        let existing_subdomains = connection.query(statement, &[])?;
        args.subdomains = existing_subdomains
            .iter()
            .map(|row| {
                let subdomain = Subdomain {
                    name: row.get("name"),
                };
                subdomain.name
            })
            .collect();
    }
    let _ = connection.close().is_ok();
    logic::works_with_data(args)?;

    std::process::exit(0)
}

pub fn return_existing_subdomains(args: &Args) -> Result<HashSet<String>> {
    let mut connection = return_database_connection(&args.postgres_connection);

    prepare_database(&args.postgres_connection)?;

    let statement = format!(
        "SELECT name FROM subdomains WHERE root_domain = '{}' OR name LIKE '%.{}'",
        args.target, args.target
    );

    let existing_subdomains: HashSet<String> = connection
        .query(&statement, &[])?
        .iter()
        .map(|row| {
            let subdomain = Subdomain {
                name: row.get("name"),
            };
            subdomain.name
        })
        .collect();

    connection.close()?;

    Ok(existing_subdomains)
}
