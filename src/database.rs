use {
    crate::{
        errors::*,
        logic,
        structs::{Args, ResolvData, Subdomain},
    },
    postgres::{Client, NoTls},
    std::collections::HashMap,
};

pub fn prepare_database(postgres_connection: &str) -> Result<()> {
    let mut connection: postgres::Client = Client::connect(postgres_connection, NoTls)?;
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
    update_database_schema(connection)?;
    Ok(())
}

fn update_database_schema(mut connection: postgres::Client) -> Result<()> {
    let _ = connection
        .execute("ALTER TABLE subdomains ADD COLUMN root_domain TEXT", &[])
        .is_ok();

    let _ = connection
        .execute("ALTER TABLE subdomains ADD COLUMN jobname TEXT", &[])
        .is_ok();
    Ok(())
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
                &resolv_data.http_status.http_status,
                &logic::return_ports_string(&resolv_data.open_ports, args),
                &root_domain,
                &args.jobname,
            ],
        )?;
    }
    prepared_transaction.commit()?;
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
    }

    let mut connection: postgres::Client = Client::connect(&args.postgres_connection, NoTls)?;
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
    logic::works_with_data(args)?;
    Ok(())
}
