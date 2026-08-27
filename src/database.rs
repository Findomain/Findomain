//! Persistence of results, in `PostgreSQL` or `SQLite`.
//!
//! Both backends speak the same small vocabulary: create the schema, upsert a
//! batch of hosts, list what is already known, empty the table. Every query is
//! parameterised, because target names come from the command line and from
//! files and must never be pasted into SQL.

use {
    crate::{
        config::{Backend, Config},
        errors::{fatal, Context, Result},
        output::{null_ip_checker, ports_string},
        resolve::ResolvData,
    },
    native_tls::TlsConnector,
    postgres_native_tls::MakeTlsConnector,
    std::collections::{HashMap, HashSet},
};

/// Columns added to `PostgreSQL` databases created by older versions.
///
/// Only `PostgreSQL` needs this: it is the backend Findomain has always had, so
/// tables predating these columns exist in the wild. Every SQLite database was
/// created by this code and already has the full schema.
const OPTIONAL_COLUMNS: [&str; 6] = [
    "ip TEXT",
    "http_status TEXT",
    "open_ports TEXT",
    "root_domain TEXT",
    "jobname TEXT",
    "timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP",
];

const CREATE_TABLE_POSTGRES: &str = "CREATE TABLE IF NOT EXISTS subdomains (
    id           SERIAL PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    ip           TEXT,
    http_status  TEXT,
    open_ports   TEXT,
    root_domain  TEXT,
    jobname      TEXT,
    timestamp    TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
)";

const CREATE_TABLE_SQLITE: &str = "CREATE TABLE IF NOT EXISTS subdomains (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL UNIQUE,
    ip           TEXT,
    http_status  TEXT,
    open_ports   TEXT,
    root_domain  TEXT,
    jobname      TEXT,
    timestamp    TEXT DEFAULT CURRENT_TIMESTAMP
)";

/// Indexes backing the lookups monitoring mode performs on every run.
const CREATE_INDEXES: [&str; 2] = [
    "CREATE INDEX IF NOT EXISTS subdomains_root_domain_idx ON subdomains (root_domain)",
    "CREATE INDEX IF NOT EXISTS subdomains_jobname_idx ON subdomains (jobname)",
];

/// Re-running a target must refresh what is stored rather than fail on the
/// unique name, so both backends upsert.
const UPSERT_POSTGRES: &str = "INSERT INTO subdomains \
    (name, ip, http_status, open_ports, root_domain, jobname) \
    VALUES ($1, $2, $3, $4, $5, $6) \
    ON CONFLICT (name) DO UPDATE SET ip = excluded.ip, \
    http_status = excluded.http_status, open_ports = excluded.open_ports, \
    root_domain = excluded.root_domain, jobname = excluded.jobname, \
    timestamp = CURRENT_TIMESTAMP";

const UPSERT_SQLITE: &str = "INSERT INTO subdomains \
    (name, ip, http_status, open_ports, root_domain, jobname) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
    ON CONFLICT (name) DO UPDATE SET ip = excluded.ip, \
    http_status = excluded.http_status, open_ports = excluded.open_ports, \
    root_domain = excluded.root_domain, jobname = excluded.jobname, \
    timestamp = CURRENT_TIMESTAMP";

/// An open connection to whichever backend was configured.
pub enum Database {
    Postgres(Box<postgres::Client>),
    Sqlite(Box<rusqlite::Connection>),
}

impl Database {
    /// Opens the configured backend and makes sure the schema is in place.
    ///
    /// # Errors
    ///
    /// Fails when the database cannot be opened or the schema cannot be created.
    pub fn open(config: &Config) -> Result<Self> {
        let mut database = match &config.database.backend {
            Backend::Postgres => {
                Self::Postgres(Box::new(connect_postgres(&config.database.connection)))
            }
            Backend::Sqlite(path) => Self::Sqlite(Box::new(
                rusqlite::Connection::open(path)
                    .with_context(|| format!("Can't open the SQLite database {path}"))?,
            )),
        };
        database.prepare_schema()?;
        Ok(database)
    }

    /// Creates the table and its indexes, upgrading an older `PostgreSQL` schema.
    fn prepare_schema(&mut self) -> Result<()> {
        match self {
            Self::Postgres(client) => {
                client.execute(CREATE_TABLE_POSTGRES, &[])?;
                for column in OPTIONAL_COLUMNS {
                    // Already-present columns make this fail, the normal case.
                    let _ =
                        client.execute(&format!("ALTER TABLE subdomains ADD COLUMN {column}"), &[]);
                }
                for index in CREATE_INDEXES {
                    client.execute(index, &[])?;
                }
            }
            Self::Sqlite(connection) => {
                // A rebuildable scan cache does not need full durability.
                connection.pragma_update(None, "journal_mode", "WAL")?;
                connection.pragma_update(None, "synchronous", "NORMAL")?;
                connection.execute(CREATE_TABLE_SQLITE, [])?;
                for index in CREATE_INDEXES {
                    connection.execute(index, [])?;
                }
            }
        }
        Ok(())
    }

    /// Stores every resolved subdomain in a single transaction.
    ///
    /// # Errors
    ///
    /// Fails when the transaction cannot be committed.
    pub fn upsert_all<S: std::hash::BuildHasher>(
        &mut self,
        config: &Config,
        root_domain: &str,
        subdomains_data: &HashMap<String, ResolvData, S>,
    ) -> Result<()> {
        if subdomains_data.is_empty() {
            return Ok(());
        }
        let jobname = &config.database.jobname;
        let scanning_ports = config.ports.enabled;

        match self {
            Self::Postgres(client) => {
                let mut transaction = client.transaction()?;
                let statement = transaction.prepare(UPSERT_POSTGRES)?;
                for (subdomain, data) in subdomains_data {
                    transaction.execute(
                        &statement,
                        &[
                            subdomain,
                            &null_ip_checker(&data.ip),
                            &data.http_data.http_status,
                            &ports_string(&data.open_ports, scanning_ports),
                            &root_domain,
                            jobname,
                        ],
                    )?;
                }
                transaction.commit()?;
            }
            Self::Sqlite(connection) => {
                let transaction = connection.transaction()?;
                {
                    let mut statement = transaction.prepare_cached(UPSERT_SQLITE)?;
                    for (subdomain, data) in subdomains_data {
                        statement.execute(rusqlite::params![
                            subdomain,
                            null_ip_checker(&data.ip),
                            data.http_data.http_status,
                            ports_string(&data.open_ports, scanning_ports),
                            root_domain,
                            jobname,
                        ])?;
                    }
                }
                transaction.commit()?;
            }
        }
        Ok(())
    }

    /// Returns the stored names matching `pattern`, a SQL `LIKE` expression.
    ///
    /// # Errors
    ///
    /// Fails when the query cannot be run.
    pub fn names_like(&mut self, pattern: &str) -> Result<HashSet<String>> {
        self.query_names("SELECT name FROM subdomains WHERE name LIKE $1", &[pattern])
    }

    /// Returns the stored names recorded under `jobname`.
    ///
    /// # Errors
    ///
    /// Fails when the query cannot be run.
    pub fn names_by_jobname(&mut self, jobname: &str) -> Result<HashSet<String>> {
        self.query_names("SELECT name FROM subdomains WHERE jobname = $1", &[jobname])
    }

    /// Returns everything already known about `target`.
    ///
    /// # Errors
    ///
    /// Fails when the query cannot be run.
    pub fn names_for_target(&mut self, target: &str) -> Result<HashSet<String>> {
        self.query_names(
            "SELECT name FROM subdomains WHERE root_domain = $1 OR name LIKE $2",
            &[target, &format!("%.{target}")],
        )
    }

    /// Runs a name query, translating the placeholder style per backend.
    fn query_names(&mut self, sql: &str, params: &[&str]) -> Result<HashSet<String>> {
        match self {
            Self::Postgres(client) => {
                let values: Vec<&(dyn postgres::types::ToSql + Sync)> = params
                    .iter()
                    .map(|value| value as &(dyn postgres::types::ToSql + Sync))
                    .collect();
                Ok(client
                    .query(sql, &values)?
                    .iter()
                    .map(|row| row.get::<_, String>(0))
                    .collect())
            }
            Self::Sqlite(connection) => {
                // rusqlite numbers its placeholders with `?`, not `$`.
                let sql = sql.replace('$', "?");
                let mut statement = connection.prepare(&sql)?;
                let rows = statement
                    .query_map(rusqlite::params_from_iter(params.iter()), |row| {
                        row.get::<_, String>(0)
                    })?
                    .collect::<std::result::Result<HashSet<String>, _>>()?;
                Ok(rows)
            }
        }
    }

    /// Empties the subdomains table.
    ///
    /// # Errors
    ///
    /// Fails when the table cannot be emptied.
    pub fn clear(&mut self) -> Result<()> {
        match self {
            Self::Postgres(client) => {
                client.execute("TRUNCATE TABLE subdomains", &[])?;
            }
            Self::Sqlite(connection) => {
                connection.execute("DELETE FROM subdomains", [])?;
            }
        }
        Ok(())
    }
}

/// Opens a `PostgreSQL` connection, terminating when the server is unreachable.
///
/// Self-signed certificates are accepted on purpose: the database is usually a
/// private instance owned by the same person running the scan.
fn connect_postgres(connection_string: &str) -> postgres::Client {
    let connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("build the TLS connector");

    match postgres::Client::connect(connection_string, MakeTlsConnector::new(connector)) {
        Ok(client) => client,
        Err(e) => fatal(&format!(
            "The following error happened while connecting to the database: {e}"
        )),
    }
}

/// Verifies the database is reachable before starting a long enumeration.
pub fn test_connection(config: &Config) {
    if !config.general.quiet {
        println!("Testing connection to database server...");
    }
    if let Err(e) = Database::open(config) {
        fatal(&format!(
            "The following error happened while connecting to the database: {e}"
        ));
    }
    if !config.general.quiet {
        println!("Connection to database server successful, performing enumeration!");
    }
}

/// Returns the subdomains already stored for the queried target or job name.
///
/// # Errors
///
/// Fails when the database cannot be queried.
pub fn stored_subdomains(config: &Config, target: &str) -> Result<HashSet<String>> {
    let mut database = Database::open(config)?;
    if config.database.query_by_jobname {
        database.names_by_jobname(&config.database.jobname)
    } else {
        database.names_like(&format!("%{target}"))
    }
}

/// Returns everything already known about `target`, used to spot new hosts.
///
/// # Errors
///
/// Fails when the database cannot be queried.
pub fn existing_subdomains(config: &Config, target: &str) -> Result<HashSet<String>> {
    Database::open(config)?.names_for_target(target)
}

/// Stores a batch of results.
///
/// # Errors
///
/// Fails when the database cannot be written to.
pub fn commit<S: std::hash::BuildHasher>(
    config: &Config,
    root_domain: &str,
    subdomains_data: &HashMap<String, ResolvData, S>,
) -> Result<()> {
    Database::open(config)?.upsert_all(config, root_domain, subdomains_data)
}

/// Empties the subdomains table.
///
/// # Errors
///
/// Fails when the table cannot be emptied.
pub fn reset(config: &Config) -> Result<()> {
    Database::open(config)?.clear()
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{config::Backend, test_support::TempDir},
        fhc::structs::HttpData,
    };

    fn sqlite_config(dir: &TempDir, name: &str) -> Config {
        let mut config = Config::default();
        config.database.backend = Backend::Sqlite(dir.path(name));
        config
    }

    fn resolv_data(ip: &str, status: &str, ports: &[i32]) -> ResolvData {
        ResolvData {
            ip: ip.to_owned(),
            http_data: HttpData {
                http_status: status.to_owned(),
                ..HttpData::default()
            },
            open_ports: ports.to_vec(),
            ..ResolvData::default()
        }
    }

    fn batch(entries: &[(&str, ResolvData)]) -> HashMap<String, ResolvData> {
        entries
            .iter()
            .map(|(host, data)| ((*host).to_owned(), data.clone()))
            .collect()
    }

    #[test]
    fn a_fresh_sqlite_database_starts_empty() {
        let dir = TempDir::new("db_fresh");
        let config = sqlite_config(&dir, "findomain.db");

        let mut database = Database::open(&config).expect("open");
        assert!(database.names_like("%example.com").unwrap().is_empty());
    }

    #[test]
    fn stored_hosts_can_be_read_back() {
        let dir = TempDir::new("db_roundtrip");
        let config = sqlite_config(&dir, "findomain.db");
        let mut database = Database::open(&config).expect("open");

        database
            .upsert_all(
                &config,
                "example.com",
                &batch(&[
                    ("a.example.com", resolv_data("1.2.3.4", "ACTIVE", &[80])),
                    ("b.example.com", resolv_data("", "INACTIVE", &[])),
                ]),
            )
            .expect("write");

        let names = database.names_like("%example.com").unwrap();
        assert_eq!(names.len(), 2);
        assert!(names.contains("a.example.com"));
        assert!(names.contains("b.example.com"));
    }

    #[test]
    fn writing_the_same_host_twice_updates_it_instead_of_failing() {
        let dir = TempDir::new("db_upsert");
        let config = sqlite_config(&dir, "findomain.db");
        let mut database = Database::open(&config).expect("open");

        let first = batch(&[("a.example.com", resolv_data("1.2.3.4", "ACTIVE", &[]))]);
        let second = batch(&[("a.example.com", resolv_data("5.6.7.8", "INACTIVE", &[]))]);

        database.upsert_all(&config, "example.com", &first).unwrap();
        database
            .upsert_all(&config, "example.com", &second)
            .expect("a repeated host must not abort the batch");

        assert_eq!(database.names_for_target("example.com").unwrap().len(), 1);
    }

    #[test]
    fn a_repeated_host_does_not_lose_the_rest_of_the_batch() {
        let dir = TempDir::new("db_batch");
        let config = sqlite_config(&dir, "findomain.db");
        let mut database = Database::open(&config).expect("open");

        database
            .upsert_all(
                &config,
                "example.com",
                &batch(&[("a.example.com", resolv_data("1.2.3.4", "ACTIVE", &[]))]),
            )
            .unwrap();
        database
            .upsert_all(
                &config,
                "example.com",
                &batch(&[
                    ("a.example.com", resolv_data("1.2.3.4", "ACTIVE", &[])),
                    ("b.example.com", resolv_data("5.6.7.8", "ACTIVE", &[])),
                ]),
            )
            .unwrap();

        assert_eq!(database.names_for_target("example.com").unwrap().len(), 2);
    }

    #[test]
    fn hosts_are_found_by_job_name() {
        let dir = TempDir::new("db_jobname");
        let mut config = sqlite_config(&dir, "findomain.db");
        config.database.jobname = "nightly".to_owned();
        let mut database = Database::open(&config).expect("open");

        database
            .upsert_all(
                &config,
                "example.com",
                &batch(&[("a.example.com", resolv_data("1.2.3.4", "ACTIVE", &[]))]),
            )
            .unwrap();

        assert_eq!(database.names_by_jobname("nightly").unwrap().len(), 1);
        assert!(database.names_by_jobname("other").unwrap().is_empty());
    }

    #[test]
    fn hosts_of_another_target_are_not_returned() {
        let dir = TempDir::new("db_scope");
        let config = sqlite_config(&dir, "findomain.db");
        let mut database = Database::open(&config).expect("open");

        database
            .upsert_all(
                &config,
                "example.com",
                &batch(&[("a.example.com", resolv_data("1.2.3.4", "ACTIVE", &[]))]),
            )
            .unwrap();
        database
            .upsert_all(
                &config,
                "other.com",
                &batch(&[("a.other.com", resolv_data("1.2.3.4", "ACTIVE", &[]))]),
            )
            .unwrap();

        let names = database.names_like("%example.com").unwrap();
        assert_eq!(names.len(), 1);
        assert!(names.contains("a.example.com"));
    }

    #[test]
    fn clearing_removes_everything() {
        let dir = TempDir::new("db_clear");
        let config = sqlite_config(&dir, "findomain.db");
        let mut database = Database::open(&config).expect("open");

        database
            .upsert_all(
                &config,
                "example.com",
                &batch(&[("a.example.com", resolv_data("1.2.3.4", "ACTIVE", &[]))]),
            )
            .unwrap();
        database.clear().unwrap();

        assert!(database.names_like("%example.com").unwrap().is_empty());
    }

    #[test]
    fn an_empty_batch_is_a_no_op() {
        let dir = TempDir::new("db_empty_batch");
        let config = sqlite_config(&dir, "findomain.db");
        let mut database = Database::open(&config).expect("open");

        database
            .upsert_all(&config, "example.com", &HashMap::new())
            .expect("an empty batch must not fail");
        assert!(database.names_like("%example.com").unwrap().is_empty());
    }

    #[test]
    fn the_schema_survives_being_prepared_twice() {
        let dir = TempDir::new("db_reopen");
        let config = sqlite_config(&dir, "findomain.db");

        {
            let mut database = Database::open(&config).expect("first open");
            database
                .upsert_all(
                    &config,
                    "example.com",
                    &batch(&[("a.example.com", resolv_data("1.2.3.4", "ACTIVE", &[]))]),
                )
                .unwrap();
        }

        let mut reopened = Database::open(&config).expect("second open");
        assert_eq!(reopened.names_for_target("example.com").unwrap().len(), 1);
    }

    #[test]
    fn a_name_pattern_matches_only_its_suffix() {
        let dir = TempDir::new("db_like");
        let config = sqlite_config(&dir, "findomain.db");
        let mut database = Database::open(&config).expect("open");

        database
            .upsert_all(
                &config,
                "example.com",
                &batch(&[
                    ("a.example.com", resolv_data("1.2.3.4", "ACTIVE", &[])),
                    ("a.other.com", resolv_data("1.2.3.4", "ACTIVE", &[])),
                ]),
            )
            .unwrap();

        let names = database.names_like("%example.com").unwrap();
        assert_eq!(names.len(), 1);
        assert!(names.contains("a.example.com"));
    }

    #[test]
    fn a_quote_in_the_target_cannot_break_the_query() {
        let dir = TempDir::new("db_injection");
        let config = sqlite_config(&dir, "findomain.db");
        let mut database = Database::open(&config).expect("open");

        database
            .upsert_all(
                &config,
                "example.com",
                &batch(&[("a.example.com", resolv_data("1.2.3.4", "ACTIVE", &[]))]),
            )
            .unwrap();

        // Parameter binding means this is a literal name, never SQL.
        let hostile = "'; DROP TABLE subdomains; --";
        assert!(database.names_for_target(hostile).unwrap().is_empty());
        assert_eq!(database.names_for_target("example.com").unwrap().len(), 1);
    }
}
