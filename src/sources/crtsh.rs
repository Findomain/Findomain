//! crt.sh, queried through its public `PostgreSQL` mirror with the JSON API as
//! a fallback.
//!
//! The database is preferred because the HTTP endpoint answers 503 far more
//! often than it answers data, but it is the flakier connection of the two, so
//! any failure quietly falls back to the API.

use {
    super::{fetch, models::CrtshEntry, SourceContext},
    postgres::{NoTls, SimpleQueryMessage},
    std::{collections::HashSet, sync::mpsc, thread, time::Duration},
};

/// Read-only credentials published by crt.sh.
const DB_HOST: &str = "crt.sh";
const DB_PORT: u16 = 5432;
const DB_USER: &str = "guest";
const DB_NAME: &str = "certwatch";
const DB_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Rows a single query is allowed to return.
const DB_ROW_LIMIT: usize = 100_000;

/// Reports whether `target` is safe to inline into a simple-protocol query.
///
/// crt.sh sits behind a connection pooler that rejects prepared statements, so
/// the query cannot bind parameters and the target has to be part of the SQL
/// text. Callers only ever pass a hostname that already went through
/// [`validate_target`](crate::filters::validate_target); this re-checks it
/// here so the guarantee is enforced next to the code that depends on it.
fn is_inlinable(target: &str) -> bool {
    !target.is_empty()
        && target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

/// Builds the certificate query for `target`, capped at `timeout` when given.
///
/// `2.5.4.3` is the OID of the X.509 common name attribute.
///
/// The cap has to travel as a `SET` in the same batch as the query itself. The
/// pooler in front of crt.sh rejects `options` as an unsupported startup
/// parameter, and in transaction pooling a `SET` sent on its own would apply to
/// somebody else's next transaction rather than to this one; batching the two
/// makes them a single transaction, so the cap lands where it is meant to.
fn db_query(target: &str, timeout: Option<Duration>) -> String {
    let cap = timeout.map_or_else(String::new, |timeout| {
        format!("SET statement_timeout = {}; ", timeout.as_millis())
    });
    format!(
        "{cap}SELECT cai.NAME_VALUE FROM certificate_and_identities cai \
         WHERE plainto_tsquery('certwatch', '{target}') @@ identities(cai.CERTIFICATE) \
         AND cai.NAME_VALUE LIKE '%.{target}' \
         AND cai.NAME_TYPE = '2.5.4.3' LIMIT {DB_ROW_LIMIT}"
    )
}

/// Reports whether a database failure is worth immediately trying again.
///
/// crt.sh serves this query from a streaming replica, which cancels readers
/// whenever replaying the write log would touch rows they are still reading.
/// It says so in as many words, it clears on its own, and the retry is far more
/// valuable than it looks: the JSON API this would otherwise fall back to
/// matches on the certificate common name alone, so it returns a small fraction
/// of what the query finds.
fn is_transient(reason: &str) -> bool {
    reason.contains("conflict with recovery")
}

/// Runs the database query, giving up once `deadline` has passed.
///
/// The server's statement timeout only starts counting once the query is
/// running, and crt.sh sits behind a transaction pooler that can hold a client
/// waiting for a free backend long before that. Measured against owasp.org, a
/// five second statement timeout still took fifty seven seconds to answer. The
/// only clock that covers the wait is one this side of the connection, so the
/// query runs on a thread of its own and is abandoned when the time is up.
fn within(budget: Option<Duration>, target: &str) -> Result<HashSet<String>, String> {
    let Some(deadline) = budget else {
        return query(target, None);
    };

    let (sender, receiver) = mpsc::channel();
    let owned = target.to_owned();
    // Abandoned on timeout: the thread finishes into a dropped receiver.
    thread::spawn(move || {
        let _ = sender.send(query(&owned, budget));
    });

    receiver.recv_timeout(deadline).unwrap_or_else(|_| {
        Err("querying the Crtsh database. Error: it did not answer within the time budget".into())
    })
}

/// Queries crt.sh, preferring the database mirror over the JSON API.
#[must_use]
pub fn subdomains(context: &SourceContext, target: &str) -> Option<HashSet<String>> {
    context.announce("Crtsh database");

    let mut attempt = from_database(context, target);
    if attempt.as_ref().is_err_and(|reason| is_transient(reason)) {
        attempt = from_database(context, target);
    }

    match attempt {
        Ok(subdomains) => Some(subdomains),
        Err(reason) => {
            if !context.quiet {
                eprintln!("❌ A error has occurred while {reason}. Trying the API method...");
            }
            from_api(context, target)
        }
    }
}

/// Runs the certificate query against the crt.sh `PostgreSQL` mirror.
///
/// The error carries the phrase describing which step failed.
fn from_database(context: &SourceContext, target: &str) -> Result<HashSet<String>, String> {
    if !is_inlinable(target) {
        return Err("preparing the Crtsh query. Error: the target is not a plain hostname".into());
    }

    let cap = context.remaining();
    if cap == Some(Duration::ZERO) {
        return Err(
            "querying the Crtsh database. Error: the time budget for the sources is spent".into(),
        );
    }
    within(cap, target)
}

/// Runs the certificate query against the crt.sh `PostgreSQL` mirror.
fn query(target: &str, cap: Option<Duration>) -> Result<HashSet<String>, String> {
    let mut client = postgres::config::Config::new()
        .connect_timeout(DB_CONNECT_TIMEOUT)
        // The statement timeout is the server's promise, and it says nothing
        // about a connection that simply stops carrying data. Without this a
        // stalled crt.sh holds the whole run open long past its budget.
        .tcp_user_timeout(cap.unwrap_or(DB_CONNECT_TIMEOUT))
        .keepalives_idle(DB_CONNECT_TIMEOUT)
        .user(DB_USER)
        .host(DB_HOST)
        .port(DB_PORT)
        .dbname(DB_NAME)
        .connect(NoTls)
        .map_err(|e| format!("connecting to the Crtsh database. Error: {}", describe(&e)))?;

    let messages = client
        .simple_query(&db_query(target, cap))
        .map_err(|e| format!("querying the Crtsh database. Error: {}", describe(&e)))?;

    Ok(messages
        .iter()
        .filter_map(|message| match message {
            SimpleQueryMessage::Row(row) => row.get(0).map(str::to_owned),
            _ => None,
        })
        .filter(|name| !name.is_empty())
        .collect())
}

/// Renders a database error together with the detail the server sent.
///
/// The driver's own message is just "db error"; what the server objected to
/// lives in the wrapped source.
fn describe(error: &postgres::Error) -> String {
    std::error::Error::source(error)
        .map_or_else(|| error.to_string(), |source| format!("{error}: {source}"))
}

/// Queries the crt.sh JSON API.
fn from_api(context: &SourceContext, target: &str) -> Option<HashSet<String>> {
    const API: &str = "Crtsh";
    context.announce(API);

    let request = context.get(&format!("https://crt.sh/?q=%.{target}&output=json"));
    fetch::<Vec<CrtshEntry>>(context, API, request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_hostnames_may_be_inlined() {
        assert!(is_inlinable("example.com"));
        assert!(is_inlinable("a-b_c.example.co.uk"));
    }

    #[test]
    fn anything_that_could_alter_the_sql_is_rejected() {
        for hostile in [
            "",
            "example.com'",
            "'; DROP TABLE certificate_and_identities; --",
            "example.com\\",
            "exa mple.com",
            "example.com;select 1",
            "exämple.com",
        ] {
            assert!(!is_inlinable(hostile), "{hostile} must not be inlined");
        }
    }

    #[test]
    fn a_rejected_target_never_reaches_the_server() {
        let context = SourceContext::new(&crate::config::Config::default());
        let error = from_database(&context, "bad'target").expect_err("must refuse");
        assert!(error.contains("not a plain hostname"));
    }

    #[test]
    fn a_query_that_outlives_its_deadline_is_abandoned() {
        // The thread it runs on keeps going; what matters is that the caller
        // stops waiting, because the pooler in front of crt.sh can hold a
        // query far longer than any server side timeout would suggest.
        let started = std::time::Instant::now();
        let error = within(Some(Duration::from_millis(200)), "example.com");
        assert!(started.elapsed() < Duration::from_secs(5));
        if let Err(reason) = error {
            assert!(reason.contains("time budget") || reason.contains("Crtsh"));
        }
    }

    #[test]
    fn only_the_replica_conflict_is_retried() {
        // Retrying our own statement timeout would just burn the budget again,
        // and a rejected target would fail identically the second time.
        assert!(is_transient(
            "querying the Crtsh database. Error: db error: ERROR: canceling statement due to conflict with recovery"
        ));
        assert!(!is_transient(
            "querying the Crtsh database. Error: db error: ERROR: canceling statement due to statement timeout"
        ));
        assert!(!is_transient(
            "preparing the Crtsh query. Error: the target is not a plain hostname"
        ));
    }

    #[test]
    fn the_query_scopes_results_to_the_target() {
        let query = db_query("example.com", None);
        assert!(query.contains("plainto_tsquery('certwatch', 'example.com')"));
        assert!(query.contains("LIKE '%.example.com'"));
        assert!(query.contains("LIMIT 100000"));
        assert!(!query.contains("statement_timeout"));
    }

    #[test]
    fn the_time_cap_travels_in_the_same_batch_as_the_query() {
        // The pooler rejects `options` and drops a standalone SET on the floor,
        // so the cap is only effective if it shares the batch with the SELECT.
        let query = db_query("example.com", Some(Duration::from_secs(12)));
        assert!(query.starts_with("SET statement_timeout = 12000; SELECT "));
    }

    #[test]
    fn a_spent_budget_stops_the_query_before_it_connects() {
        let config = crate::config::Config {
            sources: crate::config::Sources {
                budget: 1,
                ..crate::config::Sources::default()
            },
            ..crate::config::Config::default()
        };
        let mut context = SourceContext::new(&config);
        context.deadline = Some(std::time::Instant::now());

        let error = from_database(&context, "example.com").expect_err("must refuse");
        assert!(error.contains("time budget"));
    }
}
