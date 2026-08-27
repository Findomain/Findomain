//! Mutable state of a run.
//!
//! [`Config`](crate::config::Config) answers "what was asked for" and never
//! changes; `Session` answers "where are we" and is the only thing the stages
//! mutate. One session covers a whole invocation, being re-pointed at each
//! target in turn.

use std::{collections::HashSet, time::Instant};

/// Progress of the current run.
#[derive(Debug)]
pub struct Session {
    pub target: String,
    pub file_name: String,
    pub subdomains: HashSet<String>,
    pub wildcard_ips: HashSet<String>,
    /// Whether this is the last target, used to skip the final rate limit.
    pub is_last_target: bool,
    pub started_at: Instant,
    pub database_checked: bool,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            target: String::new(),
            file_name: String::new(),
            subdomains: HashSet::new(),
            wildcard_ips: HashSet::new(),
            is_last_target: false,
            started_at: Instant::now(),
            database_checked: false,
        }
    }
}

impl Session {
    /// Starts a session for a single target.
    #[must_use]
    pub fn new(target: String, file_name: String) -> Self {
        Self {
            target,
            file_name,
            is_last_target: true,
            ..Self::default()
        }
    }

    pub fn start_target(&mut self, target: String, file_name: String, is_last: bool) {
        self.target = target;
        self.file_name = file_name;
        self.is_last_target = is_last;
        self.subdomains.clear();
        self.wildcard_ips.clear();
    }

    pub fn restart_clock(&mut self) {
        self.started_at = Instant::now();
    }

    /// Seconds spent on the current target.
    #[must_use]
    pub fn elapsed_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// Returns the target prefixed with a dot, for suffix matching.
    #[must_use]
    pub fn base_target(&self) -> String {
        format!(".{}", self.target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_target_session_is_also_the_last_one() {
        let session = Session::new("example.com".to_owned(), "out.txt".to_owned());
        assert!(session.is_last_target);
        assert_eq!(session.base_target(), ".example.com");
    }

    #[test]
    fn starting_a_target_clears_the_previous_results() {
        let mut session = Session::default();
        session.subdomains.insert("a.example.com".to_owned());
        session.wildcard_ips.insert("1.2.3.4".to_owned());
        session.database_checked = true;

        session.start_target("other.com".to_owned(), "other.txt".to_owned(), false);

        assert_eq!(session.target, "other.com");
        assert_eq!(session.file_name, "other.txt");
        assert!(session.subdomains.is_empty());
        assert!(session.wildcard_ips.is_empty());
        assert!(!session.is_last_target);
        // Cross-target state survives.
        assert!(session.database_checked);
    }
}
