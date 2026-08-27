//! Findomain: a cross-platform subdomain enumerator.
//!
//! The crate is organised around two values. [`Config`] holds everything the
//! user asked for and never changes once built; [`Session`] holds the state of
//! the run and is the only thing the stages mutate. The stages themselves read
//! top to bottom:
//!
//! - [`cli`] and [`config`] turn flags, files and environment into a `Config`.
//! - [`runner`] decides which targets to process and in which order.
//! - [`discovery`] fans out over the passive [`sources`].
//! - [`resolve`] performs the DNS, HTTP, screenshot and port checks.
//! - [`output`], [`alerts`] and [`database`] report and persist the results.

pub mod alerts;
pub mod cli;
pub mod config;
pub mod database;
pub mod discovery;
pub mod email;
pub mod errors;
pub mod files;
pub mod filters;
pub mod output;
pub mod permutations;
pub mod resolve;
pub mod runner;
pub mod screenshots;
pub mod session;
pub mod sources;
pub mod tools;
pub mod utils;
pub mod webhooks;

#[doc(hidden)]
pub mod test_support;

pub use crate::{cli::Cli, config::Config, errors::Result, runner::run, session::Session};
