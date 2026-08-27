//! Loading of the optional configuration file and the `FINDOMAIN_*` environment
//! variables.
//!
//! Every value ends up as a plain string keyed by its lowercase name; the
//! [`builder`](super::builder) is responsible for turning those strings into
//! typed configuration.

use {
    crate::errors::fatal,
    std::{collections::HashMap, env, path::Path, str::FromStr},
};

const DEFAULT_BASENAME: &str = "findomain";

/// Extensions probed for [`DEFAULT_BASENAME`], in the order the `config` crate
/// understands them.
const SUPPORTED_EXTENSIONS: [&str; 4] = ["toml", "json", "ini", "yml"];

/// Prefix for environment variables, e.g. `FINDOMAIN_C99_API_KEY`.
const ENV_PREFIX: &str = "FINDOMAIN";

/// Overrides `--config` when set.
const ENV_CONFIG_FILE: &str = "FINDOMAIN_CONFIG_FILE";

/// Flattened view of the configuration file plus the `FINDOMAIN_*` environment.
///
/// `sequences` keeps the values that were written as a list, because the
/// flattened form cannot tell `["-mc", "200,301"]` from `["-mc", "200", "301"]`
/// and the passthrough arguments depend on that boundary.
#[derive(Debug, Default, Clone)]
pub struct Settings {
    values: HashMap<String, String>,
    sequences: HashMap<String, Vec<String>>,
}

impl Settings {
    /// Reads the configuration file (if any) and the environment.
    ///
    /// The file is only consulted when `--config` was given, when
    /// `FINDOMAIN_CONFIG_FILE` is set, or when a `findomain.<ext>` file exists
    /// in the working directory. Environment variables always take precedence
    /// over the file.
    #[must_use]
    pub fn load(config_file: Option<&str>) -> Self {
        let mut builder = ::config::Config::builder();

        if let Some(file) = configured_file(config_file) {
            builder = builder.add_source(::config::File::with_name(&file));
        } else if default_file_exists() {
            builder = builder.add_source(::config::File::with_name(DEFAULT_BASENAME));
        }

        builder = builder.add_source(::config::Environment::with_prefix(ENV_PREFIX));

        match builder.build() {
            Ok(settings) => match settings.try_deserialize::<HashMap<String, ::config::Value>>() {
                Ok(values) => {
                    let sequences: HashMap<String, Vec<String>> = values
                        .iter()
                        .filter_map(|(key, value)| Some((key.clone(), sequence(value)?)))
                        .collect();
                    Self {
                        values: values
                            .into_iter()
                            .map(|(key, value)| (key, flatten(value)))
                            .collect(),
                        sequences,
                    }
                }
                Err(e) => fatal(&format!("Error parsing configuration: {e}")),
            },
            Err(e) => fatal(&format!("Error building configuration: {e}")),
        }
    }

    /// Builds settings straight from a map of flattened values.
    #[cfg(test)]
    #[must_use]
    pub fn from_map(values: HashMap<String, String>) -> Self {
        Self {
            values,
            sequences: HashMap::new(),
        }
    }

    /// Builds settings holding a single list valued key.
    #[cfg(test)]
    #[must_use]
    pub fn from_sequence(key: &str, items: &[&str]) -> Self {
        let items: Vec<String> = items.iter().map(|item| (*item).to_owned()).collect();
        Self {
            values: HashMap::from([(key.to_owned(), items.join(","))]),
            sequences: HashMap::from([(key.to_owned(), items)]),
        }
    }

    /// Returns the raw value for `key`, or `default` when it is not set.
    ///
    /// The shipped example configuration files list every supported key with
    /// an empty value, so an empty value means "not set" rather than "set to
    /// the empty string".
    #[must_use]
    pub fn string(&self, key: &str, default: &str) -> String {
        self.raw(key)
            .map_or_else(|| default.to_owned(), str::to_owned)
    }

    /// Returns the value for `key` parsed as `T`, or `None` when the key is
    /// not set or cannot be parsed.
    #[must_use]
    pub fn get<T: FromStr>(&self, key: &str) -> Option<T> {
        self.raw(key).and_then(|value| value.parse().ok())
    }

    /// Returns the non-empty value stored for `key`.
    fn raw(&self, key: &str) -> Option<&str> {
        self.values
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    /// Returns the value for `key` parsed as `T`, falling back to `default`
    /// when the key is missing or cannot be parsed.
    #[must_use]
    pub fn parse<T: FromStr>(&self, key: &str, default: T) -> T {
        self.get(key).unwrap_or(default)
    }

    /// Returns a comma separated value as a collection, empty when absent.
    #[must_use]
    pub fn list<C: FromIterator<String>>(&self, key: &str) -> C {
        self.string(key, "")
            .split_terminator(',')
            .map(str::to_owned)
            .collect()
    }

    /// Returns `key` as one command line argument per entry.
    ///
    /// A list keeps its entries verbatim, so an argument may contain a comma.
    /// A plain string has no boundaries to preserve and is split on commas,
    /// which is all an INI file or an environment variable can express.
    #[must_use]
    pub fn args(&self, key: &str) -> Vec<String> {
        self.sequences
            .get(key)
            .cloned()
            .unwrap_or_else(|| self.list(key))
    }
}

/// Returns the entries of `value` when it was written as a list.
fn sequence(value: &::config::Value) -> Option<Vec<String>> {
    let items = value.clone().into_array().ok()?;
    Some(items.into_iter().map(|item| item.to_string()).collect())
}

/// Renders one configuration value as the string the builder expects.
///
/// A list is the natural way to write several values in TOML, JSON or YAML, so
/// a sequence is joined with the same commas a single-line value would use.
/// Anything else keeps its scalar form.
fn flatten(value: ::config::Value) -> String {
    value.clone().into_array().map_or_else(
        |_| value.to_string(),
        |items| {
            items
                .into_iter()
                .map(|item| item.to_string())
                .collect::<Vec<_>>()
                .join(",")
        },
    )
}

/// Resolves the explicitly requested configuration file, if any.
///
/// `FINDOMAIN_CONFIG_FILE` wins over the `--config` flag.
fn configured_file(config_file: Option<&str>) -> Option<String> {
    env::var(ENV_CONFIG_FILE)
        .ok()
        .or_else(|| config_file.map(str::to_owned))
}

fn default_file_exists() -> bool {
    SUPPORTED_EXTENSIONS
        .iter()
        .any(|extension| Path::new(&format!("{DEFAULT_BASENAME}.{extension}")).exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(pairs: &[(&str, &str)]) -> Settings {
        Settings::from_map(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        )
    }

    #[test]
    fn string_falls_back_to_the_default() {
        let settings = settings(&[("jobname", "scan")]);
        assert_eq!(settings.string("jobname", "findomain"), "scan");
        assert_eq!(settings.string("missing", "findomain"), "findomain");
    }

    #[test]
    fn parse_falls_back_on_missing_and_invalid_values() {
        let settings = settings(&[("http_timeout", "9"), ("http_retries", "not-a-number")]);
        assert_eq!(settings.parse::<u64>("http_timeout", 5), 9);
        assert_eq!(settings.parse::<usize>("http_retries", 2), 2);
        assert_eq!(settings.parse::<usize>("missing", 7), 7);
    }

    #[test]
    fn list_splits_on_commas_and_yields_nothing_when_absent() {
        let settings = settings(&[("exclude_sources", "crtsh,anubis")]);
        assert_eq!(
            settings.list::<Vec<String>>("exclude_sources"),
            vec!["crtsh".to_owned(), "anubis".to_owned()]
        );
        assert!(settings.list::<Vec<String>>("missing").is_empty());
    }

    #[test]
    fn a_list_may_be_written_as_a_sequence_or_as_one_line() {
        use ::config::Value;

        assert_eq!(
            flatten(Value::from(vec!["wayback", "commoncrawl"])),
            "wayback,commoncrawl"
        );
        assert_eq!(
            flatten(Value::from("wayback,commoncrawl")),
            "wayback,commoncrawl"
        );
        assert_eq!(flatten(Value::from(30_i64)), "30");
        assert_eq!(flatten(Value::from(true)), "true");
        assert_eq!(flatten(Value::from(Vec::<String>::new())), "");
    }

    #[test]
    fn an_empty_value_means_not_set() {
        // The example configuration files list every key with an empty value.
        let settings = settings(&[("jobname", ""), ("http_timeout", ""), ("tokens", "")]);
        assert_eq!(settings.string("jobname", "findomain"), "findomain");
        assert_eq!(settings.parse::<u64>("http_timeout", 5), 5);
        assert!(settings.list::<Vec<String>>("tokens").is_empty());
    }

    #[test]
    fn list_ignores_a_trailing_separator() {
        let settings = settings(&[("tokens", "a,b,")]);
        assert_eq!(
            settings.list::<Vec<String>>("tokens"),
            vec!["a".to_owned(), "b".to_owned()]
        );
    }
}
