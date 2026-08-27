//! Throwaway filesystem helpers for the unit and integration tests.
//!
//! Kept dependency free on purpose: the crate ships a security tool and its
//! dependency tree is worth keeping small.

use std::{
    fs,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU32, Ordering},
};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A directory under the system temporary directory, removed on drop.
#[derive(Debug)]
pub struct TempDir {
    root: PathBuf,
}

impl TempDir {
    /// Creates a uniquely named directory tagged with `label`.
    ///
    /// # Panics
    ///
    /// Panics when the directory cannot be created, which always means the
    /// test environment itself is broken.
    #[must_use]
    pub fn new(label: &str) -> Self {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("findomain-test-{}-{label}-{unique}", process::id()));
        fs::create_dir_all(&root).expect("create temporary directory");
        Self { root }
    }

    /// Returns the directory itself.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns `name` resolved inside the directory, as a string.
    #[must_use]
    pub fn path(&self, name: &str) -> String {
        self.root.join(name).to_string_lossy().into_owned()
    }

    /// Writes `contents` to `name` and returns its full path.
    ///
    /// # Panics
    ///
    /// Panics when the file cannot be written.
    #[allow(clippy::must_use_candidate)]
    pub fn write(&self, name: &str, contents: &str) -> String {
        let path = self.root.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent directory");
        }
        fs::write(&path, contents).expect("write temporary file");
        path.to_string_lossy().into_owned()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
