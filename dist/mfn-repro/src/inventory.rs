//! Canonical source file list for a rebuild.
//!
//! The inventory is the set of paths a rebuild is allowed to read. It
//! rejects build output, version-control metadata, and any path that
//! escapes the workspace.

use thiserror::Error;

/// One relative source path, using `/` separators.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceInventory {
    /// Sorted relative paths.
    pub paths: Vec<String>,
}

/// Why a path cannot be part of a source inventory.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum InventoryError {
    /// The path is absolute, empty, or contains `..`.
    #[error("path escapes the workspace: {0}")]
    Escapes(String),
    /// The path is build output or version-control metadata.
    #[error("path is not source: {0}")]
    NotSource(String),
}

const SKIP_PREFIXES: &[&str] = &[".git/", "target/", "dist/target/"];
const SKIP_EXACT: &[&str] = &[".git", "target"];

/// Sort and check `paths`. Duplicates collapse.
pub fn source_inventory<I, S>(paths: I) -> Result<SourceInventory, InventoryError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = Vec::new();
    for raw in paths {
        let path = normalize(raw.as_ref())?;
        if out.iter().any(|p: &String| p == &path) {
            continue;
        }
        out.push(path);
    }
    out.sort();
    Ok(SourceInventory { paths: out })
}

fn normalize(raw: &str) -> Result<String, InventoryError> {
    let path = raw.replace('\\', "/");
    if path.is_empty() || path.starts_with('/') || path.starts_with(':') {
        return Err(InventoryError::Escapes(raw.to_string()));
    }
    // Windows drive prefix.
    if path.as_bytes().get(1) == Some(&b':') {
        return Err(InventoryError::Escapes(raw.to_string()));
    }
    let mut parts = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err(InventoryError::Escapes(raw.to_string()));
        }
        parts.push(part);
    }
    if parts.is_empty() {
        return Err(InventoryError::Escapes(raw.to_string()));
    }
    let joined = parts.join("/");
    if SKIP_EXACT.contains(&joined.as_str()) || SKIP_PREFIXES.iter().any(|p| joined.starts_with(p))
    {
        return Err(InventoryError::NotSource(joined));
    }
    Ok(joined)
}

impl SourceInventory {
    /// Canonical text: one relative path per line, trailing newline.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for path in &self.paths {
            out.push_str(path);
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_sorts_and_drops_duplicates() {
        let inv = source_inventory(["b.rs", "a.rs", "a.rs", r"src\lib.rs"]).unwrap();
        assert_eq!(
            inv.paths,
            vec![
                "a.rs".to_string(),
                "b.rs".to_string(),
                "src/lib.rs".to_string()
            ]
        );
        assert_eq!(inv.render(), "a.rs\nb.rs\nsrc/lib.rs\n");
    }

    #[test]
    fn inventory_rejects_git_target_and_escape() {
        assert!(matches!(
            source_inventory([".git/config"]),
            Err(InventoryError::NotSource(_))
        ));
        assert!(matches!(
            source_inventory(["target/release/mfnd"]),
            Err(InventoryError::NotSource(_))
        ));
        assert!(matches!(
            source_inventory(["../secret"]),
            Err(InventoryError::Escapes(_))
        ));
        assert!(matches!(
            source_inventory(["/etc/passwd"]),
            Err(InventoryError::Escapes(_))
        ));
    }

    #[test]
    fn same_set_renders_the_same_bytes() {
        let a = source_inventory(["z", "m", "a"]).unwrap().render();
        let b = source_inventory(["a", "z", "m"]).unwrap().render();
        assert_eq!(a, b);
    }
}
