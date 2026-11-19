//! Release catalog.
//!
//! A version is usable when at least `threshold` different mirrors report
//! the same bundle hash. Threshold is at least 2, so one mirror is never
//! enough. If two different hashes both reach the threshold, that version
//! is a split and is skipped. Among the versions that agree, the newest
//! wins.
//!
//! Mirror names are not URLs. A clearnet address cannot be a mirror id.

use std::collections::{BTreeMap, BTreeSet};

/// One mirror's statement about a version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vote {
    /// Short name, such as `alice`. Not a URL.
    pub mirror: String,
    /// Lowercase hex SHA-256 of the bundle.
    pub bundle_sha256: String,
}

/// One published version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    /// Dotted numbers, such as `0.2.0`.
    pub version: String,
    /// What each mirror said.
    pub votes: Vec<Vote>,
}

/// The catalog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Catalog {
    /// How many mirrors must agree. At least 2.
    pub threshold: usize,
    /// Versions in the order they were written.
    pub releases: Vec<Release>,
}

/// The version a caller should fetch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Choice {
    /// Newest version that met the threshold.
    pub version: String,
    /// The hash the mirrors agreed on.
    pub bundle_sha256: String,
    /// How many distinct mirrors agreed.
    pub mirrors: usize,
}

/// Why no version was chosen.
#[derive(Debug, PartialEq, Eq)]
pub enum CatalogError {
    /// The text was not a catalog.
    Format(&'static str),
    /// Threshold was below 2, or a mirror name was a URL.
    Threshold,
    /// No version had enough mirrors on one hash.
    NoQuorum,
}

impl std::fmt::Display for CatalogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Format(msg) => write!(f, "catalog: {msg}"),
            Self::Threshold => write!(
                f,
                "need at least two mirrors, and a mirror name is not a URL"
            ),
            Self::NoQuorum => write!(f, "no version has enough mirrors agreeing on one hash"),
        }
    }
}

impl std::error::Error for CatalogError {}

fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.contains("://")
        && !name.contains('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn digest_ok(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

fn version_ok(text: &str) -> bool {
    !text.is_empty()
        && text
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn version_key(text: &str) -> Vec<u64> {
    text.split('.').map(|p| p.parse().unwrap_or(0)).collect()
}

/// Parse a catalog. A URL-shaped mirror name refuses the file.
pub fn parse(text: &str) -> Result<Catalog, CatalogError> {
    let mut lines = text.lines().filter(|l| !l.is_empty());
    if lines.next() != Some("permawrite-catalog-v1") {
        return Err(CatalogError::Format("missing header"));
    }
    let threshold: usize = lines
        .next()
        .and_then(|l| l.strip_prefix("threshold="))
        .and_then(|n| n.parse().ok())
        .ok_or(CatalogError::Format("threshold"))?;
    if threshold < 2 {
        return Err(CatalogError::Threshold);
    }
    let mut releases = Vec::new();
    let mut current: Option<Release> = None;
    for line in lines {
        if let Some(version) = line.strip_prefix("version ") {
            if let Some(done) = current.take() {
                releases.push(done);
            }
            if !version_ok(version) {
                return Err(CatalogError::Format("version"));
            }
            current = Some(Release {
                version: version.to_string(),
                votes: Vec::new(),
            });
        } else if let Some(rest) = line.strip_prefix("mirror ") {
            let mut parts = rest.split_whitespace();
            let mirror = parts.next().ok_or(CatalogError::Format("mirror"))?;
            let hash = parts.next().ok_or(CatalogError::Format("mirror"))?;
            if parts.next().is_some() || !name_ok(mirror) || !digest_ok(hash) {
                return Err(CatalogError::Threshold);
            }
            let release = current
                .as_mut()
                .ok_or(CatalogError::Format("mirror before version"))?;
            if release.votes.iter().any(|v| v.mirror == mirror) {
                return Err(CatalogError::Format("duplicate mirror"));
            }
            release.votes.push(Vote {
                mirror: mirror.to_string(),
                bundle_sha256: hash.to_ascii_lowercase(),
            });
        } else {
            return Err(CatalogError::Format("unknown line"));
        }
    }
    if let Some(done) = current.take() {
        releases.push(done);
    }
    if releases.is_empty() {
        return Err(CatalogError::Format("no versions"));
    }
    Ok(Catalog {
        threshold,
        releases,
    })
}

/// Agreeing hash for one version, if exactly one hash meets the threshold.
pub fn agreeing_hash(release: &Release, threshold: usize) -> Result<Choice, CatalogError> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for vote in &release.votes {
        if !seen.insert(vote.mirror.as_str()) {
            return Err(CatalogError::Format("duplicate mirror"));
        }
        *counts.entry(vote.bundle_sha256.as_str()).or_insert(0) += 1;
    }
    let winners: Vec<_> = counts
        .iter()
        .filter(|(_, n)| **n >= threshold)
        .map(|(hash, n)| ((*hash).to_string(), *n))
        .collect();
    match winners.as_slice() {
        [(hash, n)] => Ok(Choice {
            version: release.version.clone(),
            bundle_sha256: hash.clone(),
            mirrors: *n,
        }),
        [] => Err(CatalogError::NoQuorum),
        _ => Err(CatalogError::NoQuorum),
    }
}

/// Newest version whose mirrors agree.
pub fn select(catalog: &Catalog) -> Result<Choice, CatalogError> {
    let mut best: Option<Choice> = None;
    for release in &catalog.releases {
        if let Ok(choice) = agreeing_hash(release, catalog.threshold) {
            let replace = match &best {
                None => true,
                Some(prev) => version_key(&choice.version) > version_key(&prev.version),
            };
            if replace {
                best = Some(choice);
            }
        }
    }
    best.ok_or(CatalogError::NoQuorum)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> String {
        "ab".repeat(31) + &format!("{byte:02x}")
    }

    #[test]
    fn newest_agreed_version_wins_and_a_single_mirror_does_not() {
        let text = format!(
            "\
permawrite-catalog-v1
threshold=2
version 0.1.0
mirror alice {a}
mirror bob {a}
version 0.2.0
mirror alice {b}
mirror bob {b}
mirror cara {c}
",
            a = hash(1),
            b = hash(2),
            c = hash(3)
        );
        let catalog = parse(&text).unwrap();
        let choice = select(&catalog).unwrap();
        assert_eq!(choice.version, "0.2.0");
        assert_eq!(choice.bundle_sha256, hash(2));
        assert_eq!(choice.mirrors, 2);
        assert!(parse("permawrite-catalog-v1\nthreshold=1\nversion 0.1.0\n").is_err());
    }

    #[test]
    fn a_split_version_is_skipped_for_an_older_agreement() {
        let text = format!(
            "\
permawrite-catalog-v1
threshold=2
version 0.1.0
mirror alice {a}
mirror bob {a}
version 0.9.0
mirror alice {b}
mirror bob {b}
mirror cara {c}
mirror dave {c}
",
            a = hash(1),
            b = hash(2),
            c = hash(3)
        );
        let choice = select(&parse(&text).unwrap()).unwrap();
        assert_eq!(choice.version, "0.1.0");
    }

    #[test]
    fn a_url_is_not_a_mirror_name() {
        let text = format!(
            "\
permawrite-catalog-v1
threshold=2
version 0.1.0
mirror https://github.com {a}
mirror bob {a}
",
            a = hash(1)
        );
        assert!(parse(&text).is_err());
        let text = format!(
            "\
permawrite-catalog-v1
threshold=2
version 0.1.0
mirror alice {a}
",
            a = hash(1)
        );
        assert!(matches!(
            select(&parse(&text).unwrap()),
            Err(CatalogError::NoQuorum)
        ));
    }
}
