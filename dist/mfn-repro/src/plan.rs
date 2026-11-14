//! Pinned toolchain and deterministic compiler flags.

/// Rustc version the release workflow and local rebuild both use.
pub const PINNED_RUSTC: &str = "1.83.0";

/// Release binaries a tag build must hash.
pub const BINARIES: &[&str] = &["mfnd", "mfn-cli", "mfn-storage-operator"];

/// Placeholder substituted for the absolute workspace path.
pub const REMAP_DEST: &str = "/permawrite";

/// One reproducible build plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReproPlan {
    /// Pinned rustc version (`1.83.0`, not a floating channel).
    pub rustc: &'static str,
    /// `SOURCE_DATE_EPOCH` for this commit.
    pub source_date_epoch: u64,
    /// Cargo target triple.
    pub target: String,
    /// Workspace root that must be remapped out of the binary.
    pub workspace_root: String,
    /// Compiler flags, including the remap of `workspace_root`.
    pub rustflags: String,
    /// Binaries the plan covers.
    pub binaries: &'static [&'static str],
}

/// Flags for `target`. Linux drops the GNU build id; other targets do not
/// pass a GNU linker argument.
pub fn rustflags_for(target: &str, workspace_root: &str) -> String {
    let mut flags = format!(
        "-D warnings --remap-path-prefix={workspace_root}={REMAP_DEST} -C target-cpu=generic -C debuginfo=0 -C incremental=false -C codegen-units=1"
    );
    if target.contains("linux") {
        flags.push_str(" -C link-arg=-Wl,--build-id=none");
    }
    flags
}

impl ReproPlan {
    /// Build a plan. `workspace_root` is the absolute path that must not
    /// survive inside the binary.
    pub fn new(
        source_date_epoch: u64,
        target: impl Into<String>,
        workspace_root: impl Into<String>,
    ) -> Self {
        let target = target.into();
        let workspace_root = workspace_root.into();
        let rustflags = rustflags_for(&target, &workspace_root);
        Self {
            rustc: PINNED_RUSTC,
            source_date_epoch,
            target,
            workspace_root,
            rustflags,
            binaries: BINARIES,
        }
    }

    /// Shell exports a builder can eval. The absolute root appears only as
    /// the left-hand side of `--remap-path-prefix`.
    pub fn shell_exports(&self) -> String {
        format!(
            "export SOURCE_DATE_EPOCH={epoch}\nexport CARGO_INCREMENTAL=0\nexport LC_ALL=C\nexport TZ=UTC\nexport RUSTFLAGS={flags:?}\n",
            epoch = self.source_date_epoch,
            flags = self.rustflags,
        )
    }

    /// True when the flags remap this workspace and refuse host-CPU tuning.
    pub fn hides_builder_path(&self) -> bool {
        let remap = format!("--remap-path-prefix={}={REMAP_DEST}", self.workspace_root);
        self.rustflags.contains(&remap)
            && self.rustflags.contains("-C target-cpu=generic")
            && self.rustflags.contains("-C debuginfo=0")
            && self.rustflags.contains("-C incremental=false")
            && !self.rustflags.contains("-C target-cpu=native")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_pins_rustc_and_hides_the_workspace_path() {
        let plan = ReproPlan::new(
            1_700_000_000,
            "x86_64-unknown-linux-gnu",
            "/home/builder/permawrite",
        );
        assert_eq!(plan.rustc, "1.83.0");
        assert_eq!(plan.source_date_epoch, 1_700_000_000);
        assert!(plan.hides_builder_path());
        assert!(plan.rustflags.contains("-Wl,--build-id=none"));
        assert!(plan
            .shell_exports()
            .contains("SOURCE_DATE_EPOCH=1700000000"));
        assert!(plan.shell_exports().contains("CARGO_INCREMENTAL=0"));
        assert_eq!(plan.binaries, BINARIES);
    }

    #[test]
    fn windows_plan_does_not_pass_gnu_build_id() {
        let plan = ReproPlan::new(10, "x86_64-pc-windows-msvc", r"C:\src");
        assert!(!plan.rustflags.contains("build-id"));
        assert!(plan.hides_builder_path());
    }

    #[test]
    fn macos_plan_stays_generic() {
        let plan = ReproPlan::new(10, "aarch64-apple-darwin", "/Users/builder/src");
        assert!(!plan.rustflags.contains("build-id"));
        assert!(plan.rustflags.contains("target-cpu=generic"));
    }

    #[test]
    fn script_carries_the_same_pin() {
        let script = include_str!("../../../scripts/reproducible-build.sh");
        assert!(script.contains(PINNED_RUSTC));
        assert!(script.contains("--remap-path-prefix"));
        assert!(script.contains("SOURCE_DATE_EPOCH"));
        assert!(script.contains("CARGO_INCREMENTAL=0"));
        assert!(script.contains("target-cpu=generic"));
        assert!(script.contains("build-id=none"));
        assert!(script.contains("--compare"));
    }
}
