//! Compiles the ramline-ebpf crate into an eBPF object (Linux targets only)
//! and places it in OUT_DIR, where `src/monitor/linux.rs` embeds it.
//! Requires a nightly toolchain with rust-src and the `bpf-linker` binary.

use anyhow::Context as _;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    // Resolve the eBPF crates through the workspace metadata instead of
    // hardcoding paths relative to this crate.
    for name in ["ramline-ebpf", "ramline-ebpf-common"] {
        println!(
            "cargo:rerun-if-changed={}",
            package_root(&packages, name)?.as_str()
        );
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return Ok(());
    }
    let ebpf_package = aya_build::Package {
        name: "ramline-ebpf",
        root_dir: package_root(&packages, "ramline-ebpf")?.as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], aya_build::Toolchain::default())
}

/// Root directory of workspace package `name`.
fn package_root<'a>(
    packages: &'a [cargo_metadata::Package],
    name: &str,
) -> anyhow::Result<&'a cargo_metadata::camino::Utf8Path> {
    packages
        .iter()
        .find(|cargo_metadata::Package { name: n, .. }| n.as_str() == name)
        .and_then(|cargo_metadata::Package { manifest_path, .. }| manifest_path.parent())
        .with_context(|| format!("{name} package not found"))
}
