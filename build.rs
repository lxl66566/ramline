//! Compiles the ramline-ebpf crate into an eBPF object (Linux targets only)
//! and places it in OUT_DIR, where `src/monitor/linux.rs` embeds it.
//! Requires a nightly toolchain with rust-src and the `bpf-linker` binary.

use anyhow::{Context as _, anyhow};

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=ramline-ebpf");
    println!("cargo:rerun-if-changed=ramline-ebpf-common");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return Ok(());
    }
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "ramline-ebpf")
        .ok_or_else(|| anyhow!("ramline-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], aya_build::Toolchain::default())
}
