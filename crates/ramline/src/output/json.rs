//! JSON report writer.

use std::{fs, path::Path};

use anyhow::{Context as _, Result};

use crate::model::Report;

pub fn write_json(report: &Report, path: &Path) -> Result<()> {
    let text = serde_json::to_string_pretty(report).context("failed to serialize report")?;
    fs::write(path, text)
        .with_context(|| format!("failed to write JSON report to `{}`", path.display()))
}
