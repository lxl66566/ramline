//! Command-line interface definition.

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Sampling interval in milliseconds.
    #[arg(short, long, default_value_t = 100)]
    pub interval: u64,
    /// Kill the whole process tree once total RSS exceeds this size
    /// (e.g. 512M, 2G, 1048576).
    #[arg(short, long, value_parser = parse_size)]
    pub max_memory: Option<u64>,
    /// Write a JSON report to this path.
    #[arg(long)]
    pub json: Option<PathBuf>,
    /// Write an SVG line chart to this path.
    #[arg(long)]
    pub chart: Option<PathBuf>,
    /// Enable verbose (debug) logging.
    #[arg(short, long)]
    pub verbose: bool,
    /// Attach to an existing process tree instead of spawning a command.
    #[arg(long, conflicts_with = "command")]
    pub pid: Option<u32>,
    /// Command to spawn and monitor; place after `--`.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required_unless_present = "pid"
    )]
    pub command: Vec<String>,
}

/// Errors returned by [`parse_size`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SizeError {
    #[error("invalid number in size `{0}`")]
    InvalidNumber(String),
    #[error("unknown size suffix in `{0}` (expected K, M, G or T)")]
    UnknownSuffix(String),
    #[error("size `{0}` is negative or out of range")]
    OutOfRange(String),
}

/// Parse a human-readable size like `512M`, `2GiB` or `1048576` into bytes.
/// Suffixes are powers of 1024; a trailing `B`/`iB` decoration is accepted.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub fn parse_size(input: &str) -> Result<u64, SizeError> {
    let input = input.trim();
    let split = input.find(char::is_alphabetic).unwrap_or(input.len());
    let (number, suffix) = input.split_at(split);
    let value: f64 = number
        .trim()
        .parse()
        .map_err(|_| SizeError::InvalidNumber(input.to_owned()))?;
    let mut suffix = suffix.trim().to_ascii_uppercase();
    while suffix.ends_with('B') || suffix.ends_with('I') {
        suffix.pop();
    }
    let multiplier: u64 = match suffix.as_str() {
        "" => 1,
        "K" => 1 << 10,
        "M" => 1 << 20,
        "G" => 1 << 30,
        "T" => 1 << 40,
        _ => return Err(SizeError::UnknownSuffix(input.to_owned())),
    };
    if !value.is_finite() || value < 0.0 {
        return Err(SizeError::OutOfRange(input.to_owned()));
    }
    let bytes = value * multiplier as f64;
    if bytes >= u64::MAX as f64 {
        return Err(SizeError::OutOfRange(input.to_owned()));
    }
    Ok(bytes as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_bytes() {
        assert_eq!(parse_size("0").unwrap(), 0);
        assert_eq!(parse_size("1048576").unwrap(), 1_048_576);
        assert_eq!(parse_size(" 512 ").unwrap(), 512);
    }

    #[test]
    fn parses_suffixes() {
        assert_eq!(parse_size("512M").unwrap(), 512 << 20);
        assert_eq!(parse_size("512m").unwrap(), 512 << 20);
        assert_eq!(parse_size("2G").unwrap(), 2 << 30);
        assert_eq!(parse_size("1T").unwrap(), 1 << 40);
        assert_eq!(parse_size("1.5K").unwrap(), 1536);
        assert_eq!(parse_size("512MB").unwrap(), 512 << 20);
        assert_eq!(parse_size("4GiB").unwrap(), 4 << 30);
        assert_eq!(parse_size("100B").unwrap(), 100);
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(
            parse_size("abc"),
            Err(SizeError::InvalidNumber(_))
        ));
        assert!(matches!(parse_size(""), Err(SizeError::InvalidNumber(_))));
        assert!(matches!(
            parse_size("1.2.3"),
            Err(SizeError::InvalidNumber(_))
        ));
        assert!(matches!(
            parse_size("10X"),
            Err(SizeError::UnknownSuffix(_))
        ));
        assert!(matches!(
            parse_size("1e300"),
            Err(SizeError::UnknownSuffix(_))
        ));
        assert!(matches!(parse_size("-5"), Err(SizeError::OutOfRange(_))));
        assert!(matches!(
            parse_size("9999999999999999999999"),
            Err(SizeError::OutOfRange(_))
        ));
    }
}
