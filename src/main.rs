//! ramline: memory monitor for a command and its spawned process tree.

mod cli;
mod engine;
mod model;
mod monitor;
mod output;

use std::{process::ExitCode, sync::Arc, time::Duration};

use anyhow::Result;
use clap::Parser as _;
use log::info;
use spdlog::{Level, LevelFilter, Logger, sink::StdStreamSink};

use crate::{cli::Cli, engine::Target};

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Err(e) = init_logger(cli.verbose) {
        eprintln!("failed to init logger: {e:#}");
        return ExitCode::from(2);
    }
    match run(&cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            log::error!("{e:#}");
            ExitCode::from(2)
        },
    }
}

fn init_logger(verbose: bool) -> Result<()> {
    let level = if verbose { Level::Debug } else { Level::Info };
    let logger = Logger::builder()
        .name("ramline")
        .sink(StdStreamSink::builder().stderr().build_arc()?)
        .level_filter(LevelFilter::MoreSevereEqual(level))
        .build()?;
    spdlog::set_default_logger(Arc::new(logger));
    spdlog::init_log_crate_proxy()?;
    log::set_max_level(log::LevelFilter::Trace);
    Ok(())
}

fn run(cli: &Cli) -> Result<u8> {
    let target = match cli.pid {
        Some(pid) => Target::Attach(pid),
        None => Target::Spawn(cli.command.clone()),
    };
    let mut backend = monitor::default_backend();
    let (report, exit_code) = engine::Engine::new(
        &mut backend,
        target,
        Duration::from_millis(cli.interval),
        cli.max_memory,
    )
    .run()?;

    if let Some(path) = &cli.json {
        output::write_json(&report, path)?;
        info!("wrote JSON report to `{}`", path.display());
    }
    if let Some(path) = &cli.chart {
        output::write_chart(&report, path, cli.max_memory)?;
        info!("wrote chart to `{}`", path.display());
    }
    info!(
        "peak total RSS: {} bytes, duration: {} ms",
        report.summary.peak_total_rss_bytes, report.summary.duration_ms
    );
    Ok(exit_code)
}
