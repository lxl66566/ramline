//! SVG line chart via plotters: elapsed seconds on x, MiB on y.

use std::{cmp::Reverse, path::Path};

use anyhow::Result;
use plotters::prelude::*;

use crate::model::Report;

const MIB: f64 = 1024.0 * 1024.0;
/// Per-process series beyond the top N by peak RSS are omitted to avoid clutter.
const MAX_PROCESS_SERIES: usize = 8;
/// Dash segments used to draw the memory limit line.
const LIMIT_SEGMENTS: u32 = 60;

#[allow(clippy::cast_precision_loss)]
pub fn write_chart(report: &Report, path: &Path, limit_bytes: Option<u64>) -> Result<()> {
    let root = SVGBackend::new(path, (1024, 640)).into_drawing_area();
    root.fill(&WHITE)?;

    let duration_s = f64::max(report.summary.duration_ms as f64 / 1000.0, 0.01);
    let mut peak_mib = report.summary.peak_total_rss_bytes as f64 / MIB;
    if let Some(limit) = limit_bytes {
        peak_mib = peak_mib.max(limit as f64 / MIB);
    }
    let y_max = (peak_mib * 1.1).max(1.0);

    let target = if report.command.is_empty() {
        format!("pid {}", report.root_pid)
    } else {
        report.command.join(" ")
    };
    let title = format!("ramline: {target} (peak {peak_mib:.1} MiB)");

    let mut chart = ChartBuilder::on(&root)
        .caption(title, ("sans-serif", 22))
        .margin(12)
        .x_label_area_size(40)
        .y_label_area_size(70)
        .build_cartesian_2d(0.0..duration_s, 0.0..y_max)?;
    chart
        .configure_mesh()
        .x_desc("elapsed (s)")
        .y_desc("RSS (MiB)")
        .draw()?;

    let to_xy = |t_ms: u64, bytes: u64| (t_ms as f64 / 1000.0, bytes as f64 / MIB);

    chart
        .draw_series(LineSeries::new(
            report.totals.iter().map(|t| to_xy(t.t_ms, t.rss_bytes)),
            BLACK.stroke_width(2),
        ))?
        .label("total")
        .legend(|(x, y)| PathElement::new([(x, y), (x + 16, y)], BLACK.stroke_width(2)));

    // One thin line per process, capped at the top N by peak RSS.
    let mut processes: Vec<_> = report.processes.iter().collect();
    processes.sort_by_key(|p| Reverse(p.samples.iter().map(|s| s.rss_bytes).max().unwrap_or(0)));
    for (i, p) in processes.into_iter().take(MAX_PROCESS_SERIES).enumerate() {
        let style = Palette99::pick(i).stroke_width(1);
        chart
            .draw_series(LineSeries::new(
                p.samples.iter().map(|s| to_xy(s.t_ms, s.rss_bytes)),
                style,
            ))?
            .label(format!("{} ({})", p.name, p.pid))
            .legend(move |(x, y)| PathElement::new([(x, y), (x + 16, y)], style));
    }

    if let Some(limit) = limit_bytes {
        let y = limit as f64 / MIB;
        let dashes = (0..LIMIT_SEGMENTS).filter(|i| i % 2 == 0).map(|i| {
            let x0 = duration_s * f64::from(i) / f64::from(LIMIT_SEGMENTS);
            let x1 = duration_s * f64::from(i + 1) / f64::from(LIMIT_SEGMENTS);
            PathElement::new([(x0, y), (x1, y)], RED.stroke_width(1))
        });
        chart
            .draw_series(dashes)?
            .label("limit")
            .legend(|(x, y)| PathElement::new([(x, y), (x + 16, y)], RED.stroke_width(1)));
    }

    chart
        .configure_series_labels()
        .border_style(BLACK)
        .background_style(WHITE.mix(0.8))
        .draw()?;
    root.present()?;
    Ok(())
}
