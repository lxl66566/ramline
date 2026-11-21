//! Report writers: JSON and SVG chart.

mod chart;
mod json;

pub use chart::write_chart;
pub use json::write_json;
