mod app;
mod capture;
mod cli;
mod compare;
mod dissect;
#[cfg(test)]
mod e2e_tests;
#[cfg(test)]
mod e2e_live_tests;
#[cfg(test)]
mod e2e_http_tests;
mod engine;
mod hpack;
mod huffman;
mod filter;
mod h2;
mod model;
mod procs;
mod quic;
mod streams;
mod timeline;
mod tls;

use eframe::egui;
use std::path::PathBuf;

fn main() -> eframe::Result {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if let Some(code) = cli::run(&argv) {
        std::process::exit(code);
    }
    let mut file: Option<PathBuf> = None;
    let mut keylog: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-k" | "--keylog" => keylog = args.next().map(PathBuf::from),
            "-h" | "--help" => {
                println!("{}", cli::USAGE);
                return Ok(());
            }
            _ => file = Some(PathBuf::from(a)),
        }
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("NetSift - packet analyzer")
            .with_inner_size([1440.0, 900.0])
            .with_min_inner_size([960.0, 600.0])
            .with_drag_and_drop(true)
            .with_icon(eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon.png")).expect("bundled icon is a valid PNG")),
        ..Default::default()
    };
    eframe::run_native("NetSift", options, Box::new(move |cc| Ok(Box::new(app::App::new(cc, file, keylog)))))
}


