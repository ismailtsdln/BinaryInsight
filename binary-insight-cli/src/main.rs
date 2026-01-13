use anyhow::Result;
use binary_insight_core::binary::BinaryFile;
use clap::Parser;
use tracing::info;

pub mod tui;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the binary file to analyze
    #[arg(required = true)]
    file: String,

    /// Run in CLI mode instead of TUI
    #[arg(short, long)]
    cli: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    info!("Analyzing file: {}", args.file);

    let binary = BinaryFile::load(&args.file)?;
    info!("Identified format: {}", binary.identify());

    if args.cli {
        println!("=== Binary Analysis Report ===");
        println!("File:         {}", binary.name);
        println!("Format:       {}", binary.identify());
        println!("Arch:         {}", binary.info.arch);
        println!("Entry Point:  0x{:x}", binary.info.entry_point);
        println!("\n[Security Features]");
        println!("  PIE:    {}", binary.info.security.pie);
        println!("  NX:     {}", binary.info.security.nx);
        println!("  RELRO:  {}", binary.info.security.relro);
        println!("  Canary: {}", binary.info.security.canary);

        println!("\n[Sections]");
        println!("{:<20} {:<18} {:<18}", "Name", "Address", "Size");
        for section in &binary.info.sections {
            println!(
                "{:<20} 0x{:<16x} 0x{:<16x}",
                section.name, section.addr, section.size
            );
        }

        println!("\n[Symbols]");
        println!("Total symbols: {}", binary.info.symbols.len());
        // Show first 20 symbols
        for symbol in binary.info.symbols.iter().take(20) {
            println!("{:<40} 0x{:<16x}", symbol.name, symbol.addr);
        }
        if binary.info.symbols.len() > 20 {
            println!("... and {} more", binary.info.symbols.len() - 20);
        }

        println!("\n[Strings]");
        println!("Total strings found: {}", binary.info.strings.len());
        // Show first 20 strings
        for s in binary.info.strings.iter().take(20) {
            println!("{}", s);
        }
        if binary.info.strings.len() > 20 {
            println!("... and {} more", binary.info.strings.len() - 20);
        }
    } else {
        println!("Running in TUI mode");
        tui::run(binary)?;
    }

    Ok(())
}
