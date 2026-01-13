use anyhow::Result;
use binary_insight_core::analysis::{disassembly, entropy, hashes, yara};
use binary_insight_core::binary::BinaryFile;
use clap::Parser;
use std::fs;
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

    /// Path to YARA rules file
    #[arg(long)]
    yara: Option<String>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    info!("Analyzing file: {}", args.file);

    let binary = BinaryFile::load(&args.file)?;
    info!("Identified format: {}", binary.identify());

    // Calculate advanced analysis data
    // We need to read the raw file content again or expose it from binary if stored.
    // BinaryFile stores 'data', but let's read it for now to be safe or assuming BinaryFile holds it.
    // Checking binary-insight-core code, BinaryFile struct likely has `pub data: Vec<u8>`.
    // Let's verify via view_file if needed, but assuming standard flow:

    // Actually, let's look at BinaryFile definition first to be sure.
    // Wait, I can't look inside replace_file_content.
    // I will assume reading file again for safety in this step or I'll check it in next step if this fails.
    // Better: Read file content here.
    let file_data = fs::read(&args.file)?;
    let hashes = hashes::calculate_hashes(&file_data);
    let entropy_val = entropy::calculate_entropy(&file_data);

    if args.cli {
        println!("=== Binary Analysis Report ===");
        println!("File:         {}", binary.name);
        println!("Format:       {}", binary.identify());
        println!("Arch:         {}", binary.info.arch);
        println!("Entry Point:  0x{:x}", binary.info.entry_point);

        println!("\n[Advanced Analysis]");
        println!("  Entropy: {:.4} (Scale: 0.0-8.0)", entropy_val);
        println!("  MD5:     {}", hashes.md5);
        println!("  SHA1:    {}", hashes.sha1);
        println!("  SHA256:  {}", hashes.sha256);

        println!("\n[Security Features]");
        println!("  PIE:    {}", binary.info.security.pie);
        println!("  NX:     {}", binary.info.security.nx);
        println!("  RELRO:  {}", binary.info.security.relro);
        println!("  Canary: {}", binary.info.security.canary);

        if let Some(yara_path) = &args.yara {
            println!("\n[YARA Scan]");
            match fs::read_to_string(yara_path) {
                Ok(rules) => match yara::YaraScanner::scan(&file_data, &rules) {
                    Ok(matches) => {
                        if matches.is_empty() {
                            println!("  No matches found.");
                        } else {
                            for m in matches {
                                println!("  Match: {}", m);
                            }
                        }
                    }
                    Err(e) => println!("  Scan failed: {}", e),
                },
                Err(e) => println!("  Failed to read YARA file: {}", e),
            }
        }

        println!("\n[Disassembly (Entry Point / .text)]");
        // Try to find a code section
        let code_section = binary
            .info
            .sections
            .iter()
            .find(|s| s.name == ".text" || s.name == "__text" || s.name.contains("text"));

        if let Some(section) = code_section {
            let start = section.offset as usize;
            let end = start + section.size as usize;
            // Ensure bounds
            let start = start.min(file_data.len());
            let end = end.min(file_data.len());

            if start < end {
                let code = &file_data[start..end];
                match disassembly::disassemble(&binary.info.arch, code, section.addr, 10) {
                    Ok(instructions) => {
                        for ins in instructions {
                            println!(
                                "  0x{:x}:  {:<10} {}",
                                ins.address, ins.mnemonic, ins.op_str
                            );
                        }
                    }
                    Err(e) => println!("  Disassembly failed: {}", e),
                }
            } else {
                println!("  Section data out of bounds or empty.");
            }
        } else {
            println!("  No code section found.");
        }

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
