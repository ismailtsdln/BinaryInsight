use anyhow::{anyhow, Result};
use capstone::prelude::*;

#[derive(Debug)]
pub struct InstructionInfo {
    pub address: u64,
    pub mnemonic: String,
    pub op_str: String,
}

pub fn disassemble(
    arch: &str,
    code: &[u8],
    address: u64,
    limit: usize,
) -> Result<Vec<InstructionInfo>> {
    let cs = match arch {
        "x86_64" => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .build()
            .map_err(|e| anyhow!("Failed to initialize Capstone: {}", e))?,
        "x86" => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .build()
            .map_err(|e| anyhow!("Failed to initialize Capstone: {}", e))?,
        "aarch64" => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build()
            .map_err(|e| anyhow!("Failed to initialize Capstone: {}", e))?,
        // Add more as needed or if we improve arch detection
        _ => {
            return Err(anyhow!(
                "Unsupported architecture for disassembly: {}",
                arch
            ))
        }
    };

    let instructions = cs
        .disasm_count(code, address, limit)
        .map_err(|e| anyhow!("Disassembly failed: {}", e))?;

    let mut results = Vec::new();
    for i in instructions.iter() {
        results.push(InstructionInfo {
            address: i.address(),
            mnemonic: i.mnemonic().unwrap_or("???").to_string(),
            op_str: i.op_str().unwrap_or("").to_string(),
        });
    }

    Ok(results)
}
