use crate::analysis;
use anyhow::{Context, Result};
use goblin::{elf, mach, pe, Object};
use std::fs;
use std::path::Path;

#[derive(Debug, Default)]
pub struct BinaryInfo {
    pub format: String,
    pub arch: String,
    pub entry_point: u64,
    pub sections: Vec<SectionInfo>,
    pub symbols: Vec<SymbolInfo>,
    pub security: analysis::SecurityFeatures,
    pub strings: Vec<String>,
}

#[derive(Debug)]
pub struct SectionInfo {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u64,
}

#[derive(Debug)]
pub struct SymbolInfo {
    pub name: String,
    pub addr: u64,
}

pub struct BinaryFile {
    pub name: String,
    pub data: Vec<u8>,
    pub info: BinaryInfo,
}

impl BinaryFile {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let name = path
            .as_ref()
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let data = fs::read(path).context("Failed to read file")?;

        let info = Self::parse(&data)?;

        Ok(Self { name, data, info })
    }

    fn parse(data: &[u8]) -> Result<BinaryInfo> {
        let mut info = match Object::parse(data)? {
            Object::Elf(elf) => Self::parse_elf(&elf)?,
            Object::PE(pe) => Self::parse_pe(&pe)?,
            Object::Mach(mach) => Self::parse_mach(&mach)?,
            _ => BinaryInfo {
                format: "Unknown/Archive".to_string(),
                ..Default::default()
            },
        };
        info.strings = analysis::extract_strings(data);
        Ok(info)
    }

    fn parse_elf(elf: &elf::Elf) -> Result<BinaryInfo> {
        let sections = elf
            .section_headers
            .iter()
            .map(|sh| {
                let name = elf
                    .shdr_strtab
                    .get_at(sh.sh_name)
                    .unwrap_or("<unknown>")
                    .to_string();
                SectionInfo {
                    name,
                    addr: sh.sh_addr,
                    size: sh.sh_size,
                    offset: sh.sh_offset,
                }
            })
            .collect();

        let symbols = elf
            .syms
            .iter()
            .map(|sym| {
                let name = elf
                    .strtab
                    .get_at(sym.st_name)
                    .unwrap_or("<unknown>")
                    .to_string();
                SymbolInfo {
                    name,
                    addr: sym.st_value,
                }
            })
            .collect();

        let security = analysis::analyze_security_elf(elf);

        Ok(BinaryInfo {
            format: "ELF".to_string(),
            arch: elf::header::machine_to_str(elf.header.e_machine).to_string(),
            entry_point: elf.entry,
            sections,
            symbols,
            security,
            strings: Vec::new(),
        })
    }

    fn parse_pe(pe: &pe::PE) -> Result<BinaryInfo> {
        let sections = pe
            .sections
            .iter()
            .map(|s| SectionInfo {
                name: s.name().unwrap_or("<bad>").to_string(),
                addr: s.virtual_address as u64,
                size: s.virtual_size as u64,
                offset: s.pointer_to_raw_data as u64,
            })
            .collect();

        // PE exports/imports as symbols for now? Goblin PE symbol handling is complex across tables.
        // Simplified usage: exports
        let mut symbols = Vec::new();
        for export in &pe.exports {
            symbols.push(SymbolInfo {
                name: export.name.unwrap_or_default().to_string(),
                addr: export.rva as u64,
            });
        }

        let security = analysis::analyze_security_pe(pe);

        Ok(BinaryInfo {
            format: "PE".to_string(),
            arch: if pe.is_64 {
                "x86_64".to_string()
            } else {
                "x86".to_string()
            },
            entry_point: pe.entry as u64,
            sections,
            symbols,
            security,
            strings: Vec::new(),
        })
    }

    fn parse_mach(mach: &mach::Mach) -> Result<BinaryInfo> {
        match mach {
            mach::Mach::Binary(macho) => {
                let mut sections = Vec::new();
                for segment in &macho.segments {
                    if let Ok(iter) = segment.sections() {
                        for (section, _) in iter {
                            sections.push(SectionInfo {
                                name: section.name().unwrap_or("<bad>").to_string(),
                                addr: section.addr,
                                size: section.size,
                                offset: section.offset as u64,
                            });
                        }
                    }
                }

                let symbols = macho
                    .symbols()
                    .into_iter()
                    .filter_map(|s| s.ok())
                    .map(|(name, nlist)| SymbolInfo {
                        name: name.to_string(),
                        addr: nlist.n_value,
                    })
                    .collect();

                let security = analysis::analyze_security_mach(mach);

                Ok(BinaryInfo {
                    format: "Mach-O".to_string(),
                    arch: match macho.header.cputype {
                        goblin::mach::cputype::CPU_TYPE_X86_64 => "x86_64".to_string(),
                        goblin::mach::cputype::CPU_TYPE_X86 => "x86".to_string(),
                        goblin::mach::cputype::CPU_TYPE_ARM64 => "aarch64".to_string(),
                        _ => format!("Unknown ({})", macho.header.cputype),
                    },
                    entry_point: macho.entry,
                    sections,
                    symbols,
                    security,
                    strings: Vec::new(),
                })
            }
            mach::Mach::Fat(_) => Ok(BinaryInfo {
                format: "Mach-O (Fat)".to_string(),
                ..Default::default()
            }),
        }
    }

    pub fn identify(&self) -> &str {
        &self.info.format
    }
}
