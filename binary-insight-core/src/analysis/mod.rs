use goblin::elf::Elf;
use goblin::mach::Mach;
use goblin::pe::PE;

#[derive(Debug, Default, Clone)]
pub struct SecurityFeatures {
    pub pie: bool,
    pub nx: bool,
    pub relro: bool, // Simplified: Full/Partial/None can be enum, sticking to bool = "has relro" for now
    pub canary: bool,
}

pub fn analyze_security_elf(elf: &Elf) -> SecurityFeatures {
    let mut features = SecurityFeatures::default();

    // PIE: ET_DYN (3) usually implies PIE for executables (though shared libs are also ET_DYN)
    // Actually, distinct PIE vs Shared Lib is harder without context, but strictly, ET_DYN means it supports ASLR.
    if elf.header.e_type == goblin::elf::header::ET_DYN {
        features.pie = true;
    }

    // NX: PT_GNU_STACK header with !PF_X
    if let Some(phdr) = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_type == goblin::elf::program_header::PT_GNU_STACK)
    {
        if phdr.p_flags & goblin::elf::program_header::PF_X == 0 {
            features.nx = true;
        }
    } else {
        // Default stack executable? Typically yes if missing on older linux, but modern often default NX.
        // Let's assume false (executable stack) if not explicitly disabled, to be safe/conservative in reporting "NX".
    }

    // RELRO: PT_GNU_RELRO
    if elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == goblin::elf::program_header::PT_GNU_RELRO)
    {
        features.relro = true;
    }

    // Canary: Check for symbol like __stack_chk_fail
    // This is a naive check.
    if elf.syms.iter().any(|sym| {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            name.contains("__stack_chk_fail")
        } else {
            false
        }
    }) {
        features.canary = true;
    } else if elf.dynsyms.iter().any(|sym| {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            name.contains("__stack_chk_fail")
        } else {
            false
        }
    }) {
        features.canary = true;
    }

    features
}

pub fn analyze_security_pe(pe: &PE) -> SecurityFeatures {
    let mut features = SecurityFeatures::default();

    // DLL Characteristics
    if let Some(opt_header) = &pe.header.optional_header {
        let dll_char = opt_header.windows_fields.dll_characteristics;

        // ASLR / PIE
        if dll_char & 0x0040 != 0 {
            // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            features.pie = true;
        }

        // NX / DEP
        if dll_char & 0x0100 != 0 {
            // IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            features.nx = true;
        }
    }

    // RELRO / Canary concepts don't map 1:1 same way.
    // PE has /GS for stack cookies. We'd check for imports like __security_check_cookie.
    // For now leaving false.

    // Check imports for stack cookie check
    for import in &pe.imports {
        if import.name.eq_ignore_ascii_case("VCRUNTIME140.dll")
            || import.name.eq_ignore_ascii_case("KERNEL32.dll")
        {
            // Simplified heuristic
            /* Real check would iterate import.imports expecting __security_check_cookie or similar */
        }
    }

    features
}

pub fn analyze_security_mach(mach: &Mach) -> SecurityFeatures {
    match mach {
        Mach::Binary(macho) => {
            let flags = macho.header.flags;
            SecurityFeatures {
                pie: (flags & 0x200000) != 0, // MH_PIE
                nx: (flags & 0x20000) == 0, // MH_ALLOW_STACK_EXECUTION (0x20000). If NOT set, stack is non-exec (NX is true).
                ..Default::default()
            }
        }
        _ => SecurityFeatures::default(),
    }
}

pub fn extract_strings(data: &[u8]) -> Vec<String> {
    let min_len = 4;
    let mut strings = Vec::new();
    let mut current_string = Vec::new();

    for &b in data {
        if b.is_ascii_graphic() || b == b' ' {
            current_string.push(b);
        } else {
            if current_string.len() >= min_len {
                if let Ok(s) = String::from_utf8(current_string.clone()) {
                    strings.push(s);
                }
            }
            current_string.clear();
        }
    }
    // catch last one
    if current_string.len() >= min_len {
        if let Ok(s) = String::from_utf8(current_string) {
            strings.push(s);
        }
    }

    strings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_strings_basic() {
        let data = b"Hello World\x00\x01\x02TestString\x00";
        let strings = extract_strings(data);
        assert!(strings.contains(&"Hello World".to_string()));
        assert!(strings.contains(&"TestString".to_string()));
    }

    #[test]
    fn test_extract_strings_short() {
        let data = b"abc\x00123\x00"; // Too short (min 4)
        let strings = extract_strings(data);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_strings_unicode_approx() {
        // Our extractor is ASCII/Basic implementation.
        // It skips non-graphic.
        let data = b"Rust\x00";
        let strings = extract_strings(data);
        assert_eq!(strings[0], "Rust");
    }
}
