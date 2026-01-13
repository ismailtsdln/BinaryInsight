use anyhow::{anyhow, Result};
use boreal::Compiler;

pub struct YaraScanner;

impl YaraScanner {
    pub fn scan(data: &[u8], rules_str: &str) -> Result<Vec<String>> {
        let mut compiler = Compiler::new();
        if let Err(err) = compiler.add_rules_str(rules_str) {
            return Err(anyhow!("Failed to compile YARA rules: {:?}", err));
        }

        let scanner = compiler.into_scanner();
        let scan_result = scanner.scan_mem(data); // Returns Result or ScanResult depending on version, check error msg

        // Error message: no field `rules` on type `Result<ScanResult<'_>, ...>`
        // So it returns a Result in this version.

        let scan_results = match scan_result {
            Ok(res) => res,
            Err((_err, res)) => res, // Partial results on timeout/error
        };

        let mut matches = Vec::new();
        for rule in scan_results.matched_rules {
            matches.push(rule.name.to_string());
        }

        Ok(matches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yara_scan_match() {
        let rules = r#"
            rule TestRule {
                strings:
                    $a = "Hello"
                condition:
                    $a
            }
        "#;
        let data = b"Hello World";
        let matches = YaraScanner::scan(data, rules).expect("Scan failed");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], "TestRule");
    }

    #[test]
    fn test_yara_scan_no_match() {
        let rules = r#"
            rule TestRule {
                strings:
                    $a = "Goodbye"
                condition:
                    $a
            }
        "#;
        let data = b"Hello World";
        let matches = YaraScanner::scan(data, rules).expect("Scan failed");
        assert!(matches.is_empty());
    }
}
