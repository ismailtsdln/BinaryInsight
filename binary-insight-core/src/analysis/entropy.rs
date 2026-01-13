use std::collections::HashMap;

pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequency = HashMap::new();
    for &byte in data {
        *frequency.entry(byte).or_insert(0) += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in frequency.values() {
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_entropy_zero() {
        let data = b"";
        assert_eq!(calculate_entropy(data), 0.0);
    }

    #[test]
    fn test_calculate_entropy_low() {
        let data = b"AAAA";
        assert_eq!(calculate_entropy(data), 0.0);
    }

    #[test]
    fn test_calculate_entropy_high() {
        // High entropy (random data roughly)
        let data = b"0123456789abcdef";
        // Each byte is unique, so entropy should be log2(16) = 4.0
        assert_eq!(calculate_entropy(data), 4.0);
    }
}
