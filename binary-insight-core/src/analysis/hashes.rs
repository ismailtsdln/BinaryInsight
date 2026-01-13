use md5::Md5;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize)]
pub struct FileHashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

pub fn calculate_hashes(data: &[u8]) -> FileHashes {
    let mut md5_hasher = Md5::new();
    md5_hasher.update(data);
    let md5 = hex::encode(md5_hasher.finalize());

    let mut sha1_hasher = Sha1::new();
    sha1_hasher.update(data);
    let sha1 = hex::encode(sha1_hasher.finalize());

    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(data);
    let sha256 = hex::encode(sha256_hasher.finalize());

    FileHashes { md5, sha1, sha256 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_hashes() {
        let data = b"hello world";
        let hashes = calculate_hashes(data);

        assert_eq!(hashes.md5, "5eb63bbbe01eeed093cb22bb8f5acdc3");
        assert_eq!(hashes.sha1, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
        assert_eq!(
            hashes.sha256,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
