use aho_corasick::AhoCorasick;
use memmap2::MmapOptions;
use std::fs::File;
use std::io;
use std::path::Path;

pub struct Scanner {
    automaton: AhoCorasick,
}

impl Scanner {
    pub fn new(signatures: &[&[u8]]) -> Self {
        let automaton =
            AhoCorasick::new(signatures).expect("Failed to build Aho-Corasick automation");

        Scanner { automaton }
    }

    pub fn scan_file(&self, file_path: &Path) -> Result<bool, io::Error> {
        let file = File::open(file_path)?;

        let mmap = unsafe { MmapOptions::new().map(&file)? };

        let is_infected = self.automaton.is_match(&mmap);

        Ok(is_infected)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile; // You'd need to add `tempfile = "3.10"` to [dev-dependencies]

    #[test]
    fn test_scanner_detects_malware() {
        // A fake "virus" signature (EICAR standard test string concept)
        let signatures: &[&[u8]] = &[b"MALWARE_STRING_123", b"RANSOMWARE_HEADER"];
        let scanner = Scanner::new(signatures);

        // Create a temporary file infected with our fake virus
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file
            .write_all(b"Some random data... MALWARE_STRING_123 ...more data")
            .unwrap();

        // Scan it
        let is_infected = scanner.scan_file(temp_file.path()).unwrap();

        assert!(
            is_infected,
            "Scanner failed to detect the malware signature!"
        );
    }
}
