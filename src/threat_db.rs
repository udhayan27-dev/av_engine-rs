use bloomfilter::Bloom;
use dashmap::DashMap;
use std::fs;
use std::sync::RwLock;

pub struct ThreatDb {
    bloom: RwLock<Bloom<[u8]>>,
    hashes: DashMap<String, ()>,
}

impl ThreatDb {
    pub fn load(path: &str) -> Self {
        let bloom = RwLock::new(
            Bloom::new_for_fp_rate(100_000, 0.001)
        );
        let hashes: DashMap<String, ()> = DashMap::new();
        
        let content = fs::read_to_string(path)
            .unwrap_or_else(|_| {
                eprintln!("Warning: threat DB not found at {path}, starting empty");
                String::new()
            });
        
        for line in content.lines() {
            let hash = line.trim().to_lowercase();
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()){
                continue;
            }
            bloom.write().unwrap().set(hash.as_bytes());
            hashes.insert(hash, ());
        }
        
        ThreatDb { bloom, hashes }
    }
    
    pub fn count(&self) -> usize {
        self.hashes.len()
    }
    
    pub fn check(&self,hash: &str) -> bool {
        let hash = hash.to_lowercase();
        {
            let bloom = self.bloom.read().unwrap();
            if !bloom.check(hash.as_bytes()) {
                return false;
            }
        }        
        self.hashes.contains_key(&hash)
    }
}