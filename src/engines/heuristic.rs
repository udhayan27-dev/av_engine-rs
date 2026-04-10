pub struct HeuristicResult{
    pub entropy: f64,
    pub suspicious: bool,
}

const ENTROPY_THRESHOLD: f64 = 7.2;

pub fn scan(bytes: &[u8]) -> HeuristicResult{
    let entropy = shannon_entropy(bytes);
    HeuristicResult { entropy, suspicious: entropy > ENTROPY_THRESHOLD }
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0
    }
    
    let mut counts = [0u64; 256];
    for &b in bytes{
        counts[b as usize] += 1;
    }
    
    let len = bytes.len() as f64;
    
    counts.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}