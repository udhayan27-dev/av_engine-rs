use std::path::PathBuf;

pub struct ScanResult{
    pub path: PathBuf,
    pub hash: String,
    pub is_threat: bool,
    pub matched_rules: Vec<String>,
    pub entropy: f64,
}

pub fn print_summary(results: &[ScanResult], elapsed_secs: f64) {
    // let threat_count = results.iter().filter(|r| r.is_threat).count();
    // let hash_hits = results.iter().filter(|r| r.is_threat && !r.matched_rules.is_empty()).count();
    // let yara_hits = results.iter().filter(|r| r.matched_rules.len() > 0).count();
    // let entropy_hits = results.iter().filter(|r| r.entropy > 7.7).count();

    // println!(
    //     "Scanned {:>9} files — {} threats found",
    //     crate::format_count(results.len()),
    //     threat_count
    // );
    // println!("Scan complete in {:.2}s", elapsed_secs);
    // println!();
    // println!("Breakdown:");
    // println!("  entropy hits (>7.2) : {}", entropy_hits);
    // println!("  yara hits           : {}", yara_hits);
    // println!("  throughput          : {:.0} files/sec",
    //     results.len() as f64 / elapsed_secs);
    let mut ext_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for r in results.iter().filter(|r| r.entropy > 7.7) {
        let ext = r.path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("no_extension")
            .to_string();
        *ext_counts.entry(ext).or_insert(0) += 1;
    }
    let mut ext_vec: Vec<_> = ext_counts.iter().collect();
    ext_vec.sort_by(|a, b| b.1.cmp(a.1));
    println!();
    println!("Top extensions with high entropy:");
    for (ext, count) in ext_vec.iter().take(10) {
        println!("  .{:<15} : {}", ext, count);
    }
}