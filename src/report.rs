use std::path::PathBuf;

pub struct ScanResult{
    pub path: PathBuf,
    pub hash: String,
    pub is_threat: bool,
    pub matched_rules: Vec<String>,
    pub entropy: f64,
}

pub fn print_summary(results: &[ScanResult], elapsed_secs: f64)
{
    let threat_count  = results.iter().filter(|r| r.is_threat).count();
    
    println!(
        "Scanned {:>9} files - {} threats found",
        crate::format_count(results.len()),
        threat_count
    );
    println!("Scan complete in {:.2}s",elapsed_secs);
    
    if threat_count > 0 {
        println!();
        println!("Threats detected: ");
        for r in results.iter().filter(|r| r.is_threat) {
            println!(" {}",r.path.display());
            println!("hash: {}",r.hash);
            println!("entropy: {:.2}",r.entropy);
            if !r.matched_rules.is_empty() {
                println!(" rules : {}", r.matched_rules.join(", "));
            }
            
        }
    }
}