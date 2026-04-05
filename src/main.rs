mod engines;
mod threat_db;
mod walker;
mod report;

use rayon::ThreadPoolBuilder;
use std::sync::Arc;

fn main(){
    
    let physical_cores = num_cpus::get_physical();
    
    ThreadPoolBuilder::new()
        .num_threads(physical_cores)
        .build_global()
        .expect("Failed to build rayon thread pool");
    
    println!("av-engine starting ...");
    println!("Thread pool: {} physical workers ready",physical_cores);
    
    let rule_count = engines::yara::rule_count();
    println!("YARA rules compiled - {} rules loaded",rule_count);

    let db = Arc::new(threat_db::ThreatDb::load("data/threats.txt"));
    println!("Threat DB loaded - {} hashes indexed", db.count());
}
