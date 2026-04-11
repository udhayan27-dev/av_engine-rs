mod engines;
mod threat_db;
mod walker;
mod report;
mod scanner;

use crossbeam::channel;
use std::path::PathBuf;
use rayon::ThreadPoolBuilder;
use std::sync::Arc;

const CHANNEL_CAP: usize = 4096;

pub fn format_count(n:usize) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, ch) in s.chars().rev().enumerate(){
        if i > 0 && i % 3 == 0 {
            result.push(',')
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}

fn main(){
    
    let physical_cores = num_cpus::get_physical();
    ThreadPoolBuilder::new()
        .num_threads(physical_cores-1)
        .build_global()
        .expect("Failed to build rayon thread pool");
    
    println!("av-engine starting ...");
    println!("Thread pool: {} physical workers ready",physical_cores);
    
    let rule_count = engines::yara::rule_count();
    println!("YARA rules compiled - {} rules loaded",rule_count);

    let db = Arc::new(threat_db::ThreatDb::load("data/threats.txt"));
    println!("Threat DB loaded - {} hashes indexed", db.count());
    
    let (tx, rx) = channel::bounded::<PathBuf>(CHANNEL_CAP);
    
        println!();
        println!("┌─────────────────────────────────────┐");
        println!("│         av-engine ready             │");
        println!("├─────────────────────────────────────┤");
        println!("│ workers      : {:<21}│", physical_cores);
        println!("│ yara rules   : {:<21}│", rule_count);
        println!("│ known threats: {:<21}│", db.count());
        println!("│ channel cap  : {:<21}│", CHANNEL_CAP);
        println!("└─────────────────────────────────────┘");
        println!();
        
        let start = std::time::Instant::now();
        
        let walker_thread = std::thread::spawn(move || {
            walker::walk_and_send(".", tx)
        });
       
        let results = scanner::run_workers(rx, Arc::clone(&db));
        let file_count = walker_thread.join().expect("Walker thread panicked");
        let elapsed = start.elapsed();
        
        println!("Walked {:>9} files in {:.2}s",
            format_count(file_count),
            elapsed.as_secs_f64()
        );
        
        report::print_summary(&results, elapsed.as_secs_f64());
}


