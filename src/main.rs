mod engines;
mod thread_db;
mod walker;
mod report;

use rayon::ThreadPoolBuilder;

fn main(){
    
    let physical_cores = num_cpus::get_physical();
    
    ThreadPoolBuilder::new()
        .num_threads(physical_cores)
        .build_global()
        .expect("Failed to build rayon thread pool");
    
    println!("av-engine starting ...");
    println!("Thread pool: {} physical workers ready",physical_cores);
}