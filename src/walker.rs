use std::path::PathBuf;
use walkdir::WalkDir;
use crossbeam::channel::Sender;



pub fn walk_and_send(root: &str, tx: Sender<PathBuf>) -> usize{
    
    //counter to track the elapsed time to scan all the files AtomicUsize for multiple-thread safety
    let mut counter: usize = 0;
        
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let _ = tx.send(entry.into_path());
        counter += 1
    }   
    counter
}