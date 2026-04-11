use std::path::PathBuf;
use dashmap::mapref::entry;
use rayon::prelude::*;
use walkdir::WalkDir;
use crossbeam::channel::Sender;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize,Ordering};

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
        counter.fetch_add(1, Ordering::Relaxed);
    }   
    counter.load(Ordering::Relaxed)
}