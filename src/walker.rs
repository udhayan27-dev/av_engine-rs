use std::path::PathBuf;
use rayon::prelude::*;
use walkdir::WalkDir;
use crossbeam::channel::Sender;

pub fn walk_and_send(root: &str, tx: Sender<PathBuf>){
    WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .par_bridge()
        .for_each(|entry| {
            let _ = tx.send(entry.into_path());
        });
}