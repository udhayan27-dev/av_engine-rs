use crate::engines;
use crate::report::ScanResult;
use crate::threat_db::ThreatDb;
use crossbeam::channel::Receiver;
use memmap2::Mmap;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;

pub fn run_workers(rx: Receiver<PathBuf>, db: Arc<ThreatDb>) -> Vec<ScanResult> {
    let (result_tx, result_rx) = crossbeam::channel::unbounded::<ScanResult>();

    
    rayon::scope(|s| {
        for path in rx {
            let db = Arc::clone(&db);
            let result_tx = result_tx.clone();
            s.spawn(move |_| {
                if let Some(result) = scan_file(path, &db){
                    let _ = result_tx.send(result);
                }
            });
        }
    });    

    drop(result_tx);
     result_rx.into_iter().collect()
}

fn scan_file(path: PathBuf, db: &ThreatDb) -> Option<ScanResult> {
    let file = match File::open(&path) {
        Ok(f) => f,
        Err(_) => return None,
    };

    let metadata = match file.metadata() {
        Ok(m) => m,
        Err(_) => return None,
    };
    if metadata.len() == 0 {
        return None;
    }

    let mmap = match unsafe { Mmap::map(&file) } {
        Ok(m) => m,
        Err(_) => return None,
    };
    let bytes: &[u8] = &mmap;

    let hash_result = engines::hash::scan(bytes);
    let yara_result = engines::yara::scan(bytes);
    let heuristic_result = engines::heuristic::scan(bytes);

    let is_threat =
        db.check(&hash_result.hash) || yara_result.matched || heuristic_result.suspicious;

    Some(ScanResult {
        path,
        hash: hash_result.hash,
        is_threat,
        matched_rules: yara_result.rule_names,
        entropy: heuristic_result.entropy,
    })
}
