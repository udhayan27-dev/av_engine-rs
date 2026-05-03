use std::path::Path;

pub struct HeuristicResult {
    pub entropy: f64,
    pub suspicious: bool,
}

const ENTROPY_THRESHOLD: f64 = 7.7;

// These extensions are legitimately high entropy — skip entropy check
const SKIP_ENTROPY_EXTENSIONS: &[&str] = &[
    // compressed
    "gz", "bz2", "xz", "zst", "zip", "7z", "rar", "tar",
    // media
    "jpg", "jpeg", "png", "gif", "webp", "mp3", "mp4", "mkv",
    "avi", "flac", "ogg", "wav", "webm",
    // fonts
    "woff", "woff2", "ttf", "otf",
    // packages
    "deb", "rpm", "AppImage",
];

pub fn scan_with_path(bytes: &[u8], path: &Path) -> HeuristicResult {
    // skip entropy check for known high-entropy but safe formats
    let ext = path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    if SKIP_ENTROPY_EXTENSIONS.contains(&ext.as_str()) {
        return HeuristicResult {
            entropy: 0.0,
            suspicious: false,
        };
    }

    let entropy = shannon_entropy(bytes);
    HeuristicResult {
        entropy,
        suspicious: entropy > ENTROPY_THRESHOLD,
    }
}

// keep the old scan() for compatibility
pub fn scan(bytes: &[u8]) -> HeuristicResult {
    let entropy = shannon_entropy(bytes);
    HeuristicResult {
        entropy,
        suspicious: entropy > ENTROPY_THRESHOLD,
    }
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &b in bytes {
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