pub struct HashResult{
    pub hash: String,
}

pub fn scan(bytes: &[u8]) -> HashResult
{
    let hash = blake3::hash(bytes);
    HashResult { hash: hash.to_hex().to_string(), }
}