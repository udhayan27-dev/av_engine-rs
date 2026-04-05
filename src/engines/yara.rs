use once_cell::sync::Lazy;
use std::sync::Arc;
use yara_x::{Rules};

pub static RULES: Lazy<Arc<Rules>> = Lazy::new(|| {
    let mut compiler = yara_x::Compiler::new();

    compiler
        .add_source(include_str!("../../rules/malware.yar"))
        .expect("failed to parse YARA rules");

    Arc::new(compiler.build())
});


pub fn rule_count() -> usize {
    RULES.iter().len()
}

pub struct YaraResult {
    pub matched: bool,
    pub rule_names: Vec<String>,
}

pub fn scan(bytes: &[u8]) -> YaraResult {
    let mut scanner = yara_x::Scanner::new(&RULES);
    let results = scanner.scan(bytes).expect("YARA scan failed");
    
    let rule_names: Vec<String> = results
        .matching_rules()
        .map(|r| r.identifier().to_string())
        .collect();
    
    YaraResult {
        matched: !rule_names.is_empty(),
        rule_names,
    }
}