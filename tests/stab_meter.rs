use std::fs;
use std::path::{Path, PathBuf};

#[derive(Default)]
struct Stabs {
    loc: u64,
    characters: u64,
    comments: u64,
    smart_pointers: u64,
    synchronization: u64,
    code_paths: u64,
    unsafe_uses: u64,
    cpu_ms: u64,
    db_accesses: u64,
    io_bytes: u64,
}

impl Stabs {
    fn total(&self) -> f64 {
        self.loc as f64 * 0.3
            + self.characters as f64 * 0.1
            + self.comments as f64 * 10.0
            + self.smart_pointers as f64 * 30.0
            + self.synchronization as f64 * 30.0
            + self.code_paths as f64 * 5.0
            + self.unsafe_uses as f64 * 100.0
            + self.cpu_ms as f64
            + self.db_accesses as f64
            + self.io_bytes as f64
    }
}

fn rust_files(root: &Path, output: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or_default();
            if !name.starts_with('.')
                && !matches!(name, "target" | "tests" | "spec_tests" | "benches")
            {
                rust_files(&path, output);
            }
        } else if path.extension().and_then(|v| v.to_str()) == Some("rs") {
            output.push(path);
        }
    }
}

fn occurrences(line: &str, needles: &[&str]) -> u64 {
    needles
        .iter()
        .map(|needle| line.matches(needle).count() as u64)
        .sum()
}

fn source_stabs(root: &Path) -> (Stabs, Vec<(f64, String)>) {
    let mut files = Vec::new();
    rust_files(root, &mut files);
    let mut total = Stabs::default();
    let mut ranked = Vec::new();
    for path in files {
        let text = fs::read_to_string(&path).unwrap();
        let mut file = Stabs::default();
        let mut cfg_test = false;
        let mut test_depth = 0_i64;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed == "#[cfg(test)]" {
                cfg_test = true;
                continue;
            }
            if cfg_test {
                test_depth += line.matches('{').count() as i64;
                test_depth -= line.matches('}').count() as i64;
                if test_depth <= 0 && line.contains('}') {
                    cfg_test = false;
                    test_depth = 0;
                }
                continue;
            }
            if trimmed.is_empty() {
                continue;
            }
            file.loc += 1;
            file.characters += line.chars().count() as u64;
            file.comments += u64::from(trimmed.starts_with("//") || trimmed.contains("/*"));
            file.smart_pointers += occurrences(line, &["Arc<", "Rc<", "Box<", "Pin<", "Cow<"]);
            file.synchronization += occurrences(
                line,
                &[
                    "Mutex<",
                    "RwLock<",
                    "Atomic",
                    "Semaphore",
                    "Notify",
                    "channel(",
                    "sync_channel(",
                ],
            );
            file.code_paths +=
                occurrences(line, &["if ", "match ", "=>", "while ", "for ", "loop {"]);
            file.unsafe_uses += occurrences(line, &["unsafe ", "unsafe{"]);
        }
        let score = file.total();
        total.loc += file.loc;
        total.characters += file.characters;
        total.comments += file.comments;
        total.smart_pointers += file.smart_pointers;
        total.synchronization += file.synchronization;
        total.code_paths += file.code_paths;
        total.unsafe_uses += file.unsafe_uses;
        ranked.push((
            score,
            path.strip_prefix(root).unwrap().display().to_string(),
        ));
    }
    ranked.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    (total, ranked)
}

#[test]
fn stab_meter() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (stabs, ranked) = source_stabs(root);
    println!("stab_total\t{:.1}", stabs.total());
    println!("loc\t{}", stabs.loc);
    println!("characters\t{}", stabs.characters);
    println!("comments\t{}", stabs.comments);
    println!("smart_pointers\t{}", stabs.smart_pointers);
    println!("synchronization\t{}", stabs.synchronization);
    println!("code_paths\t{}", stabs.code_paths);
    println!("unsafe\t{}", stabs.unsafe_uses);
    for (score, path) in ranked.into_iter().take(10) {
        println!("source\t{score:.1}\t{path}");
    }
    assert!(stabs.loc <= 31_836, "production LOC stabs increased");
    assert!(
        stabs.characters <= 1_158_346,
        "production character stabs increased"
    );
    assert!(stabs.comments == 0, "comment stabs increased");
    assert!(stabs.smart_pointers <= 126, "smart-pointer stabs increased");
    assert!(
        stabs.synchronization <= 182,
        "synchronization stabs increased"
    );
    assert!(stabs.code_paths <= 3_373, "code-path stabs increased");
    assert!(stabs.unsafe_uses == 0, "unsafe stabs increased");
    assert!(stabs.total() <= 151_490.5, "total static stabs increased");
}
