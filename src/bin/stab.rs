use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, ExitCode};

fn value(text: &str, name: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix('\t')?.parse().ok())
}

fn executable(text: &str) -> Option<String> {
    text.lines().rev().find_map(|line| {
        let value = line.split_once("\"executable\":\"")?.1;
        Some(value.split_once('"')?.0.replace("\\/", "/"))
    })
}

fn main() -> ExitCode {
    let mut arguments = env::args().skip(1);
    let Some(name) = arguments.next() else {
        eprintln!("usage: rinse-stab NAME CARGO_ARGS -- TEST_ARGS");
        return ExitCode::FAILURE;
    };
    let arguments = arguments.collect::<Vec<_>>();
    let separator = arguments
        .iter()
        .position(|value| value == "--")
        .unwrap_or(arguments.len());
    let cargo_arguments = &arguments[..separator];
    let test_arguments = arguments.get(separator + 1..).unwrap_or_default();
    let build = Command::new("cargo")
        .arg("test")
        .args(cargo_arguments)
        .args(["--no-run", "--message-format=json"])
        .output()
        .unwrap();
    if !build.status.success() {
        eprint!("{}", String::from_utf8_lossy(&build.stderr));
        return ExitCode::FAILURE;
    }
    let Some(executable) = executable(&String::from_utf8_lossy(&build.stdout)) else {
        eprintln!("test executable not found");
        return ExitCode::FAILURE;
    };
    let run = Command::new("/usr/bin/time")
        .arg("-p")
        .arg(executable)
        .args(test_arguments)
        .arg("--nocapture")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    let measured_output = format!("{stdout}\n{stderr}");
    print!("{stdout}");
    eprint!("{stderr}");
    if !run.status.success() {
        return ExitCode::FAILURE;
    }
    let cpu_ms = stderr
        .lines()
        .filter_map(|line| {
            line.strip_prefix("user ")
                .or_else(|| line.strip_prefix("sys "))?
                .parse::<f64>()
                .ok()
        })
        .sum::<f64>()
        .mul_add(1000.0, 0.0) as u64;
    let fields = ["db_accesses", "network_bytes", "disk_bytes", "wal_bytes"];
    let Some(values) = fields
        .map(|field| value(&measured_output, field))
        .into_iter()
        .collect::<Option<Vec<_>>>()
    else {
        eprintln!("test did not emit every runtime stab counter");
        return ExitCode::FAILURE;
    };
    let total = cpu_ms + values.iter().sum::<u64>();
    let report = format!(
        "cpu_ms\t{cpu_ms}\ndb_accesses\t{}\nnetwork_bytes\t{}\ndisk_bytes\t{}\nwal_bytes\t{}\ntotal_stabs\t{total}\n",
        values[0], values[1], values[2], values[3]
    );
    let baseline_path = Path::new("tests/stab-baselines").join(format!("{name}.tsv"));
    let baseline = fs::read_to_string(&baseline_path).unwrap();
    for (field, measured) in [
        ("cpu_ms", cpu_ms),
        ("db_accesses", values[0]),
        ("network_bytes", values[1]),
        ("disk_bytes", values[2]),
        ("wal_bytes", values[3]),
        ("total_stabs", total),
    ] {
        let maximum = value(&baseline, field).unwrap();
        if measured > maximum {
            eprintln!("{field} stabs increased: {measured} > {maximum}");
            return ExitCode::FAILURE;
        }
    }
    let directory = Path::new("target/stabs");
    fs::create_dir_all(directory).unwrap();
    fs::write(directory.join(format!("{name}.tsv")), &report).unwrap();
    print!("{report}");
    ExitCode::SUCCESS
}
