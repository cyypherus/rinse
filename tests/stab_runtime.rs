use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

use bzip2::Compression;
use bzip2::read::BzDecoder;
use bzip2::write::BzEncoder;
use rusqlite::Connection;
use rusqlite::trace::{TraceEvent, TraceEventCodes};
use sha2::{Digest, Sha256};

static DB_ACCESSES: AtomicU64 = AtomicU64::new(0);

fn count_db_access(event: TraceEvent<'_>) {
    if matches!(event, TraceEvent::Stmt(_, _)) {
        DB_ACCESSES.fetch_add(1, Ordering::Relaxed);
    }
}

fn bytes(path: &Path) -> u64 {
    fs::metadata(path).map_or(0, |metadata| metadata.len())
}

#[test]
fn runtime_stab_meter_counts_real_resources() {
    let root = std::env::temp_dir().join(format!("rinse-stabs-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let database = root.join("meter.db");
    let wal = root.join("meter.db-wal");
    DB_ACCESSES.store(0, Ordering::Relaxed);
    let mut connection = Connection::open(&database).unwrap();
    connection.trace_v2(TraceEventCodes::SQLITE_TRACE_STMT, Some(count_db_access));
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .unwrap();
    connection
        .pragma_update(None, "synchronous", "FULL")
        .unwrap();
    connection
        .execute("CREATE TABLE stab(value BLOB NOT NULL)", [])
        .unwrap();
    let transaction = connection.transaction().unwrap();
    let payload = vec![7_u8; 4096];
    let mut digest = [0_u8; 32];
    for _ in 0..25_000 {
        let mut hash = Sha256::new();
        hash.update(digest);
        hash.update(&payload);
        digest.copy_from_slice(&hash.finalize());
    }
    std::hint::black_box(digest);
    let mut encoder = BzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&payload).unwrap();
    let encoded = encoder.finish().unwrap();
    transaction
        .execute(
            "WITH RECURSIVE count(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM count WHERE n<100) INSERT INTO stab SELECT ?1 FROM count",
            [&encoded],
        )
        .unwrap();
    transaction.commit().unwrap();
    let mut statement = connection.prepare("SELECT value FROM stab").unwrap();
    let stored = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(stored.len(), 100);
    for value in stored {
        let mut decoded = Vec::new();
        BzDecoder::new(value.as_slice())
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, payload);
    }
    drop(statement);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let wire_bytes = encoded.len();
    let receiver = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut received = vec![0; wire_bytes];
        stream.read_exact(&mut received).unwrap();
        stream.write_all(&received).unwrap();
    });
    let mut stream = TcpStream::connect(address).unwrap();
    stream.write_all(&encoded).unwrap();
    let mut echoed = vec![0; encoded.len()];
    stream.read_exact(&mut echoed).unwrap();
    receiver.join().unwrap();
    let mut decoded = Vec::new();
    BzDecoder::new(echoed.as_slice())
        .read_to_end(&mut decoded)
        .unwrap();
    assert_eq!(decoded, payload);
    let db_accesses = DB_ACCESSES.load(Ordering::Relaxed);
    let network_bytes = (encoded.len() + echoed.len()) as u64;
    let disk_bytes = bytes(&database);
    let wal_bytes = bytes(&wal);
    let total = db_accesses + network_bytes + disk_bytes + wal_bytes;
    let report = format!(
        "db_accesses\t{db_accesses}\nnetwork_bytes\t{network_bytes}\ndisk_bytes\t{disk_bytes}\nwal_bytes\t{wal_bytes}\nworkload_stabs\t{total}\n"
    );
    let reports = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/stabs");
    fs::create_dir_all(&reports).unwrap();
    fs::write(reports.join("runtime_meter.tsv"), &report).unwrap();
    eprint!("{report}");
    assert!(db_accesses <= 10);
    assert!(network_bytes < 256);
    assert!(disk_bytes <= 4_096);
    assert!(wal_bytes <= 30_000);
    assert!(total <= 35_000);
    drop(connection);
    fs::remove_dir_all(root).unwrap();
}
