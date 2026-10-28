//! RFC-0006 A6 §1: actual canonical files and bounded layout preparation.
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
use stele_field::{Field, Serialize, OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_sumcheck::{
    file::{prepare, FileSource},
    prove, prove_into, verify_public, Dense, Error, Instance, Proof, Source, Streaming, Term,
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "stele-source-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("exclusive temporary directory");
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove owned fixture");
    }
}
fn files<K: ChallengeField>(dir: &Directory, m: u32) -> (Vec<Vec<K>>, Vec<PathBuf>) {
    let mut rng = Transcript::<K>::new(b"file-source-fixture").expect("domain");
    let tables: Vec<Vec<K>> = (0..3)
        .map(|_| {
            (0..1usize << m)
                .map(|_| rng.challenge(ChallengeLabel::Sumcheck).expect("field"))
                .collect()
        })
        .collect();
    let paths = tables
        .iter()
        .enumerate()
        .map(|(a, t)| {
            let original = dir.path(&format!("{a}.original"));
            fs::write(
                &original,
                t.iter()
                    .flat_map(|v| v.to_le_bytes().as_ref().to_vec())
                    .collect::<Vec<_>>(),
            )
            .expect("fixture");
            original
        })
        .collect();
    (tables, paths)
}
fn descriptor<K: ChallengeField>(tables: &[Vec<K>], m: u32) -> Instance<K> {
    Instance {
        id: 1,
        num_vars: m,
        inputs: vec![11, 12, 13],
        terms: vec![Term {
            coefficient: K::from_i64(1),
            factors: vec![0, 1, 0],
        }],
        claimed_sum: (0..1usize << m).fold(K::from_i64(0), |sum, j| {
            sum + tables[0][j] * tables[1][j] * tables[0][j]
        }),
    }
}
fn parity<K: ChallengeField + Eq + core::fmt::Debug>()
where
    K::Bytes: AsMut<[u8]>,
{
    for (m, windows) in [(0, vec![]), (3, vec![]), (3, vec![1]), (3, vec![1, 2])] {
        let dir = Directory::new();
        let (tables, originals) = files::<K>(&dir, m);
        let paths: Vec<_> = originals
            .iter()
            .enumerate()
            .map(|(a, original)| {
                let before = fs::read(original).expect("original");
                let path = dir.path(&format!("{a}.source"));
                let counts = prepare::<K>(original, &path, m).expect("prepare");
                assert_eq!(counts.reads, 1 << m);
                assert_eq!(counts.writes, 1 << m);
                assert_eq!(counts.seeks, 1 << m);
                assert_eq!(counts.read_bytes, (1 << m) * 4 * K::DEGREE as u64);
                assert_eq!(counts.written_bytes, counts.read_bytes);
                assert_eq!(counts.eof_checks, 1);
                assert_eq!(fs::read(original).expect("preserved"), before);
                let raw = fs::read(&path).expect("prepared");
                for j in 0..1usize << m {
                    let at = if m == 0 {
                        0
                    } else {
                        j.reverse_bits() >> (usize::BITS - m)
                    };
                    let k = 4 * K::DEGREE;
                    assert_eq!(
                        &raw[j * k..(j + 1) * k],
                        tables[a][at].to_le_bytes().as_ref()
                    );
                }
                path
            })
            .collect();
        let i = descriptor(&tables, m);
        let source = FileSource::<K>::open(&i, &paths).expect("source");
        let heap = source.heap_bytes().expect("source allocation");
        assert!(heap >= 3 * core::mem::size_of::<fs::File>());
        let n = Streaming::<K, FileSource<K>>::workspace_len(&i, &windows).expect("plan");
        let mut state =
            Streaming::new(&i, source, &windows, vec![K::from_i64(0); n], n).expect("state");
        let mut out = Proof {
            rounds: vec![vec![K::from_i64(0); 4]; m as usize],
            final_values: vec![K::from_i64(0); 3],
        };
        let mut a = Transcript::new(b"files").expect("domain");
        let mut b = Transcript::new(b"files").expect("domain");
        let mut c = Transcript::new(b"files").expect("domain");
        prove_into(&i, &mut state, &mut out, &mut [0; 512], &mut a).expect("proof");
        assert_eq!(
            out,
            prove(&i, Dense::new(&i, tables.clone()).expect("dense"), &mut b).expect("proof")
        );
        let receipt = verify_public(&i, &out, &tables, &mut c).expect("original consumer");
        assert_eq!(receipt.claims.len(), 3);
        let next = a.challenge(ChallengeLabel::Sumcheck);
        assert_eq!(next, b.challenge(ChallengeLabel::Sumcheck));
        assert_eq!(next, c.challenge(ChallengeLabel::Sumcheck));
        let visits = (windows.len() + 1) as u64;
        let counts = state.source().counts();
        assert_eq!(counts.reads, visits * 3 * (1 << m));
        assert_eq!(counts.read_bytes, counts.reads * 4 * K::DEGREE as u64);
        assert_eq!(counts.seeks, visits * 3);
        assert_eq!(counts.eof_checks, visits * 3);
        assert_eq!(counts.writes, 0);
        assert_eq!(state.source().heap_bytes(), Ok(heap));
    }
}
#[test]
fn matches_reference_file_source_qm31() {
    parity::<QM31>();
}
#[test]
fn matches_reference_file_source_om31() {
    parity::<OM31>();
}
#[test]
fn rejects_malformed_files_and_preserves_existing_paths() {
    let dir = Directory::new();
    let (tables, originals) = files::<QM31>(&dir, 2);
    let i = descriptor(&tables, 2);
    let source = dir.path("source");
    let original = &originals[0];
    let valid = fs::read(original).expect("bytes");
    for bad in [
        valid[..valid.len() - 1].to_vec(),
        [valid.clone(), vec![0]].concat(),
        [QM31::MODULUS.to_le_bytes().to_vec(), valid[4..].to_vec()].concat(),
    ] {
        fs::write(original, &bad).expect("malform");
        assert_eq!(prepare::<QM31>(original, &source, 2), Err(Error::Source));
        assert!(!source.exists());
        assert_eq!(fs::read(original).expect("original"), bad);
    }
    fs::write(original, &valid).expect("restore");
    fs::write(&source, b"keep").expect("existing");
    assert_eq!(prepare::<QM31>(original, &source, 2), Err(Error::Source));
    assert_eq!(fs::read(&source).expect("preserved"), b"keep");
    assert_eq!(prepare::<QM31>(original, original, 2), Err(Error::Source));
    assert_eq!(fs::read(original).expect("preserved"), valid);
    assert!(matches!(
        FileSource::<QM31>::open(&i, &originals[..2]),
        Err(Error::PublicShape)
    ));
    fs::write(original, &valid[..valid.len() - 1]).expect("truncate");
    assert!(matches!(
        FileSource::<QM31>::open(&i, &originals),
        Err(Error::Source)
    ));
    fs::write(
        original,
        [QM31::MODULUS.to_le_bytes().to_vec(), valid[4..].to_vec()].concat(),
    )
    .expect("noncanonical");
    let mut source = FileSource::<QM31>::open(&i, &originals).expect("length valid");
    source.rewind().expect("rewind");
    assert_eq!(
        source.next_row(&mut [QM31::from_i64(0); 3]),
        Err(Error::Source)
    );
}
#[test]
fn rejects_changed_length_on_replay_and_short_rows() {
    let dir = Directory::new();
    let (tables, paths) = files::<OM31>(&dir, 1);
    let i = descriptor(&tables, 1);
    let mut source = FileSource::<OM31>::open(&i, &paths).expect("open");
    assert_eq!(
        source.next_row(&mut [OM31::from_i64(0); 2]),
        Err(Error::PublicShape)
    );
    source.rewind().expect("rewind");
    fs::write(&paths[0], b"").expect("truncate open file");
    assert_eq!(
        source.next_row(&mut [OM31::from_i64(0); 3]),
        Err(Error::Source)
    );
    assert_eq!(source.rewind(), Err(Error::Source));
}

#[test]
fn rejects_extra_bytes_after_open_and_keeps_original_handles() {
    use std::io::Write;
    let dir = Directory::new();
    let (tables, paths) = files::<OM31>(&dir, 0);
    let i = descriptor(&tables, 0);
    let mut source = FileSource::<OM31>::open(&i, &paths).expect("open");
    source.rewind().expect("rewind");
    let mut row = [OM31::from_i64(0); 3];
    assert_eq!(source.next_row(&mut row), Ok(true));
    fs::OpenOptions::new()
        .append(true)
        .open(&paths[0])
        .expect("append handle")
        .write_all(&[0])
        .expect("extra byte");
    assert_eq!(source.next_row(&mut row), Err(Error::Source));
    fs::write(&paths[0], tables[0][0].to_le_bytes()).expect("restore");
    fs::rename(&paths[0], dir.path("original-handle")).expect("rename");
    fs::write(&paths[0], b"different path contents").expect("replace path");
    source.rewind().expect("original handle length");
    assert_eq!(source.next_row(&mut row), Ok(true));
    assert_eq!(row, [tables[0][0], tables[1][0], tables[2][0]]);
}
#[test]
fn accepts_empty_file_source_without_size_overflow() {
    let i = Instance {
        id: 1,
        num_vars: 63,
        inputs: vec![],
        terms: vec![],
        claimed_sum: QM31::from_i64(0),
    };
    let source = FileSource::<QM31>::open(&i, &[] as &[PathBuf]).expect("no files");
    assert_eq!(source.heap_bytes(), Ok(0));
    let state = Streaming::new(&i, source, &[], vec![], 0).expect("no reads");
    assert_eq!(state.source().counts(), Default::default());
}
