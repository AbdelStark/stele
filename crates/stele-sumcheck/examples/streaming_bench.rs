//! RFC-0006 A6 / RFC-0018 §1: complete native streaming pipeline measurements.
use serde_json::{json, Value};
use std::{
    fs::File,
    io::{Read, Write},
    mem::size_of,
    path::{Path, PathBuf},
    time::Instant,
};
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_sumcheck::{
    file::{prepare, FileSource, IoCounts},
    message_size, prove_into, verify_public, Dense, Instance, Proof, Streaming, Term,
};
struct Plan {
    dir: PathBuf,
    degree: usize,
    m: u32,
    dense: bool,
    windows: Vec<u32>,
    budget: usize,
}
impl Plan {
    fn new(dir: PathBuf, degree: usize, m: u32, mode: &str, budget: usize) -> Result<Self, String> {
        if degree > 4 || ![4, 8, 18].contains(&m) {
            return Err("unsupported benchmark shape".into());
        }
        let windows = match mode {
            "dense" | "tail" => vec![],
            "one" => vec![m / 2],
            "multi" => vec![m / 3, m / 3],
            _ => return Err("unknown strategy".into()),
        };
        Ok(Self {
            dir,
            degree,
            m,
            dense: mode == "dense",
            windows,
            budget,
        })
    }
    fn paths(&self, extension: &str) -> Vec<PathBuf> {
        (0..3)
            .map(|a| self.dir.join(format!("{a}.{extension}")))
            .collect()
    }
    fn heap_bytes(&self) -> usize {
        self.windows.capacity() * size_of::<u32>() + self.dir.capacity()
    }
}
fn ns(start: Instant) -> Result<u64, String> {
    start
        .elapsed()
        .as_nanos()
        .try_into()
        .map_err(|_| "time overflow".into())
}
fn error(e: impl core::fmt::Debug) -> String {
    format!("{e:?}")
}
fn io_value(c: IoCounts) -> Value {
    json!({"reads":c.reads,"writes":c.writes,"seeks":c.seeks,"read_bytes":c.read_bytes,"written_bytes":c.written_bytes,"eof_checks":c.eof_checks})
}
fn paths_bytes(paths: &Vec<PathBuf>) -> usize {
    paths.capacity() * size_of::<PathBuf>() + paths.iter().map(|p| p.capacity()).sum::<usize>()
}
fn descriptor<K: ChallengeField>(p: &Plan) -> Instance<K> {
    Instance {
        id: 305,
        num_vars: p.m,
        inputs: vec![11, 12, 13],
        terms: if p.degree == 0 {
            vec![Term {
                coefficient: K::from_i64(5),
                factors: vec![],
            }]
        } else {
            vec![
                Term {
                    coefficient: K::from_i64(1),
                    factors: vec![0; p.degree],
                },
                Term {
                    coefficient: K::from_i64(-1),
                    factors: vec![1],
                },
            ]
        },
        claimed_sum: K::from_i64(if p.degree == 0 { 5 * (1i64 << p.m) } else { 0 }),
    }
}
fn descriptor_bytes<K>(i: &Instance<K>) -> usize {
    i.inputs.capacity() * size_of::<u64>()
        + i.terms.capacity() * size_of::<Term<K>>()
        + i.terms
            .iter()
            .map(|t| t.factors.capacity() * size_of::<u32>())
            .sum::<usize>()
}
fn proof<K: ChallengeField>(p: &Plan) -> Proof<K> {
    Proof {
        rounds: vec![vec![K::from_i64(0); p.degree + 1]; p.m as usize],
        final_values: vec![K::from_i64(0); 3],
    }
}
fn proof_bytes<K>(p: &Proof<K>) -> usize {
    p.rounds.capacity() * size_of::<Vec<K>>()
        + p.rounds
            .iter()
            .map(|r| r.capacity() * size_of::<K>())
            .sum::<usize>()
        + p.final_values.capacity() * size_of::<K>()
}
fn transcript<K: ChallengeField>() -> Result<Transcript<K>, String> {
    Transcript::new(b"synthetic streaming pipeline").map_err(error)
}
fn prepare_files<K: ChallengeField>(p: &Plan) -> Result<Value, String>
where
    K::Bytes: AsMut<[u8]>,
{
    let start = Instant::now();
    let original = p.paths("raw");
    let prepared = p.paths("rev");
    let c = Transcript::<K>::new(b"streaming fixture coefficient")
        .map_err(error)?
        .challenge(ChallengeLabel::Sumcheck)
        .map_err(error)?;
    let mut fixture = IoCounts::default();
    for (a, path) in original.iter().enumerate() {
        let mut file = File::create_new(path).map_err(error)?;
        for j in 0..1usize << p.m {
            let x = c * K::from_i64(((j * 73 + 19) % 15) as i64 - 7);
            let value = match a {
                0 => x,
                1 => (0..p.degree).fold(K::from_i64(1), |v, _| v * x),
                _ => c * K::from_i64((j % 31) as i64 - 15),
            };
            file.write_all(value.to_le_bytes().as_ref())
                .map_err(error)?;
            fixture.writes += 1;
            fixture.written_bytes += (4 * K::DEGREE) as u64;
        }
    }
    let fixture_ns = ns(start)?;
    let mut counts = IoCounts::default();
    let start = Instant::now();
    if !p.dense {
        for (input, output) in original.iter().zip(&prepared) {
            let c = prepare::<K>(input, output, p.m).map_err(error)?;
            counts.reads += c.reads;
            counts.writes += c.writes;
            counts.seeks += c.seeks;
            counts.read_bytes += c.read_bytes;
            counts.written_bytes += c.written_bytes;
            counts.eof_checks += c.eof_checks;
        }
    }
    let preparation_ns = if p.dense { 0 } else { ns(start)? };
    Ok(
        json!({"fixture_ns":fixture_ns,"preparation_ns":preparation_ns,"fixture_io":io_value(fixture),"preparation_io":io_value(counts),
        "preparation_buffer_capacity_bytes":p.heap_bytes()+paths_bytes(&original)+paths_bytes(&prepared),"record_bytes":4*K::DEGREE,
        "external_input_bytes":fixture.written_bytes+counts.written_bytes}),
    )
}
fn read_tables<K: ChallengeField>(
    paths: &[PathBuf],
    m: u32,
) -> Result<(Vec<Vec<K>>, IoCounts), String>
where
    K::Bytes: AsMut<[u8]>,
{
    let n = 1usize << m;
    let mut tables = Vec::with_capacity(paths.len());
    let mut counts = IoCounts::default();
    for path in paths {
        let mut file = File::open(path).map_err(error)?;
        if file.metadata().map_err(error)?.len() != (n * 4 * K::DEGREE) as u64 {
            return Err("Source".into());
        }
        let mut row = Vec::with_capacity(n);
        for _ in 0..n {
            let mut bytes = K::from_i64(0).to_le_bytes();
            file.read_exact(bytes.as_mut()).map_err(error)?;
            row.push(K::from_le_bytes(bytes).ok_or("Source")?);
            counts.reads += 1;
            counts.read_bytes += (4 * K::DEGREE) as u64;
        }
        if file.read(&mut [0; 1]).map_err(error)? != 0 {
            return Err("Source".into());
        }
        counts.eof_checks += 1;
        tables.push(row);
    }
    Ok((tables, counts))
}
fn table_bytes<K>(tables: &Vec<Vec<K>>) -> usize {
    tables.capacity() * size_of::<Vec<K>>()
        + tables
            .iter()
            .map(|t| t.capacity() * size_of::<K>())
            .sum::<usize>()
}
// Benchmark transport only, not the RFC-0016 inference-proof container.
fn pack<K: ChallengeField>(i: &Instance<K>, proof: &Proof<K>, next: K) -> Result<Vec<u8>, String> {
    let mut bytes = i.encode().map_err(error)?;
    for value in proof
        .rounds
        .iter()
        .flatten()
        .chain(&proof.final_values)
        .chain(core::iter::once(&next))
    {
        bytes.extend_from_slice(value.to_le_bytes().as_ref());
    }
    Ok(bytes)
}
fn produce<K: ChallengeField + Eq>(p: &Plan) -> Result<Value, String>
where
    K::Bytes: AsMut<[u8]>,
{
    let start = Instant::now();
    let i = descriptor::<K>(p);
    let paths = p.paths(if p.dense { "raw" } else { "rev" });
    let mut output = proof::<K>(p);
    let mut bytes = vec![
        0;
        i.encoded_len()
            .map_err(error)?
            .max(message_size::<K>((p.degree + 1).max(3)).map_err(error)?)
    ];
    let mut pt = transcript::<K>()?;
    let common = p.heap_bytes()
        + paths_bytes(&paths)
        + descriptor_bytes(&i)
        + proof_bytes(&output)
        + bytes.capacity();
    let (counts, storage, inline, work_capacity) = if p.dense {
        let (tables, counts) = read_tables::<K>(&paths, p.m)?;
        let storage = table_bytes(&tables);
        let mut state = Dense::new(&i, tables).map_err(error)?;
        prove_into(&i, &mut state, &mut output, &mut bytes, &mut pt).map_err(error)?;
        (counts, storage, size_of::<Dense<K>>(), 0)
    } else {
        let n = Streaming::<K, FileSource<K>>::workspace_len(&i, &p.windows).map_err(error)?;
        if n > p.budget {
            return Err("Capacity".into());
        }
        let source = FileSource::<K>::open(&i, &paths).map_err(error)?;
        let source_heap = source.heap_bytes().map_err(error)?;
        let mut state = Streaming::new(&i, source, &p.windows, vec![K::from_i64(0); n], p.budget)
            .map_err(error)?;
        let capacity = state.workspace_capacity();
        prove_into(&i, &mut state, &mut output, &mut bytes, &mut pt).map_err(error)?;
        assert_eq!(state.workspace_capacity(), capacity);
        (
            state.source().counts(),
            capacity * size_of::<K>() + source_heap,
            size_of::<Streaming<K, FileSource<K>>>(),
            capacity,
        )
    };
    let next = pt.challenge(ChallengeLabel::Sumcheck).map_err(error)?;
    let transport = pack(&i, &output, next)?;
    File::create_new(p.dir.join("proof.bin"))
        .and_then(|mut f| f.write_all(&transport))
        .map_err(error)?;
    let elapsed = ns(start)?;
    Ok(
        json!({"prover_ns":elapsed,"source_io":io_value(counts),"work_capacity_cells":work_capacity,"work_budget_cells":p.budget,
        "prover_buffer_capacity_bytes":common+storage,"strategy_storage_bytes":storage,"proof_capacity_bytes":proof_bytes(&output),"absorb_capacity_bytes":bytes.capacity(),
        "descriptor_heap_bytes":descriptor_bytes(&i),"caller_heap_bytes":p.heap_bytes()+paths_bytes(&paths),
        "named_inline_bytes":inline+size_of::<Plan>()+size_of::<Instance<K>>()+size_of::<Proof<K>>()+size_of::<Transcript<K>>()+size_of::<Vec<u8>>()+size_of::<Vec<PathBuf>>(),
        "transport_capacity_bytes":transport.capacity(),"transport_bytes":transport.len()}),
    )
}
fn consume<K: ChallengeField + Eq>(p: &Plan) -> Result<Value, String>
where
    K::Bytes: AsMut<[u8]>,
{
    let start = Instant::now();
    let i = descriptor::<K>(p);
    let header = i.encode().map_err(error)?;
    let path = p.dir.join("proof.bin");
    let size = header.len() + (p.m as usize * (p.degree + 1) + 4) * 4 * K::DEGREE;
    let mut file = File::open(&path).map_err(error)?;
    if file.metadata().map_err(error)?.len() != size as u64 {
        return Err("ProofShape".into());
    }
    let mut bytes = vec![0; size];
    file.read_exact(&mut bytes).map_err(error)?;
    if file.read(&mut [0; 1]).map_err(error)? != 0 {
        return Err("ProofShape".into());
    }
    if bytes[..header.len()] != header {
        return Err("descriptor mismatch".into());
    }
    let mut cursor = header.len();
    let mut value = || -> Result<K, String> {
        let mut raw = K::from_i64(0).to_le_bytes();
        let n = raw.as_ref().len();
        raw.as_mut().copy_from_slice(&bytes[cursor..cursor + n]);
        cursor += n;
        K::from_le_bytes(raw).ok_or("NoncanonicalField".into())
    };
    let mut output = proof::<K>(p);
    for x in output
        .rounds
        .iter_mut()
        .flatten()
        .chain(&mut output.final_values)
    {
        *x = value()?;
    }
    let next = value()?;
    let paths = p.paths("raw");
    let (tables, counts) = read_tables::<K>(&paths, p.m)?;
    let retained = p.heap_bytes()
        + paths_bytes(&paths)
        + path.capacity()
        + descriptor_bytes(&i)
        + header.capacity()
        + bytes.capacity()
        + proof_bytes(&output)
        + table_bytes(&tables);
    let mut vt = transcript::<K>()?;
    let receipt = verify_public(&i, &output, &tables, &mut vt).map_err(error)?;
    if vt.challenge(ChallengeLabel::Sumcheck).map_err(error)? != next {
        return Err("continuation mismatch".into());
    }
    assert_eq!(receipt.claims.len(), 3);
    assert_eq!(receipt.sc.numerator, u64::from(p.m) * p.degree as u64);
    drop(tables);
    let elapsed = ns(start)?;
    Ok(
        json!({"consumer_ns":elapsed,"claims":receipt.claims.len(),"sc":{"id":receipt.sc.id,"m":receipt.sc.m,"degree":receipt.sc.degree,"field_degree":receipt.sc.field_degree,"numerator":receipt.sc.numerator},
        "source_io":io_value(counts),"consumer_retained_buffer_bytes":retained,"transport_bytes":bytes.len()}),
    )
}
fn run<K: ChallengeField + Eq>(p: &Plan, stage: u8) -> Result<Value, String>
where
    K::Bytes: AsMut<[u8]>,
{
    match stage {
        0 => prepare_files::<K>(p),
        1 => produce::<K>(p),
        _ => consume::<K>(p),
    }
}
fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 7 {
        return Err("expected QM31|OM31 degree m dense|tail|one|multi budget_cells directory prepare|prove|consume".into());
    }
    let field = match args[0].as_str() {
        "QM31" => 4,
        "OM31" => 8,
        _ => return Err("invalid field".into()),
    };
    let p = Plan::new(
        Path::new(&args[5]).to_owned(),
        args[1].parse().map_err(error)?,
        args[2].parse().map_err(error)?,
        &args[3],
        args[4].parse().map_err(error)?,
    )?;
    let stage = match args[6].as_str() {
        "prepare" => 0,
        "prove" => 1,
        "consume" => 2,
        _ => return Err("invalid stage".into()),
    };
    drop(args);
    let result = if field == 4 {
        run::<QM31>(&p, stage)?
    } else {
        run::<OM31>(&p, stage)?
    };
    println!("{result}");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use stele_field::{Field, Serialize};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "stele-stream-bench-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&p).expect("fixture directory");
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).expect("cleanup");
        }
    }
    fn check<K: ChallengeField + Eq>()
    where
        K::Bytes: AsMut<[u8]>,
    {
        for degree in 0..=4 {
            let mut expected = None;
            for mode in ["dense", "tail", "one", "multi"] {
                let dir = Temp::new();
                let p = Plan::new(dir.0.clone(), degree, 4, mode, usize::MAX).expect("plan");
                let prepared = prepare_files::<K>(&p).expect("prepare");
                assert_eq!(prepared["fixture_io"]["writes"], 48);
                let produced = produce::<K>(&p).expect("prove");
                let proof = std::fs::read(dir.0.join("proof.bin")).expect("transport");
                if let Some(expected) = &expected {
                    assert_eq!(&proof, expected);
                } else {
                    expected = Some(proof);
                }
                let receipt = consume::<K>(&p).expect("all original claims");
                assert_eq!(receipt["claims"], 3);
                assert_eq!(receipt["sc"]["numerator"], 4 * degree);
                assert_eq!(
                    produced["source_io"]["reads"],
                    48 * if p.dense { 1 } else { p.windows.len() + 1 }
                );
                assert!(produced["proof_capacity_bytes"].as_u64().expect("capacity") > 0);
            }
        }
    }
    #[test]
    fn matches_reference_streaming_benchmark_pipeline() {
        check::<QM31>();
        check::<OM31>();
    }
    #[test]
    fn rejects_streaming_benchmark_false_final_and_bad_plan() {
        let dir = Temp::new();
        let p = Plan::new(dir.0.clone(), 1, 4, "one", 1024).expect("plan");
        prepare_files::<QM31>(&p).expect("prepare");
        produce::<QM31>(&p).expect("prove");
        let path = dir.0.join("proof.bin");
        let honest = std::fs::read(&path).expect("transport");
        let mut bytes = honest.clone();
        let at = bytes.len() - 32;
        let mut raw = [0u8; 16];
        raw.copy_from_slice(&bytes[at..at + 16]);
        let value = QM31::from_le_bytes(raw).expect("canonical") + QM31::from_i64(1);
        bytes[at..at + 16].copy_from_slice(&value.to_le_bytes());
        std::fs::write(&path, &bytes).expect("tamper");
        assert_eq!(consume::<QM31>(&p), Err("ClaimMismatch".into()));
        std::fs::write(&path, &honest[..honest.len() - 1]).expect("truncate transport");
        assert_eq!(consume::<QM31>(&p), Err("ProofShape".into()));
        let mut changed = honest;
        let at = changed.len() - 16;
        raw.copy_from_slice(&changed[at..]);
        let next = QM31::from_le_bytes(raw).expect("canonical") + QM31::from_i64(1);
        changed[at..].copy_from_slice(&next.to_le_bytes());
        std::fs::write(&path, changed).expect("change continuation");
        assert_eq!(consume::<QM31>(&p), Err("continuation mismatch".into()));
        let mut p = p;
        p.budget = 1;
        assert!(produce::<QM31>(&p).is_err());
        assert!(Plan::new(dir.0.clone(), 5, 4, "one", 1024).is_err());
        assert!(Plan::new(dir.0.clone(), 1, 64, "one", 1024).is_err());
        assert!(Plan::new(dir.0.clone(), 1, 4, "unknown", 1024).is_err());
    }
}
