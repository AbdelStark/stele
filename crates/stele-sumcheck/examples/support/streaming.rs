//! RFC-0006 A6 corpus adapter: real preparation/source, not a Dense fallback.
use super::{array, small};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    sync::atomic::{AtomicU64, Ordering},
};
use stele_hash::{ChallengeField, Transcript};
use stele_sumcheck::{
    file::{prepare, FileSource},
    message_size, prove_into, Instance, Proof, Streaming,
};
static NEXT: AtomicU64 = AtomicU64::new(0);
pub fn run<K: ChallengeField + Eq>(
    i: &Instance<K>,
    tables: &[Vec<K>],
    metadata: &Value,
    transcript: &mut Transcript<K>,
) -> Result<(Proof<K>, Value), String>
where
    K::Bytes: AsMut<[u8]>,
{
    let windows = array(&metadata["windows"])?
        .iter()
        .map(small)
        .collect::<Result<Vec<_>, _>>()?;
    let n =
        Streaming::<K, FileSource<K>>::workspace_len(i, &windows).map_err(|e| format!("{e:?}"))?;
    let degree = i.terms.iter().map(|t| t.factors.len()).max().unwrap_or(0);
    let bytes = i
        .encoded_len()
        .and_then(|size| Ok(size.max(message_size::<K>((degree + 1).max(i.inputs.len()))?)))
        .map_err(|e| format!("{e:?}"))?;
    let dir = std::env::temp_dir().join(format!(
        "stele-streaming-corpus-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&dir).map_err(|_| "Source")?;
    let result = (|| -> Result<(Proof<K>, Value), String> {
        let mut paths = Vec::new();
        for (index, table) in tables.iter().enumerate() {
            let original = dir.join(format!("{index}.original"));
            let prepared = dir.join(format!("{index}.source"));
            let mut file = fs::File::create_new(&original).map_err(|_| "Source")?;
            for value in table {
                file.write_all(value.to_le_bytes().as_ref())
                    .map_err(|_| "Source")?;
            }
            drop(file);
            prepare::<K>(&original, &prepared, i.num_vars).map_err(|e| format!("{e:?}"))?;
            paths.push(prepared);
        }
        let source = FileSource::<K>::open(i, &paths).map_err(|e| format!("{e:?}"))?;
        let mut state = Streaming::new(i, source, &windows, vec![K::from_i64(0); n], n)
            .map_err(|e| format!("{e:?}"))?;
        let mut proof = Proof {
            rounds: vec![vec![K::from_i64(0); degree + 1]; i.num_vars as usize],
            final_values: vec![K::from_i64(0); i.inputs.len()],
        };
        prove_into(i, &mut state, &mut proof, &mut vec![0; bytes], transcript)
            .map_err(|e| format!("{e:?}"))?;
        let count = state.source().counts();
        Ok((
            proof,
            json!({"reads":count.reads,"read_bytes":count.read_bytes,"seeks":count.seeks,"eof_checks":count.eof_checks}),
        ))
    })();
    fs::remove_dir_all(&dir).map_err(|_| "Source")?;
    result
}
