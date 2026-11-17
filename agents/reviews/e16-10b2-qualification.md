# NC-1308 column-routing qualification

This is a producer-only experiment, not registered control execution or a
performance result. Reference source: `6f7182b9110de8dd7b0c250dd10ab48e2d851cc1`.
The isolated producer copy has only the patch below; the verifier is unchanged.
The ordinary production library and a separately built CLI both accept every
honest proof and reject every rerouted proof with exactly
`Engine(Sumcheck(RoundSumMismatch))`. The CLI source is
`9e215b19ffe3e87300144d47fe2a579f8e759969`; its verifier is unchanged at the
reference source. CLI exits are 0/1 with `YES`/the exact nested rejection.

## Fixtures and results

The one-layer T=16 (L0) and eight-layer T=64 (L1) fixtures use source profiles 3
and 5. The selected real witness columns are ColumnId(147) `L0/norm1/Z0` and
ColumnId(148) `L0/norm1/Z1`, group 1 positions 5 and 6, of lengths 2^10 / 2^12.
Their full assigned vectors are equal. Both runs pass the plain checker before
proving; neither changes those values. The producer patch selects only the first
claim on column 147 and changes its stacked column prefix to column 148. Its
claim value and non-Boolean tail are unchanged. It asserts the one-claim change
and complete restoration equality before ordinary batch production continues.

| Fixture/profile | Honest proof SHA-256 | Rerouted proof SHA-256 |
|---|---|---|
| one-layer-3 | `e910f3d4e08c8a7f8c6a288601921e70a1a0e160ac93d01bbd86c268b08c9bcf` | `59820e5c71be1d04d5102afb9f3ea4083370d94bc5682cd2c64f32f90ae393ab` |
| one-layer-5 | `b87cf7a35ea8c1f5879fe15cc400a32884841e6627a64e911b04eb401e21f70a` | `cbd14ddc3b593804f7e75b24e6d71cce4cd7def43c2240080e81b1ead78b764b` |
| eight-layer-3 | `60bec98c7d81a01c364f0dc78a91f054b0e225f333682e3d5a3f6ae12f5ea900` | `5512d9c75fb1db7bd7800bcdedde32863b289d500df8461c1f236cc1d027bda6` |
| eight-layer-5 | `899e5745baedfb8a296112f6a61adde966d3f371c5845d94b0a2654ff561d9c1` | `06af12b7240ec0f9493fbc54ee0cff5cfb255e820226379ab084237e2bbe0afb` |

All four public-input bundles match byte for byte between honest and rerouted
runs. Decoding the proof containers confirms identical headers, group and
multiplicity certificates, identities, lookups and matmuls. Opening-section
counts match, and the dependent opening bytes differ. The two profile-5 honest
hashes also match the pre-existing pinned public artifacts used in A17's
qualification. No changed final scalar, dishonest certificate, alternate
verifier map or producer failure is credited.

## Reproduction

1. Make two isolated checkouts of the reference source. Apply the patch below to
   the producer copy only. Do not change the ordinary checkout or any verifier.
2. Use the `one-layer` and `eight-layer` fixture byte spans referenced by
   `tests/negative-controls/src/development.rs::span_of`. Generate the statement
   with `development::prove_window_development`, starting at tokens `[1]`,
   `start=0`, `end=1`, `next=None`, for window lengths 16/64 and profiles 3/5.
   Accept that honest proof through `development::verify`.
3. In each checkout, decode the model/preparation/scales and build `Weights` and
   `Committed` with the same source set. Construct the same `Public` and statement.
   Use `Layout::declare`, `Executor::capture(statement.tokens)` and `Layout::assign`
   to obtain the relation and values. Require the plain checker to accept and
   the two selected column vectors to be equal.
4. Reconstruct model sources with `relation::model_layout` and `model_messages`,
   prepare and certify them, and require their roots to match `Public.commitment`.
   Create `Transcript::new(development::public_input(...))`; call
   `relation::prove` and assemble its sections into the ordinary `Container`
   with `model_identity` and `statement_digest_for`. The patched copy changes
   only one producer-side step-7 point, then uses ordinary batching and openings.
5. Require complete producer success in both copies. Verify both containers with
   the unchanged development verifier, compare full typed results, and compare
   public inputs and all pre-opening sections as above. Also run the ordinary
   CLI `stele verify-dev --public public.bin --proof proof.bin` on each artifact.

The external qualification harness followed these steps with the existing pinned
public statements. It built separate optimized binaries from each checkout.
An initial diagnostic macro was unavailable in the no_std relation crate; it was
removed before the successful rerouted run. This was a compile failure, not a
verifier rejection. Logs, full harness source, artifacts and checksums remain in
`/Users/abdel/dev/stele-validation/column-route-qualification/` for independent
local replay. No timing is a benchmark claim.

## Isolated producer patch

This patch is qualification material, not production code or a verifier option.
It applies only to the producer's first `group_claims` call at step 7; the later
verifier call is unchanged. Its SHA-256 is
`dd21c346044da9b0c87e191c7b11cb9fb327e57e499edddd2e13f5e044dec7d6`.

```diff
diff --git a/crates/stele-reductions/src/relation.rs b/crates/stele-reductions/src/relation.rs
index 6cbbb6f4..77673fb6 100644
--- a/crates/stele-reductions/src/relation.rs
+++ b/crates/stele-reductions/src/relation.rs
@@ -1557,7 +1557,35 @@ fn prove_plan(
     laps.lap("dev/matmul");
     // Step 7: one claim batch and one opening of the stack, then per weight source.
     if let (Some(stack), Some((prepared, handle))) = (&plan.stack, &stacked) {
-        let batch = group_claims(plan, stack, &claims);
+        let mut batch = group_claims(plan, stack, &claims);
+        // Qualification only: reroute one real column claim, leaving the verifier unchanged.
+        let before = batch.clone();
+        let mut at = 0;
+        let mut changed = None;
+        for group in &plan.groups {
+            for (j, c) in group.columns.iter().enumerate() {
+                if c.0 == 147 {
+                    let neighbour = group.columns[j + 1];
+                    assert_eq!(neighbour.0, 148);
+                    assert_eq!(column(relation, values, *c)?, column(relation, values, neighbour)?);
+                    let (tail, value) = &claims.0[c.0 as usize][0];
+                    let prefix = stack.bits - group.n;
+                    let index = (group.offset >> group.n) + j;
+                    assert_eq!(batch[at], (bits_point(index, prefix, tail), *value));
+                    batch[at].0 = bits_point(index + 1, prefix, tail);
+                    assert_eq!(&batch[at].0[usize::from(prefix)..], tail);
+                    assert_eq!(batch[at].1, *value);
+                    assert!(changed.replace(at).is_none());
+                }
+                at += claims.0[c.0 as usize].len();
+            }
+        }
+        let changed = changed.expect("selected real column must have a claim");
+        assert_eq!(before.iter().zip(&batch).filter(|(a, b)| a != b).count(), 1);
+        assert_ne!(before[changed].0, batch[changed].0);
+        let mut restored = batch.clone();
+        restored[changed] = before[changed].clone();
+        assert_eq!(restored, before);
         if !batch.is_empty() {
             let opening = Opening {
                 id: BATCH,
```

NC-1308 remains `todo`. E16-10b still needs a reviewed producer interface,
mandatory harness registration, full control coverage and sensitivity checks
where practical. This qualification covers profiles 3 and 5 only; it does not
establish the old ValueMismatch expectation for another source profile, or
replace PCS value-authentication coverage. No security or promotion claim follows.
