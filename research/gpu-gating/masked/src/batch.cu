// RFC-0013 A5 item 5: one thread owns one data position. Runs in its tile
// preserve claim and contribution order, even for overlapping or repeated positions.
extern "C" __global__ void batch_weights(const u32 *packed, const u32 *gammas,
    const u64 *runs, const u64 *offsets, u32 *weights, u64 tile, u64 half) {
  GRID_STRIDE(i, half) {
    Q sum = qzero();
    const u64 t = i / tile;
    for (u64 j = offsets[t]; j < offsets[t + 1]; ++j) {
      const u64 *r = runs + 4*j;
      if (r[0] <= i && i < r[1])
        sum = qadd(sum, qmul(qload(packed, r[2] + (i-r[0])), qload(gammas, r[3])));
    }
    qstore(weights, i, sum);
  }
}

// Y=0 of every row, including mask rows. Keep the source at M31 width.
extern "C" __global__ void batch_face(const u32 *message, u32 *face, u64 columns, u64 len) {
  GRID_STRIDE(i, len) face[i] = mcanon(message[(i/columns)*2*columns + i%columns]);
}
