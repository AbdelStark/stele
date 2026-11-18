// RFC-0013 A5 item 5: repeated positions accumulate in original claim order.
extern "C" __global__ void batch_weights(const u32 *pairs, const u64 *offsets, u32 *weights, u64 len) {
  GRID_STRIDE(i, len) {
    Q sum = qzero();
    if (i < len/2) for (u64 j = offsets[i]; j < offsets[i+1]; ++j)
      sum = qadd(sum, qmul(qload(pairs, 2*j), qload(pairs, 2*j+1)));
    qstore(weights, i, sum);
  }
}

// Y=0 of every row, including mask rows. Keep the source at M31 width.
extern "C" __global__ void batch_face(const u32 *message, u32 *face, u64 columns, u64 len) {
  GRID_STRIDE(i, len) face[i] = mcanon(message[(i/columns)*2*columns + i%columns]);
}
