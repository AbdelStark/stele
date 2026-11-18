// RFC-0003 §§1/2/6: exercise the actual helpers; no advice or protocol output.
__device__ void field_case(const u32 *in, u32 *out) {
  Q x = qload(in, 0), y = qload(in, 1);
  out[0] = madd(x.a0, y.a0);
  out[1] = msub(x.a0, y.a0);
  out[2] = mmul(x.a0, y.a0);
  out[3] = mneg(x.a0);
  qstore(out, 1, qadd(x, y));
  qstore(out, 2, qsub(x, y));
  qstore(out, 3, qmulm(x, y.a0));
  qstore(out, 4, qmul(x, y));
  qstore(out, 5, x);
  qstore(out, 6, qembed(x.a0));
}
