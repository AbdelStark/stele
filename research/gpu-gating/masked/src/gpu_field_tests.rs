//! RFC-0003 §6 / RFC-0014 §5: explicit H100 primitive parity, never a skip.
//! Synthetic field words only; no committed/virtual columns or proof admission.
use super::{available, Device, PushKernelArg, KERNELS};
use crate::field_cases::{inputs, verify, CALLS, CASES, OUTPUT_WORDS, SEED};

#[test]
#[ignore = "requires an explicitly allocated H100 and CUDA/NVRTC"]
fn matches_reference_raw_field_helpers_on_h100() {
    assert!(available(), "required CUDA driver and NVRTC absent");
    let dev = Device::new().expect("CUDA device");
    assert!(dev.name.contains("H100"), "H100 required: {}", dev.name);
    let launch = r#"
extern "C" __global__ void field_cases(const u32 *in, u32 *out, u64 count) {
  GRID_STRIDE(i, count) field_case(in + 8*i, out + 28*i);
}
"#;
    let module = Device::compile(&dev.ctx, dev.arch, &format!("{KERNELS}\n{CALLS}\n{launch}"))
        .expect("actual helper qualification kernel");
    let function = module.load_function("field_cases").expect("field kernel");
    let input = inputs();
    let device_input = dev.stream.clone_htod(&input).expect("raw input upload");
    let device_output = dev
        .stream
        .alloc_zeros::<u32>(CASES * OUTPUT_WORDS)
        .expect("outputs");
    let (source, target, count) = (
        dev.ptr(&device_input),
        dev.ptr(&device_output),
        CASES as u64,
    );
    let mut call = dev.stream.launch_builder(&function);
    call.arg(&source).arg(&target).arg(&count);
    // SAFETY: RFC-0003 §6 fixture has count*8 raw limbs in [0,2p); each grid-stride
    // case reads its eight limbs and writes its disjoint 28-word output slice.
    unsafe { call.launch(dev.grid(CASES)) }.expect("field kernel launch");
    dev.sync().expect("field kernel completion");
    let output = dev
        .stream
        .clone_dtoh(&device_output)
        .expect("actual device outputs");
    verify(&input, &output);
    eprintln!("field_device_cases={CASES} seed={SEED} device={}", dev.name);
}
