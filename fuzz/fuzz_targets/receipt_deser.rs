#![no_main]

use libfuzzer_sys::fuzz_target;

#[cfg(not(feature = "zk"))]
compile_error!("receipt_deser requires the `zk` feature (build with `--features zk`).");

fuzz_target!(|data: &[u8]| {
    // Must never panic or allocate unbounded memory for arbitrary bytes.
    let _ = mprd_zk::bounded_deser::deserialize_receipt::<risc0_zkvm::Receipt>(data);
});
