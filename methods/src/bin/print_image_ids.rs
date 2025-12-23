fn main() {
    use mprd_risc0_methods::{MPRD_GUEST_ID, MPRD_MPB_GUEST_ID, MPRD_TAU_COMPILED_GUEST_ID};

    println!("// Paste into `methods/src/expected_image_ids.rs`");
    println!(
        "pub const EXPECTED_MPRD_GUEST_ID: [u32; 8] = {:?};",
        MPRD_GUEST_ID
    );
    println!(
        "pub const EXPECTED_MPRD_MPB_GUEST_ID: [u32; 8] = {:?};",
        MPRD_MPB_GUEST_ID
    );
    println!(
        "pub const EXPECTED_MPRD_TAU_COMPILED_GUEST_ID: [u32; 8] = {:?};",
        MPRD_TAU_COMPILED_GUEST_ID
    );
}
