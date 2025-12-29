fn main() {
    // Silence `unexpected_cfgs` for Kani harnesses (`#[cfg(kani)]`), while keeping the
    // default check-cfg lint enabled for other cfg typos.
    println!("cargo::rustc-check-cfg=cfg(kani)");
}
