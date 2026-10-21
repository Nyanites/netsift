fn main() {
    println!("cargo:rerun-if-changed=csrc/procsock.c");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new().file("csrc/procsock.c").warnings(true).compile("procsock");
    }
}
