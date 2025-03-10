fn main() {
    println!("cargo:rerun-if-changed=ui.slint");
    println!("cargo:rerun-if-changed=src/files/oui.txt");

    slint_build::compile("ui.slint").expect("Failed to compile ui.slint");

    let out_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let dest_dir = std::path::Path::new(&out_dir).join("target/release");

    std::fs::copy("src/files/oui.txt", dest_dir.join("oui.txt"))
        .expect("Failed to copy oui.txt");
    println!("cargo:warning=copied oui.txt to {:?}", dest_dir.join("oui.txt"));
}