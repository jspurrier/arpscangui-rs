use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs"); // Force rerun on build.rs change
    println!("cargo:rerun-if-changed=src/files/oui.txt"); // Force rerun if oui.txt changes
    println!("cargo:rerun-if-changed=oui.txt"); // Force rerun if root oui.txt changes

    // Select the appropriate UI file based on the feature flag
    #[cfg(feature = "windows-no-popup")]
    let ui_file = "ui_windows.slint";
    #[cfg(not(feature = "windows-no-popup"))]
    let ui_file = "ui_linux.slint";

    // Compile the selected Slint UI file
    println!("Compiling Slint UI file: {}", ui_file);
    slint_build::compile(ui_file).unwrap();

    // Check and copy oui.txt to target/release
    let oui_source = if Path::new("src/files/oui.txt").exists() {
        println!("Found oui.txt at src/files/oui.txt");
        "src/files/oui.txt"
    } else if Path::new("oui.txt").exists() {
        println!("Found oui.txt at root directory");
        "oui.txt"
    } else {
        panic!("oui.txt not found in src/files/ or root directory! Please place oui.txt in src/files/ or the project root.");
    };

    let target_dir = env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
    let release_dir = format!("{}/release", target_dir);
    println!("Target release directory: {}", release_dir);
    let out_path = format!("{}/oui.txt", release_dir);
    println!("Attempting to copy {} to {}", oui_source, out_path);
    fs::create_dir_all(&release_dir).unwrap_or_else(|e| panic!("Failed to create release directory {}: {}", release_dir, e));
    fs::copy(oui_source, &out_path).unwrap_or_else(|e| {
        panic!("Failed to copy {} to {}: {}", oui_source, out_path, e);
    });
    println!("Copied oui.txt to {}", out_path);
}