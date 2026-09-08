use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command};

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn main() {
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-env-changed=NINNA_SOURCE_COMMIT");
    if let Some(head_ref) = git_output(&["symbolic-ref", "-q", "HEAD"]) {
        println!("cargo:rerun-if-changed=.git/{head_ref}");
    }

    let source_commit = std::env::var("NINNA_SOURCE_COMMIT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| git_output(&["rev-parse", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_string());
    let lock = fs::read(Path::new("Cargo.lock")).expect("read Cargo.lock");
    let lock_sha256 = format!("{:x}", Sha256::digest(lock));
    let dirty = git_output(&["status", "--porcelain"]).is_some_and(|value| !value.is_empty());
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());

    println!("cargo:rustc-env=NINNA_SOURCE_COMMIT={source_commit}");
    println!("cargo:rustc-env=NINNA_CARGO_LOCK_SHA256={lock_sha256}");
    println!("cargo:rustc-env=NINNA_BUILD_TARGET={target}");
    println!(
        "cargo:rustc-env=NINNA_SOURCE_DIRTY={}",
        if dirty { "true" } else { "false" }
    );
}
