use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=modules/mcpu/module/enrollment_ui.swift");
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("build output directory"));
    let source = manifest_dir.join("modules/mcpu/module/enrollment_ui.swift");
    let executable = out_dir.join("McpuEnrollment");
    let module_cache = out_dir.join("swift-module-cache");
    std::fs::create_dir_all(&module_cache).expect("create Swift module cache");

    let architecture = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x86_64",
        Ok("aarch64") => "arm64",
        target => panic!("unsupported macOS Swift helper architecture: {target:?}"),
    };
    let default_deployment_target = if architecture == "arm64" {
        "11.0"
    } else {
        "10.13"
    };
    let deployment_target = env::var("MACOSX_DEPLOYMENT_TARGET")
        .unwrap_or_else(|_| default_deployment_target.to_string());
    if deployment_target.is_empty()
        || !deployment_target
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || !deployment_target.bytes().any(|byte| byte.is_ascii_digit())
    {
        panic!("invalid MACOSX_DEPLOYMENT_TARGET: {deployment_target:?}");
    }
    let target = format!("{architecture}-apple-macosx{deployment_target}");

    let output = Command::new("/usr/bin/swiftc")
        .arg("-parse-as-library")
        .arg("-target")
        .arg(target)
        .arg("-module-cache-path")
        .arg(module_cache)
        .arg("-O")
        .arg(source)
        .arg("-o")
        .arg(executable)
        .output()
        .expect("macOS builds require /usr/bin/swiftc to package the enrollment UI");
    if !output.status.success() {
        panic!(
            "swiftc could not package the native enrollment UI ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
