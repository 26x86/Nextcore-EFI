use std::{env, path::PathBuf, process::Command};
fn run(command: &mut Command) {
    let status = command
        .status()
        .expect("failed to launch C runtime compiler/archive tool");
    assert!(status.success(), "C runtime build failed: {command:?}");
}
fn main() {
    if env::var_os("CARGO_FEATURE_ARM_JIT").is_none() {
        return;
    }
    let target = env::var("TARGET").unwrap();
    if target != "x86_64-unknown-uefi" {
        return;
    }
    let runtime = env::var_os("NEXTCORE_PREOS_RUNTIME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(nextcore_ise::EFI_RUNTIME_DIR));
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let pauth = runtime.join("preos/src/pauth.rs");
    println!("cargo:rerun-if-changed={}", pauth.display());
    std::fs::write(
        output.join("jit_pauth.rs"),
        format!(
            "#[allow(dead_code)]\n#[path = {:?}]\nmod pauth;\n",
            pauth
                .canonicalize()
                .expect("missing shared PAC runtime source")
                .to_string_lossy()
        ),
    )
    .expect("write PAC module path");
    let compiler = env::var_os("NEXTCORE_CLANG").unwrap_or_else(|| "clang".into());
    let archive = output.join("libnextcore_arm_jit.a");
    let mut objects = Vec::new();
    for source in [
        "jit.c",
        "arch.c",
        "boot_jit.c",
        "jit_protection.c",
        "gop_scanout.c",
    ] {
        let input = runtime.join(source);
        println!("cargo:rerun-if-changed={}", input.display());
        let object = output.join(source.replace(".c", ".obj"));
        run(Command::new(&compiler)
            .args([
                "--target=x86_64-pc-windows-msvc",
                "-ffreestanding",
                "-fno-builtin",
                "-fno-stack-protector",
                "-mno-red-zone",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-c",
            ])
            .arg(&input)
            .arg("-o")
            .arg(&object));
        objects.push(object);
    }
    for header in ["jit.h", "boot_jit.h", "uefi.h", "gop_scanout.h"] {
        println!("cargo:rerun-if-changed={}", runtime.join(header).display());
    }
    run(
        Command::new(env::var_os("NEXTCORE_LLVM_AR").unwrap_or_else(|| "llvm-ar".into()))
            .arg("crs")
            .arg(&archive)
            .args(&objects),
    );
    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-lib=static=nextcore_arm_jit");
    for name in [
        "NEXTCORE_PREOS_RUNTIME",
        "NEXTCORE_CLANG",
        "NEXTCORE_LLVM_AR",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
}
