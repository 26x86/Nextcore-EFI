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
    let memory_provider = env::var_os("CARGO_FEATURE_ARM_JIT_MEMORY_PROVIDER").is_some();
    let stage1_probe = env::var_os("CARGO_FEATURE_ARM_JIT_STAGE1_PROBE").is_some();
    let dynamic_probe = env::var_os("CARGO_FEATURE_ARM_JIT_DYNAMIC_PROBE").is_some();
    let mut shared_modules = String::new();
    for module in ["pauth", "platform"] {
        if module == "platform" && env::var_os("CARGO_FEATURE_ARM_JIT_TRACE").is_none() {
            continue;
        }
        let source = runtime.join(format!("preos/src/{module}.rs"));
        println!("cargo:rerun-if-changed={}", source.display());
        shared_modules.push_str(&format!(
            "#[allow(dead_code)]\n#[path = {:?}]\nmod {module};\n",
            source
                .canonicalize()
                .expect("missing shared runtime source")
                .to_string_lossy()
        ));
    }
    if memory_provider {
        for module in if stage1_probe {
            &["memory_boot", "memory_boot_v2"][..]
        } else {
            &["memory_boot"][..]
        } {
            let source = runtime.join(format!("{module}.rs"));
            println!("cargo:rerun-if-changed={}", source.display());
            shared_modules.push_str(&format!(
                "#[allow(dead_code)]\n#[path = {:?}]\nmod {module};\n",
                source
                    .canonicalize()
                    .expect("missing canonical memory result ABI")
                    .to_string_lossy()
            ));
        }
    }
    if dynamic_probe {
        let source = runtime.join("memory_dynamic.rs");
        println!("cargo:rerun-if-changed={}", source.display());
        shared_modules.push_str(&format!(
            "#[allow(dead_code)]\n#[path = {:?}]\nmod memory_dynamic;\n",
            source
                .canonicalize()
                .expect("missing dynamic result ABI")
                .to_string_lossy()
        ));
    }
    std::fs::write(output.join("jit_pauth.rs"), shared_modules)
        .expect("write shared runtime module paths");
    let compiler = env::var_os("NEXTCORE_CLANG").unwrap_or_else(|| "clang".into());
    let archive = output.join("libnextcore_arm_jit.a");
    let mut objects = Vec::new();
    let mut sources = vec![
        "jit.c",
        "arch.c",
        "boot_jit.c",
        "jit_protection.c",
        "gop_scanout.c",
    ];
    if memory_provider {
        sources.push("memory_boot.c");
    }
    if stage1_probe {
        sources.push("memory_boot_v2.c");
    }
    if dynamic_probe {
        sources.push("memory_dynamic.c");
    }
    for source in sources {
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
            .args(
                if env::var_os("CARGO_FEATURE_ARM_JIT_PROVIDER_UNCACHED").is_some() {
                    &["-DNEXTCORE_DISABLE_PROVIDER_CACHE"][..]
                } else {
                    &[][..]
                },
            )
            .arg(&input)
            .arg("-o")
            .arg(&object));
        objects.push(object);
    }
    for header in [
        "jit.h",
        "boot_jit.h",
        "platform_abi.h",
        "uefi.h",
        "gop_scanout.h",
        "memory_abi.h",
        "memory_boot.h",
        "memory_abi_v2.h",
        "memory_boot_v2.h",
        "memory_stage1.inc",
        "memory_dynamic.h",
        "memory_dynamic.inc",
    ] {
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
