use cxx_build::bridge;
use std::env;

fn main() {
    let files = vec![
        "src/OAEP/OAEP-methods.cpp",
        "src/CJacob314-Hash/Hashing.cpp",
        "src/StringAssembler/StringAssembler.cpp",
        "src/RSA/RSA-operators.cpp",
        "src/RSA/RSA-constructors.cpp",
        "src/RSA/RSA-methods.cpp",
        "src/RSA/RSA-rust-interface.cpp",
    ];

    println!("cargo:rustc-env=CC=gcc");
    println!("cargo:rustc-env=CXX=g++");

    let mut build = cxx_build::bridge("src/main.rs");

    // Add all C++ files to the build
    for file in files.iter() {
        build.file(file);
    }

    build.flag_if_supported("-std=c++17");
    build.flag_if_supported("-pthread");
    build.flag_if_supported("-flto=auto");
    build.flag_if_supported("-march=native");
    build.flag_if_supported("-mtune=native");
    build.flag_if_supported("-fomit-frame-pointer");
    build.flag_if_supported("-Ofast");
    build.flag_if_supported("-funroll-loops");
    build.flag_if_supported("-static");

    build.compile("rsa_crypto_lib");

    // Check for the BOOST_LIB_PATH environment variable
    let boost_lib_path = env::var("BOOST_LIB_PATH").unwrap_or_else(|_| {
        // Default paths if BOOST_LIB_PATH is not set
        String::from("/usr/local/lib:/usr/lib:/usr/lib/x86_64-linux-gnu")
    });

    // Add the Boost library paths to the build script
    for path in boost_lib_path.split(':') {
        println!("cargo:rustc-link-search=native={}", path);
    }

    // Linking directives for native libraries
    println!("cargo:rustc-link-lib=stdc++");
    println!("cargo:rustc-link-lib=boost_random");
    println!("cargo:rustc-link-lib=boost_system");

    // Attempt to statically link boost libraries
    println!("cargo:rustc-link-lib=static=boost_random");
    println!("cargo:rustc-link-lib=static=boost_system");

    // Rerun build.rs if any of the following files change
    println!("cargo:rerun-if-changed=src/main.rs");
    println!("cargo:rerun-if-changed=src/RSA.h");
    println!("cargo:rerun-if-changed=src/hashing.h");
    println!("cargo:rerun-if-changed=src/OAEP.h");
    println!("cargo:rerun-if-changed=src/StringAssembler.h");
    println!("cargo:rerun-if-changed=src/Utilities.h");
    println!("cargo:rerun-if-changed=src/OAEP/OAEP-methods.cpp");
    println!("cargo:rerun-if-changed=src/CJacob314-Hash/Hashing.cpp");
    println!("cargo:rerun-if-changed=src/StringAssembler/StringAssembler.cpp");
    println!("cargo:rerun-if-changed=src/RSA/RSA-operators.cpp");
    println!("cargo:rerun-if-changed=src/RSA/RSA-rust-interface.cpp");
    println!("cargo:rerun-if-changed=src/RSA/RSA-constructors.cpp");
    println!("cargo:rerun-if-changed=src/RSA/RSA-methods.cpp");
}
