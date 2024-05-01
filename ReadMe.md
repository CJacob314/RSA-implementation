# The Rust Clap Wrapper
This branch is a polished [clap](https://docs.rs/clap/latest/clap/) CLI interface for my RSA project, built in Rust with [CXX](https://cxx.rs/) enabling interoperability with my C++ code.

# Building
1. Make sure you have `cargo` for Rust installed ([rustup](https://rustup.rs/) is the easiest way to get this done quickly).
2. Make sure you have `boost` for C++ installed (as well as a C++ compiler like GNU's `g++`)
- If you use `apt`, `sudo apt update && sudo apt install -y build-essential libboost-all-dev` should handle this
3. Clone this repository, `cd` into the directory, and run `cargo build --release`
- **Note**: If you have your `boost` libraries installed somewhere that isn't `/usr/lib/something`, you should run `BOOST_LIB_PATH='/path/to/your/boost/libraries' cargo build --release` instead.
4. If it builds successfully, your `rsa_tool` binary should be available in `repo_directory/target/release/rsa_tool`.