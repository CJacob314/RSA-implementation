use clap::{
    builder::styling::{AnsiColor, Styles},
    Args, ColorChoice, CommandFactory, Parser, Subcommand,
};
use clap_complete::{generate, shells::Bash, shells::Fish, shells::Zsh, Shell};
use cxx::UniquePtr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::pin::Pin;

#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("rsa_tool/src/RSA.h");
        type RSA;
        fn new_rsa(bits: u16) -> UniquePtr<RSA>;
        fn encrypt_wrapper(
            self: &RSA,
            message: &str,
            compressedAsciiOutput: bool,
        ) -> UniquePtr<CxxString>;
        fn decrypt_wrapper(
            self: &RSA,
            message: &str,
            compressedAsciiInput: bool,
        ) -> UniquePtr<CxxString>;
        fn sign_wrapper(self: &RSA, message: &str) -> UniquePtr<CxxString>;
        fn verify_wrapper(self: &RSA, signedMessage: &str) -> bool;
        fn getFingerprint_wrapper(self: &RSA) -> UniquePtr<CxxString>;
        fn exportToFile_wrapper(
            self: &RSA,
            filepath: &str,
            exportPrivateKey: bool,
            forWebVersion: bool,
        ) -> bool;
        fn importFromFile_wrapper(
            self: Pin<&mut RSA>,
            filepath: &str,
            importPrivateKey: bool,
        ) -> bool;
        // fn importFromString_wrapper(self: &mut RSA, s: &str, importPrivateKey: bool) -> bool;
        fn getPublicKeyLength(self: &RSA) -> u64;
        fn buildFromKeyFile(
            filepath_str: &str,
            importPrivateKey: bool,
            fromWebVersion: bool,
        ) -> UniquePtr<RSA>;
    }
}

#[derive(Debug, Parser)]
#[command(name = "RSA Tool", about = "RSA Implementation CLI Tool", styles=Styles::styled()
    .header(AnsiColor::Yellow.on_default())
    .usage(AnsiColor::Green.on_default())
    .literal(AnsiColor::Green.on_default())
    .placeholder(AnsiColor::Green.on_default()))]
struct Opt {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generates a new RSA keypair.
    Generate(GenerateArgs),
    /// Encrypts a file or stdin.
    Encrypt(EncryptArgs),
    /// Decrypts a file or stdin.
    Decrypt(DecryptArgs),
    /// Signs a file or stdin.
    Sign(SignArgs),
    /// Verifies a signature of a file or stdin.
    Verify(VerifyArgs),
    /// Generate shell autocompletions
    Completions {
        /// The shell for which to generate the completion script.
        shell: String,
    },
}

#[derive(Debug, Args)]
struct GenerateArgs {
    /// The number of bits for the key.
    bits: u16,

    /// Path where the key will be saved.
    key_path: String,

    /// Flag to indicate if the keypair should be suitable for web usage (on rsa.jacobcohen.dev).
    #[arg(short = 'w', long = "for-web")]
    for_web: bool,

    /// Flag to only generate and save the public key (there are not many uses for this).
    #[arg(long = "public-only")]
    public_only: bool,
}

#[derive(Debug, Args)]
struct EncryptArgs {
    /// Path to the public key (or keypair) file used for encryption.
    key: String,

    /// Path to the plaintext file to encrypt or "-" to read from stdin.
    input: String,

    /// Whether or not to import the key from a web (rsa.jacobcohen.dev) file.
    #[arg(short = 'w', long)]
    from_web: bool,

    /// Disable base64-like encoding of encrypted output (not recommended).
    #[arg(long)]
    uncompressed_output: bool,
}

#[derive(Debug, Args)]
struct DecryptArgs {
    /// Path to the private key file used for decryption.
    #[arg(short, long)]
    key: String,

    /// Path to the encrypted file to decrypt or "-" to read from stdin.
    #[arg(short, long)]
    input: String,

    /// Path to save the decrypted file.
    #[arg(short, long)]
    output: Option<String>,

    /// Whether or not to import the key from a web (rsa.jacobcohen.dev) file.
    #[arg(short = 'w', long)]
    from_web: bool,

    /// Disable base64-like decoding of encrypted input (not recommended).
    #[arg(long)]
    uncompressed_input: bool,

    /// Overwrite existing files.
    #[arg(short = 'f', long = "force")]
    force: bool,
}

#[derive(Debug, Args)]
struct SignArgs {
    /// Path to the file to sign or "-" to read from stdin.
    #[arg()]
    input: String,

    /// Path to the private key file used for signing.
    #[arg()]
    key: String,

    /// Whether or not to import the key from a web (rsa.jacobcohen.dev) file.
    #[arg(short = 'w', long)]
    from_web: bool,

    /// Path to the signature output file (stdout is used if not specified).
    #[arg(short, long)]
    output: Option<String>,

    #[arg(short = 'f', long = "force")]
    force: bool,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    /// Path to the file to verify or "-" to read from stdin.
    #[arg()]
    input: String,

    /// Path to the public key file used for verification.
    #[arg()]
    key: String,

    /// Whether or not to import the key from a web (rsa.jacobcohen.dev) file.
    #[arg(short = 'w', long)]
    from_web: bool,
}

fn main() {
    let mut opt = Opt::command();
    opt.color(ColorChoice::Auto);
    let opt = Opt::parse();

    match opt.command {
        Command::Generate(GenerateArgs {
            bits,
            key_path,
            for_web,
            public_only,
        }) => {
            let rsa = ffi::new_rsa(bits);
            let rsa = unsafe { Pin::new_unchecked(rsa) };

            rsa.exportToFile_wrapper(key_path.as_str(), !public_only, for_web);
        }
        Command::Encrypt(EncryptArgs {
            input,
            key,
            from_web,
            uncompressed_output,
        }) => {
            let rsa = import_key_from_file(&key, false, from_web);
            let data = read_data(&input);
            let encrypted = rsa.encrypt_wrapper(data.as_str(), !uncompressed_output);
            println!("{}", encrypted);
        }
        Command::Decrypt(DecryptArgs {
            input,
            output,
            key,
            from_web,
            uncompressed_input,
            force,
        }) => {
            let rsa = import_key_from_file(&key, true, from_web);
            let data = read_data(&input);
            let decrypted = rsa.decrypt_wrapper(data.as_str(), !uncompressed_input);
            match output {
                None => {
                    println!("{}", decrypted);
                }
                Some(fname) => {
                    if !force && File::open(&fname).is_ok() {
                        eprintln!("File {} already exists, use -f to force overwrite", fname);
                        std::process::exit(EXIT_FAILURE);
                    }

                    write_data(&fname, decrypted.to_str().unwrap());
                }
            }
        }
        Command::Sign(SignArgs {
            input,
            output,
            key,
            force,
            from_web,
        }) => {
            let rsa = import_key_from_file(&key, true, from_web);
            let data = read_data(&input);
            let signature = rsa.sign_wrapper(data.as_str());
            if signature.is_null() {
                eprintln!("Failed to sign data");
                std::process::exit(EXIT_FAILURE);
            }
            match output {
                None => {
                    println!("{}", signature);
                }
                Some(fname) => {
                    if !force && File::open(&fname).is_ok() {
                        eprintln!("File {} already exists, use -f to force overwrite", fname);
                        std::process::exit(EXIT_FAILURE);
                    }

                    write_data(&fname, signature.to_str().unwrap());
                }
            }
        }
        Command::Verify(VerifyArgs {
            input,
            key,
            from_web,
        }) => {
            let rsa = import_key_from_file(&key, false, from_web);
            let data = read_data(&input);
            let is_valid = rsa.verify_wrapper(data.as_str());
            if is_valid {
                println!("\033[1;32mMessage verified successfully\033[0m");
            } else {
                println!("\033[1;31mMessage unable to be verified with given public key!\033[0m");
            }
        }
        Command::Completions { shell } => {
            let shell = shell.as_str();
            let mut app = Opt::command();
            let filename = format!("rsa_tool.{}", shell);
            let mut file = File::create(&filename).expect("Failed to create file");
            match shell {
                "bash" => {
                    generate(Bash, &mut app, "rsa_tool", &mut file);
                }
                "zsh" => {
                    generate(Zsh, &mut app, "rsa_tool", &mut file);
                }
                "fish" => {
                    generate(Fish, &mut app, "rsa_tool", &mut file);
                }
                _ => eprintln!("Unsupported shell: {}", shell),
            }
            println!("The autocompletion script has been saved to {}. Just source the file when you want autocompletions.", filename);
        }
    }
}

fn read_data(path: &str) -> String {
    if path == "-" {
        let mut buffer = String::new();
        io::stdin()
            .read_to_string(&mut buffer)
            .expect("Failed to read from stdin");
        buffer
    } else {
        std::fs::read_to_string(path).expect("Failed to read file")
    }
}

fn write_data(path: &str, data: &str) {
    if path == "-" {
        io::stdout()
            .write_all(data.as_bytes())
            .expect("Failed to write to stdout");
    } else {
        std::fs::write(path, data).expect("Failed to write to file");
    }
}

fn import_key_from_file(filepath: &str, private: bool, from_web_key: bool) -> UniquePtr<ffi::RSA> {
    let rsa_uptr = ffi::buildFromKeyFile(filepath, private, from_web_key);
    if rsa_uptr.is_null() {
        eprintln!("Failed to import key from file {}", filepath);
        std::process::exit(EXIT_FAILURE);
    }

    rsa_uptr
}

const EXIT_FAILURE: i32 = 1;
