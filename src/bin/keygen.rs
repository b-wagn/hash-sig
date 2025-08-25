use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

use clap::Parser;
use hashsig::signature::{
    generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8,
    SignatureScheme,
};
use rand::Rng;

/// A CLI tool to generate cryptographic keys.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Number of keys to generate
    #[arg(long)]
    num_keys: usize,

    /// Log2 of the desired lifetime (e.g., 18 for a lifetime of 2^18)
    #[arg(long)]
    lifetime: usize,

    /// Directory to save the keys to
    #[arg(long)]
    output_dir: PathBuf,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    // Create the output directory if it doesn't exist
    fs::create_dir_all(&args.output_dir)?;

    println!(
        "Generating {} keys with a lifetime of 2^{} in directory: {}\n",
        args.num_keys,
        args.lifetime,
        args.output_dir.display()
    );

    let mut rng = rand::thread_rng();
    let activation_duration = 1 << args.lifetime;

    for i in 0..args.num_keys {
        println!("Generating key {}...", i);

        // Generate the key pair
        let (pk, sk) = SIGTopLevelTargetSumLifetime32Dim64Base8::key_gen(&mut rng, 0, activation_duration);

        // Serialize the public key
        let pk_json = serde_json::to_string_pretty(&pk).expect("Failed to serialize public key");
        let mut pk_file = File::create(args.output_dir.join(format!("key_{}_pk.json", i)))?;
        pk_file.write_all(pk_json.as_bytes())?;

        // Serialize the secret key
        let sk_json = serde_json::to_string_pretty(&sk).expect("Failed to serialize secret key");
        let mut sk_file = File::create(args.output_dir.join(format!("key_{}_sk.json", i)))?;
        sk_file.write_all(sk_json.as_bytes())?;
    }

    println!("\nSuccessfully generated and saved {} key pairs.", args.num_keys);

    Ok(())
}
