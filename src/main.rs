use std::process;
use std::iter;
use std::thread;
use std::sync::atomic;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

extern crate ed25519_dalek;
use ed25519_dalek::{PublicKey, SecretKey};

extern crate blake2;
use blake2::Blake2b;

extern crate digest;
use digest::{Input, VariableOutput};

extern crate clap;
extern crate hex;
extern crate num_cpus;

extern crate rand;
use rand::{OsRng, Rng};

extern crate num_bigint;
use num_bigint::BigInt;

extern crate num_traits;
use num_traits::cast::ToPrimitive;

extern crate ocl;

mod gpu;
use gpu::Gpu;

const ACCOUNT_LOOKUP: &[u8] = b"13456789abcdefghijkmnopqrstuwxyz";

/// Only used when outputting addresses to user. Not for speed.
fn account_encode(pubkey: [u8; 32]) -> String {
    let mut reverse_chars = Vec::<u8>::new();
    let mut check_hash = Blake2b::new(5).unwrap();
    check_hash.process(&pubkey as &[u8]);
    let mut check = [0u8; 5];
    check_hash.variable_result(&mut check).unwrap();
    let mut ext_addr = pubkey.to_vec();
    ext_addr.extend(check.iter().rev());
    let mut ext_addr = BigInt::from_bytes_be(num_bigint::Sign::Plus, &ext_addr);
    for _ in 0..60 {
        let n: BigInt = (&ext_addr) % 32; // lower 5 bits
        reverse_chars.push(ACCOUNT_LOOKUP[n.to_usize().unwrap()]);
        ext_addr = ext_addr >> 5;
    }
    reverse_chars.extend(b"_brx"); // xrb_ reversed
    reverse_chars
        .iter()
        .rev()
        .map(|&c| c as char)
        .collect::<String>()
}

fn main() {
    let args = clap::App::new("nano-vanity")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Lee Bousfield <ljbousfield@gmail.com>")
        .about("Generate NANO cryptocurrency addresses with a given prefix")
        .arg(
            clap::Arg::with_name("prefix")
                .value_name("PREFIX")
                .required(true)
                .help("The prefix for the address"),
        )
        .arg(
            clap::Arg::with_name("threads")
                .short("t")
                .long("threads")
                .value_name("N")
                .help("The number of threads to use"),
        )
        .arg(
            clap::Arg::with_name("gpu")
                .short("g")
                .long("gpu")
                .help("Enable use of the GPU through OpenCL"),
        )
        .arg(
            clap::Arg::with_name("gpu_threads")
                .long("gpu-threads")
                .value_name("N")
                .default_value("1048576")
                .help("The number of GPU threads to use"),
        )
        .arg(
            clap::Arg::with_name("limit")
                .short("l")
                .long("limit")
                .value_name("N")
                .default_value("1")
                .help("Generate N addresses, then exit (0 for infinite)"),
        )
        .get_matches();
    let mut prefix = args.value_of("prefix").unwrap();
    if prefix.starts_with("xrb_") {
        prefix = &prefix[4..];
    }
    let mut public_key_req = BigInt::default();
    let mut public_key_mask = BigInt::default();
    let mut prefix_chars = prefix.chars();
    for ch in (&mut prefix_chars).chain(iter::repeat('.')).take(52) {
        let mut byte: u8 = 0;
        let mut mask: u8 = 0;
        if ch != '.' && ch != '*' {
            let lookup = ACCOUNT_LOOKUP.iter().position(|&c| (c as char) == ch);
            match lookup {
                Some(p) => {
                    byte = p as u8;
                    mask = (1 << 5) - 1;
                }
                None => {
                    eprintln!("Invalid character in prefix: {:?}", ch);
                    process::exit(1);
                }
            }
        }
        public_key_req = public_key_req << 5;
        public_key_req = public_key_req + byte;
        public_key_mask = public_key_mask << 5;
        public_key_mask = public_key_mask + mask;
    }
    if prefix_chars.next().is_some() {
        eprintln!("Warning: matching the address checksum is not yet supported.");
        eprintln!("Only the first 52 characters of your prefix (not including xrb_) will be used.");
        eprintln!("");
    }
    let mut public_key_req = public_key_req.to_bytes_be().1;
    let mut public_key_mask = public_key_mask.to_bytes_be().1;
    if public_key_req.len() > 32 {
        let len = public_key_req.len();
        public_key_req = public_key_req.split_off(len - 32);
        eprintln!("Warning: requested public key required is longer than possible.");
        eprintln!("A \"true\" address can only start with 1 or 3.");
        eprintln!(
            "The first character of your \"true\" address will be {}.",
            1 + 2 * (public_key_req[0] >> 7)
        );
        eprintln!("You can still replace that first character with the one in your prefix, and send NANO there.");
        eprintln!(
            "However, when you look at your account, you will always see your \"true\" address."
        );
        eprintln!("");
    }
    public_key_req.resize(32, 0);
    if public_key_mask.len() > 32 {
        let len = public_key_mask.len();
        public_key_mask = public_key_mask.split_off(len - 32);
    }
    public_key_mask.resize(32, 0);
    for (r, m) in public_key_req.iter_mut().zip(public_key_mask.iter_mut()) {
        *r = *r & *m;
    }
    let limit = args.value_of("limit")
        .unwrap()
        .parse()
        .expect("Failed to parse limit option");
    let found_n_base = Arc::new(AtomicUsize::new(0));
    let threads = args.value_of("threads")
        .map(|s| s.parse().expect("Failed to parse thread count option"))
        .unwrap_or_else(|| num_cpus::get() - 1);
    let mut thread_handles = Vec::with_capacity(threads);
    let mut rng = OsRng::new().expect("Failed to get RNG for seed");
    for _ in 0..threads {
        let mut private_key = [0u8; 32];
        rng.fill_bytes(&mut private_key);
        let public_key_req = public_key_req.clone();
        let public_key_mask = public_key_mask.clone();
        let found_n = found_n_base.clone();
        thread_handles.push(thread::spawn(move || loop {
            let secret_key = SecretKey::from_bytes(&private_key).unwrap();
            let public_key = PublicKey::from_secret::<Blake2b>(&secret_key);
            let public_key_bytes = public_key.to_bytes();
            let mut matches = true;
            for (byte, (req, mask)) in public_key_bytes
                .iter()
                .zip(public_key_req.iter().zip(public_key_mask.iter()))
            {
                if byte & mask != *req {
                    matches = false;
                    break;
                }
            }
            if matches {
                println!(
                    "{} {}",
                    account_encode(public_key_bytes),
                    hex::encode_upper(&private_key as &[u8])
                );
                if limit != 0 && found_n.fetch_add(1, atomic::Ordering::Relaxed) + 1 >= limit {
                    process::exit(0);
                }
            }
            for byte in private_key.iter_mut().rev() {
                *byte = byte.wrapping_add(1);
                if *byte != 0 {
                    break;
                }
            }
        }));
    }
    if args.is_present("gpu") {
        let gpu_threads = args.value_of("gpu_threads")
            .unwrap()
            .parse()
            .expect("Failed to parse GPU threads option");
        let mut key_base = [0u8; 32];
        let found_n = found_n_base.clone();
        thread::spawn(move || {
            let mut gpu = Gpu::new(gpu_threads, &public_key_req, &public_key_mask).unwrap();
            loop {
                rng.fill_bytes(&mut key_base);
                let found_private_key = gpu.compute(&key_base as &[u8])
                    .expect("Failed to run GPU computation");
                if found_private_key.iter().all(|&x| x == 0) {
                    continue;
                }
                let secret_key = SecretKey::from_bytes(&found_private_key).unwrap();
                let public_key = PublicKey::from_secret::<Blake2b>(&secret_key);
                let public_key_bytes = public_key.to_bytes();
                let mut matches = true;
                for (byte, (req, mask)) in public_key_bytes
                    .iter()
                    .zip(public_key_req.iter().zip(public_key_mask.iter()))
                {
                    if byte & mask != *req {
                        matches = false;
                        break;
                    }
                }
                if matches {
                    println!(
                        "{} {}",
                        account_encode(public_key_bytes),
                        hex::encode_upper(&found_private_key as &[u8])
                    );
                    if limit != 0 && found_n.fetch_add(1, atomic::Ordering::Relaxed) + 1 >= limit {
                        process::exit(0);
                    }
                }
            }
        }).join()
            .expect("Failed to join GPU thread");
    }
    for handle in thread_handles {
        handle.join().expect("Failed to join thread");
    }
}
