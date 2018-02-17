use std::process;
use std::iter;
use std::thread;
use std::sync::atomic;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;

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
use num_traits::ToPrimitive;

extern crate ocl;

mod matcher;
use matcher::Matcher;

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
        .arg(
            clap::Arg::with_name("no_progress")
                .long("no-progress")
                .help("Disable progress output"),
        )
        .arg(
            clap::Arg::with_name("simple_output")
                .long("simple-output")
                .help("Output found keys in the form \"[key] [address]\""),
        )
        .arg(
            clap::Arg::with_name("gpu_device")
                .long("gpu-device")
                .value_name("DEVICE")
                .multiple(true)
                .default_value("0")
                .help("The GPU device index to use"),
        )
        .get_matches();
    let mut prefix = args.value_of("prefix").unwrap();
    if prefix.starts_with("xrb_") {
        prefix = &prefix[4..];
    }
    let mut ext_pubkey_req = BigInt::default();
    let mut ext_pubkey_mask = BigInt::default();
    let mut prefix_chars = prefix.chars();
    for ch in (&mut prefix_chars).chain(iter::repeat('.')).take(60) {
        let mut byte: u8;
        let mut mask: u8;
        if ch == '.' || ch == '*' {
            byte = 0;
            mask = 0;
        } else if ch == '#' {
            byte = 0;
            mask = (1 << 5) - (1 << 3);
        } else {
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
        ext_pubkey_req = ext_pubkey_req << 5;
        ext_pubkey_req = ext_pubkey_req + byte;
        ext_pubkey_mask = ext_pubkey_mask << 5;
        ext_pubkey_mask = ext_pubkey_mask + mask;
    }
    if prefix_chars.next().is_some() {
        eprintln!("Warning: prefix too long.");
        eprintln!("Only the first 60 characters of your prefix (not including xrb_) will be used.");
        eprintln!("");
    }
    let mut ext_pubkey_req = ext_pubkey_req.to_bytes_be().1;
    let mut ext_pubkey_mask = ext_pubkey_mask.to_bytes_be().1;
    if ext_pubkey_req.len() > 37 {
        let len = ext_pubkey_req.len();
        ext_pubkey_req = ext_pubkey_req.split_off(len - 37);
        eprintln!("Warning: requested public key required is longer than possible.");
        eprintln!("A \"true\" address can only start with 1 or 3.");
        eprintln!(
            "The first character of your \"true\" address will be {}.",
            1 + 2 * (ext_pubkey_req[0] >> 7)
        );
        eprintln!(
            "You can still replace that first character with the one in your prefix, \
             and send NANO there."
        );
        eprintln!(
            "However, when you look at your account, you will always see your \"true\" address."
        );
        eprintln!("");
    } else if ext_pubkey_req.len() < 37 {
        ext_pubkey_req = iter::repeat(0)
            .take(37 - ext_pubkey_req.len())
            .chain(ext_pubkey_req.into_iter())
            .collect();
    }
    if ext_pubkey_mask.len() > 37 {
        let len = ext_pubkey_mask.len();
        ext_pubkey_mask = ext_pubkey_mask.split_off(len - 37);
    } else if ext_pubkey_mask.len() < 37 {
        ext_pubkey_mask = iter::repeat(0)
            .take(37 - ext_pubkey_mask.len())
            .chain(ext_pubkey_mask.into_iter())
            .collect();
    }
    let matcher_base = Matcher::new(ext_pubkey_req, ext_pubkey_mask);
    let estimated_attempts = matcher_base.estimated_attempts();
    let matcher_base = Arc::new(matcher_base);
    let limit = args.value_of("limit")
        .unwrap()
        .parse()
        .expect("Failed to parse limit option");
    let found_n_base = Arc::new(AtomicUsize::new(0));
    let attempts_base = Arc::new(AtomicUsize::new(0));
    let output_progress = !args.is_present("no_progress");
    let simple_output = args.is_present("simple_output");
    let threads = args.value_of("threads")
        .map(|s| s.parse().expect("Failed to parse thread count option"))
        .unwrap_or_else(|| num_cpus::get() - 1);
    let mut thread_handles = Vec::with_capacity(threads);
    eprintln!("Estimated attempts needed: {}", estimated_attempts);
    let mut rng = OsRng::new().expect("Failed to get RNG for seed");
    for _ in 0..threads {
        let mut private_key = [0u8; 32];
        rng.fill_bytes(&mut private_key);
        let matcher = matcher_base.clone();
        let found_n = found_n_base.clone();
        let attempts = attempts_base.clone();
        thread_handles.push(thread::spawn(move || {
            loop {
                let secret_key = SecretKey::from_bytes(&private_key).unwrap();
                let public_key = PublicKey::from_secret::<Blake2b>(&secret_key);
                let public_key_bytes = public_key.to_bytes();
                if output_progress {
                    attempts.fetch_add(1, atomic::Ordering::Relaxed);
                }
                if matcher.matches(&public_key_bytes) {
                    if output_progress {
                        attempts.store(0, atomic::Ordering::Relaxed);
                        eprintln!("");
                    }
                    if simple_output {
                        println!(
                            "{} {}",
                            hex::encode_upper(&private_key as &[u8]),
                            account_encode(public_key_bytes),
                        );
                    } else {
                        println!(
                            "Found matching account!\nKey:     {}\nAccount: {}",
                            hex::encode_upper(&private_key as &[u8]),
                            account_encode(public_key_bytes),
                        );
                    }
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
            }
        }));
    }
    let mut gpu_thread = None;
    if args.is_present("gpu") {
        let gpu_device = args.value_of("gpu_device")
            .unwrap()
            .parse()
            .expect("Failed to parse GPU device index");
        let gpu_threads = args.value_of("gpu_threads")
            .unwrap()
            .parse()
            .expect("Failed to parse GPU threads option");
        let mut key_base = [0u8; 32];
        let matcher = matcher_base.clone();
        let found_n = found_n_base.clone();
        let attempts = attempts_base.clone();
        eprintln!("Initializing GPU");
        let mut gpu = Gpu::new(gpu_device, gpu_threads, &matcher).unwrap();
        gpu_thread = Some(thread::spawn(move || {
            let mut found_private_key = [0u8; 32];
            loop {
                rng.fill_bytes(&mut key_base);
                let found = gpu.compute(&mut found_private_key as _, &key_base as _)
                    .expect("Failed to run GPU computation");
                if output_progress {
                    attempts.fetch_add(gpu_threads, atomic::Ordering::Relaxed);
                }
                if !found {
                    continue;
                }
                let secret_key = SecretKey::from_bytes(&found_private_key).unwrap();
                let public_key = PublicKey::from_secret::<Blake2b>(&secret_key);
                let public_key_bytes = public_key.to_bytes();
                if matcher.matches(&public_key_bytes) {
                    if output_progress {
                        attempts.store(0, atomic::Ordering::Relaxed);
                        eprintln!("");
                    }
                    if simple_output {
                        println!(
                            "{} {}",
                            hex::encode_upper(&found_private_key as &[u8]),
                            account_encode(public_key_bytes),
                        );
                    } else {
                        println!(
                            "Found matching account!\nKey:     {}\nAccount: {}",
                            hex::encode_upper(&found_private_key as &[u8]),
                            account_encode(public_key_bytes),
                        );
                    }
                    if limit != 0 && found_n.fetch_add(1, atomic::Ordering::Relaxed) + 1 >= limit {
                        process::exit(0);
                    }
                } else {
                    eprintln!("GPU returned non-matching account");
                }
                for byte in &mut found_private_key {
                    *byte = 0;
                }
            }
        }));
    }
    if output_progress {
        let attempts = attempts_base;
        thread::spawn(move || {
            loop {
                let attempts = attempts.load(atomic::Ordering::Relaxed);
                let estimated_percent = 100. * (attempts as f32) / (estimated_attempts as f32);
                eprint!("\rTried {} keys (~{:.2}%)", attempts, estimated_percent);
                thread::sleep(Duration::from_millis(250));
            }
        });
    }
    if let Some(gpu_thread) = gpu_thread {
        gpu_thread.join().expect("Failed to join GPU thread");
    }
    for handle in thread_handles {
        handle.join().expect("Failed to join thread");
    }
    eprintln!("No computation devices specified");
    process::exit(1);
}
