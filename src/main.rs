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
use num_traits::{ToPrimitive, Zero};

extern crate ocl_core;
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

fn char_byte_mask(ch: char) -> (u8, u8) {
    if ch == '.' || ch == '*' {
        (0, 0)
    } else if ch == '#' {
        (0, (1 << 5) - (1 << 3))
    } else {
        let lookup = ACCOUNT_LOOKUP.iter().position(|&c| (c as char) == ch);
        match lookup {
            Some(p) => (p as u8, (1 << 5) - 1),
            None => {
                eprintln!("Invalid character in prefix: {:?}", ch);
                process::exit(1);
            }
        }
    }
}

struct ThreadParams {
    limit: usize,
    found_n: Arc<AtomicUsize>,
    output_progress: bool,
    attempts: Arc<AtomicUsize>,
    simple_output: bool,
    matcher: Arc<Matcher>,
}

fn check_soln(params: &ThreadParams, key_or_seed: [u8; 32], is_seed: bool) -> bool {
    let private_key = if is_seed {
        let mut private_key = [0u8; 32];
        let mut hasher = Blake2b::new(32).unwrap();
        hasher.process(&key_or_seed);
        hasher.process(&[0, 0, 0, 0]);
        hasher.variable_result(&mut private_key).unwrap();
        private_key
    } else {
        key_or_seed
    };
    let secret_key = SecretKey::from_bytes(&private_key).unwrap();
    let public_key = PublicKey::from_secret::<Blake2b>(&secret_key);
    let public_key_bytes = public_key.to_bytes();
    if params.output_progress {
        params.attempts.fetch_add(1, atomic::Ordering::Relaxed);
    }
    let matches = params.matcher.matches(&public_key_bytes);
    if matches {
        if params.output_progress {
            params.attempts.store(0, atomic::Ordering::Relaxed);
            eprintln!("");
        }
        if params.simple_output {
            println!(
                "{} {}",
                hex::encode_upper(&key_or_seed as &[u8]),
                account_encode(public_key_bytes),
            );
        } else if is_seed {
            println!(
                "Found matching account!\nSeed:    {}\nAccount: {}",
                hex::encode_upper(&key_or_seed as &[u8]),
                account_encode(public_key_bytes),
            );
        } else {
            println!(
                "Found matching account!\nPrivate Key: {}\nAccount:     {}",
                hex::encode_upper(&private_key as &[u8]),
                account_encode(public_key_bytes),
            );
        }
        if params.limit != 0 && params.found_n.fetch_add(1, atomic::Ordering::Relaxed) + 1 >= params.limit {
            process::exit(0);
        }
    }
    matches
}

fn main() {
    let args = clap::App::new("nano-vanity")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Lee Bousfield <ljbousfield@gmail.com>")
        .about("Generate NANO cryptocurrency addresses with a given prefix")
        .arg(
            clap::Arg::with_name("prefix")
                .value_name("PREFIX")
                .required_unless("suffix")
                .help("The prefix for the address"),
        )
        .arg(
            clap::Arg::with_name("suffix")
                .short("s")
                .long("suffix")
                .value_name("SUFFIX")
                .help("The suffix for the address (characters are ordered normally)"),
        )
        .arg(
            clap::Arg::with_name("generate_seed")
                .long("generate-seed")
                .help("Generate a seed instead of a private key")
        )
        .arg(
            clap::Arg::with_name("threads")
                .short("t")
                .long("threads")
                .value_name("N")
                .help("The number of threads to use [default: number of cores minus one]"),
        )
        .arg(
            clap::Arg::with_name("gpu")
                .short("g")
                .long("gpu")
                .help("Enable use of the GPU through OpenCL"),
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
            clap::Arg::with_name("gpu_threads")
                .long("gpu-threads")
                .value_name("N")
                .default_value("1048576")
                .help("The number of GPU threads to use"),
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
            clap::Arg::with_name("gpu_platform")
                .long("gpu-platform")
                .value_name("INDEX")
                .default_value("0")
                .help("The GPU platform to use"),
        )
        .arg(
            clap::Arg::with_name("gpu_device")
                .long("gpu-device")
                .value_name("INDEX")
                .default_value("0")
                .help("The GPU device to use"),
        )
        .get_matches();
    let mut ext_pubkey_req = BigInt::default();
    let mut ext_pubkey_mask = BigInt::default();
    if let Some(mut prefix) = args.value_of("prefix") {
        if prefix.starts_with("xrb_") {
            prefix = &prefix[4..];
        }
        let mut prefix_chars = prefix.chars();
        let mut prefix_req = BigInt::default();
        let mut prefix_mask = BigInt::default();
        for ch in (&mut prefix_chars).chain(iter::repeat('.')).take(60) {
            let (byte, mask) = char_byte_mask(ch);
            debug_assert!(byte & !mask == 0);
            prefix_req = prefix_req << 5;
            prefix_req = prefix_req + byte;
            prefix_mask = prefix_mask << 5;
            prefix_mask = prefix_mask + mask;
        }
        ext_pubkey_req = prefix_req;
        ext_pubkey_mask = prefix_mask;
        if prefix_chars.next().is_some() {
            eprintln!("Warning: prefix too long.");
            eprintln!(
                "Only the first 60 characters of your prefix (not including xrb_) will be used."
            );
            eprintln!("");
        }
    }
    if let Some(suffix) = args.value_of("suffix") {
        let mut suffix_chars = suffix.chars();
        let mut suffix_req = BigInt::default();
        let mut suffix_mask = BigInt::default();
        for ch in (&mut suffix_chars).take(60) {
            let (byte, mask) = char_byte_mask(ch);
            debug_assert!(byte & !mask == 0);
            suffix_req = suffix_req << 5;
            suffix_req = suffix_req + byte;
            suffix_mask = suffix_mask << 5;
            suffix_mask = suffix_mask + mask;
        }
        if ext_pubkey_mask
            .to_bytes_le()
            .1
            .into_iter()
            .zip(suffix_mask.to_bytes_le().1.into_iter())
            .any(|(a, b)| a & b != 0)
        {
            eprintln!("Error: prefix and suffix restrict the same character position.");
            eprintln!("Look for duplicate character positions and resolve the conflict.");
            process::exit(1);
        }
        ext_pubkey_req = ext_pubkey_req + suffix_req;
        ext_pubkey_mask = ext_pubkey_mask + suffix_mask;
        if suffix_chars.next().is_some() {
            eprintln!("Warning: suffix too long.");
            eprintln!("Only the first 60 characters of your suffix will be used.");
            eprintln!("");
        }
    }
    if ext_pubkey_mask.is_zero() {
        eprintln!("You must specify a non-empty prefix or suffix");
        process::exit(1);
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
    let generate_seed = args.is_present("generate_seed");
    let threads = args.value_of("threads")
        .map(|s| s.parse().expect("Failed to parse thread count option"))
        .unwrap_or_else(|| num_cpus::get() - 1);
    let mut thread_handles = Vec::with_capacity(threads);
    eprintln!("Estimated attempts needed: {}", estimated_attempts);
    for _ in 0..threads {
        let mut rng = OsRng::new().expect("Failed to get RNG for seed");
        let mut key_or_seed = [0u8; 32];
        rng.fill_bytes(&mut key_or_seed);
        let params = ThreadParams {
            limit,
            output_progress,
            simple_output,
            matcher: matcher_base.clone(),
            found_n: found_n_base.clone(),
            attempts: attempts_base.clone(),
        };
        thread_handles.push(thread::spawn(move || {
            loop {
                if check_soln(&params, key_or_seed, generate_seed) {
                    rng.fill_bytes(&mut key_or_seed);
                } else {
                    if output_progress {
                        params.attempts.fetch_add(1, atomic::Ordering::Relaxed);
                    }
                    for byte in key_or_seed.iter_mut().rev() {
                        *byte = byte.wrapping_add(1);
                        if *byte != 0 {
                            break;
                        }
                    }
                }
            }
        }));
    }
    let mut gpu_thread = None;
    if args.is_present("gpu") {
        let gpu_platform = args.value_of("gpu_platform")
            .unwrap()
            .parse()
            .expect("Failed to parse GPU platform index");
        let gpu_device = args.value_of("gpu_device")
            .unwrap()
            .parse()
            .expect("Failed to parse GPU device index");
        let gpu_threads = args.value_of("gpu_threads")
            .unwrap()
            .parse()
            .expect("Failed to parse GPU threads option");
        let mut key_base = [0u8; 32];
        let params = ThreadParams {
            limit,
            output_progress,
            simple_output,
            matcher: matcher_base.clone(),
            found_n: found_n_base.clone(),
            attempts: attempts_base.clone(),
        };
        let mut gpu = Gpu::new(gpu_platform, gpu_device, gpu_threads, &params.matcher, generate_seed).unwrap();
        gpu_thread = Some(thread::spawn(move || {
            let mut rng = OsRng::new().expect("Failed to get RNG for seed");
            let mut found_private_key = [0u8; 32];
            loop {
                rng.fill_bytes(&mut key_base);
                let found = gpu.compute(&mut found_private_key as _, &key_base as _)
                    .expect("Failed to run GPU computation");
                if output_progress {
                    params.attempts.fetch_add(gpu_threads, atomic::Ordering::Relaxed);
                }
                if !found {
                    continue;
                }
                if !check_soln(&params, found_private_key, generate_seed) {
                    eprintln!("GPU returned non-matching solution: {}", hex::encode_upper(&found_private_key));
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
