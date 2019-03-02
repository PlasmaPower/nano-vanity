use std::f64;
use std::iter;
use std::process;
use std::sync::atomic;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

extern crate curve25519_dalek;
use curve25519_dalek::edwards::CompressedEdwardsY;

extern crate blake2;
extern crate clap;
extern crate digest;
extern crate ed25519_dalek;
extern crate hex;
extern crate num_cpus;

extern crate rand;
use rand::{OsRng, Rng};

extern crate num_bigint;
use num_bigint::BigInt;

extern crate num_traits;
use num_traits::{ToPrimitive, Zero};

#[cfg(feature = "gpu")]
extern crate ocl;

mod derivation;
use derivation::{pubkey_to_address, secret_to_pubkey, GenerateKeyType, ADDRESS_ALPHABET};

mod pubkey_matcher;
use pubkey_matcher::PubkeyMatcher;

#[cfg(feature = "gpu")]
mod gpu_impl;

mod gpu;
use gpu::{Gpu, GpuOptions};

fn char_byte_mask(ch: char) -> (u8, u8) {
    if ch == '.' || ch == '*' {
        (0, 0)
    } else if ch == '#' {
        (0, (1 << 5) - (1 << 3))
    } else {
        let lookup = ADDRESS_ALPHABET.iter().position(|&c| (c as char) == ch);
        match lookup {
            Some(p) => (p as u8, (1 << 5) - 1),
            None => {
                eprintln!("Invalid character in prefix: {:?}", ch);
                process::exit(1);
            }
        }
    }
}

fn print_solution(
    secret_key_material: [u8; 32],
    secret_key_type: GenerateKeyType,
    public_key: [u8; 32],
    simple_output: bool,
) {
    if simple_output {
        println!(
            "{} {}",
            hex::encode_upper(&secret_key_material as &[u8]),
            pubkey_to_address(public_key),
        );
    } else {
        match secret_key_type {
            GenerateKeyType::PrivateKey => println!(
                "Found matching account!\nPrivate Key: {}\nAddress:     {}",
                hex::encode_upper(&secret_key_material as &[u8]),
                pubkey_to_address(public_key),
            ),
            GenerateKeyType::Seed => println!(
                "Found matching account!\nSeed:    {}\nAddress: {}",
                hex::encode_upper(&secret_key_material as &[u8]),
                pubkey_to_address(public_key),
            ),
            GenerateKeyType::ExtendedPrivateKey(_) => println!(
                "Found matching account!\nExtended private key: {}\nAddress:              {}",
                hex::encode_upper(&secret_key_material as &[u8]),
                pubkey_to_address(public_key),
            ),
        }
    }
}

struct ThreadParams {
    limit: usize,
    found_n: Arc<AtomicUsize>,
    output_progress: bool,
    attempts: Arc<AtomicUsize>,
    simple_output: bool,
    generate_key_type: GenerateKeyType,
    matcher: Arc<PubkeyMatcher>,
}

fn check_solution(params: &ThreadParams, key_material: [u8; 32]) -> bool {
    let public_key = secret_to_pubkey(key_material, params.generate_key_type);
    let matches = params.matcher.matches(&public_key);
    if matches {
        if params.output_progress {
            eprintln!("");
        }
        print_solution(
            key_material,
            params.generate_key_type,
            public_key,
            params.simple_output,
        );
        if params.limit != 0
            && params.found_n.fetch_add(1, atomic::Ordering::Relaxed) + 1 >= params.limit
        {
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
        ).arg(
            clap::Arg::with_name("suffix")
                .short("s")
                .long("suffix")
                .value_name("SUFFIX")
                .help("The suffix for the address (characters are ordered normally)"),
        ).arg(
            clap::Arg::with_name("generate_seed")
                .long("generate-seed")
                .help("Generate a seed instead of a private key"),
        ).arg(
            clap::Arg::with_name("threads")
                .short("t")
                .long("threads")
                .value_name("N")
                .help("The number of threads to use [default: number of cores minus one]"),
        ).arg(
            clap::Arg::with_name("gpu")
                .short("g")
                .long("gpu")
                .help("Enable use of the GPU through OpenCL"),
        ).arg(
            clap::Arg::with_name("limit")
                .short("l")
                .long("limit")
                .value_name("N")
                .default_value("1")
                .help("Generate N addresses, then exit (0 for infinite)"),
        ).arg(
            clap::Arg::with_name("gpu_threads")
                .long("gpu-threads")
                .value_name("N")
                .default_value("1048576")
                .help("The number of GPU threads to use"),
        ).arg(
            clap::Arg::with_name("gpu_local_work_size")
                .long("gpu-local-work-size")
                .value_name("N")
                .help("The GPU local work size. Increasing it may increase performance. For advanced users only."),
        ).arg(
            clap::Arg::with_name("no_progress")
                .long("no-progress")
                .help("Disable progress output"),
        ).arg(
            clap::Arg::with_name("simple_output")
                .long("simple-output")
                .help("Output found keys in the form \"[key] [address]\""),
        ).arg(
            clap::Arg::with_name("gpu_platform")
                .long("gpu-platform")
                .value_name("INDEX")
                .default_value("0")
                .help("The GPU platform to use"),
        ).arg(
            clap::Arg::with_name("gpu_device")
                .long("gpu-device")
                .value_name("INDEX")
                .default_value("0")
                .help("The GPU device to use"),
        ).arg(
            clap::Arg::with_name("public_offset")
                .long("public-offset")
                .conflicts_with("generate_seed")
                .value_name("HEX")
                .help(
                    "The curve point of the blinding factor (used to mine keys for somebody else)",
                ),
        ).get_matches();
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
        eprintln!("Error: requested public key required is longer than possible.");
        eprintln!("An address can only start with 1 or 3.");
        eprintln!(
            "To generate the prefix after that, add a period to the beginning of your prefix."
        );
        process::exit(1);
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
    let matcher_base = PubkeyMatcher::new(ext_pubkey_req, ext_pubkey_mask);
    let estimated_attempts = matcher_base.estimated_attempts();
    let matcher_base = Arc::new(matcher_base);
    let limit = args
        .value_of("limit")
        .unwrap()
        .parse()
        .expect("Failed to parse limit option");
    let found_n_base = Arc::new(AtomicUsize::new(0));
    let attempts_base = Arc::new(AtomicUsize::new(0));
    let output_progress = !args.is_present("no_progress");
    let simple_output = args.is_present("simple_output");
    let generate_seed = args.is_present("generate_seed");
    let public_offset_bytes = args.value_of("public_offset").map(hex::decode).map(|r| {
        let bytes = r.expect("Failed to parse public offset as hex");
        if bytes.len() != 32 {
            panic!(
                "Public offset length was {} bytes, not 32 bytes as expected",
                bytes.len(),
            );
        }
        let mut slice = [0u8; 32];
        slice.copy_from_slice(&bytes);
        slice
    });
    let public_offset = public_offset_bytes.map(|b| {
        CompressedEdwardsY(b)
            .decompress()
            .expect("Public offset was not valid edwards curve point")
    });
    let gen_key_ty = if let Some(offset) = public_offset {
        GenerateKeyType::ExtendedPrivateKey(offset)
    } else if generate_seed {
        GenerateKeyType::Seed
    } else {
        GenerateKeyType::PrivateKey
    };
    let threads = args
        .value_of("threads")
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
            generate_key_type: gen_key_ty.clone(),
            matcher: matcher_base.clone(),
            found_n: found_n_base.clone(),
            attempts: attempts_base.clone(),
        };
        thread_handles.push(thread::spawn(move || loop {
            if check_solution(&params, key_or_seed) {
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
        }));
    }
    let mut gpu_thread = None;
    if args.is_present("gpu") {
        let gpu_platform = args
            .value_of("gpu_platform")
            .unwrap()
            .parse()
            .expect("Failed to parse GPU platform index");
        let gpu_device = args
            .value_of("gpu_device")
            .unwrap()
            .parse()
            .expect("Failed to parse GPU device index");
        let gpu_threads = args
            .value_of("gpu_threads")
            .unwrap()
            .parse()
            .expect("Failed to parse GPU threads option");
        let gpu_local_work_size = args.value_of("gpu_local_work_size").map(|s| {
            s.parse()
                .expect("Failed to parse GPU local work size option")
        });
        let mut key_base = [0u8; 32];
        let params = ThreadParams {
            limit,
            output_progress,
            simple_output,
            generate_key_type: gen_key_ty.clone(),
            matcher: matcher_base.clone(),
            found_n: found_n_base.clone(),
            attempts: attempts_base.clone(),
        };
        let mut gpu = Gpu::new(GpuOptions {
            platform_idx: gpu_platform,
            device_idx: gpu_device,
            threads: gpu_threads,
            local_work_size: gpu_local_work_size,
            matcher: &params.matcher,
            generate_key_type: gen_key_ty,
        })
        .unwrap();
        gpu_thread = Some(thread::spawn(move || {
            let mut rng = OsRng::new().expect("Failed to get RNG for seed");
            let mut found_private_key = [0u8; 32];
            loop {
                rng.fill_bytes(&mut key_base);
                let found = gpu
                    .compute(&mut found_private_key as _, &key_base as _)
                    .expect("Failed to run GPU computation");
                if output_progress {
                    params
                        .attempts
                        .fetch_add(gpu_threads, atomic::Ordering::Relaxed);
                }
                if !found {
                    continue;
                }
                if !check_solution(&params, found_private_key) {
                    eprintln!(
                        "GPU returned non-matching solution: {}",
                        hex::encode_upper(&found_private_key)
                    );
                }
                for byte in &mut found_private_key {
                    *byte = 0;
                }
            }
        }));
    }
    if output_progress {
        let start_time = Instant::now();
        let attempts = attempts_base;
        thread::spawn(move || loop {
            let attempts = attempts.load(atomic::Ordering::Relaxed);
            let estimated_percent =
                100. * (attempts as f64) / estimated_attempts.to_f64().unwrap_or(f64::INFINITY);
            let runtime = start_time.elapsed();
            let keys_per_second = (attempts as f64)
                // simplify to .as_millis() when available
                / (runtime.as_secs() as f64 + runtime.subsec_millis() as f64 / 1000.0);
            eprint!(
                "\rTried {} keys (~{:.2}%; {:.1} keys/s)",
                attempts, estimated_percent, keys_per_second,
            );
            thread::sleep(Duration::from_millis(250));
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
