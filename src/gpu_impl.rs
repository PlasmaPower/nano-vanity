use byteorder::ByteOrder;
use byteorder::NativeEndian;
use ocl;
use ocl::builders::DeviceSpecifier;
use ocl::builders::ProgramBuilder;
use ocl::flags::MemFlags;
use ocl::Buffer;
use ocl::Platform;
use ocl::ProQue;
use ocl::Result;

use derivation::GenerateKeyType;
use gpu::GpuOptions;

pub struct Gpu {
    kernel: ocl::Kernel,
    result: Buffer<u64>,
    key_root: Buffer<u8>,
}

impl Gpu {
    pub fn new(opts: GpuOptions) -> Result<Gpu> {
        let mut prog_bldr = ProgramBuilder::new();
        prog_bldr
            .src(include_str!("opencl/blake2b.cl"))
            .src(include_str!("opencl/curve25519-constants.cl"))
            .src(include_str!("opencl/curve25519-constants2.cl"))
            .src(include_str!("opencl/curve25519.cl"))
            .src(include_str!("opencl/entry.cl"));
        let platforms = Platform::list();
        if platforms.len() == 0 {
            return Err("No OpenCL platforms exist (check your drivers and OpenCL setup)".into());
        }
        if opts.platform_idx >= platforms.len() {
            return Err(format!(
                "Platform index {} too large (max {})",
                opts.platform_idx,
                platforms.len() - 1
            )
            .into());
        }
        let mut pro_que = ProQue::builder()
            .prog_bldr(prog_bldr)
            .platform(platforms[opts.platform_idx])
            .device(DeviceSpecifier::Indices(vec![opts.device_idx]))
            .dims(1)
            .build()?;

        let device = pro_que.device();
        eprintln!("Initializing GPU {} {}", device.vendor()?, device.name()?);

        let result = pro_que
            .buffer_builder::<u64>()
            .flags(MemFlags::new().write_only())
            .build()?;
        pro_que.set_dims(64);
        let key_root = pro_que
            .buffer_builder::<u8>()
            .flags(MemFlags::new().read_only().host_write_only())
            .build()?;
        pro_que.set_dims(opts.matcher.prefix_len());
        let req = pro_que
            .buffer_builder::<u8>()
            .flags(MemFlags::new().read_only().host_write_only())
            .build()?;
        let mask = pro_que
            .buffer_builder::<u8>()
            .flags(MemFlags::new().read_only().host_write_only())
            .build()?;
        pro_que.set_dims(32);
        let public_offset = pro_que
            .buffer_builder::<u8>()
            .flags(MemFlags::new().read_only().host_write_only())
            .build()?;
        pro_que.set_dims(1);

        req.write(opts.matcher.req()).enq()?;
        mask.write(opts.matcher.mask()).enq()?;
        result.write(&[!0u64] as &[u64]).enq()?;
        let gen_key_type_code: u8 = match opts.generate_key_type {
            GenerateKeyType::PrivateKey => 0,
            GenerateKeyType::Seed => 1,
            GenerateKeyType::ExtendedPrivateKey(offset) => {
                let compressed = offset.compress();
                public_offset.write(compressed.as_bytes() as &[u8]).enq()?;
                2
            }
        };

        let kernel = {
            let mut kernel_builder = pro_que.kernel_builder("generate_pubkey");
            kernel_builder
                .global_work_size(opts.threads)
                .arg(&result)
                .arg(&key_root)
                .arg(&req)
                .arg(&mask)
                .arg(opts.matcher.prefix_len() as u8)
                .arg(gen_key_type_code)
                .arg(&public_offset);
            if let Some(local_work_size) = opts.local_work_size {
                kernel_builder.local_work_size(local_work_size);
            }
            kernel_builder.build()?
        };

        Ok(Gpu {
            kernel,
            result,
            key_root,
        })
    }

    pub fn compute(&mut self, out: &mut [u8], key_root: &[u8]) -> Result<bool> {
        self.key_root.write(key_root).enq()?;
        debug_assert!(out.iter().all(|&b| b == 0));
        debug_assert!({
            let mut result = [0u64];
            self.result.read(&mut result as &mut [u64]).enq()?;
            result == [!0u64]
        });

        unsafe {
            self.kernel.enq()?;
        }

        let mut buf = [0u64];
        self.result.read(&mut buf as &mut [u64]).enq()?;
        let thread = buf[0];
        let success = thread != !0u64;
        if success {
            self.result.write(&[!0u64] as &[u64]).enq()?;
            let base = NativeEndian::read_u64(key_root);
            NativeEndian::write_u64(out, base.wrapping_add(thread));
            out[8..].copy_from_slice(&key_root[8..]);
        }
        Ok(success)
    }
}
