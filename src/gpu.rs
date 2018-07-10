use ocl;
use ocl::ProQue;
use ocl::Result;
use ocl::Buffer;
use ocl::Platform;
use ocl::flags::MemFlags;
use ocl::builders::ProgramBuilder;
use ocl::builders::DeviceSpecifier;

use matcher::Matcher;

pub struct Gpu {
    kernel: ocl::Kernel,
    result: Buffer<u8>,
    key_root: Buffer<u8>,
}

impl Gpu {
    pub fn new(platform_idx: usize, device_idx: usize, threads: usize, matcher: &Matcher, generate_seed: bool) -> Result<Gpu> {
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
        if platform_idx >= platforms.len() {
            return Err(format!("Platform index {} too large (max {})", platform_idx, platforms.len() - 1).into());
        }
        let mut pro_que = ProQue::builder()
            .prog_bldr(prog_bldr)
            .platform(platforms[platform_idx])
            .device(DeviceSpecifier::Indices(vec![device_idx]))
            .dims(64)
            .build()?;

        let device = pro_que.device();
        eprintln!("Initializing GPU {} {}", device.vendor()?, device.name()?);

        let result = pro_que
            .buffer_builder::<u8>()
            .flags(MemFlags::new().write_only())
            .build()?;
        let key_root = pro_que
            .buffer_builder::<u8>()
            .flags(MemFlags::new().read_only().host_write_only())
            .build()?;
        pro_que.set_dims(matcher.prefix_len());
        let req = pro_que
            .buffer_builder::<u8>()
            .flags(MemFlags::new().read_only().host_write_only())
            .build()?;
        let mask = pro_que
            .buffer_builder::<u8>()
            .flags(MemFlags::new().read_only().host_write_only())
            .build()?;
        pro_que.set_dims(1);

        req.write(matcher.req()).enq()?;
        mask.write(matcher.mask()).enq()?;
        result.write(&[0u8; 32] as &[u8]).enq()?;

        let kernel = pro_que
            .kernel_builder("generate_pubkey")
            .global_work_size(threads)
            .arg(&result)
            .arg(&key_root)
            .arg(&req)
            .arg(&mask)
            .arg(matcher.prefix_len() as u8)
            .arg(generate_seed as u8)
            .build()?;

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
            let mut result = [0u8; 32];
            self.result.read(&mut result as &mut [u8]).enq()?;
            result.iter().all(|&b| b == 0)
        });

        unsafe {
            self.kernel.enq()?;
        }

        self.result.read(&mut *out).enq()?;
        let success = !out.iter().all(|&b| b == 0);
        if success {
            self.result.write(&[0u8; 32] as &[u8]).enq()?;
        }
        Ok(success)
    }
}
