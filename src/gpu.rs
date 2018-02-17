use ocl;
use ocl::ProQue;
use ocl::Result;
use ocl::Buffer;
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
    pub fn new(device: usize, threads: usize, matcher: &Matcher) -> Result<Gpu> {
        let prog_bldr = ProgramBuilder::new()
            .src(include_str!("opencl/blake2b.cl"))
            .src(include_str!("opencl/curve25519-constants.cl"))
            .src(include_str!("opencl/curve25519-constants2.cl"))
            .src(include_str!("opencl/curve25519.cl"))
            .src(include_str!("opencl/entry.cl"));
        let pro_que = ProQue::builder()
            .prog_bldr(prog_bldr)
            .device(DeviceSpecifier::Indices(vec![device]))
            .dims(1)
            .build()?;

        let result = Buffer::<u8>::builder()
            .queue(pro_que.queue().clone())
            .flags(MemFlags::new().write_only())
            .dims(64)
            .build()?;
        let key_root = Buffer::<u8>::builder()
            .queue(pro_que.queue().clone())
            .flags(MemFlags::new().read_only().host_write_only())
            .dims(64)
            .build()?;
        let req = Buffer::<u8>::builder()
            .queue(pro_que.queue().clone())
            .flags(MemFlags::new().read_only().host_write_only())
            .dims(matcher.prefix_len())
            .build()?;
        let mask = Buffer::<u8>::builder()
            .queue(pro_que.queue().clone())
            .flags(MemFlags::new().read_only().host_write_only())
            .dims(matcher.prefix_len())
            .build()?;

        req.write(matcher.req()).enq()?;
        mask.write(matcher.mask()).enq()?;

        let kernel = pro_que
            .create_kernel("generate_pubkey")?
            .gws(threads)
            .arg_buf(&result)
            .arg_buf(&key_root)
            .arg_buf(&req)
            .arg_buf(&mask)
            .arg_scl(matcher.prefix_len() as u8);

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
