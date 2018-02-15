use ocl;
use ocl::ProQue;
use ocl::Result;
use ocl::Buffer;
use ocl::flags::MemFlags;
use ocl::builders::ProgramBuilder;

pub struct Gpu {
    kernel: ocl::Kernel,
    result: Buffer<u8>,
    key_root: Buffer<u8>,
}

impl Gpu {
    pub fn new(threads: usize, public_key_req: &[u8], public_key_mask: &[u8]) -> Result<Gpu> {
        let prog_bldr = ProgramBuilder::new()
            .src(include_str!("opencl/blake2b.cl"))
            .src(include_str!("opencl/curve25519-constants.cl"))
            .src(include_str!("opencl/curve25519-constants2.cl"))
            .src(include_str!("opencl/curve25519.cl"))
            .src(include_str!("opencl/entry.cl"));
        let pro_que = ProQue::builder().prog_bldr(prog_bldr).dims(1).build()?;

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
            .dims(64)
            .build()?;
        let mask = Buffer::<u8>::builder()
            .queue(pro_que.queue().clone())
            .flags(MemFlags::new().read_only().host_write_only())
            .dims(64)
            .build()?;

        req.write(public_key_req).enq()?;
        mask.write(public_key_mask).enq()?;

        let kernel = pro_que
            .create_kernel("generate_pubkey")?
            .gws(threads)
            .arg_buf(&result)
            .arg_buf(&key_root)
            .arg_buf(&req)
            .arg_buf(&mask);

        Ok(Gpu {
            kernel,
            result,
            key_root,
        })
    }

    pub fn compute(&mut self, key_root: &[u8]) -> Result<[u8; 32]> {
        self.key_root.write(key_root).enq()?;
        let mut res = [0u8; 32];
        self.result.write(&res as &[u8]).enq()?;

        unsafe {
            self.kernel.enq()?;
        }

        self.result.read(&mut res as &mut [u8]).enq()?;
        Ok(res)
    }
}
