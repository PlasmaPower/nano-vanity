use std::cmp;

use blake2::VarBlake2b;
use digest::{Update, VariableOutput};
use num_bigint::BigInt;

#[derive(Clone)]
pub struct PubkeyMatcher {
    req: Vec<u8>,
    mask: Vec<u8>,
    prefix_len: usize,
}

impl PubkeyMatcher {
    pub fn new(mut req: Vec<u8>, mut mask: Vec<u8>) -> PubkeyMatcher {
        debug_assert!(req.iter().zip(mask.iter()).all(|(&r, &m)| r & !m == 0));
        let prefix_len = mask
            .iter()
            .enumerate()
            .rev()
            .find(|&(_i, &m)| m != 0)
            .map(|(i, _m)| i + 1)
            .unwrap_or(0);
        assert!(prefix_len <= 37);
        req.truncate(prefix_len);
        mask.truncate(prefix_len);
        assert!(req.len() >= prefix_len);
        assert!(mask.len() >= prefix_len);
        PubkeyMatcher {
            req: req,
            mask: mask,
            prefix_len,
        }
    }

    #[allow(dead_code)]
    pub fn req(&self) -> &[u8] {
        &self.req
    }

    #[allow(dead_code)]
    pub fn mask(&self) -> &[u8] {
        &self.mask
    }

    #[allow(dead_code)]
    pub fn prefix_len(&self) -> usize {
        self.prefix_len
    }

    pub fn matches(&self, pubkey: &[u8; 32]) -> bool {
        for i in 0..cmp::min(self.prefix_len, 32) {
            if pubkey[i] & self.mask[i] != self.req[i] {
                return false;
            }
        }
        if self.prefix_len > 32 {
            let mut checksum = [0u8; 5];
            let mut hasher = VarBlake2b::new(checksum.len()).unwrap();
            hasher.update(pubkey as &[u8]);
            hasher.finalize_variable(|h| checksum.copy_from_slice(h));
            for i in 32..self.prefix_len {
                if checksum[4 - (i - 32)] & self.mask[i] != self.req[i] {
                    return false;
                }
            }
        }
        true
    }

    pub fn estimated_attempts(&self) -> BigInt {
        let mut bits_in_mask = 0;
        for byte in &self.mask {
            bits_in_mask += byte.count_ones() as usize;
        }
        BigInt::from(1) << bits_in_mask
    }
}
