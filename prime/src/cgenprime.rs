use libc::{c_ulong};
use gmp::mpz::*;


#[link(name = "rust_genprime", kind = "static")]
extern "C" {
    pub fn rust_genprime(p: mpz_ptr, p_bits: c_ulong, p_min_bits: c_ulong, k: c_ulong, tmp_seed: c_ulong);
    pub fn rust_genprime_safe(p: mpz_ptr, p_bits: c_ulong, k: c_ulong, tmp_seed: c_ulong);
}

pub fn genprime(p_bits: u32, p_min_bits: u32, k: u32, tmp_seed: u32) -> Mpz     {
    unsafe {
        let mut res = Mpz::new();
        rust_genprime(res.inner_mut(), p_bits as c_ulong, p_min_bits as c_ulong, k as c_ulong, tmp_seed as c_ulong);
        res
    }
}

pub fn gen_safe_prime(p_bits: u32, tmp_seed: u32) -> Mpz     {
    unsafe {
        let mut res = Mpz::new();
        let k: u32 = 1;
        rust_genprime_safe(res.inner_mut(), p_bits as c_ulong, k as c_ulong, tmp_seed as c_ulong);
        res
    }
}
