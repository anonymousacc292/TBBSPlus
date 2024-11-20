mod cgenprime;
use gmp::mpz::*;
fn main() {
    let p_bits: u32 = 1000;
    let p_min_bits: u32 = 999;
    let k:u32 = 20;
    let tmp_seed:u32 = 3423;
    let a: Mpz = cgenprime::genprime(p_bits, p_min_bits, k, tmp_seed);
    println!("prime p: {}",a.to_string());
}
