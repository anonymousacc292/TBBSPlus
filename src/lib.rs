#![allow(clippy::too_many_arguments)]
#![allow(non_snake_case)]

pub mod utils;

pub mod n_out_of_n;
use bls12_381::G1Affine;
pub use n_out_of_n::*;

pub mod t_out_of_n;
pub use t_out_of_n::*;

pub mod comzk;
pub use comzk::*;

pub mod util;
pub use util::*;

pub mod zk;
pub use zk::*;

pub const MODULUS: &str = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

pub const LAMBDA: u32 = 128;

#[derive(Clone, Debug, PartialEq)]
pub struct ElGCiphertext {
    pub c1: G1Affine,
    pub c2: G1Affine,
}
