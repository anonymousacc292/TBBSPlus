#![allow(clippy::too_many_arguments)]
#![allow(non_snake_case)]

pub mod utils;

pub mod n_out_of_n;
pub use n_out_of_n::*;

// pub mod wmc24;

pub mod comzk;
pub use comzk::*;

pub mod util;
pub use util::*;

pub mod zk;
pub use zk::*;

pub const MODULUS: &str = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

pub const LAMBDA: u32 = 128;
