

pub mod sebbsplus;
use bls12_381::G1Affine;
pub use sebbsplus::*;

pub mod wmc24;
pub use wmc24::*;

#[derive(Clone, Debug, PartialEq)]
pub struct ElGCiphertext {
    pub c1: G1Affine,
    pub c2: G1Affine,
}
