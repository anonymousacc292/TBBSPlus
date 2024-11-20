use bicycl::QFI;
use bls12_381::{G1Affine, G2Affine};
use sha2::{Digest, Sha256};

pub fn commit_G2(B: &G2Affine) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for item in &[B.to_compressed()] {
        hasher.update(item);
    }

    let res = hasher.finalize().to_vec();

    res
}

pub fn commit_G1(B: &G1Affine) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for item in &[B.to_compressed()] {
        hasher.update(item);
    }

    let res = hasher.finalize().to_vec();

    res
}

pub fn commit_QFI(B: &QFI) -> Vec<u8> {
    let mut hasher = Sha256::new();

    for item in &[B.to_bytes()] {
        hasher.update(item);
    }

    let res = hasher.finalize().to_vec();

    res
}
