use std::ops::Neg;

use bicycl::{CL_HSMqk, Mpz, QFI};
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;
use rand_chacha::ChaChaRng;
use sha2::{Digest, Sha256, Sha512};

use crate::{commit_G1, commit_G2, commit_QFI};

#[derive(Clone, Debug, PartialEq)]
pub struct ComZkDlComClproof {
    pub com: Vec<u8>,
    pub e: Mpz,
    pub z_1: Mpz,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ComZkDlComElproof {
    pub com: Vec<u8>,
    pub e: Scalar,
    pub z_1: Scalar,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ComZkDlComEgproof {
    pub com: Vec<u8>,
    pub e: Scalar,
    pub z_1: Scalar,
}

impl ComZkDlComClproof {
    pub fn prove(pp: &CL_HSMqk, rng: &mut ChaChaRng, pow1: &QFI, secret_keyi: &Mpz) -> Self {
        let u_1 = Scalar::random(rng);

        let U1 = pp.power_of_h(&Mpz::from(&u_1));

        let e = Self::challenge(pow1, &U1);
        let z_1 = Mpz::from(&u_1) + e.clone() * secret_keyi;

        Self {
            com: commit_QFI(pow1),
            e,
            z_1,
        }
    }

    pub fn verify(&self, pp: &CL_HSMqk, pow1: &QFI) -> bool {
        let U1 = pp
            .power_of_h(&self.z_1)
            .compose(&pp, &pow1.exp(&pp, &self.e.clone().neg()));

        let e = Self::challenge(pow1, &U1);
        e == self.e
    }

    fn challenge(pow1: &QFI, U1: &QFI) -> Mpz {
        let mut hasher = Sha256::new();

        for item in &[pow1.to_bytes(), U1.to_bytes()] {
            hasher.update(item);
        }

        Mpz::from_bytes(&hasher.finalize())
    }
}

impl ComZkDlComElproof {
    pub fn prove(rng: &mut ChaChaRng, pow1: &G2Affine, secret_keyi: &Scalar) -> Self {
        let u_1 = Scalar::random(rng);

        let U1 = G2Projective::generator() * u_1;

        let e = Self::challenge(pow1, &U1.into());
        let z_1 = u_1 + e.clone() * secret_keyi;

        Self {
            com: commit_G2(pow1),
            e,
            z_1,
        }
    }

    pub fn verify(&self, pow1: &G2Affine) -> bool {
        let pow: G2Projective = pow1.into();

        let U1 = G2Projective::generator() * &self.z_1 - pow * &self.e;

        let e = Self::challenge(pow1, &U1.into());
        e == self.e
    }

    fn challenge(pow1: &G2Affine, U1: &G2Affine) -> Scalar {
        // println!("{:?}",U1);
        let mut hasher = Sha512::new();

        for item in &[pow1.to_compressed(), U1.to_compressed()] {
            hasher.update(item);
        }
        let tmp = hasher.finalize()[0..64].to_vec();
        let tmp_2: [u8; 64] = tmp.try_into().unwrap();
        // Scalar::from_bytes(hasher.finalize()[0..32].try_into().unwrap()).unwrap()
        //Scalar::from_bytes(&tmp_2).unwrap()
        Scalar::from_bytes_wide(&tmp_2)
        //(&hasher.finalize())
    }
}

impl ComZkDlComEgproof {
    pub fn prove(rng: &mut ChaChaRng, pow1: &G1Affine, secret_keyi: &Scalar) -> Self {
        let u_1 = Scalar::random(rng);

        let U1 = G1Projective::generator() * u_1;

        let e = Self::challenge(pow1, &U1.into());
        let z_1 = u_1 + e.clone() * secret_keyi;

        Self {
            com: commit_G1(pow1),
            e,
            z_1,
        }
    }

    pub fn verify(&self, pow1: &G1Affine) -> bool {
        let pow: G1Projective = pow1.into();

        let U1 = G1Projective::generator() * &self.z_1 - pow * &self.e;

        let e = Self::challenge(pow1, &U1.into());
        e == self.e
    }

    fn challenge(pow1: &G1Affine, U1: &G1Affine) -> Scalar {
        // println!("{:?}",U1);
        let mut hasher = Sha512::new();

        for item in &[pow1.to_compressed(), U1.to_compressed()] {
            hasher.update(item);
        }
        let tmp = hasher.finalize()[0..64].to_vec();
        let tmp_2: [u8; 64] = tmp.try_into().unwrap();
        // Scalar::from_bytes(hasher.finalize()[0..32].try_into().unwrap()).unwrap()
        //Scalar::from_bytes(&tmp_2).unwrap()
        Scalar::from_bytes_wide(&tmp_2)
        //(&hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use bicycl::{CL_HSMqk, RandGen};
    use curv::{arithmetic::Converter, BigInt};
    use rand::SeedableRng;

    use crate::MODULUS;

    use super::*;

    #[test]
    fn test_clcom_nizk() {
        let seed = [0u8; 32];
        let scalr_rng = ChaChaRng::from_seed(seed);

        let mut rng = RandGen::new();
        rng.set_seed(&Mpz::from(&Scalar::random(scalr_rng.clone())));

        let cl = CL_HSMqk::with_rand_gen(
            &Mpz::from_bytes(&BigInt::from_hex(MODULUS).unwrap().to_bytes()),
            1,
            1827,
            &mut rng,
            &(Mpz::from_bytes(&(BigInt::from(1) << 40).to_bytes())),
            false,
        );

        let x_i = rng.random_mpz(&cl.encrypt_randomness_bound());

        let pk_i = cl.power_of_h(&x_i);

        //let pow1 = round2_msg.xk_ciphertexts.get(&1).unwrap().get(&1).unwrap();

        let pow1 = pk_i.clone();

        let proof = ComZkDlComClproof::prove(&cl, &mut scalr_rng.clone(), &pow1, &x_i);

        assert_eq!(true, proof.verify(&cl, &pow1))
    }

    #[test]
    fn test_clcom_elnizk() {
        let seed = [0u8; 32];
        let scalr_rng = ChaChaRng::from_seed(seed);

        let x_i = Scalar::random(scalr_rng.clone());

        let pk_i = G2Projective::generator() * x_i;

        //let pow1 = round2_msg.xk_ciphertexts.get(&1).unwrap().get(&1).unwrap();

        let proof = ComZkDlComElproof::prove(&mut scalr_rng.clone(), &pk_i.into(), &x_i);

        assert_eq!(true, proof.verify(&pk_i.into()))
    }
}
