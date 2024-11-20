use std::{
    collections::BTreeMap,
    ops::{Div, Mul},
};

use bicycl::{CL_HSMqk, Mpz, RandGen, QFI};
use bls12_381::Scalar;
use cgenprime::cgenprime::genprime;
use ff::{Field, PrimeField};
use rand_chacha::ChaChaRng;
use sha2::{Digest, Sha256};

use crate::{commit_G2, commit_QFI, LAMBDA};

#[derive(Clone, Debug, PartialEq)]
pub struct ComZkDlYuanComClproof {
    pub com: Vec<u8>,
    pub e: Mpz,
    pub K: QFI,
    pub e_: Mpz,
    pub K_: QFI,
    pub map: BTreeMap<Vec<u8>, Mpz>,
}

impl ComZkDlYuanComClproof {
    pub fn prove(
        pp: &CL_HSMqk,
        rng: &mut RandGen,
        chacharng: &mut ChaChaRng,
        pow1: &QFI,
        secret_keyi: &Mpz,
        q: &Mpz,
    ) -> Self {
        let k = secret_keyi.clone().div(q);
        let e = secret_keyi - &k.clone().mul(q);
        let mut map = BTreeMap::new();

        let K = pp.power_of_h(&k);

        let p_bits: u32 = LAMBDA;
        let p_min_bits: u32 = LAMBDA - 1;
        let k: u32 = 1;
        let tmp_seed: u32 = 3423;
        let cq_: gmp::mpz::Mpz = genprime(p_bits, p_min_bits, k, tmp_seed);
        let q_ = Mpz::from(cq_.to_string().as_str());

        map.insert(Self::challenge(pow1, &K, &e), q_.clone());

        let k_ = secret_keyi.clone().div(q_.clone());
        let e_ = secret_keyi - &k_.clone().mul(q_);
        let K_ = pp.power_of_h(&k_);

        Self {
            com: commit_QFI(pow1),
            e: e,
            K: K,
            e_: e_,
            K_: K_,
            map: map,
        }
    }

    pub fn verify(&self, pp: &CL_HSMqk, pow1: &QFI, q: &Mpz) {
        let KH = self.K.exp(&pp, &q).compose(&pp, &pp.power_of_h(&self.e));

        assert_eq!(pow1, &KH);

        if let Some(q_) = self.map.get(&Self::challenge(pow1, &self.K, &self.e)) {
            let KH_ = self.K_.exp(&pp, &q_).compose(&pp, &pp.power_of_h(&self.e_));
            assert_eq!(pow1, &KH_);
        } else {
            panic!("No q_");
        }
    }

    fn challenge(pow1: &QFI, U1: &QFI, e: &Mpz) -> Vec<u8> {
        let mut hasher = Sha256::new();

        for item in &[pow1.to_bytes(), U1.to_bytes(), e.to_bytes()] {
            hasher.update(item);
        }

        // Mpz::from_bytes(&hasher.finalize()[..16])
        hasher.finalize()[..16].to_vec()
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

        let q = Mpz::from_bytes(&BigInt::from_hex(MODULUS).unwrap().to_bytes());
        let cl = CL_HSMqk::with_rand_gen(
            &q,
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

        let proof = ComZkDlYuanComClproof::prove(
            &cl,
            &mut rng.clone(),
            &mut scalr_rng.clone(),
            &pow1,
            &x_i,
            &q,
        );

        proof.verify(&cl, &pow1, &q);
    }
}
