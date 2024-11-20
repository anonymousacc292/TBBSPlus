use std::{
    collections::BTreeMap,
    ops::{Div, Mul},
};

use cgenprime::cgenprime::genprime;
use sha2::Sha256;

use crate::{commit_QFI, LAMBDA};

use super::*;

// const q_str: &str = "172495418075785542394385897185716297629";

#[derive(Clone, Debug, PartialEq)]
pub struct CLRandYuanProof {
    pub com: Vec<u8>,
    pub e_1: Mpz,
    pub e_2: Mpz,
    pub K: QFI,
    pub e_1_: Mpz,
    pub e_2_: Mpz,
    pub K_: QFI,
    pub map: BTreeMap<Vec<u8>, Mpz>,
    pub alpha: Mpz,
}

impl CLRandYuanProof {
    pub fn prove(
        pp: &CL_HSMqk,
        rng: &mut RandGen,
        ct1_pow: &QFI,
        ct1_gen: &QFI,
        m: &Scalar,
        cl_rand: &Mpz,
        // chacharng: &mut ChaChaRng,
        q: &Mpz,
        B: &Mpz,
    ) -> Self {
        let r1 = rng.random_mpz(&B);
        let r2 = rng.random_mpz(&B);
        let mut map = BTreeMap::new();

        let m_mpz = Mpz::from(m);

        let R = ct1_gen.exp(&pp, &r1).compose(&pp, &pp.power_of_h(&r2));

        let alpha = Self::challenge_e(&R);

        let beta_1 = &r1 + alpha.clone() * &m_mpz;
        let beta_2 = &r2 + alpha.clone() * cl_rand;

        let k_1 = beta_1.clone().div(q);
        let e_1 = beta_1.clone() - k_1.clone().mul(q);

        let k_2 = beta_2.clone().div(q);
        let e_2 = beta_2.clone() - k_2.clone().mul(q);

        let K = ct1_gen.exp(&pp, &k_1).compose(&pp, &pp.power_of_h(&k_2));

        let p_bits: u32 = LAMBDA;
        let p_min_bits: u32 = LAMBDA - 1;
        let k: u32 = 1;
        let tmp_seed: u32 = 3423;
        let cq_: gmp::mpz::Mpz = genprime(p_bits, p_min_bits, k, tmp_seed);
        let q_ = Mpz::from(cq_.to_string().as_str());
        // println!("{:?}", q_.to_string());
        // let q_ = Mpz::from(q_str);

        map.insert(Self::challenge(ct1_pow, &K, &e_1, &e_2), q_.clone());

        let k_1_ = beta_1.clone().div(&q_);
        let e_1_ = beta_1.clone() - k_1_.clone().mul(&q_);

        let k_2_ = beta_2.clone().div(&q_);
        let e_2_ = beta_2.clone() - k_2_.clone().mul(&q_);

        let K_ = ct1_gen.exp(&pp, &k_1_).compose(&pp, &pp.power_of_h(&k_2_));

        Self {
            com: commit_QFI(ct1_pow),
            e_1,
            e_2,
            K,
            e_1_,
            e_2_,
            K_,
            map,
            alpha,
        }
    }

    pub fn verify(&self, pp: &CL_HSMqk, ct1_pow: &QFI, ct1_gen: &QFI, q: &Mpz) {
        let R = self
            .K
            .exp(&pp, &q)
            .compose(&pp, &ct1_gen.exp(&pp, &self.e_1))
            .compose(&pp, &pp.power_of_h(&self.e_2))
            .compose(&pp, &ct1_pow.exp(&pp, &-self.alpha.clone()));

        let alpha_ = Self::challenge_e(&R);

        assert_eq!(alpha_, self.alpha);
        if let Some(q_) = self
            .map
            .get(&Self::challenge(ct1_pow, &self.K, &self.e_1, &self.e_2))
        {
            let R_ = self
                .K_
                .exp(&pp, &q_)
                .compose(&pp, &ct1_gen.exp(&pp, &self.e_1_))
                .compose(&pp, &pp.power_of_h(&self.e_2_))
                .compose(&pp, &ct1_pow.exp(&pp, &-self.alpha.clone()));
            assert_eq!(R, R_);
        } else {
            panic!("No q_");
        }
    }

    // pub fn verify(&self, pp: &CL_HSMqk, clpk: &PublicKey, clct: &CipherText) -> bool {
    //     let U1 = pp
    //         .power_of_h(&self.z1)
    //         .compose(&pp, &clct.c1().exp(&pp, &-Mpz::from(&self.e)));
    //     // let U2 = pp
    //     //     .power_of_f(&Mpz::from(&self.z2))
    //     //     .compose(&pp, &clpk.exponentiation(&pp, &self.z1))
    //     //     .compose(&pp, &clct.c2().exp(&pp, &-Mpz::from(&self.e)));

    //     let e = Self::challenge(clpk, clct, &U1);
    //     e == self.e
    // }

    fn challenge(pow1: &QFI, U1: &QFI, e_1: &Mpz, e_2: &Mpz) -> Vec<u8> {
        let mut hasher = Sha256::new();

        for item in &[
            pow1.to_bytes(),
            U1.to_bytes(),
            e_1.to_bytes(),
            e_2.to_bytes(),
        ] {
            hasher.update(item);
        }

        // Mpz::from_bytes(&hasher.finalize()[..16])
        hasher.finalize()[..16].to_vec()
    }

    fn challenge_e(R: &QFI) -> Mpz {
        let mut hasher = Sha512::new();

        for item in &[R.to_bytes()] {
            hasher.update(item);
        }

        // let tmp = hasher.finalize()[0..16].to_vec();
        // let tmp_2: [u8; 64] = tmp.try_into().unwrap();

        // Scalar::from_bytes_wide(&tmp_2)
        Mpz::from_bytes(&hasher.finalize()[0..16])
    }
    // fn challenge(clpk: &PublicKey, clct: &CipherText, U1: &QFI) -> Scalar {
    //     let mut hasher = Sha512::new();

    //     for item in &[
    //         clpk.to_bytes(),
    //         clct.c1().to_bytes(),
    //         clct.c2().to_bytes(),
    //         U1.to_bytes()
    //     ] {
    //         hasher.update(item);
    //     }

    //     let tmp = hasher.finalize()[0..64].to_vec();
    //     let tmp_2: [u8; 64] = tmp.try_into().unwrap();

    //     Scalar::from_bytes_wide(&tmp_2)
    // }
}

#[cfg(test)]
mod tests {
    use bls12_381::G2Projective;
    use curv::{arithmetic::Converter, BigInt};
    use rand::SeedableRng;

    use crate::MODULUS;

    use super::*;

    #[test]
    fn test_clenc_nizk() {
        let seed: [u8; 32] = [0u8; 32];
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
        let sk = rng.random_mpz(&cl.encrypt_randomness_bound());
        let pk = PublicKey::from_qfi(&cl, &cl.power_of_h(&sk));

        let m = Scalar::random(scalr_rng.clone());
        let _: G2Projective = G2Projective::generator() * m;
        let cl_rand = rng.random_mpz(&cl.encrypt_randomness_bound());
        let c1 = cl.power_of_h(&cl_rand);
        let c2 = cl
            .power_of_f(&Mpz::from(&m))
            .compose(&cl, &pk.exponentiation(&cl, &cl_rand));

        let ct = CipherText::new(&c1, &c2);

        let alpha = Scalar::random(scalr_rng.clone());
        let r = rng.random_mpz(&cl.encrypt_randomness_bound());

        let ct1_pow = ct
            .c1()
            .exp(&cl, &Mpz::from(&alpha))
            .compose(&cl, &cl.power_of_h(&r));

        let B = cl.encrypt_randomness_bound();

        let proof = CLRandYuanProof::prove(&cl, &mut rng, &ct1_pow, &ct.c1(), &alpha, &r, &q, &B);
        proof.verify(&cl, &ct1_pow, &ct.c1(), &q);
    }
}
