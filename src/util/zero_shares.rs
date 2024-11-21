use std::collections::BTreeMap;

use bicycl::{CL_HSMqk, Mpz, RandGen};

pub struct ZeroShare {
    pub beta_t_is: BTreeMap<usize, Mpz>,
}

impl ZeroShare {
    pub fn share(cl: &CL_HSMqk, rng: &mut RandGen, t: usize, n: usize) -> Self {
        let mut beta_primei = BTreeMap::new();
        let mut beta_t_is = BTreeMap::new();
        for i in 1..=n {
            let mut beta_prime = BTreeMap::new();
            for j in 1..=n {
                if j != i {
                    beta_prime.insert(j, rng.random_mpz(&cl.encrypt_randomness_bound()));
                }
            }
            beta_primei.insert(i, beta_prime);
        }
        let mut beta_ijss = BTreeMap::new();
        for i in 1..=n {
            let beta_prime_ijs = beta_primei.get(&i).unwrap().clone();
            let mut beta_ijs = BTreeMap::new();
            for j in 1..=n {
                let beta_ij;
                if j != i {
                    let beta_prime_ij = beta_prime_ijs.get(&j).unwrap().clone();
                    let beta_prime_ji = beta_primei.get(&j).unwrap().get(&i).unwrap().clone();
                    if i > j {
                        beta_ij = beta_prime_ij - beta_prime_ji;
                    } else {
                        beta_ij = beta_prime_ji - beta_prime_ij;
                    }
                    beta_ijs.insert(j, beta_ij);
                }
            }
            beta_ijss.insert(i, beta_ijs);
        }
        let mut sum = Mpz::from(0u64);
        for i in 1..=t {
            let beta_ijs = beta_ijss.get(&i).unwrap().clone();
            let mut beta_t_i = Mpz::from(0u64);
            for j in 1..=t {
                if j < i {
                    beta_t_i = beta_t_i + beta_ijs.get(&j).unwrap().clone();
                }
                if j > i {
                    beta_t_i = beta_t_i - beta_ijs.get(&j).unwrap().clone();
                }
            }
            sum = sum + beta_t_i.clone();
            beta_t_is.insert(i, beta_t_i);
        }
        assert_eq!(Mpz::from(0u64), sum);
        ZeroShare { beta_t_is }
    }
}

#[cfg(test)]
mod tests {
    use bls12_381::Scalar;
    use curv::{arithmetic::Converter, BigInt};
    use ff::Field;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use crate::MODULUS;

    use super::*;
    #[test]
    fn test_zero_share() {
        let seed: [u8; 32] = [0u8; 32];
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
        let n = 5;
        let t = 3;
        let beta_t_is = ZeroShare::share(&cl, &mut rng, t, n);
        let mut sum = Mpz::from(0u64);
        for i in 1..=t {
            sum = sum + beta_t_is.beta_t_is.get(&i).unwrap().clone();
        }
        assert_eq!(Mpz::from(0u64), sum);
    }
}
