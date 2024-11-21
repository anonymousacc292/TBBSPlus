use std::collections::BTreeMap;

use bicycl::{CL_HSMqk, Mpz, RandGen, QFI};
use rand_chacha::ChaChaRng;

use crate::ComZkDlComClproof;

pub struct PVSS {
    pub A: BTreeMap<usize, Vec<QFI>>,
    pub a: BTreeMap<usize, Vec<Mpz>>,
    pub ss: BTreeMap<usize, BTreeMap<usize, Mpz>>,
}

impl PVSS {
    pub fn share(
        cl: &CL_HSMqk,
        rng: &mut RandGen,
        chacharng: &mut ChaChaRng,
        cl_keys: &BTreeMap<usize, Mpz>,
        b: &Mpz,
        t: usize,
        n: usize,
        n_factorial: &Mpz,
    ) -> Self{
        let mut msgs = BTreeMap::new();
        let mut A = BTreeMap::new();
        let mut ss = BTreeMap::new();
        let mut a = BTreeMap::new();
        let n_sq = n_factorial.clone() * n_factorial;
        for (i, item) in cl_keys.clone() {
            let mut coes = Vec::with_capacity(t);
            let mut As = Vec::with_capacity(t);
            let mut sjs: BTreeMap<usize, Mpz> = BTreeMap::new();
            let mut Asproofs = Vec::with_capacity(t);
            let s = item.clone();
            let mut tmp;
            coes.push(n_factorial.clone() * &s);
            As.push(cl.power_of_h(&s));
            Asproofs.push(ComZkDlComClproof::prove(&cl, chacharng, &As[0], &s));
            for j in 1..=(t - 1) {
                coes.push(rng.random_mpz(b));
                tmp = n_factorial.clone() * &coes[j];
                As.push(cl.power_of_h(&tmp));
                Asproofs.push(ComZkDlComClproof::prove(&cl, chacharng, &As[j], &tmp));
            }
            for j in 1..=n {
                let mut sj = Mpz::from(0u64);
                for k in (0..t).rev() {
                    sj = sj * Mpz::from(j as u64) + coes[k as usize].clone();
                }
                sjs.insert(j, sj);
            }
            msgs.insert(i, Asproofs);
            A.insert(i, As);
            a.insert(i, coes);
            ss.insert(i, sjs);
        }

        for i in 1..=n {
            let exp = Mpz::from(i as i64);
            for j in 1..=n {
                let mut As = A.get(&j).unwrap().clone();
                let Asproofs = msgs.get(&j).unwrap().clone();
                let si = ss.get(&j).unwrap().clone().get(&i).unwrap().clone();
                let zero = Mpz::from(0u64);
                let tmp_A0 = As[0].clone();
                assert_eq!(true, Asproofs[0].verify(&cl, &As[0]));
                As[0] = As[0].exp(&cl, &n_sq);
                let mut pro = cl.power_of_h(&zero);
                for k in (0..t).rev() {
                    if k != 0{
                        assert_eq!(true, Asproofs[k].verify(&cl, &As[k]));
                    }
                    pro = pro.exp(&cl, &exp).compose(&cl, &As[k]);
                }
                As[0] = tmp_A0;
                let left_exp = si * n_factorial;
                let left = cl.power_of_h(&left_exp);
                assert_eq!(left, pro);
            }
        }
        return PVSS { A, a, ss };
    }

    pub fn recover() {}
}


#[cfg(test)]
mod tests {
    use bls12_381::Scalar;
    use curv::{arithmetic::Converter, BigInt};
    use ff::Field;
    use rand::SeedableRng;

    use crate::{sebbsplus::KeyGen, MODULUS};

    use super::*;

    #[test]
    fn test_pvss() {
        let seed: [u8; 32] = [0u8; 32];
        let mut scalr_rng = ChaChaRng::from_seed(seed);

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
        let n = 3;
        let mut n_factorial = Mpz::from(1u64);
        for i in 1..=n {
            n_factorial = Mpz::from(i as u64) * &n_factorial;
        }
        let key_msg = KeyGen::keygen(&cl, n, n, &mut rng, &mut scalr_rng);
        PVSS::share(&cl, &mut rng, &mut scalr_rng, &key_msg.cl_keys.sk_shares, &cl.encrypt_randomness_bound(), n, n, &n_factorial);
    }
}
