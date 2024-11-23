use crate::ComZkDlComEgproof;
use bls12_381::{G1Projective, Scalar};
use ff::Field;
use rand_chacha::ChaChaRng;
use std::collections::BTreeMap;

pub struct PVSSG {
    pub A: BTreeMap<usize, Vec<G1Projective>>,
    pub a: BTreeMap<usize, Vec<Scalar>>,
    pub ss: BTreeMap<usize, BTreeMap<usize, Scalar>>,
}

impl PVSSG {
    pub fn share(
        chacharng: &mut ChaChaRng,
        eg_keys: &BTreeMap<usize, Scalar>,
        t: usize,
        n: usize,
    ) -> Self {
        let mut msgs = BTreeMap::new();
        let mut A = BTreeMap::new();
        let mut ss = BTreeMap::new();
        let mut a = BTreeMap::new();
        for (i, item) in eg_keys.clone() {
            let mut coes = Vec::with_capacity(t);
            let mut As = Vec::with_capacity(t);
            let mut sjs = BTreeMap::new();
            let mut Asproofs = Vec::with_capacity(t);
            let s = item.clone();
            coes.push(s);
            As.push(s * G1Projective::generator());
            Asproofs.push(ComZkDlComEgproof::prove(
                &mut chacharng.clone(),
                &As[0].into(),
                &coes[0],
            ));
            for j in 1..=(t - 1) {
                coes.push(Scalar::random(chacharng.clone()));
                As.push(coes[j] * G1Projective::generator());
                Asproofs.push(ComZkDlComEgproof::prove(
                    &mut chacharng.clone(),
                    &As[j].into(),
                    &coes[j],
                ));
            }
            for j in 1..=n {
                let mut sj = Scalar::from(0u64);
                for k in (0..t).rev() {
                    sj = sj * Scalar::from(j as u64) + coes[k as usize].clone();
                }
                sjs.insert(j, sj);
            }
            msgs.insert(i, Asproofs);
            A.insert(i, As);
            a.insert(i, coes);
            ss.insert(i, sjs);
        }

        for i in 1..=n {
            let exp = Scalar::from(i as u64);
            for j in 1..=n {
                let As = A.get(&j).unwrap().clone();
                let Asproofs = msgs.get(&j).unwrap().clone();
                let si = ss.get(&j).unwrap().clone().get(&i).unwrap().clone();
                let mut pro = G1Projective::identity();
                for k in (0..t).rev() {
                    assert_eq!(true, Asproofs[k].verify(&As[k].into()));
                    pro = pro * exp + As[k];
                }
                let left = si * G1Projective::generator();
                assert_eq!(left, pro);
            }
        }
        return PVSSG { A, a, ss };
    }

    pub fn recover(
        pv: &PVSSG,
        t: usize,
        n: usize,
    ) -> (BTreeMap<usize, Scalar>, BTreeMap<usize, G1Projective>) {
        let mut dis = BTreeMap::new();
        let mut update_pub_shares = BTreeMap::new();
        let lag_coes = Self::lagrange_coeffs(t);
        for i in 1..=t {
            let lagi = lag_coes.get(&i).unwrap().clone();
            let mut sum = Scalar::from(0u64);
            for j in 1..=n {
                let si = pv.ss.get(&j).unwrap().get(&i).unwrap().clone();
                sum = sum + si;
            }
            let di = sum * lagi;
            dis.insert(i, di);
            update_pub_shares.insert(i, di * G1Projective::generator());
        }
        (dis, update_pub_shares)
    }

    pub fn lagrange_coeffs(t: usize) -> BTreeMap<usize, Scalar> {
        let mut coeffs = BTreeMap::new();
        for i in 1..=t {
            let mut result = Scalar::from(1u64);
            let i_mpz = Scalar::from(i as u64);
            for j in 1..=t {
                if i != j {
                    let j_mpz = Scalar::from(j as u64);
                    let j_i_inv = (j_mpz - &i_mpz).invert().unwrap();
                    result = result * &j_mpz * &j_i_inv;
                }
            }
            coeffs.insert(i, result);
        }
        coeffs
    }
}

#[cfg(test)]
mod tests {
    use bicycl::{CL_HSMqk, Mpz, RandGen};
    use bls12_381::Scalar;
    use curv::{arithmetic::Converter, BigInt};
    use ff::Field;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use crate::{t_out_of_n::wmc24::KeyGen, MODULUS};

    use super::PVSSG;

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
        let n = 5;
        let t = 3;
        let key_msg = KeyGen::keygen(&cl, n, t, 5, &mut rng, &mut scalr_rng);

        let pvssmsg = PVSSG::share(&mut scalr_rng, &key_msg.eg_keys.sk_shares, t, n);

        let mut left_sum = Scalar::from(0u64);
        for (_, item) in key_msg.eg_keys.sk_shares.clone() {
            left_sum = left_sum + item;
        }

        let dis = PVSSG::recover(&pvssmsg, t, n);
        let mut right_sum = Scalar::from(0u64);
        for (_, item) in dis.0 {
            right_sum = right_sum + item;
        }

        assert_eq!(left_sum, right_sum);
    }
}
