use crate::{ComZkDlComClproof, PVSS};

use super::*;

pub struct KeyGen {
    pub cl_keys: CLKeys,
    pub sign_keys: SignKeys,
    pub each_party_x_ciphertexts: BTreeMap<usize, CipherText>,
}

#[derive(Clone)]
pub struct CLKeys {
    pub sk_shares: BTreeMap<usize, Mpz>,
    pub pub_key: PublicKey,
    pub n_factorial: Mpz,
}
#[derive(Clone)]
pub struct SignKeys {
    pub sk_shares: BTreeMap<usize, Scalar>,
    pub pub_shares: BTreeMap<usize, G2Projective>,
    pub pub_key: G2Projective,
    pub H: Vec<G1Projective>,
    pub x: Scalar,
}

impl KeyGen {
    pub fn clkeygen(
        rng: &mut RandGen,
        chacharng: &mut ChaChaRng,
        cl: &CL_HSMqk,
        n: usize,
        t: usize,
    ) -> CLKeys {
        // let mut rng = RandGen::new();
        let mut each_party_gen = Vec::with_capacity(n as usize);
        let mut pk_shares = Vec::with_capacity(n as usize);
        let mut sk_shares = BTreeMap::new();
        for i in 1..=n {
            let d_i = rng.random_mpz(&cl.encrypt_randomness_bound());

            let pk_i = cl.power_of_h(&d_i);

            pk_shares.push(pk_i.clone());

            sk_shares.insert(i, d_i.clone());

            let proof_i = ComZkDlComClproof::prove(&cl, chacharng, &pk_i, &d_i);

            each_party_gen.push((i, pk_i, proof_i));
        }
        let mut each_party_pubkey = Vec::with_capacity(n as usize);
        let d = sk_shares
            .values()
            .cloned()
            .into_iter()
            .reduce(|acc, d_i| acc + d_i)
            .unwrap();
        for i in 1..=n {
            let pk = pk_shares
                .clone()
                .into_iter()
                .reduce(|acc, pk_i| acc.compose(&cl, &pk_i))
                .unwrap();
            for (j, pk_i, proof_i) in each_party_gen.iter() {
                if *j == i {
                    continue;
                }
                assert_eq!(true, proof_i.verify(&cl, &pk_i));
            }
            each_party_pubkey.push(pk);
        }
        assert_eq!(each_party_pubkey[0], cl.power_of_h(&d));

        for (i, _) in each_party_pubkey.iter().enumerate() {
            if i != 0 {
                assert_eq!(each_party_pubkey[i - 1], each_party_pubkey[i]);
            }
        }
        let pub_key = PublicKey::from_qfi(&cl, &each_party_pubkey[0]);

        let mut n_factorial = Mpz::from(1u64);
        for i in 1..=n {
            n_factorial = Mpz::from(i as u64) * &n_factorial;
        }
        let pvssmsg = PVSS::share(
            &cl,
            rng,
            chacharng,
            &sk_shares,
            &cl.encrypt_randomness_bound(),
            t,
            n,
            &n_factorial,
        );

        sk_shares = PVSS::recover(&pvssmsg, t, n, &n_factorial);
        // let left_sum = d * n_factorial.clone() * n_factorial.clone() * n_factorial.clone();
        // let mut right_sum = Mpz::from(0u64);
        // for (_, item) in sk_shares.clone() {
        //     right_sum = right_sum + item;
        // }
        // assert_eq!(left_sum, right_sum);
        CLKeys {
            sk_shares,
            pub_key,
            n_factorial,
        }
    }

    pub fn signkeygen(chacharng: &mut ChaChaRng, n: usize, l: usize) -> SignKeys {
        let mut each_party_gen = Vec::with_capacity(n as usize);
        let mut pk_shares = Vec::with_capacity(n as usize);
        let mut sk_shares = BTreeMap::new();
        let mut pub_shares = BTreeMap::new();
        let mut pub_H_shares: BTreeMap<usize, Vec<G1Projective>> = BTreeMap::new();
        //let mut pub_H_share: Vec<Vec<G1Projective>> = Vec::with_capacity(n.into());
        for i in 1..=n {
            for j in 0..=l {
                if let Some(value) = pub_H_shares.get(&j) {
                    let mut H_i = value.clone();
                    let k_i = Scalar::random(chacharng.clone());
                    let H_ii = G1Projective::generator() * &k_i;
                    H_i.push(H_ii);
                    pub_H_shares.insert(j, value.clone());
                } else {
                    let mut H_i = Vec::with_capacity(n.into());
                    let k_i = Scalar::random(chacharng.clone());
                    let H_ii = G1Projective::generator() * &k_i;
                    H_i.push(H_ii);
                    pub_H_shares.insert(j, H_i);
                }
                // let k_i = Scalar::random(chacharng.clone());
                // let H_ii = G1Projective::generator() * &k_i;
                // pub_H_share[i as usize - 1][j] = H_ii;
            }

            let x_i = Scalar::random(chacharng.clone());

            let pk_i = G2Projective::generator() * &x_i;

            pk_shares.push(pk_i.clone());

            sk_shares.insert(i, x_i.clone());

            pub_shares.insert(i, pk_i.clone());

            let proof_i = ComZkDlComElproof::prove(&mut chacharng.clone(), &pk_i.into(), &x_i);

            each_party_gen.push((i, pk_i, proof_i));
        }
        let mut each_party_pubkey = Vec::with_capacity(n as usize);
        let mut each_party_Hs = Vec::with_capacity(n as usize);
        let x = sk_shares
            .values()
            .cloned()
            .into_iter()
            .reduce(|acc, d_i| acc + d_i)
            .unwrap();
        for i in 1..=n {
            let mut H = Vec::with_capacity(l + 1);
            for (_, H_items) in pub_H_shares.clone() {
                let H_i = H_items.into_iter().reduce(|acc, pk_i| acc + pk_i).unwrap();
                H.push(H_i);
            }
            // for H_items in pub_H_share.clone().into_iter(){
            //     let H_i = H_items
            //     .into_iter()
            //     .reduce(|acc, pk_i| acc + pk_i)
            //     .unwrap();
            //     H.push(H_i);
            // }

            each_party_Hs.push(H);

            let pk = pk_shares
                .clone()
                .into_iter()
                .reduce(|acc, pk_i| acc + pk_i)
                .unwrap();
            for (j, pk_i, proof_i) in each_party_gen.iter() {
                if *j == i {
                    continue;
                }
                assert_eq!(true, proof_i.verify(&pk_i.into()));
            }
            each_party_pubkey.push(pk);
        }
        assert_eq!(each_party_pubkey[0], G2Projective::generator() * x.clone());

        for (i, _) in each_party_Hs.iter().enumerate() {
            if i != 0 {
                for j in 0..=l {
                    assert_eq!(each_party_Hs[i - 1][j], each_party_Hs[i][j]);
                }
            }
        }

        for (i, _) in each_party_pubkey.iter().enumerate() {
            if i != 0 {
                assert_eq!(each_party_pubkey[i - 1], each_party_pubkey[i]);
            }
        }
        let pub_key = each_party_pubkey[0].clone();
        let H = each_party_Hs[0].clone();
        SignKeys {
            sk_shares,
            pub_shares,
            pub_key,
            H,
            x,
        }
    }

    pub fn keygen(
        cl: &CL_HSMqk,
        t: usize,
        n: usize,
        l: usize,
        rng: &mut RandGen,
        chacharng: &mut ChaChaRng,
    ) -> Self {
        let cl_keys = Self::clkeygen(rng, chacharng, cl, n, t);
        let sign_keys = Self::signkeygen(chacharng, n, l);

        let mut msgs = Vec::with_capacity(n as usize);
        let mut per_cipher = BTreeMap::new();
        let cl_pk = cl_keys.pub_key.clone();
        let mut x = Scalar::zero();
        for i in 1..=n {
            let x_i = sign_keys.sk_shares.get(&i).unwrap().clone();
            let pk_i = sign_keys.pub_shares.get(&i).unwrap().clone();
            x = x + &x_i;
            let cl_rand = rng.random_mpz(&cl.encrypt_randomness_bound());
            let c1 = cl.power_of_h(&cl_rand);
            let c2 = cl
                .power_of_f(&Mpz::from(&x_i))
                .compose(&cl, &cl_pk.exponentiation(&cl, &cl_rand));
            let xi_ciphertext = CipherText::new(&c1, &c2);
            let proof = CLEncProof::prove(
                &cl,
                rng,
                &cl_pk,
                &xi_ciphertext,
                &pk_i,
                &x_i,
                &cl_rand,
                chacharng,
            );
            msgs.push((i, xi_ciphertext.clone(), pk_i.clone(), proof));
            per_cipher.insert(i, xi_ciphertext);
        }
        let mut each_party_x_ciphertexts = BTreeMap::new();
        for i in 1..=n {
            let xi_ciphertexts: Vec<_> = msgs
                .iter()
                .filter_map(|(_, xi_ciphertext, pk_i, proof)| {
                    //if proof.verify(pp, &pp.pk, ki_ciphertext) && *j != i {
                    if proof.verify(&cl, &cl_pk, xi_ciphertext, pk_i) {
                        //Some((*j, gammai_ciphertext.clone(), proof.clone()))
                        Some(xi_ciphertext.clone())
                    } else {
                        None
                    }
                })
                .collect();

            //each_party_k_ciphertexts.insert(i, per_cipher.get(&i).unwrap().clone());

            let x_ciphertext = xi_ciphertexts
                .into_iter()
                .reduce(|acc, ct| {
                    CipherText::new(
                        &acc.c1().compose(&cl, &ct.c1()),
                        &acc.c2().compose(&cl, &ct.c2()),
                    )
                })
                .unwrap();
            each_party_x_ciphertexts.insert(i, x_ciphertext);
            //msgs.rotate_left(1);
        }
        //Gen gamma x
        Self {
            cl_keys,
            sign_keys,
            each_party_x_ciphertexts,
        }
    }
}

#[cfg(test)]
mod tests {
    use curv::{arithmetic::Converter, BigInt};
    use rand::SeedableRng;

    use crate::MODULUS;

    use super::*;

    #[test]
    fn test_clkeygen() {
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

        KeyGen::keygen(&cl, 3, 5, 5, &mut rng, &mut scalr_rng);
    }
}
