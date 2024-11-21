use std::ops::Add;

use bicycl::QFI;
use ff::PrimeField;
use rayon::iter::IntoParallelRefMutIterator;
use tokio::time::Sleep;

use crate::{CLELProof, CLEncSProof, CLPDProof, CLRandProof, ELPDProof};

use super::*;

pub struct Sign {
    pub each_party_gamma_e_x_ciphertext: BTreeMap<usize, CipherText>,
    pub each_party_eg_ciphertext: BTreeMap<usize, ElGCiphertext>,
    pub each_party_pd_gamma_e_x_ciphertext: BTreeMap<usize, (QFI, QFI, QFI, CLPDProof)>,
    pub each_party_pd_eg_ciphertext:
        BTreeMap<usize, (G1Projective, G1Projective, G1Projective, ELPDProof)>,
    pub e: Scalar,
    pub s: Scalar,
}

impl Sign {
    pub fn sign(
        cl: &CL_HSMqk,
        n: usize,
        l: usize,
        mut rng: &mut RandGen,
        chacharng: &mut ChaChaRng,
        key_msg: &KeyGen,
        msgs: &[Scalar],
    ) -> Self {
        // let mut each_party_ei_ciphertext = Vec::with_capacity(n);
        let mut each_party_ciphertext = Vec::with_capacity(n);

        for i in 1..=n {
            let e_i = Scalar::random(chacharng.clone());
            let s_i = Scalar::random(chacharng.clone());
            let e_i_rand = rng.random_mpz(&cl.encrypt_randomness_bound());
            let c1: QFI = cl.power_of_h(&e_i_rand);
            let c2 = cl
                .power_of_f(&Mpz::from(&e_i))
                .compose(&cl, &key_msg.cl_keys.pub_key.exponentiation(&cl, &e_i_rand));
            let e_i_ciphertext = CipherText::new(&c1, &c2);

            let proof_e_i = CLEncSProof::prove(
                &cl,
                rng,
                &key_msg.cl_keys.pub_key,
                &e_i_ciphertext,
                &e_i,
                &e_i_rand,
                &mut chacharng.clone(),
            );

            let s_i_rand = rng.random_mpz(&cl.encrypt_randomness_bound());
            let c1: QFI = cl.power_of_h(&s_i_rand);
            let c2 = cl
                .power_of_f(&Mpz::from(&s_i))
                .compose(&cl, &key_msg.cl_keys.pub_key.exponentiation(&cl, &s_i_rand));
            let s_i_ciphertext = CipherText::new(&c1, &c2);

            let proof_s_i = CLEncSProof::prove(
                &cl,
                rng,
                &key_msg.cl_keys.pub_key,
                &s_i_ciphertext,
                &s_i,
                &s_i_rand,
                &mut chacharng.clone(),
            );

            each_party_ciphertext.push((
                i,
                e_i_ciphertext.clone(),
                s_i_ciphertext.clone(),
                proof_e_i,
                proof_s_i,
            ))
        }

        let mut each_party_e_ciphertexts = BTreeMap::new();
        let mut each_party_s_ciphertexts = BTreeMap::new();
        let mut each_party_e_x_ciphertexts = BTreeMap::new();
        for i in 1..=n {
            let x_ciphertext = key_msg.each_party_x_ciphertexts.get(&i).unwrap().clone();
            let ciphertexts: Vec<_> = each_party_ciphertext
                .iter()
                .filter_map(
                    |(j, e_i_ciphertext, s_i_ciphertext, proof_e_i, proof_s_i)| {
                        //if proof.verify(pp, &pp.pk, ki_ciphertext) && *j != i {
                        if proof_e_i.verify(&cl, &key_msg.cl_keys.pub_key, &e_i_ciphertext)
                            && proof_s_i.verify(&cl, &key_msg.cl_keys.pub_key, &s_i_ciphertext)
                        {
                            //Some((*j, gammai_ciphertext.clone(), proof.clone()))
                            Some((e_i_ciphertext.clone(), s_i_ciphertext.clone()))
                        } else {
                            None
                        }
                    },
                )
                .collect();

            //each_party_k_ciphertexts.insert(i, per_cipher.get(&i).unwrap().clone());

            let (e_ciphertext, s_ciphertext) = ciphertexts
                .into_iter()
                .reduce(|(acc1, acc2), (ct1, ct2)| {
                    (
                        CipherText::new(
                            &acc1.c1().compose(&cl, &ct1.c1()),
                            &acc1.c2().compose(&cl, &ct1.c2()),
                        ),
                        CipherText::new(
                            &acc2.c1().compose(&cl, &ct2.c1()),
                            &acc2.c2().compose(&cl, &ct2.c2()),
                        ),
                    )
                })
                .unwrap();

            let e_x_ciphertext = CipherText::new(
                &x_ciphertext.c1().compose(&cl, &e_ciphertext.c1()),
                &x_ciphertext.c2().compose(&cl, &e_ciphertext.c2()),
            );
            each_party_e_ciphertexts.insert(i, e_ciphertext);
            each_party_s_ciphertexts.insert(i, s_ciphertext);
            each_party_e_x_ciphertexts.insert(i, e_x_ciphertext);
        }
        let mut each_party_pde_ciphertexts = BTreeMap::new();
        let mut each_party_pds_ciphertexts = BTreeMap::new();
        for i in 1..=n {
            let d_i = key_msg.cl_keys.sk_shares.get(&i).unwrap().clone();
            let e = each_party_e_ciphertexts.get(&i).unwrap().clone();
            let s = each_party_s_ciphertexts.get(&i).unwrap().clone();

            let pd_e = e.c1().exp(cl, &d_i);
            let pd_s = s.c1().exp(cl, &d_i);

            each_party_pde_ciphertexts.insert(i, pd_e);
            each_party_pds_ciphertexts.insert(i, pd_s);
        }

        let mut each_party_e = BTreeMap::new();
        let mut each_party_s = BTreeMap::new();
        for i in 1..=n {
            let ec = each_party_e_ciphertexts.get(&i).unwrap().clone();
            let sc = each_party_s_ciphertexts.get(&i).unwrap().clone();

            let pd_e = each_party_pde_ciphertexts
                .values()
                .cloned()
                .into_iter()
                .reduce(|acc, pd_i| acc.compose(cl, &pd_i))
                .unwrap();

            let pd_s = each_party_pds_ciphertexts
                .values()
                .cloned()
                .into_iter()
                .reduce(|acc, pd_i| acc.compose(cl, &pd_i))
                .unwrap();

            let e = cl.dlog_in_F(&ec.c2().compose(&cl, &pd_e.exp(&cl, &Mpz::from(-1i64))));
            let s = cl.dlog_in_F(&sc.c2().compose(&cl, &pd_s.exp(&cl, &Mpz::from(-1i64))));

            // let tmp = e.to_bytes();
            // let tmp_2: [u8; 64] = tmp.try_into().unwrap();
            // let e_scalar = Scalar::from_bytes_wide(&tmp_2);
            let mut e_bytes: [u8; 32] = e.to_bytes().try_into().unwrap();
            e_bytes.reverse();
            let e_scalar = Scalar::from_bytes(&e_bytes).unwrap();

            each_party_e.insert(i, e_scalar);

            // let tmp = s.to_bytes();
            // let tmp_2: [u8; 64] = tmp.try_into().unwrap();
            // let s_scalar = Scalar::from_bytes_wide(&tmp_2);
            let mut s_bytes: [u8; 32] = s.to_bytes().try_into().unwrap();
            s_bytes.reverse();
            let s_scalar = Scalar::from_bytes(&s_bytes).unwrap();

            each_party_s.insert(i, s_scalar);
        }
        let cl_pk = key_msg.cl_keys.pub_key.clone();
        let eg_pk = key_msg.eg_keys.pub_key.clone();
        let mut msg = Vec::with_capacity(n);
        let H = key_msg.sign_keys.H.clone();
        for i in 1..=n {
            let e_x_ciphertext = each_party_e_x_ciphertexts.get(&i).unwrap().clone();
            let gamma_i = Scalar::random(chacharng.clone());
            let cl_rand1 = rng.random_mpz(&cl.encrypt_randomness_bound());
            let ct_pow = CipherText::new(
                &e_x_ciphertext
                    .c1()
                    .exp(&cl, &Mpz::from(&gamma_i))
                    .compose(&cl, &cl.power_of_h(&cl_rand1)),
                &e_x_ciphertext
                    .c2()
                    .exp(&cl, &Mpz::from(&gamma_i))
                    .compose(&cl, &cl_pk.exponentiation(&cl, &cl_rand1)),
            );
            let s = each_party_s.get(&i).unwrap().clone();
            let eg_rand = Scalar::random(chacharng.clone());
            let mut B = G1Projective::generator();
            for i in 0..l {
                B = B + H[i] * msgs[i];
            }
            B = B + H[l] * s;
            let U1 = G1Projective::generator() * &eg_rand;
            let U2 = B * &gamma_i + eg_pk * &eg_rand;

            let eg_ciphertext = ElGCiphertext {
                c1: U1.into(),
                c2: U2.into(),
            };

            let proof_i = CLELProof::prove(
                &cl,
                &mut rng,
                &mut chacharng.clone(),
                &cl_pk,
                &eg_pk,
                &ct_pow,
                &e_x_ciphertext,
                &eg_ciphertext,
                &B,
                &gamma_i,
                &eg_rand,
                &cl_rand1,
            );
            msg.push((
                i,
                ct_pow.clone(),
                e_x_ciphertext.clone(),
                eg_ciphertext.clone(),
                proof_i,
                B.clone(),
            ));
        }

        let mut each_party_gamma_e_x_ciphertext = BTreeMap::new();
        let mut each_party_eg_ciphertext = BTreeMap::new();
        for i in 1..=n {
            let ciphertexts: Vec<_> = msg
                .iter()
                .filter_map(
                    |(j, gamma_i_e_x_ciphertext, e_x_ciphertext, eg_ciphertext, proof, B)| {
                        //if proof.verify(pp, &pp.pk, ki_ciphertext) && *j != i {
                        if proof.verify(
                            &cl,
                            &mut rng,
                            &cl_pk,
                            &eg_pk,
                            &gamma_i_e_x_ciphertext,
                            &e_x_ciphertext,
                            &eg_ciphertext,
                            &B,
                        ) {
                            //Some((*j, gammai_ciphertext.clone(), proof.clone()))
                            Some((gamma_i_e_x_ciphertext.clone(), eg_ciphertext.clone()))
                        } else {
                            None
                        }
                    },
                )
                .collect();
            let (gamma_e_x_ciphertext, eg_ciphertext) = ciphertexts
                .into_iter()
                .reduce(|(acc1, acc2), (ct1, ct2)| {
                    let pro_acc2_c1: G1Projective = acc2.c1.into();
                    let pro_acc2_c2: G1Projective = acc2.c2.into();
                    let pro_ct2_c1: G1Projective = ct2.c1.into();
                    let pro_ct2_c2: G1Projective = ct2.c2.into();
                    (
                        CipherText::new(
                            &acc1.c1().compose(&cl, &ct1.c1()),
                            &acc1.c2().compose(&cl, &ct1.c2()),
                        ),
                        ElGCiphertext {
                            c1: (pro_acc2_c1 + pro_ct2_c1).into(),
                            c2: (pro_acc2_c2 + pro_ct2_c2).into(),
                        },
                    )
                })
                .unwrap();
            each_party_gamma_e_x_ciphertext.insert(i, gamma_e_x_ciphertext);
            each_party_eg_ciphertext.insert(i, eg_ciphertext);
        }
        let mut each_party_pd_gamma_e_x_ciphertext = BTreeMap::new();
        let mut each_party_pd_eg_ciphertext: BTreeMap<
            usize,
            (G1Projective, G1Projective, G1Projective, ELPDProof),
        > = BTreeMap::new();
        for i in 1..=n {
            let gamma_e_x_ciphertext = each_party_gamma_e_x_ciphertext.get(&i).unwrap().clone();
            let eg_ciphertext = each_party_eg_ciphertext.get(&i).unwrap().clone();
            let cl_pub_share = key_msg.cl_keys.pk_shares.get(&i).unwrap().clone();
            let eg_pub_share = key_msg.eg_keys.pub_shares.get(&i).unwrap().clone();
            let cl_d_i = key_msg.cl_keys.sk_shares.get(&i).unwrap().clone();
            let eg_d_i = key_msg.eg_keys.sk_shares.get(&i).unwrap().clone();

            let pd_gamma_e_x_ciphertext = gamma_e_x_ciphertext.c1().exp(&cl, &cl_d_i);
            let proof_pd_gamma_e_x = CLPDProof::prove(
                &cl,
                rng,
                &cl_pub_share,
                &pd_gamma_e_x_ciphertext,
                &gamma_e_x_ciphertext.c1(),
                &cl_d_i,
            );

            each_party_pd_gamma_e_x_ciphertext.insert(
                i,
                (
                    cl_pub_share,
                    pd_gamma_e_x_ciphertext,
                    gamma_e_x_ciphertext.c1(),
                    proof_pd_gamma_e_x,
                ),
            );

            let pd_eg_ciphertext = &eg_ciphertext.c1 * &eg_d_i;
            let proof_pd_eg = ELPDProof::prove(
                &mut chacharng.clone(),
                &pd_eg_ciphertext,
                &eg_ciphertext.c1.into(),
                &eg_pub_share,
                &eg_d_i,
            );
            each_party_pd_eg_ciphertext.insert(
                i,
                (
                    pd_eg_ciphertext,
                    eg_ciphertext.c1.into(),
                    eg_pub_share,
                    proof_pd_eg,
                ),
            );
        }

        // for i in 1..=n {
        //     let gamma_e_x_ciphertext = each_party_gamma_e_x_ciphertext.get(&i).unwrap().clone();
        //     let eg_ciphertext = each_party_eg_ciphertext.get(&i).unwrap().clone();

        //     let pd_gamma_e_x = each_party_pd_gamma_e_x_ciphertext
        //         .values()
        //         .cloned()
        //         .into_iter()
        //         .reduce(|acc, pd_i| acc.compose(cl, &pd_i))
        //         .unwrap();

        //     let gamma_e_x = cl.dlog_in_F(
        //         &gamma_e_x_ciphertext
        //             .c2()
        //             .compose(&cl, &pd_gamma_e_x.exp(&cl, &Mpz::from(-1i64))),
        //     );

        //     let gamma_e_x = Scalar::from_str_vartime(&gamma_e_x.to_string()).unwrap();

        //     let pd_eg = each_party_pd_eg_ciphertext
        //         .values()
        //         .cloned()
        //         .into_iter()
        //         .reduce(|acc, pd_i| acc + pd_i)
        //         .unwrap();

        //     let EG = eg_ciphertext.c2 - pd_eg;

        //     let A = EG * gamma_e_x.invert().unwrap();
        // }
        Self {
            each_party_gamma_e_x_ciphertext,
            each_party_eg_ciphertext,
            each_party_pd_gamma_e_x_ciphertext,
            each_party_pd_eg_ciphertext,
            e: each_party_e.get(&1).unwrap().clone(),
            s: each_party_s.get(&1).unwrap().clone(),
        }
    }

    pub fn client(cl: &CL_HSMqk, sign_msg: &Sign) {
        let gamma_e_x_ciphertext = sign_msg
            .each_party_gamma_e_x_ciphertext
            .get(&1)
            .unwrap()
            .clone();
        let eg_ciphertext = sign_msg.each_party_eg_ciphertext.get(&1).unwrap().clone();

        let pd_gamma_e_xs: Vec<_> = sign_msg
            .each_party_pd_gamma_e_x_ciphertext
            .values()
            .into_iter()
            .filter_map(
                |(
                    cl_pub_share,
                    pd_gamma_e_x_ciphertext,
                    gamma_e_x_ciphertext_c1,
                    proof_pd_gamma_e_x,
                )| {
                    //if proof.verify(pp, &pp.pk, ki_ciphertext) && *j != i {
                    if proof_pd_gamma_e_x.verify(
                        &cl,
                        &cl_pub_share,
                        &pd_gamma_e_x_ciphertext,
                        &gamma_e_x_ciphertext_c1,
                    ) {
                        //Some((*j, gammai_ciphertext.clone(), proof.clone()))
                        Some(pd_gamma_e_x_ciphertext.clone())
                    } else {
                        None
                    }
                },
            )
            .collect();

        let pd_gamma_e_x = pd_gamma_e_xs
            .into_iter()
            .reduce(|acc, pd_i| acc.compose(cl, &pd_i))
            .unwrap();

        let gamma_e_x = cl.dlog_in_F(
            &gamma_e_x_ciphertext
                .c2()
                .compose(&cl, &pd_gamma_e_x.exp(&cl, &Mpz::from(-1i64))),
        );

        let gamma_e_x = Scalar::from_str_vartime(&gamma_e_x.to_string()).unwrap();

        let pd_egs: Vec<_> = sign_msg
            .each_party_pd_eg_ciphertext
            .values()
            .into_iter()
            .filter_map(
                |(pd_eg_ciphertext, eg_ciphertext_c1, eg_pub_share, proof_pd_eg)| {
                    //if proof.verify(pp, &pp.pk, ki_ciphertext) && *j != i {
                    if proof_pd_eg.verify(pd_eg_ciphertext, eg_ciphertext_c1, eg_pub_share) {
                        //Some((*j, gammai_ciphertext.clone(), proof.clone()))
                        Some(pd_eg_ciphertext.clone())
                    } else {
                        None
                    }
                },
            )
            .collect();

        let pd_eg = pd_egs.into_iter().reduce(|acc, pd_i| acc + pd_i).unwrap();

        let EG = eg_ciphertext.c2 - pd_eg;

        let A = EG * gamma_e_x.invert().unwrap();
    }
}

mod tests {
    use curv::{arithmetic::Converter, BigInt};
    use rand::SeedableRng;

    use crate::MODULUS;

    use super::*;

    #[test]
    fn test_clsign() {
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
        let l = 10;
        let mut msg: Vec<Scalar> = Vec::with_capacity(l);

        for i in 0..l {
            let tmp = Scalar::random(scalr_rng.clone());
            msg.push(tmp);
        }
        let key_msg = KeyGen::keygen(&cl, n, l, &mut rng, &mut scalr_rng);
        let sign_msg = Sign::sign(&cl, n, l, &mut rng, &mut scalr_rng, &key_msg, &msg);
        Sign::client(&cl, &sign_msg);
    }
}
