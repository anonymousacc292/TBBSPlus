use bicycl::QFI;
use ff::PrimeField;

use crate::{CLRandProof, CLRandYuanProof};

use super::*;

pub struct Sign {
    pub H: Vec<G1Projective>,
    pub X: G2Projective,
    pub e: Scalar,
    pub s: Scalar,
    pub zis: BTreeMap<usize, Scalar>,
    pub Bis: BTreeMap<usize, G1Projective>,
    pub pdis: BTreeMap<usize, QFI>,
    pub n_cube: Mpz,
}

impl Sign {
    pub fn sign(
        cl: &CL_HSMqk,
        n: usize,
        l: usize,
        mut rng: &mut RandGen,
        chacharng: &mut ChaChaRng,
        key_msg: &KeyGen,
        msg: &[Scalar],
        q: &Mpz,
    ) -> Self {
        let mut eis = Vec::with_capacity(n);
        let mut sis = Vec::with_capacity(n);

        let mut es = Vec::with_capacity(n);
        let mut ss = Vec::with_capacity(n);

        let mut each_party_gammaix_ct1 = Vec::with_capacity(n as usize);
        let mut each_party_gammaix_ct2 = BTreeMap::new();

        let mut each_party_gammai = BTreeMap::new();

        let mut zis: BTreeMap<usize, Scalar> = BTreeMap::new();
        let mut Bis: BTreeMap<usize, G1Projective> = BTreeMap::new();
        let mut pdis: BTreeMap<usize, QFI> = BTreeMap::new();
        for _ in 1..=n {
            eis.push(Scalar::random(chacharng.clone()));
            sis.push(Scalar::random(chacharng.clone()));
        }

        for (i, item) in key_msg.each_party_x_ciphertexts.clone() {
            let e = eis
                .clone()
                .into_iter()
                .reduce(|acc, e_i| acc + e_i)
                .unwrap();
            let s = sis
                .clone()
                .into_iter()
                .reduce(|acc, e_i| acc + e_i)
                .unwrap();

            let gamma_i = Scalar::random(chacharng.clone());

            each_party_gammai.insert(i, gamma_i);

            let r = rng.random_mpz(&cl.encrypt_randomness_bound());

            let ct1_pow = item
                .c1()
                .exp(&cl, &Mpz::from(&gamma_i))
                .compose(&cl, &cl.power_of_h(&r));

            let ct2_pow = item
                .c2()
                .exp(&cl, &Mpz::from(&gamma_i))
                .compose(&cl, &key_msg.cl_keys.pub_key.exponentiation(cl, &r));

            each_party_gammaix_ct2.insert(i, ct2_pow);
            //let gammaix_ciphertext = CipherText::new(&ct1_pow, &ct2_pow);

            let proof_i = CLRandYuanProof::prove(
                &cl,
                &mut rng,
                &ct1_pow,
                &item.c1(),
                &gamma_i,
                &r,
                &q,
                &cl.encrypt_randomness_bound(),
            );

            es.push(e);
            ss.push(s);

            each_party_gammaix_ct1.push((i, ct1_pow.clone(), item.c1().clone(), proof_i))
        }

        for (i, _) in es.iter().enumerate() {
            if i != 0 {
                assert_eq!(es[i - 1].clone(), es[i].clone());
                assert_eq!(ss[i - 1].clone(), ss[i].clone());
            }
        }

        let mut each_party_gammax_ct1 = BTreeMap::new();

        for i in 1..=n {
            let gammaix_ct1: Vec<_> = each_party_gammaix_ct1
                .iter()
                .filter_map(|(_, ct1_pow, ct1_gen, proof)| {
                    //if proof.verify(pp, &pp.pk, ki_ciphertext) && *j != i {
                    // if proof.verify(&cl, &ct1_pow, ct1_gen, &q) {
                    //     //Some((*j, gammai_ciphertext.clone(), proof.clone()))
                    //     Some(ct1_pow.clone())
                    // } else {
                    //     None
                    // }
                    proof.verify(&cl, &ct1_pow, ct1_gen, &q);
                    Some(ct1_pow.clone())
                })
                .collect();

            let gammax_ct1 = gammaix_ct1
                .into_iter()
                .reduce(|acc, ct| acc.compose(&cl, &ct))
                .unwrap();
            each_party_gammax_ct1.insert(i, gammax_ct1);
        }

        let H = key_msg.sign_keys.H.clone();

        let n_cube = key_msg.cl_keys.n_factorial.clone()
            * key_msg.cl_keys.n_factorial.clone()
            * key_msg.cl_keys.n_factorial.clone();
        for i in 1..=n {
            let mut B = G1Projective::generator();
            let e = es[i - 1];
            let s = ss[i - 1];
            let rho_i = Scalar::random(chacharng.clone());
            let gamma_i = each_party_gammai.get(&i).unwrap().clone();
            let ct1 = each_party_gammax_ct1.get(&i).unwrap().clone();
            let ct2 = each_party_gammaix_ct2.get(&i).unwrap().clone();
            let d_i = key_msg.cl_keys.sk_shares.get(&i).unwrap().clone();
            for i in 0..l {
                B = B + H[i] * msg[i];
            }
            B = B + H[l] * s;

            let Bi = gamma_i * B;
            let zi = gamma_i * e - rho_i;

            let pd_i = ct1.exp(cl, &d_i);
            let mut v_yi = ct2.compose(cl, &cl.power_of_f(&Mpz::from(&rho_i)));
            v_yi = v_yi.exp(cl, &n_cube);

            let pd_i_v2 = v_yi.compose(&cl, &pd_i.exp(&cl, &Mpz::from(-1i64)));

            Bis.insert(i, Bi);
            zis.insert(i, zi);
            pdis.insert(i, pd_i_v2);
        }

        Self {
            H,
            X: key_msg.sign_keys.pub_key,
            e: es[0],
            s: ss[0],
            zis,
            Bis,
            pdis,
            n_cube,
        }
    }

    pub fn client(cl: &CL_HSMqk, sign_msg: &Sign, msg: &[Scalar], l: usize) {
        let B = sign_msg
            .Bis
            .values()
            .cloned()
            .into_iter()
            .reduce(|acc, B_i| acc + B_i)
            .unwrap();

        let pd = sign_msg
            .pdis
            .values()
            .cloned()
            .into_iter()
            .reduce(|acc, pd_i| acc.compose(&cl, &pd_i))
            .unwrap();

        let beta = sign_msg
            .zis
            .values()
            .cloned()
            .into_iter()
            .reduce(|acc, z_i| acc + z_i)
            .unwrap();

        let y = cl.dlog_in_F(&pd);

        let mut y_scalar = Scalar::from_str_vartime(&y.to_string()).unwrap();

        let mut f_cube = Scalar::from_str_vartime(&sign_msg.n_cube.to_string()).unwrap();
        f_cube = f_cube.invert().unwrap().clone();
        y_scalar = y_scalar * f_cube;

        let inv = (y_scalar + beta).invert().unwrap();
        let A = B * inv;
        let e = sign_msg.e;
        let s = sign_msg.s;
        let key = BBSPlusKey {
            x: sign_msg.e,
            X: sign_msg.X,
            H: sign_msg.H.clone(),
        };
        let sig = BBSPlusSig { A, e, s };
        BBSPlusSig::verify(&key, msg, l, &sig);
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

        let q = Mpz::from_bytes(&BigInt::from_hex(MODULUS).unwrap().to_bytes());
        let cl = CL_HSMqk::with_rand_gen(
            &q,
            1,
            1827,
            &mut rng,
            &(Mpz::from_bytes(&(BigInt::from(1) << 40).to_bytes())),
            false,
        );
        let n = 5;
        let t = 5;
        let l = 10;
        let mut msg: Vec<Scalar> = Vec::with_capacity(l);

        for i in 0..l {
            let tmp = Scalar::random(scalr_rng.clone());
            msg.push(tmp);
        }
        let key_msg = KeyGen::keygen(&cl, t, n, l, &mut rng, &mut scalr_rng);
        let sign_msg = Sign::sign(&cl, t, l, &mut rng, &mut scalr_rng, &key_msg, &msg, &q);
        Sign::client(&cl, &sign_msg, &msg, l);
    }
}
