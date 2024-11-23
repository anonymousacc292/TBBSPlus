use bicycl::CL_HSMqk;
use bicycl::CipherText;
use bicycl::Mpz;
use bicycl::PublicKey;
use bicycl::RandGen;
use bls12_381::{pairing, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;
use rand_chacha::ChaChaRng;
use std::collections::BTreeMap;

use crate::CLEncProof;
use crate::ComZkDlComElproof;

pub mod keygen;
pub use keygen::*;
pub mod sign;
pub use sign::*;

#[derive(Clone, Debug, PartialEq)]
pub struct BBSPlusKey {
    pub x: Scalar,
    pub X: G2Projective,
    pub H: Vec<G1Projective>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BBSPlusSig {
    pub A: G1Projective,
    pub e: Scalar,
    pub s: Scalar,
}

impl BBSPlusKey {
    pub fn keygen(rng: &mut ChaChaRng, l: usize) -> Self {
        let x = Scalar::random(rng.clone());
        let X = G2Projective::generator() * x;

        let mut H: Vec<G1Projective> = Vec::with_capacity(l);

        for _ in 0..=l {
            let tmp = Scalar::random(rng.clone());
            H.push(G1Projective::generator() * tmp);
        }

        Self { x, X, H }
    }
}

impl BBSPlusSig {
    pub fn sign(rng: &mut ChaChaRng, key: &BBSPlusKey, msg: &[Scalar], l: usize) -> Self {
        let e = Scalar::random(rng.clone());
        let s = Scalar::random(rng.clone());
        let mut B = G1Projective::generator();

        for i in 0..l {
            B = B + key.H[i] * msg[i];
        }

        B = B + key.H[l] * s;

        let xeinv = (key.x + e).invert().unwrap();

        let A = B * xeinv;

        Self { A: A.into(), e, s }
    }

    pub fn verify(key: &BBSPlusKey, msg: &[Scalar], l: usize, sig: &BBSPlusSig) {
        let mut B = G1Projective::generator();
        for i in 0..l {
            B = B + key.H[i] * msg[i];
        }
        B = B + key.H[l] * sig.s;

        let p = pairing(
            &sig.A.into(),
            &(key.X + G2Projective::generator() * sig.e).into(),
        );
        let q = pairing(&B.into(), &G2Affine::generator());

        assert_eq!(p, q);
    }
}

#[cfg(test)]
mod tests {

    use bicycl::{CL_HSMqk, Mpz, PublicKey, RandGen};
    use bls12_381::Scalar;
    use curv::{arithmetic::Converter, BigInt};
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use sha2::{Digest, Sha256};

    use crate::MODULUS;

    use super::*;

    #[test]
    fn test_sign() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let l = 10;

        let mut msg: Vec<Scalar> = Vec::with_capacity(l);

        for _ in 0..l {
            let tmp = Scalar::random(rng.clone());
            msg.push(tmp);
        }

        let key = BBSPlusKey::keygen(&mut rng, l);
        let sig = BBSPlusSig::sign(&mut rng, &key, &msg, l);

        BBSPlusSig::verify(&key, &msg, l, &sig);
    }

    #[test]
    fn test_hash_tocurve() {
        let seed = [0u8; 32];
        let rng = ChaChaRng::from_seed(seed);
        let mut hasher = Sha256::new();

        let x = Scalar::random(rng.clone());
        let X = G2Projective::generator() * x;

        let X_A: G2Affine = X.into();

        for item in &[X_A.to_compressed()] {
            hasher.update(item);
        }

        let res = hasher.finalize().to_vec();

        print!("{:?}", res);
    }

    #[test]
    fn test_encryption() {
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

        let sk = rng.random_mpz(&cl.encrypt_randomness_bound());
        let pk = PublicKey::from_qfi(&cl, &cl.power_of_h(&sk));

        let m = Scalar::random(scalr_rng);
        let cl_rand = rng.random_mpz(&cl.encrypt_randomness_bound());
        let c1 = cl.power_of_h(&cl_rand);
        let c2 = cl
            .power_of_f(&Mpz::from(&m))
            .compose(&cl, &pk.exponentiation(&cl, &cl_rand));

        let pd = c1.exp(&cl, &sk);
        let f_m = c2.compose(&cl, &pd.exp(&cl, &Mpz::from(-1i64)));

        let m_recover = cl.dlog_in_F(&f_m);

        let m_rev_scalar = Scalar::from_bytes(&m_recover.to_bytes().try_into().unwrap()).unwrap();

        assert_eq!(m, m_rev_scalar)
    }

    #[test]
    fn test_scalar() {
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

        let sk = rng.random_mpz(&cl.encrypt_randomness_bound());
        let pk = PublicKey::from_qfi(&cl, &cl.power_of_h(&sk));

        let m = Scalar::random(scalr_rng.clone());
        let cl_rand = rng.random_mpz(&cl.encrypt_randomness_bound());
        let c1 = cl.power_of_h(&cl_rand);
        let c2 = cl
            .power_of_f(&Mpz::from(&m))
            .compose(&cl, &pk.exponentiation(&cl, &cl_rand));

        let gamma = Scalar::random(scalr_rng.clone());
        //let gamma = Scalar::one();
        let c1_s = c1.exp(&cl, &Mpz::from(&gamma));
        let c2_s = c2.exp(&cl, &Mpz::from(&gamma));

        let pd = c1_s.exp(&cl, &sk);
        let f_m = c2_s.compose(&cl, &pd.exp(&cl, &Mpz::from(-1i64)));

        let m_recover = cl.dlog_in_F(&f_m);

        let mut tmp: [u8; 32] = m_recover.to_bytes().try_into().unwrap();
        tmp.reverse();
        let m_rev_scalar = Scalar::from_bytes(&tmp).unwrap();

        let m_gamma = m * gamma;

        assert_eq!(m_gamma, m_rev_scalar)
    }

    #[test]
    fn test_size() {
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

        let sk = rng.random_mpz(&cl.encrypt_randomness_bound());
        let pk = PublicKey::from_qfi(&cl, &cl.power_of_h(&sk));

        let m = Scalar::random(scalr_rng.clone());
        let cl_rand = rng.random_mpz(&cl.encrypt_randomness_bound());
        let c1 = cl.power_of_h(&cl_rand);
        let c2 = cl
            .power_of_f(&Mpz::from(&m))
            .compose(&cl, &pk.exponentiation(&cl, &cl_rand));

        println!("{:?}", cl.encrypt_randomness_bound().to_bytes().len());
        println!("{:?}", c1.to_bytes().len());
        println!("{:?}", c2.to_bytes().len());
    }
}
