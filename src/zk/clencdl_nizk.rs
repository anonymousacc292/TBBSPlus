use bls12_381::{G2Affine, G2Projective};
use ff::PrimeField;

use super::*;

#[derive(Clone, Debug, PartialEq)]
pub struct CLEncProof {
    pub e: Scalar,
    pub z1: Mpz,
    pub z2: Mpz,
}

impl CLEncProof {
    pub fn prove(
        pp: &CL_HSMqk,
        rng: &mut RandGen,
        clpk: &PublicKey,
        clct: &CipherText,
        pubk: &G2Projective,
        m: &Scalar,
        cl_rand: &Mpz,
        chacharng: &mut ChaChaRng,
    ) -> Self {
        let u1 = rng.random_mpz(&pp.encrypt_randomness_bound());
        let u2 = Scalar::random(chacharng);

        let U1 = pp.power_of_h(&u1);
        let U2 = pp
            .power_of_f(&Mpz::from(&u2))
            .compose(&pp, &clpk.exponentiation(&pp, &u1));

        let U3 = G2Projective::generator() * u2;

        let e = Self::challenge(clpk, clct, &U1, &U2, &pubk.into(), &U3.into());
        let z1 = &u1 + Mpz::from(&e) * cl_rand;
        let z2 = Mpz::from(&u2) + Mpz::from(&e) * Mpz::from(m);

        Self { e, z1, z2 }
    }

    pub fn verify(
        &self,
        pp: &CL_HSMqk,
        clpk: &PublicKey,
        clct: &CipherText,
        pubk: &G2Projective,
    ) -> bool {
        let U1 = pp
            .power_of_h(&self.z1)
            .compose(&pp, &clct.c1().exp(&pp, &-Mpz::from(&self.e)));
        let U2 = pp
            .power_of_f(&self.z2)
            .compose(&pp, &clpk.exponentiation(&pp, &self.z1))
            .compose(&pp, &clct.c2().exp(&pp, &-Mpz::from(&self.e)));

        // let mut z_2_bytes:[u8; 64] = self.z2.to_bytes().try_into().unwrap();
        // z_2_bytes.reverse();
        // let z_2_scalar = Scalar::from_bytes_wide(&z_2_bytes);
        let z_2_scalar = Scalar::from_str_vartime(&self.z2.to_string()).unwrap();

        let U3 = G2Projective::generator() * &z_2_scalar - pubk * self.e;

        let e = Self::challenge(clpk, clct, &U1, &U2, &pubk.into(), &U3.into());
        e == self.e
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

    fn challenge(
        clpk: &PublicKey,
        clct: &CipherText,
        U1: &QFI,
        U2: &QFI,
        pubk: &G2Affine,
        U3: &G2Affine,
    ) -> Scalar {
        let mut hasher = Sha512::new();

        for item in &[
            clpk.to_bytes(),
            clct.c1().to_bytes(),
            clct.c2().to_bytes(),
            U1.to_bytes(),
            U2.to_bytes(),
            pubk.to_compressed().into(),
            U3.to_compressed().into(),
        ] {
            hasher.update(item);
        }

        let tmp = hasher.finalize()[0..64].to_vec();
        let tmp_2: [u8; 64] = tmp.try_into().unwrap();

        Scalar::from_bytes_wide(&tmp_2)
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
        let pubk: G2Projective = G2Projective::generator() * m;
        let cl_rand = rng.random_mpz(&cl.encrypt_randomness_bound());
        let c1 = cl.power_of_h(&cl_rand);
        let c2 = cl
            .power_of_f(&Mpz::from(&m))
            .compose(&cl, &pk.exponentiation(&cl, &cl_rand));

        let ct = CipherText::new(&c1, &c2);

        let proof = CLEncProof::prove(
            &cl,
            &mut rng,
            &pk,
            &ct,
            &pubk,
            &m,
            &cl_rand,
            &mut scalr_rng.clone(),
        );
        assert_eq!(true, proof.verify(&cl, &pk, &ct, &pubk));
    }
}
