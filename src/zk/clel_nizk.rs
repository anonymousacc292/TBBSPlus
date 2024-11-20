use bicycl::CL_HSMqk;
use bls12_381::{G1Affine, G1Projective};
use ff::PrimeField;

use crate::wmc24::ElGCiphertext;

use super::*;

#[derive(Clone, Debug, PartialEq)]
pub struct CLELProof {
    pub e: Scalar,
    pub z_1: Mpz,
    pub z_2: Mpz,
    pub z_3: Mpz,
}

impl CLELProof {
    pub fn prove(
        pp: &CL_HSMqk,
        rng: &mut RandGen,
        chacharng: &mut ChaChaRng,
        cl_pk: &PublicKey,
        eg_pk: &G1Projective,
        pow1: &CipherText,
        gen1: &CipherText,
        pow2: &ElGCiphertext,
        gen2: &G1Projective,
        gammai: &Scalar,
        eg_rand: &Scalar,
        cl_rand: &Mpz,
    ) -> Self {
        let u_1 = Scalar::random(chacharng.clone()); //gamma
        let u_2 = Scalar::random(chacharng.clone()); //random
        let u_3 = rng.random_mpz(&pp.encrypt_randomness_bound());

        let U1 = gen1
            .c1()
            .exp(&pp, &Mpz::from(&u_1))
            .compose(&pp, &pp.power_of_h(&u_3));
        let U2 = gen1
            .c2()
            .exp(&pp, &Mpz::from(&u_1))
            .compose(&pp, &cl_pk.exponentiation(&pp, &u_3));
        let U3 = G1Projective::generator() * &u_2;
        let U4 = gen2 * &u_1 + eg_pk * &u_2;

        let e = Self::challenge(pow1, pow2, &U1, &U2, &U3.into(), &U4.into());
        let z_1 = Mpz::from(&u_1) + Mpz::from(&e) * Mpz::from(gammai);
        let z_2 = Mpz::from(&u_2) + Mpz::from(&e) * Mpz::from(eg_rand);
        let z_3 = u_3 + Mpz::from(&e) * cl_rand;

        Self {
            e,
            z_1,
            z_2,
            z_3,
            // z_1s,
            // z_2s,
        }
    }

    pub fn verify(
        &self,
        pp: &CL_HSMqk,
        _: &mut RandGen,
        cl_pk: &PublicKey,
        eg_pk: &G1Projective,
        pow1: &CipherText,
        gen1: &CipherText,
        pow2: &ElGCiphertext,
        gen2: &G1Projective,
    ) -> bool {
        let U1 = gen1
            .c1()
            .exp(&pp, &self.z_1)
            .compose(&pp, &pp.power_of_h(&self.z_3))
            .compose(&pp, &pow1.c1().exp(&pp, &-Mpz::from(&self.e)));
        let U2 = gen1
            .c2()
            .exp(&pp, &self.z_1)
            .compose(&pp, &cl_pk.exponentiation(&pp, &self.z_3))
            .compose(&pp, &pow1.c2().exp(&pp, &-Mpz::from(&self.e)));

        // let mut z_2_bytes:[u8; 64] = self.z_2.to_bytes().try_into().unwrap();
        // z_2_bytes.reverse();
        // let z_2_scalar = Scalar::from_bytes_wide(&z_2_bytes);
        let z_2_scalar = Scalar::from_str_vartime(&self.z_2.to_string()).unwrap();

        // let mut z_1_bytes:[u8; 64] = self.z_1.to_bytes().try_into().unwrap();
        // z_1_bytes.reverse();
        // let z_1_scalar = Scalar::from_bytes_wide(&z_1_bytes);
        let z_1_scalar = Scalar::from_str_vartime(&self.z_1.to_string()).unwrap();

        let U3 = G1Projective::generator() * &z_2_scalar - &pow2.c1 * &self.e;

        let U4 = gen2 * &z_1_scalar + eg_pk.clone() * &z_2_scalar - &pow2.c2 * &self.e;

        let e = Self::challenge(pow1, pow2, &U1, &U2, &U3.into(), &U4.into());
        e == self.e
    }

    fn challenge(
        pow1: &CipherText,
        pow2: &ElGCiphertext,
        U1: &QFI,
        U2: &QFI,
        U3: &G1Affine,
        U4: &G1Affine,
    ) -> Scalar {
        let mut hasher = Sha512::new();

        for item in &[
            pow1.c1().to_bytes(),
            pow1.c2().to_bytes(),
            pow2.c1.to_compressed().into(),
            pow2.c2.to_compressed().into(),
            U1.to_bytes(),
            U2.to_bytes(),
            U3.to_compressed().into(),
            U4.to_compressed().into(),
        ] {
            hasher.update(item);
        }

        let tmp = hasher.finalize()[0..64].to_vec();
        let tmp_2: [u8; 64] = tmp.try_into().unwrap();

        Scalar::from_bytes_wide(&tmp_2)
    }
}

#[cfg(test)]
mod tests {
    use curv::{arithmetic::Converter, BigInt};
    use rand::SeedableRng;

    use crate::MODULUS;

    use super::*;

    #[test]
    fn test_clel_nizk() {
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
        let cl_sk = rng.random_mpz(&cl.encrypt_randomness_bound());
        let cl_pk = PublicKey::from_qfi(&cl, &cl.power_of_h(&cl_sk));

        let eg_sk = Scalar::random(scalr_rng.clone());
        let eg_pk = G1Projective::generator() * eg_sk;

        let m = Scalar::random(scalr_rng.clone());
        let cl_rand = rng.random_mpz(&cl.encrypt_randomness_bound());
        let c1 = cl.power_of_h(&cl_rand);
        let c2 = cl
            .power_of_f(&Mpz::from(&m))
            .compose(&cl, &cl_pk.exponentiation(&cl, &cl_rand));

        let ct = CipherText::new(&c1, &c2);

        let gamma = Scalar::random(scalr_rng.clone());
        let cl_rand1 = rng.random_mpz(&cl.encrypt_randomness_bound());

        let ct_pow = CipherText::new(
            &ct.c1()
                .exp(&cl, &Mpz::from(&gamma))
                .compose(&cl, &cl.power_of_h(&cl_rand1)),
            &ct.c2()
                .exp(&cl, &Mpz::from(&gamma))
                .compose(&cl, &cl_pk.exponentiation(&cl, &cl_rand1)),
        );

        let k_i = Scalar::random(scalr_rng.clone());
        let B = G1Projective::generator() * k_i;

        let eg_rand = Scalar::random(scalr_rng.clone());
        let U1 = G1Projective::generator() * &eg_rand;
        let U2 = B * &gamma + eg_pk * &eg_rand;

        let eg_ciphertext = ElGCiphertext {
            c1: U1.into(),
            c2: U2.into(),
        };

        let proof = CLELProof::prove(
            &cl,
            &mut rng,
            &mut scalr_rng.clone(),
            &cl_pk,
            &eg_pk,
            &ct_pow,
            &ct,
            &eg_ciphertext,
            &B,
            &gamma,
            &eg_rand,
            &cl_rand1,
        );

        assert_eq!(
            true,
            proof.verify(
                &cl,
                &mut rng,
                &cl_pk,
                &eg_pk,
                &ct_pow,
                &ct,
                &eg_ciphertext,
                &B,
            )
        )
    }
}
