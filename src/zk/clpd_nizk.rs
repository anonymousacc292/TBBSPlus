use bicycl::CL_HSMqk;

use super::*;

#[derive(Clone, Debug, PartialEq)]
pub struct CLPDProof {
    pub e: Scalar,
    pub z_1: Mpz,
}

impl CLPDProof {
    pub fn prove(pp: &CL_HSMqk, rng: &mut RandGen, _: &QFI, pd: &QFI, c1: &QFI, d_i: &Mpz) -> Self {
        let u_1 = rng.random_mpz(&pp.encrypt_randomness_bound());

        let U1 = c1.exp(&pp, &u_1);
        let U2 = pp.power_of_h(&u_1);

        let e = Self::challenge(pd, c1, &U1, &U2);
        let z_1 = &u_1 + Mpz::from(&e) * d_i;

        Self { e, z_1 }
    }

    pub fn verify(&self, pp: &CL_HSMqk, cl_pub_share: &QFI, pd: &QFI, c1: &QFI) -> bool {
        let U1 = c1
            .exp(&pp, &self.z_1)
            .compose(&pp, &pd.exp(&pp, &-Mpz::from(&self.e)));
        let U2 = pp
            .power_of_h(&self.z_1)
            .compose(&pp, &cl_pub_share.exp(&pp, &-Mpz::from(&self.e)));

        let e = Self::challenge(pd, c1, &U1, &U2);
        e == self.e
    }

    fn challenge(pow1: &QFI, gen1: &QFI, U1: &QFI, U2: &QFI) -> Scalar {
        let mut hasher = Sha512::new();

        for item in &[
            pow1.to_bytes(),
            gen1.to_bytes(),
            U1.to_bytes(),
            U2.to_bytes(),
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
        let cl_pk = cl.power_of_h(&cl_sk);

        let cl_rand = rng.random_mpz(&cl.encrypt_randomness_bound());
        let c1 = cl.power_of_h(&cl_rand);

        let pd = c1.exp(&cl, &cl_sk);

        let proof = CLPDProof::prove(&cl, &mut rng, &cl_pk, &pd, &c1, &cl_sk);

        assert_eq!(true, proof.verify(&cl, &cl_pk, &pd, &c1));
    }
}
