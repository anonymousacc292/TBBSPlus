use bls12_381::{G1Affine, G1Projective};

use super::*;

#[derive(Clone, Debug, PartialEq)]
pub struct ELPDProof {
    pub e: Scalar,
    pub z: Scalar,
}

impl ELPDProof {
    pub fn prove(
        chacharng: &mut ChaChaRng,
        pow: &G1Projective,
        gen: &G1Projective,
        _: &G1Projective,
        xi: &Scalar,
    ) -> Self {
        let u = Scalar::random(chacharng.clone());
        let U1 = gen * &u;
        let U2 = G1Projective::generator() * &u;

        let e = Self::challenge(&pow.into(), &U1.into(), &U2.into());
        let z = &u + &e * xi;

        Self { e, z }
    }

    pub fn verify(&self, pow: &G1Projective, gen: &G1Projective, pubkey: &G1Projective) -> bool {
        let U1 = gen * &self.z - pow * &self.e;
        let U2 = G1Projective::generator() * &self.z - pubkey * &self.e;

        let e = Self::challenge(&pow.into(), &U1.into(), &U2.into());
        e == self.e
    }

    fn challenge(pow: &G1Affine, U1: &G1Affine, U2: &G1Affine) -> Scalar {
        let mut hasher = Sha512::new();

        for item in &[pow.to_compressed(), U1.to_compressed(), U2.to_compressed()] {
            hasher.update(item);
        }

        let tmp = hasher.finalize()[0..64].to_vec();
        let tmp_2: [u8; 64] = tmp.try_into().unwrap();

        Scalar::from_bytes_wide(&tmp_2)
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;

    #[test]
    fn test_pd_nizk() {
        let seed: [u8; 32] = [0u8; 32];
        let mut scalr_rng = ChaChaRng::from_seed(seed);

        let eg_rand = Scalar::random(scalr_rng.clone());
        let U1 = G1Projective::generator() * &eg_rand;

        let eg_sk = Scalar::random(scalr_rng.clone());
        let eg_pk = G1Projective::generator() * eg_sk;

        let pd = U1 * eg_sk;

        let proof = ELPDProof::prove(&mut scalr_rng, &pd, &U1, &eg_pk, &eg_sk);

        assert_eq!(true, proof.verify(&pd, &U1, &eg_pk));
    }
}
