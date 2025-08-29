use ark_bls12_381::{Bls12_381, Fr};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, Radix2EvaluationDomain as Domain};
use ark_poly_commit::kzg10::{Powers, UniversalParams, VerifierKey, KZG10};

pub struct KzgVc<'a> {
    k: usize,                      // branching factor
    domain: Domain<Fr>,            // size k, fixed points {ω^i}
    powers: Powers<'a, Bls12_381>, // trimmed prover key up to degree < k
    vk: VerifierKey<Bls12_381>,
}

impl<'a> KzgVc<'a> {
    fn setup(k: usize, rng: &mut impl rand::RngCore) -> Result<Self, Box<dyn std::error::Error>> {
        assert!(k.is_power_of_two(), "use a radix-2 domain for simplicity");
        let domain = Domain::<Fr>::new(k).expect("domain");
        // KZG universal setup for degree < k
        let max_degree = k - 1;
        let srs: UniversalParams<Bls12_381> =
            KZG10::<Bls12_381, DensePolynomial<Fr>>::setup(max_degree, false, rng)?;

        let powers_of_g = srs.powers_of_g[..=k].to_vec();
        let powers_of_gamma_g = (0..=k).map(|i| srs.powers_of_gamma_g[&i]).collect();

        let powers = Powers {
            powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
            powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
        };
        let vk = VerifierKey {
            g: srs.powers_of_g[0],
            gamma_g: srs.powers_of_gamma_g[&0],
            h: srs.h,
            beta_h: srs.beta_h,
            prepared_h: srs.prepared_h.clone(),
            prepared_beta_h: srs.prepared_beta_h.clone(),
        };

        Ok(Self {
            k,
            domain,
            powers,
            vk,
        })
    }
}
