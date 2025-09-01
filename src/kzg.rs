use ark_bls12_381::{Bls12_381, Fr};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, Radix2EvaluationDomain as Domain, Polynomial};
use ark_poly_commit::{kzg10::{Commitment, Powers, Proof, UniversalParams, VerifierKey, KZG10}, PCCommitmentState};

use crate::{utils::evals_to_poly, vc::{VectorCommitment, ARITY}};

type KZG = KZG10::<Bls12_381, DensePolynomial<Fr>>;

#[derive(Clone)]
pub struct KzgVc<'a> {
    domain: Domain<Fr>,            // size ARITY, fixed points {ω^i}
    powers: Powers<'a, Bls12_381>, // trimmed prover key up to degree < ARITY
    vk: VerifierKey<Bls12_381>,
}

impl<'a> KzgVc<'a> {
    pub fn setup(rng: &mut impl rand::RngCore) -> Result<Self, Box<dyn std::error::Error>> {
        assert!(ARITY.is_power_of_two(), "use a radix-2 domain for simplicity");
        let domain = Domain::<Fr>::new(ARITY).expect("domain");
        // KZG universal setup for degree < k
        let max_degree = ARITY - 1;
        let srs: UniversalParams<Bls12_381> =
           KZG::setup(max_degree, false, rng)?;

        let powers_of_g = srs.powers_of_g[..=ARITY].to_vec();
        let powers_of_gamma_g = (0..=ARITY).map(|i| srs.powers_of_gamma_g[&i]).collect();

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
            domain,
            powers,
            vk,
        })
    }
}

impl<'a> VectorCommitment for KzgVc<'a> {
    type Fr = Fr;
    type Commitment = Commitment<Bls12_381>;
    type Proof = Proof<Bls12_381>;

    fn commit_from_children(&self, children: &[Self::Fr; ARITY]) -> Self::Commitment {
        // Calculate coefficients
        let poly = evals_to_poly::<Self>(&self.domain, children);

        // Evaluate poly at the appropriate points
        let (comm, _rand) = KZG::commit(&self.powers, &poly, None, None)
            .expect("commitment");

        comm
    }

   fn open_at(&self, evals: &[Self::Fr; ARITY], index: usize) -> (Self::Fr, Self::Proof) {
       let poly = evals_to_poly::<Self>(&self.domain, evals);
       let point = self.domain.element(index);
       let value = poly.evaluate(&point);

       let rand = ark_poly_commit::kzg10::Randomness::empty();
        let proof = KZG::open(&self.powers, &poly, point, &rand)
            .expect("open");
        (value, proof)
   }

    fn verify_at(
        &self,
        comm: &Self::Commitment, index: usize, value: Self::Fr, proof: &Self::Proof,
    ) -> bool {
        // Implement verification logic
        let point = self.domain.element(index);
        KZG::check(&self.vk, comm, point, value, proof).expect("verification")
    }
}
