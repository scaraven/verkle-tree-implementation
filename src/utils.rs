use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Radix2EvaluationDomain as Domain};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

use crate::vc::{VectorCommitment, ZERO32};

#[allow(non_snake_case)]
pub(crate) fn ZERO_CHILD<V: VectorCommitment>() -> V::Fr {
    hash_to_field::<V>(&ZERO32)
}

#[allow(non_snake_case)]
pub(crate) fn ZERO_VALUE<V: VectorCommitment>() -> V::Fr {
    hash_to_field::<V>(&[])
}

pub(crate) fn evals_to_poly<V: VectorCommitment>(domain: &Domain<V::Fr>, evals: &[V::Fr]) -> DensePolynomial<V::Fr> {
    assert_eq!(domain.size(), evals.len());
    // IFFT: evaluations -> coefficients
    let coeffs = domain.ifft(evals);
    DensePolynomial::from_coefficients_vec(coeffs)
}

pub(crate) fn hash_to_field<V: VectorCommitment>(bytes: &[u8]) -> V::Fr {
    let binding = blake3::hash(bytes);
    let h = binding.as_bytes();  // 32 bytes
    V::Fr::from_le_bytes_mod_order(h)
}

pub(crate) fn digest_commit<V: VectorCommitment>(commit: &V::Commitment) -> V::Fr {
    let mut bytes = Vec::new();
    commit.serialize_compressed(&mut bytes).expect("serialize commitment");
    hash_to_field::<V>(&bytes)
}

