use ark_bls12_381::Fr;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Radix2EvaluationDomain as Domain};
use ark_ff::PrimeField;

pub(crate) fn evals_to_poly(domain: &Domain<Fr>, evals: &[Fr]) -> DensePolynomial<Fr> {
    assert_eq!(domain.size(), evals.len());
    // IFFT: evaluations -> coefficients
    let coeffs = domain.ifft(evals);
    DensePolynomial::from_coefficients_vec(coeffs)
}

pub(crate) fn hash_to_field(bytes: &[u8]) -> Fr {
    let binding = blake3::hash(bytes);
    let h = binding.as_bytes();  // 32 bytes
    Fr::from_le_bytes_mod_order(h)
}

