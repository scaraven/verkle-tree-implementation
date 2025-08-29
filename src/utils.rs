use ark_bls12_381::Fr;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Radix2EvaluationDomain as Domain};

pub(crate) fn evals_to_poly(domain: &Domain<Fr>, evals: &[Fr]) -> DensePolynomial<Fr> {
    assert_eq!(domain.size(), evals.len());
    // IFFT: evaluations -> coefficients
    let coeffs = domain.ifft(evals);
    DensePolynomial::from_coefficients_vec(coeffs)
}
