pub const ARITY: usize = 256;
pub const ZERO32: [u8; 32] = [0; 32];

/// VC interface
pub trait VectorCommitment {
    type Fr;
    type Commitment: PartialEq + Eq + Clone + std::fmt::Debug;
    type Proof: Clone + std::fmt::Debug + PartialEq + Eq;

    // Typically constructed with an SRS and fixed domain elsewhere.
    // fn new(params: ...) -> Self where Self: Sized;

    fn commit_from_children(&self, children: &[Self::Fr; ARITY]) -> Self::Commitment;

    // Return both the field value and the proof (handy for the caller).
    fn open_at(
        &self,
        children: &[Self::Fr; ARITY],
        index: usize,
    ) -> (/*value_digest*/ Self::Fr, Self::Proof);

    fn verify_at(
        &self,
        commitment: &Self::Commitment,
        index: usize,
        value_digest: Self::Fr,
        proof: &Self::Proof,
    ) -> bool;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerkleProof<V: VectorCommitment> {
    pub steps: Vec<Step<V>>, // Internal hops (0..=some depth) + the final Extension hop
    pub value: Vec<u8>,       // claimed value (for inclusion)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step<V: VectorCommitment> {
    Internal {
        parent_commit: V::Commitment,
        index: u8, // stem byte at this depth
        child_commit: V::Commitment,
        proof: V::Proof, // opening(parent, index, digest(child_commit))
    },
    Extension {
        ext_commit: V::Commitment,
        index: u8,        // suffix
        proof: V::Proof, // opening(ext, index, digest(value))
    },
}
