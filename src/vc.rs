use blake3::Hasher;

pub const ARITY: usize = 256;

pub trait Digestible {
    fn digest(&self) -> [u8; 32];
}

/// Minimal VC interface
pub trait VectorCommitment {
    type Commitment: Clone + PartialEq + Eq + core::fmt::Debug;
    type Proof: Clone + PartialEq + Eq + core::fmt::Debug;

    /// commit over ARITY child digests
    fn commit(children: &[[u8; 32]; ARITY]) -> Self::Commitment;

    /// produce an opening that "binds" (commitment, index, value_digest)
    fn open(commitment: &Self::Commitment, index: u8, value_digest: [u8; 32]) -> Self::Proof;

    /// verify the opening
    fn verify(
        commitment: &Self::Commitment,
        index: u8,
        value_digest: [u8; 32],
        proof: &Self::Proof,
    ) -> bool;
}

/// Fake VC using Blake3
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeCommitment(pub [u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeProof(pub [u8; 32]);

pub struct FakeVC;

impl VectorCommitment for FakeVC {
    type Commitment = FakeCommitment;
    type Proof = FakeProof;

    fn commit(children: &[[u8; 32]; ARITY]) -> Self::Commitment {
        let mut hasher = Hasher::new();
        for d in children {
            hasher.update(d);
        }
        FakeCommitment(*hasher.finalize().as_bytes())
    }

    fn open(commitment: &Self::Commitment, index: u8, value_digest: [u8; 32]) -> Self::Proof {
        let mut hasher = Hasher::new();
        hasher.update(&commitment.0);
        hasher.update(&[index]);
        hasher.update(&value_digest);
        FakeProof(*hasher.finalize().as_bytes())
    }

    fn verify(
        commitment: &Self::Commitment,
        index: u8,
        value_digest: [u8; 32],
        proof: &Self::Proof,
    ) -> bool {
        let expect = Self::open(commitment, index, value_digest);
        &expect == proof
    }
}

// Handy helper for anything "digestible"
pub fn hash_bytes(input: &[u8]) -> [u8; 32] {
    *blake3::hash(input).as_bytes()
}
