use blake3::Hasher;

use crate::{
    node::{split_key, Node},
    VerkleTree,
};

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

impl AsRef<[u8]> for FakeCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerkleProof {
    pub steps: Vec<Step>, // Internal hops (0..=some depth) + the final Extension hop
    pub value: Vec<u8>,   // claimed value (for inclusion)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    Internal {
        parent_commit: FakeCommitment,
        index: u8, // stem byte at this depth
        child_commit: FakeCommitment,
        proof: FakeProof, // opening(parent, index, digest(child_commit))
    },
    Extension {
        ext_commit: FakeCommitment,
        index: u8,        // suffix
        proof: FakeProof, // opening(ext, index, digest(value))
    },
}

// Handy helper for anything "digestible"
pub fn hash_bytes(input: &[u8]) -> [u8; 32] {
    *blake3::hash(input).as_bytes()
}

const ZERO32: [u8; 32] = [0u8; 32];

pub fn digest_value(bytes: &[u8]) -> [u8; 32] {
    hash_bytes(bytes)
}

pub fn digest_commitment<C: AsRef<[u8]>>(c: &C) -> [u8; 32] {
    hash_bytes(c.as_ref())
}

// generic over VC; for now use FakeVC in the call sites
pub(crate) fn recompute_commitment(node: &Node) -> FakeCommitment {
    match node {
        Node::Internal { children } => {
            let mut digests = [[0u8; 32]; ARITY];
            for i in 0..ARITY {
                digests[i] = match children[i].as_deref() {
                    None => ZERO32,
                    Some(child) => {
                        let child_commit = recompute_commitment(child);
                        digest_commitment(&child_commit)
                    }
                };
            }
            FakeVC::commit(&digests)
        }
        Node::Extension { slots, .. } => {
            let mut digests = [[0u8; 32]; ARITY];
            for i in 0..ARITY {
                digests[i] = match &slots[i] {
                    None => ZERO32,
                    Some(v) => digest_value(&v.0),
                };
            }
            FakeVC::commit(&digests)
        }
    }
}

pub fn verify_get(root_commit: FakeCommitment, key: [u8; 32], proof: &VerkleProof) -> bool {
    let (stem, suf) = split_key(key);
    let mut cur = root_commit;
    let mut depth = 0;

    // Internal hops
    for step in proof.steps.iter() {
        match step {
            Step::Internal {
                parent_commit,
                index,
                child_commit,
                proof: pi,
            } => {
                if *parent_commit != cur {
                    return false;
                }
                if *index != stem[depth] {
                    return false;
                }
                let target = digest_commitment(child_commit);
                if !FakeVC::verify(parent_commit, *index, target, pi) {
                    return false;
                }
                cur = child_commit.clone();
                depth += 1;
            }
            Step::Extension { .. } => break,
        }
    }

    if proof.steps.len() != depth + 1 {
        // Proof has inconsistent number of steps or an early extension
        return false;
    }

    // Final step must be Extension
    let last = proof.steps.last();
    let Step::Extension {
        ext_commit,
        index,
        proof: pi,
    } = (match last {
        Some(Step::Extension {
            ext_commit,
            index,
            proof,
        }) => Step::Extension {
            ext_commit: ext_commit.clone(),
            index: *index,
            proof: proof.clone(),
        },
        _ => return false,
    })
    else {
        unreachable!()
    };

    if index != suf {
        return false;
    }
    let target = digest_value(&proof.value);
    FakeVC::verify(&ext_commit, index, target, &pi)
}

pub fn root_commitment(tree: &VerkleTree) -> FakeCommitment {
    match &tree.root {
        None => FakeCommitment(ZERO32),
        Some(node) => recompute_commitment(node),
    }
}
