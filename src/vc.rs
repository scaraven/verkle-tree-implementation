use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

use crate::{node::{split_key, Node}, utils::{digest_commit, hash_to_field, ZERO_CHILD, ZERO_VALUE}};

pub const ARITY: usize = 256;
pub const ZERO32: [u8; 32] = [0; 32];

/// VC interface
pub trait VectorCommitment {
    type Fr: PrimeField;
    type Commitment: PartialEq + Eq + Clone + std::fmt::Debug + CanonicalSerialize;
    type Proof: Clone + std::fmt::Debug + PartialEq + Eq;

    // Typically constructed with an SRS and fixed domain elsewhere.
    // fn new(params: ...) -> Self where Self: Sized;

    fn commit_from_children(&self, children: &[Self::Fr; ARITY]) -> Self::Commitment;

    // Return both the field value and the proof (handy for the caller).
    fn open_at(
        &self,
        children: &[Self::Fr; ARITY],
        index: usize,
    ) -> (Self::Fr, Self::Proof);

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
        index: usize, // stem byte at this depth
        child_digest: V::Fr, // Digest of child value at index
        proof: V::Proof, // opening(parent, index, child_digest)
    },
    Extension {
        ext_commit: V::Commitment,
        index: usize,        // suffix
        proof: V::Proof, // opening(ext, index, digest(value))
    },
}

fn compute_internal_commitment<V: VectorCommitment>(vc: &V, node: &mut Node<V>) -> V::Commitment {
    match node {
        Node::Internal { children, commitments } => {
            let mut child_digests: [V::Fr; ARITY] = std::array::from_fn(|_| ZERO_CHILD::<V>());
            for (i, child_opt) in children.iter_mut().enumerate() {
                if let Some(child) = child_opt.as_deref_mut() {
                    // recurse to ensure children's commitments arrays are also populated
                    let child_commit = compute_commitment::<V>(vc, child);
                    let digest = digest_commit::<V>(&child_commit);
                    child_digests[i] = digest;
                } else {
                    child_digests[i] = ZERO_CHILD::<V>();
                }
            }
            let commit = vc.commit_from_children(&child_digests);
            *commitments = child_digests;
            commit
        }
        _ => unreachable!("compute_internal_commitment called on non-internal node"),
    }
}

fn compute_extension_commitment<V: VectorCommitment>(vc: &V, node: &mut Node<V>) -> V::Commitment {
    match node {
        Node::Extension { slots, slot_commitment, .. } => {
            let mut value_digests: [V::Fr; ARITY] = std::array::from_fn(|_| ZERO_VALUE::<V>());
            for (i, slot_opt) in slots.iter().enumerate() {
                if let Some(value) = slot_opt {
                    let digest = hash_to_field::<V>(&value.0);
                    value_digests[i] = digest;
                } else {
                    value_digests[i] = ZERO_VALUE::<V>();
                }
            }
            let commit = vc.commit_from_children(&value_digests);
            *slot_commitment = value_digests;
            commit
        }
        _ => unreachable!("compute_extension_commitment called on non-extension node"),
    }
}

pub(crate) fn compute_commitment<V: VectorCommitment>(vc: &V, node: &mut Node<V>) -> V::Commitment {
    match node {
        Node::Internal { .. } => compute_internal_commitment(vc, node),
        Node::Extension { .. } => compute_extension_commitment(vc, node),
    }
}

pub fn verify_proof<V: VectorCommitment>(vc: &V, proof: &VerkleProof<V>, key: [u8; 32]) -> bool {
    let (stem, suf) = split_key(key);
    let value = &proof.value;

    if !proof.steps.is_empty() {
        return false;
    }

    if proof.steps.len() >= stem.len() + 1 {
        return false; // Too many steps
    }

    let prev_digest = match proof.steps[0] {
            Step::Internal { child_digest, .. } => child_digest,
            Step::Extension { .. } => hash_to_field::<V>(&value),
        };

    // Verify each step in the proof
    for (i, step) in proof.steps.iter().enumerate() {
        if i > 0 && !check_parent_child_commits(prev_digest, step) {
            return false;
        }

        match step {
            Step::Internal { parent_commit, index, child_digest, proof } => {
                if !vc.verify_at(parent_commit, *index, *child_digest, proof) {
                    return false;
                } else if *index != stem[i] as usize {
                    return false; // Stem index mismatch
                } else if i == stem.len() {
                    return false; // Should not have internal nodes after stem is done
                }
            }
            Step::Extension { ext_commit, index, proof } => {
                if *index != suf as usize {
                    return false; // Suffix index mismatch
                }

                if !vc.verify_at(ext_commit, *index, hash_to_field::<V>(&value), proof) {
                    return false;
                }
            }
        }
    }
    // If all steps are valid, return true
    true
}

// Ensures that digest(commit) == parent.child_digest
fn check_parent_child_commits<V: VectorCommitment>(prev_digest: V::Fr, step: &Step<V>) -> bool {
    let commit = match step {
        Step::Internal { parent_commit, .. } => parent_commit,
        Step::Extension { ext_commit, .. } => ext_commit,
    };

    let computed_digest = digest_commit::<V>(&commit);
    computed_digest == prev_digest
}
