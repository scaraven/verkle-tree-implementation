use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

use crate::{node::{split_key, Node}, utils::{digest_commit, hash_to_field, ZERO_CHILD, ZERO_VALUE}};

pub const ARITY: usize = 256;
pub const ZERO32: [u8; 32] = [0; 32];

/// VC interface
pub trait VectorCommitment {
    type Fr: PrimeField;
    type Commitment: Default + PartialEq + Eq + Clone + std::fmt::Debug + CanonicalSerialize;
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

pub fn verify_proof<V: VectorCommitment>(vc: &V, root_commit: &V::Commitment, proof: &VerkleProof<V>, key: [u8; 32]) -> bool {
    let (stem, suf) = split_key(key);
    let value = &proof.value;

    if proof.steps.is_empty() {
        return false;
    }

    if proof.steps.len() > stem.len() + 1 { // at most all stem bytes + final extension
        return false; // Too many steps
    }

    // expected_digest stores the digest the next commitment must hash to.
    // Initially None: first step is checked directly against root.
    let mut expected_digest: Option<V::Fr> = None;
    let mut saw_extension = false;

    for (i, step) in proof.steps.iter().enumerate() {
        // Extract the commitment for this step
        let commit_ref = match step {
            Step::Internal { parent_commit, .. } => parent_commit,
            Step::Extension { ext_commit, .. } => ext_commit,
        };

        // Root check or linkage check
        if i == 0 {
            if commit_ref != root_commit { return false; }
        } else {
            let got = digest_commit::<V>(commit_ref);
            if Some(got) != expected_digest { return false; }
        }

        match step {
            Step::Internal { parent_commit, index, child_digest, proof: opening_proof } => {
                // Verify opening
                if !vc.verify_at(parent_commit, *index, *child_digest, opening_proof) { return false; }
                // Path index correctness
                if *index != stem[i] as usize { return false; }
                // Internal node cannot be after consuming all stem bytes
                if i == stem.len() { return false; }
                // Next commitment (child) must hash to this child_digest
                expected_digest = Some(*child_digest);
                // An Internal step cannot be the last step (must end with Extension)
                if i + 1 == proof.steps.len() { return false; }
            }
            Step::Extension { ext_commit, index, proof: opening_proof } => {
                // Suffix index correctness
                if *index != suf as usize { return false; }
                // Verify the slot opening to the value digest
                let val_digest = hash_to_field::<V>(&value);
                if !vc.verify_at(ext_commit, *index, val_digest, opening_proof) { return false; }
                // Extension must be terminal
                if i + 1 != proof.steps.len() { return false; }
                saw_extension = true;
                expected_digest = None; // No further steps allowed
            }
        }
    }

    if !saw_extension { return false; }
    true
}

// (former check_parent_child_commits logic now inlined in verify_proof with per-hop chaining)
