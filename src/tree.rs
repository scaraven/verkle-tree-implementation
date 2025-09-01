use crate::{
    node::{split_extension, split_key, ExtensionNode, Node}, utils::ZERO_VALUE, vc::{compute_commitment, Step, VectorCommitment, VerkleProof}, Value
};

pub struct VerkleTree<V: VectorCommitment> {
    pub(crate) root: Option<Node<V>>,
    vc: V,
}

impl<V: VectorCommitment> VerkleTree<V> {
    pub fn new(vc: V) -> Self {
        VerkleTree { root: None, vc }
    }

    pub fn get(&self, key: [u8; 32]) -> Option<&Value> {
        let (stem, suf) = split_key(key);

        let mut node: Option<&Node<V>> = self.root.as_ref();

        for i in 0..31 {
            match node {
                None => return None,
                Some(Node::Internal { children, ..}) => {
                    let idx = stem[i] as usize;
                    node = children[idx].as_deref();
                }
                Some(Node::Extension {
                    stem: node_stem,
                    slots,
                    ..
                }) => {
                    if *node_stem != stem {
                        return None;
                    }
                    return slots[suf as usize].as_ref();
                }
            }
        }

        // If we have reached here, then check whether we hit an extension node
        if let Some(Node::Extension {
            stem: node_stem,
            slots: node_slots,
            ..
        }) = node
        {
            if *node_stem == stem {
                return node_slots[suf as usize].as_ref();
            }
        }

        None
    }

    fn create_root(&mut self, key: [u8; 32], value: Value) {
        let (stem, suf) = split_key(key);
        let mut slots: [Option<Value>; 256] = std::array::from_fn(|_| None);
        slots[suf as usize] = Some(value);
        self.root = Some(Node::Extension { stem, slots, slot_commitment: std::array::from_fn(|_| ZERO_VALUE::<V>()) });
    }

    pub fn insert(&mut self, key: [u8; 32], value: Value) {
        let (stem, suf) = split_key(key);

        if self.root.is_none() {
            self.create_root(key, value);
            compute_commitment(&self.vc, self.root.as_mut().unwrap());
            return;
        }

        let mut node = self.root.as_mut().unwrap();

        for i in 0..31 {
            match node {
                Node::Internal { children , .. } => {
                    let idx = stem[i] as usize;
                    if children[idx].is_none() {
                        // Create a new extension node here
                        let mut slots: [Option<Value>; 256] = std::array::from_fn(|_| None);
                        slots[suf as usize] = Some(value);
                        children[idx] = Some(Box::new(Node::Extension { stem, slots, slot_commitment: std::array::from_fn(|_| ZERO_VALUE::<V>())}));
                        compute_commitment(&self.vc, self.root.as_mut().unwrap());
                        return;
                    } else {
                        // We iterate through
                        node = children[idx].as_mut().unwrap();
                    }
                }
                Node::Extension {
                    stem: node_stem,
                    slots,
                    ..
                } => {
                    if *node_stem != stem {
                        let old_slots = std::mem::replace(slots, std::array::from_fn(|_| None));
                        let old_node = ExtensionNode {
                            stem: *node_stem,
                            slots: old_slots,
                        };
                        // If the stems don't match, we need to split the node
                        *node = split_extension(i, old_node, stem);
                        // Advance search, so that we consume byte
                        match node {
                            Node::Internal { children, ..  } => {
                                let idx = stem[i] as usize;
                                node = children[idx].as_deref_mut().unwrap();
                            }
                            _ => unreachable!("Cannot have extension node right after splitting"),
                        }
                    } else {
                        // If the stems match, we can just insert the value
                        slots[suf as usize] = Some(value);
                        compute_commitment(&self.vc, self.root.as_mut().unwrap());
                        return;
                    }
                }
            }
        }

        match node {
            // Hit the stem bucket exactly here
            Node::Extension {
                stem: node_stem,
                slots,
                slot_commitment: _,
            } if *node_stem == stem => {
                slots[suf as usize] = Some(value);
                compute_commitment(&self.vc, self.root.as_mut().unwrap());
                return;
            }

            // The Extension is the child of this Internal (common shape)
            Node::Internal { children, .. } => {
                let idx = stem[30] as usize;
                match children[idx].as_deref_mut() {
                    Some(Node::Extension {
                        stem: node_stem,
                        slots,
                        slot_commitment: _,
                    }) if *node_stem == stem => {
                        slots[suf as usize] = Some(value);
                        compute_commitment(&self.vc, self.root.as_mut().unwrap());
                        return;
                    }
                    None => {
                        // create a fresh Extension for this stem
                        let mut slots_arr = std::array::from_fn(|_| None);
                        slots_arr[suf as usize] = Some(value);
                        children[idx] = Some(Box::new(Node::Extension {
                            stem,
                            slots: slots_arr,
                            slot_commitment: std::array::from_fn(|_| ZERO_VALUE::<V>()),
                        }));
                        compute_commitment(&self.vc, self.root.as_mut().unwrap());
                        return;
                    }
                    _ => unreachable!("invalid shape at depth 31"),
                }
            }

            // Any other shape would be a construction bug
            _ => unreachable!("unexpected node at depth 31"),
        }
    }

    pub fn prove_get(&self, key: [u8; 32]) -> Option<VerkleProof<V>> {
        let (stem, suf) = split_key(key);

        let mut node = match self.root {
            None => return None,
            Some(ref n) => n,
        };

        let mut proof_vec: VerkleProof<V> = VerkleProof { steps: Vec::new(), value: Vec::new() };

        for (_, &byte) in stem.iter().enumerate() {
            let index = byte as usize;
            match node {
                Node::Internal { children, commitments} => {
                    
                    let node_commit = self.vc.commit_from_children(commitments);
                    let (child_digest, proof) = self.vc.open_at(&commitments, index);
                    // Push a new proof
                    proof_vec.steps.push(
                        Step::Internal {
                            parent_commit: node_commit,
                            index: index,
                            child_digest,
                            proof,
                        }
                    );

                    // Iterate to next node
                    node = match children[index].as_deref() {
                        Some(n) => n,
                        None => return None,
                    };
                }
                Node::Extension { stem: node_stem, slots, slot_commitment } => {
                    if *node_stem != stem {
                        return None;
                    }
                    let ext_commit = self.vc.commit_from_children(slot_commitment);
                    let (_, proof) = self.vc.open_at(&slot_commitment, index);
                    proof_vec.steps.push(
                        Step::Extension { ext_commit, index, proof }
                    );
                    proof_vec.value = slots[suf as usize].clone().unwrap().0;
                    return Some(proof_vec);
                }
            }
        }

        match node {
            Node::Extension { stem: node_stem, slots, slot_commitment } if *node_stem == stem => {
                let ext_commit = self.vc.commit_from_children(slot_commitment);
                let (_, proof) = self.vc.open_at(&slot_commitment, suf as usize);
                proof_vec.steps.push(
                    Step::Extension { ext_commit, index: suf as usize, proof }
                );
                proof_vec.value = slots[suf as usize].clone().unwrap().0;
            }
            _ => unreachable!("unexpected node at depth 31"),
        }

        Some(proof_vec)
    }
}
