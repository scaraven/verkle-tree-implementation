use crate::{utils::{ZERO_CHILD, ZERO_VALUE}, vc::VectorCommitment};

pub(crate) type Stem = [u8; 31];
pub(crate) type Suffix = u8;

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Value(pub Vec<u8>);

pub(crate) enum Node<V: VectorCommitment> {
    Internal {
        children: [Option<Box<Node<V>>>; 256],
        commitments: [V::Fr; 256]
    },
    Extension {
        stem: Stem,
        slots: [Option<Value>; 256],
        slot_commitment: [V::Fr; 256]
    },
}

pub(crate) fn split_key(key: [u8; 32]) -> (Stem, Suffix) {
    // Take last element
    let suf = key[31];

    let stem = key[..31].try_into().unwrap();
    (stem, suf)
}

pub struct ExtensionNode {
    pub stem: Stem,
    pub slots: [Option<Value>; 256],
}

/// Replaces an encountered Extension(old_ext) with an Internal subtree that forks at the first differing byte vs new_stem.
/// Caller must pass the start_depth = number of stem bytes already consumed on the path to old_ext.
pub(crate) fn split_extension<V: VectorCommitment>(start_depth: usize, old_ext: ExtensionNode, new_stem: Stem) -> Node<V> {
    let old_stem = old_ext.stem;
    // Get first index where the stems differ
    let d = first_diff_index(old_stem, new_stem);

    debug_assert!(d < 31, "split_extension called with identical stems");
    debug_assert!(
        old_ext.stem != new_stem,
        "split_extension called with identical stems"
    );

    let mut node = Node::Internal {
        children: std::array::from_fn(|_| None),
        commitments: std::array::from_fn(|_| ZERO_CHILD::<V>()),
    };
    let mut cur = &mut node;

    debug_assert!(
        start_depth <= d,
        "start_depth must be less than or equal to first differing index"
    );

    // Create a node with internals till stems differ
    for i in start_depth..d {
        match cur {
            Node::Internal { children, ..} => {
                let idx = old_stem[i] as usize;
                children[idx] = Some(Box::new(Node::Internal {
                    children: std::array::from_fn(|_| None),
                    commitments: std::array::from_fn(|_| ZERO_CHILD::<V>()),
                }));
                cur = children[idx].as_deref_mut().unwrap();
            }
            Node::Extension { .. } => unreachable!("Unexpected Extension node while splitting"),
        }
    }

    // Once we have reached the first difference, we can now create two extension nodes
    match cur {
        Node::Internal { children, .. } => {
            let old_idx = old_stem[d] as usize;
            let new_idx = new_stem[d] as usize;

            children[old_idx] = Some(Box::new(Node::Extension {
                stem: old_stem,
                slots: old_ext.slots,
                slot_commitment: std::array::from_fn(|_| ZERO_VALUE::<V>()),
            }));
            children[new_idx] = Some(Box::new(Node::Extension {
                stem: new_stem,
                slots: std::array::from_fn(|_| None),
                slot_commitment: std::array::from_fn(|_| ZERO_VALUE::<V>()),
            }));
        }
        Node::Extension { .. } => unreachable!("Unexpected Extension node while splitting"),
    }

    node
}

fn first_diff_index(old_stem: Stem, new_stem: Stem) -> usize {
    for i in 0..31 {
        if old_stem[i] != new_stem[i] {
            return i;
        }
    }
    31
}
