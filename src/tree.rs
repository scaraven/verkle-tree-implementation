use crate::{
    node::{split_extension, split_key, ExtensionNode, Node},
    Value,
};

pub struct VerkleTree {
    pub(crate) root: Option<Node>,
}

impl VerkleTree {
    pub fn new() -> Self {
        VerkleTree { root: None }
    }

    pub fn get(&self, key: [u8; 32]) -> Option<&Value> {
        let (stem, suf) = split_key(key);

        let mut node: Option<&Node> = self.root.as_ref();

        for i in 0..31 {
            match node {
                None => return None,
                Some(Node::Internal { children }) => {
                    let idx = stem[i] as usize;
                    node = children[idx].as_deref();
                }
                Some(Node::Extension {
                    stem: node_stem,
                    slots,
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
        }) = node
        {
            if *node_stem == stem {
                return node_slots[suf as usize].as_ref();
            }
        }

        None
    }

    pub fn insert(&mut self, key: [u8; 32], value: Value) {
        let (stem, suf) = split_key(key);

        if self.root.is_none() {
            let mut slots: [Option<Value>; 256] = std::array::from_fn(|_| None);
            slots[suf as usize] = Some(value);
            self.root = Some(Node::Extension { stem, slots });
            return;
        }

        let mut node = self.root.as_mut().unwrap();

        for i in 0..31 {
            match node {
                Node::Internal { children } => {
                    let idx = stem[i] as usize;
                    if children[idx].is_none() {
                        // Create a new extension node here
                        let mut slots: [Option<Value>; 256] = std::array::from_fn(|_| None);
                        slots[suf as usize] = Some(value);
                        children[idx] = Some(Box::new(Node::Extension { stem, slots }));
                        return;
                    } else {
                        // We iterate through
                        node = children[idx].as_mut().unwrap();
                    }
                }
                Node::Extension {
                    stem: node_stem,
                    slots,
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
                            Node::Internal { children } => {
                                let idx = stem[i] as usize;
                                node = children[idx].as_deref_mut().unwrap();
                            }
                            _ => unreachable!("Cannot have extension node right after splitting"),
                        }
                    } else {
                        // If the stems match, we can just insert the value
                        slots[suf as usize] = Some(value);
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
            } if *node_stem == stem => {
                slots[suf as usize] = Some(value);
                return;
            }

            // The Extension is the child of this Internal (common shape)
            Node::Internal { children } => {
                let idx = stem[30] as usize;
                match children[idx].as_deref_mut() {
                    Some(Node::Extension {
                        stem: node_stem,
                        slots,
                    }) if *node_stem == stem => {
                        slots[suf as usize] = Some(value);
                        return;
                    }
                    None => {
                        // create a fresh Extension for this stem
                        let mut slots_arr = std::array::from_fn(|_| None);
                        slots_arr[suf as usize] = Some(value);
                        children[idx] = Some(Box::new(Node::Extension {
                            stem,
                            slots: slots_arr,
                        }));
                        return;
                    }
                    _ => unreachable!("invalid shape at depth 31"),
                }
            }

            // Any other shape would be a construction bug
            _ => unreachable!("unexpected node at depth 31"),
        }
    }
}
