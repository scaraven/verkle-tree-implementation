use crate::{node::{split_key, Node}, Value};

pub struct VerkleTree {
    root: Option<Node>
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
                },
                Some(Node::Extension { stem: node_stem, slots }) => {
                    if *node_stem != stem {
                        return None;
                    }
                    return slots[suf as usize].as_ref();
                }
            }
        }
        None
    }
}

