type Stem = [u8; 31];
type Suffix = u8;

pub struct Value(Vec<u8>);

pub(crate) enum Node {
    Internal {
        children: [Option<Box<Node>>; 256]
    },
    Extension {
        stem: Stem,
        slots: [Option<Value>; 256]
    }
}

pub(crate) fn split_key(key: [u8; 32]) -> (Stem, Suffix) {
    // Take last element
    let suf = key[31];

    let stem = key[..31].try_into().unwrap();
    (stem, suf)
}