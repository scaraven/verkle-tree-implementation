use verkle::{KzgVc, Value, VerkleTree};

fn key_from_bytes(stem: [u8; 31], suffix: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..31].copy_from_slice(&stem);
    k[31] = suffix;
    k
}

#[test]
fn stems_differ_only_at_last_byte_both_present() {
    let mut t = VerkleTree::<KzgVc>::new();

    // identical for first 30 bytes, differ at byte 30
    let mut s1 = [0u8; 31];
    let mut s2 = [0u8; 31];
    for i in 0..30 {
        s1[i] = 0x55;
        s2[i] = 0x55;
    }
    s1[30] = 0x01;
    s2[30] = 0xFE;

    let k1 = key_from_bytes(s1, 0x00);
    let k2 = key_from_bytes(s2, 0xFF);

    t.insert(k1, Value(b"v1".to_vec()));
    t.insert(k2, Value(b"v2".to_vec()));

    assert_eq!(t.get(k1).unwrap().0, b"v1");
    assert_eq!(t.get(k2).unwrap().0, b"v2");
}
