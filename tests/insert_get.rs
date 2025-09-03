use rand::{rngs::StdRng, SeedableRng};
use verkle::{KzgVc, Value, VerkleTree};

fn key_from_bytes(stem: [u8; 31], suffix: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..31].copy_from_slice(&stem);
    k[31] = suffix;
    k
}

fn stem_repeat(b: u8) -> [u8; 31] {
    let mut s = [0u8; 31];
    s.fill(b);
    s
}

#[test]
fn insert_then_get_single() {
    let mut rng = StdRng::seed_from_u64(0xDEADBEEFCAFEBABE);
    let kzg = KzgVc::setup(&mut rng).expect("KZG setup should not fail");
    let mut t = VerkleTree::<KzgVc>::new(kzg);

    let stem = stem_repeat(0xAB);
    let k = key_from_bytes(stem, 0x01);

    t.insert(k, Value(b"hello".to_vec()));
    let got = t.get(k).expect("should find inserted value");

    assert_eq!(got.0, b"hello");
}

#[test]
fn insert_shared_stem_two_suffixes() {
    let mut rng = StdRng::seed_from_u64(0xDEADBEEFCAFEBABE);
    let kzg = KzgVc::setup(&mut rng).expect("KZG setup should not fail");
    let mut t = VerkleTree::<KzgVc>::new(kzg);

    let stem = stem_repeat(0x42);
    let k0 = key_from_bytes(stem, 0x00);
    let kf = key_from_bytes(stem, 0xFF);

    t.insert(k0, Value(b"A".to_vec()));
    t.insert(kf, Value(b"B".to_vec()));

    assert_eq!(t.get(k0).unwrap().0, b"A");
    assert_eq!(t.get(kf).unwrap().0, b"B");
}

#[test]
fn split_at_root_two_different_stems() {
    // First insert makes the root an Extension; second insert with a different stem
    // should trigger a split at depth 0 and both keys must be retrievable.
    let mut rng = StdRng::seed_from_u64(0xDEADBEEFCAFEBABE);
    let kzg = KzgVc::setup(&mut rng).expect("KZG setup should not fail");
    let mut t = VerkleTree::<KzgVc>::new(kzg);

    let s1 = stem_repeat(0x11);
    let s2 = stem_repeat(0x22);

    let k1 = key_from_bytes(s1, 0x01);
    let k2 = key_from_bytes(s2, 0xF0);

    t.insert(k1, Value(b"one".to_vec()));
    t.insert(k2, Value(b"two".to_vec()));

    assert_eq!(t.get(k1).unwrap().0, b"one");
    assert_eq!(t.get(k2).unwrap().0, b"two");
}

#[test]
fn split_deep_divergence_both_retrievable() {
    // Construct two stems that match for the first 25 bytes and differ at byte 25.
    let mut rng = StdRng::seed_from_u64(0xDEADBEEFCAFEBABE);
    let kzg = KzgVc::setup(&mut rng).expect("KZG setup should not fail");
    let mut t = VerkleTree::<KzgVc>::new(kzg);

    let mut s1 = [0u8; 31];
    let mut s2 = [0u8; 31];
    // common prefix for first 25 bytes
    for i in 0..25 {
        s1[i] = 0xAA;
        s2[i] = 0xAA;
    }
    // diverge at byte 25
    s1[25] = 0x10;
    s2[25] = 0xF0;
    // rest can be anything; keep zeros

    let k1 = key_from_bytes(s1, 0x01);
    let k2 = key_from_bytes(s2, 0xF0);

    t.insert(k1, Value(b"left".to_vec()));
    t.insert(k2, Value(b"right".to_vec()));

    assert_eq!(t.get(k1).unwrap().0, b"left");
    assert_eq!(t.get(k2).unwrap().0, b"right");
}

#[test]
fn split_early_extension() {
    let mut rng = StdRng::seed_from_u64(0xDEADBEEFCAFEBABE);
    let kzg = KzgVc::setup(&mut rng).expect("KZG setup should not fail");
    let mut tree = VerkleTree::<KzgVc>::new(kzg.clone());

    let key1 = key_from_bytes(stem_repeat(1), 2);
    let value1 = Value(vec![3, 4, 5]);
    tree.insert(key1, value1);

    let mut key2 = key_from_bytes(stem_repeat(1), 3); // Different stem diverges at byte 5
    key2[1] = 99;
    let value2 = Value(vec![6, 7, 8]);
    tree.insert(key2, value2);

    assert_eq!(*tree.get(key1).unwrap().0, vec![3, 4, 5]);
    assert_eq!(*tree.get(key2).unwrap().0, vec![6, 7, 8]);
}

#[test]
fn same_stem_multiple_writes_overwrite_slot() {
    // Inserting twice into the same (stem, suffix) should replace the value.
    let mut rng = StdRng::seed_from_u64(0xDEADBEEFCAFEBABE);
    let kzg = KzgVc::setup(&mut rng).expect("KZG setup should not fail");
    let mut t = VerkleTree::<KzgVc>::new(kzg);

    let stem = stem_repeat(0x77);
    let k = key_from_bytes(stem, 0x2A);

    t.insert(k, Value(b"first".to_vec()));
    assert_eq!(t.get(k).unwrap().0, b"first");

    t.insert(k, Value(b"second".to_vec()));
    assert_eq!(t.get(k).unwrap().0, b"second");
}

#[test]
fn different_suffixes_same_stem_do_not_clobber_each_other() {
    let mut rng = StdRng::seed_from_u64(0xDEADBEEFCAFEBABE);
    let kzg = KzgVc::setup(&mut rng).expect("KZG setup should not fail");
    let mut t = VerkleTree::<KzgVc>::new(kzg);

    let stem = stem_repeat(0x33);
    let k_a = key_from_bytes(stem, 0x0A);
    let k_b = key_from_bytes(stem, 0x0B);

    t.insert(k_a, Value(b"A".to_vec()));
    t.insert(k_b, Value(b"B".to_vec()));

    assert_eq!(t.get(k_a).unwrap().0, b"A");
    assert_eq!(t.get(k_b).unwrap().0, b"B");
}
