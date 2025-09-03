use rand::{rngs::StdRng, SeedableRng};
use verkle::{vc::verify_proof, KzgVc, Value, VerkleTree};

fn make_key(stem: [u8;31], suffix: u8) -> [u8;32] {
    let mut k = [0u8;32];
    k[..31].copy_from_slice(&stem);
    k[31] = suffix;
    k
}

#[test]
fn proof_accepts_altered_trailing_stem_bytes_bug() {
    // We construct two stems that diverge at index 2 (third byte) so the extensions
    // will sit at depth 2. Only the first two stem bytes are committed via internal nodes.
    let mut rng = StdRng::seed_from_u64(0xBEEFCAFE1234);
    let kzg = KzgVc::setup(&mut rng).expect("KZG setup should not fail");
    let mut tree = VerkleTree::<KzgVc>::new(kzg.clone());

    let mut stem1 = [0u8;31];
    stem1[0] = 7; stem1[1] = 42; stem1[2] = 10; // byte 2 differs vs stem2
    // rest zero
    let mut stem2 = stem1;
    stem2[2] = 99; // divergence point (index 2)

    let key1 = make_key(stem1, 5);
    let key2 = make_key(stem2, 6); // different suffix just to populate another slot

    tree.insert(key1, Value(vec![1,2,3]));
    tree.insert(key2, Value(vec![4,5,6]));

    let root = tree.commit();

    // Generate a valid proof for key1
    let proof1 = tree.prove_get(key1).expect("proof for key1");

    // Forge a different key that shares only the committed prefix (bytes 0..=1) but
    // changes one of the UNCOMMITTED trailing bytes (here index 3) while keeping bytes 0..1 identical.
    let mut forged_stem = stem1;
    forged_stem[3] = 200; // modify after divergence position; not committed in path
    let forged_key = make_key(forged_stem, 5); // same suffix as key1
    assert_ne!(forged_key, key1, "forged key must differ");

    let accepted = verify_proof(&kzg, &root, &proof1, forged_key);
    assert!(!accepted, "Forged key was incorrectly accepted; stem not properly bound");
}
