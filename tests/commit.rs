use rand::{rngs::StdRng, SeedableRng};
use verkle::{vc::verify_proof, KzgVc, Value, VerkleTree
};

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
fn verify_single_key() {
    let mut rng = StdRng::seed_from_u64(0xDEADBEEFCAFEBABE);
    let kzg = KzgVc::setup(&mut rng).expect("KZG setup should not fail");
    let mut tree = VerkleTree::<KzgVc>::new(kzg.clone());
    let key = key_from_bytes(stem_repeat(1), 2);
    let value = Value(vec![3, 4, 5]);
    tree.insert(key, value);

    let root = tree.commit();

    let proof = tree.prove_get(key).unwrap();
    assert!(verify_proof(&kzg, &root, &proof, key));
}

#[test]
fn fail_incorrect_proof() {
    let mut rng = StdRng::seed_from_u64(0xDEADBEEFCAFEBABE);
    let kzg = KzgVc::setup(&mut rng).expect("KZG setup should not fail");
    let mut tree = VerkleTree::<KzgVc>::new(kzg.clone());
    let key = key_from_bytes(stem_repeat(1), 2);
    let value = Value(vec![3, 4, 5]);
    tree.insert(key, value);

    let root = tree.commit(); 

    let mut proof = tree.prove_get(key).unwrap();
    proof.value[0] = 99; // Corrupt proof
    assert!(!verify_proof(&kzg, &root, &proof, key));
}

#[test]
fn verify_sibling_keys() {
    let mut rng = StdRng::seed_from_u64(0xDEADBEEFCAFEBABE);
    let kzg = KzgVc::setup(&mut rng).expect("KZG setup should not fail");
    let mut tree = VerkleTree::<KzgVc>::new(kzg.clone());
    let key1 = key_from_bytes(stem_repeat(1), 2);
    let value1 = Value(vec![3, 4, 5]);
    tree.insert(key1, value1);

    let key2 = key_from_bytes(stem_repeat(1), 3);
    let value2 = Value(vec![6, 7, 8]);
    tree.insert(key2, value2);

    let root = tree.commit();

    let proof1 = tree.prove_get(key1).unwrap();
    let proof2 = tree.prove_get(key2).unwrap();

    assert!(verify_proof(&kzg, &root, &proof1, key1));
    assert!(verify_proof(&kzg, &root, &proof2, key2));
}

#[test]
fn verify_early_extension() {
    let mut rng = StdRng::seed_from_u64(0xDEADBEEFCAFEBABE);
    let kzg = KzgVc::setup(&mut rng).expect("KZG setup should not fail");
    let mut tree = VerkleTree::<KzgVc>::new(kzg.clone());
    let key1 = key_from_bytes(stem_repeat(1), 2);
    let value1 = Value(vec![3, 4, 5]);
    tree.insert(key1, value1);

    let mut key2 = key_from_bytes(stem_repeat(1), 3); // Different stem diverges at byte 5
    key2[5] = 99;
    let value2 = Value(vec![6, 7, 8]);
    tree.insert(key2, value2);

    let root = tree.commit();

    let proof1 = tree.prove_get(key1).unwrap();
    let proof2 = tree.prove_get(key2).unwrap();

    assert!(verify_proof(&kzg, &root, &proof1, key1));
    assert!(verify_proof(&kzg, &root, &proof2, key2));
}

#[test]
fn verify_incorrect_length_proof() {
    let mut rng = StdRng::seed_from_u64(0xDEADBEEFCAFEBABE);
    let kzg = KzgVc::setup(&mut rng).expect("KZG setup should not fail");
    let mut tree = VerkleTree::<KzgVc>::new(kzg.clone());
    let key = key_from_bytes(stem_repeat(1), 2);
    let value = Value(vec![3, 4, 5]);
    tree.insert(key, value);

    let root = tree.commit();

    let proof = tree.prove_get(key).unwrap();
    let mut incorrect_proof = proof.clone();
    incorrect_proof.steps.push(proof.steps[0].clone()); // Add an extra step to make it invalid length

    assert!(!verify_proof(&kzg, &root, &incorrect_proof, key));
}
