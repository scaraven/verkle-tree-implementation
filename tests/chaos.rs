use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::HashMap;
use verkle::{Value, VerkleTree};

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
fn get_non_existent_key_returns_none() {
    let mut t = VerkleTree::new();

    // Insert one key
    let stem = stem_repeat(0xAB);
    let present = key_from_bytes(stem, 0x01);
    t.insert(present, Value(b"exists".to_vec()));

    // Query the same stem, different suffix → should be None
    let absent_same_stem = key_from_bytes(stem, 0x02);
    assert!(t.get(absent_same_stem).is_none());

    // Query totally different stem → should be None
    let other_stem = stem_repeat(0xCD);
    let absent_other_stem = key_from_bytes(other_stem, 0x01);
    assert!(t.get(absent_other_stem).is_none());
}

#[test]
fn chaos_many_inserts_and_reads() {
    // Deterministic RNG so failures are reproducible.
    let mut rng = StdRng::seed_from_u64(0xDEADBEEFCAFEBABE);

    let mut t = VerkleTree::new();
    let mut expected: HashMap<[u8; 32], Vec<u8>> = HashMap::new();

    // --- Bucket 1: Many keys sharing ONE stem (maximal intersection) ---
    let shared_stem_a = stem_repeat(0x11);
    for suf in [0x00u8, 0x01, 0x02, 0x7F, 0x80, 0xFE, 0xFF] {
        let k = key_from_bytes(shared_stem_a, suf);
        let v = format!("A:{suf:02X}").into_bytes();
        t.insert(k, Value(v.clone()));
        expected.insert(k, v);
    }

    // --- Bucket 2: Another shared stem, and include overwrites for a couple of suffixes ---
    let shared_stem_b = stem_repeat(0x42);
    for suf in 0..32u8 {
        let k = key_from_bytes(shared_stem_b, suf);
        let v = format!("B:{suf:02X}:v1").into_bytes();
        t.insert(k, Value(v.clone()));
        expected.insert(k, v);
    }
    // Overwrite some slots on the same stem
    for suf in [0x00u8, 0x10, 0x1F] {
        let k = key_from_bytes(shared_stem_b, suf);
        let v2 = format!("B:{suf:02X}:v2").into_bytes();
        t.insert(k, Value(v2.clone()));
        expected.insert(k, v2);
    }

    // --- Bucket 3: Stems that share a LONG prefix but diverge at various depths (exercise splits) ---
    // Build a base prefix and then vary a byte at different positions.
    let mut base = [0u8; 31];
    for i in 0..31 {
        base[i] = 0xAA;
    } // common prefix
    let divergence_points = [0usize, 5, 10, 15, 25, 30]; // include first and last byte divergences
    for &d in &divergence_points {
        let mut s1 = base;
        let mut s2 = base;
        s1[d] = 0x10;
        s2[d] = 0xF0;

        // Insert two suffixes under each stem to increase fanout at the extension.
        for suf in [0x03u8, 0xF3] {
            let k1 = key_from_bytes(s1, suf);
            let v1 = format!("C:d{d}:s1:{suf:02X}").into_bytes();
            t.insert(k1, Value(v1.clone()));
            expected.insert(k1, v1);

            let k2 = key_from_bytes(s2, suf);
            let v2 = format!("C:d{d}:s2:{suf:02X}").into_bytes();
            t.insert(k2, Value(v2.clone()));
            expected.insert(k2, v2);
        }
    }

    // --- Bucket 4: A bunch of random stems/suffixes (mostly non-intersecting) ---
    for _ in 0..500 {
        let mut stem = [0u8; 31];
        for b in stem.iter_mut() {
            *b = rng.gen();
        }
        let suf: u8 = rng.gen();
        let k = key_from_bytes(stem, suf);
        let v = {
            // small random payload (length 1..8)
            let len: usize = 1 + (rng.gen::<u8>() as usize % 8);
            let mut bytes = vec![0u8; len];
            rng.fill(bytes.as_mut_slice());
            bytes
        };
        t.insert(k, Value(v.clone()));
        expected.insert(k, v);
    }

    // --- Verify everything reads back exactly ---
    for (k, v) in expected.iter() {
        let got = t
            .get(*k)
            .unwrap_or_else(|| panic!("missing key {:02X?}", k));
        assert_eq!(&got.0, v, "mismatch for key {:02X?}", k);
    }

    // --- Spot-check a few definitely-absent keys (same stems, unused suffixes) ---
    // For shared_stem_a, we only inserted a handful of suffixes.
    for suf in [0x04u8, 0x05, 0xAA, 0xBB] {
        let k = key_from_bytes(shared_stem_a, suf);
        assert!(
            !expected.contains_key(&k) && t.get(k).is_none(),
            "unexpected value for absent suffix {:02X} on shared stem A",
            suf
        );
    }
}
