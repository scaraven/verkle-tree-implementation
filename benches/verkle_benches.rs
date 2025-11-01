use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::HashSet;
use verkle::{vc::verify_proof, KzgVc, Value, VerkleTree};

// --- Config helpers (env tunables) ---
fn bench_sizes() -> (usize, usize) {
    let n = std::env::var("VERKLE_BENCH_N")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(512);
    let m = std::env::var("VERKLE_BENCH_VERIFY_M")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(128);
    (n, m.min(n))
}

// --- Data generators ---
fn gen_unique_keys(rng: &mut impl Rng, n: usize) -> Vec<[u8; 32]> {
    let mut set: HashSet<[u8; 32]> = HashSet::with_capacity(n);
    while set.len() < n {
        let mut stem = [0u8; 31];
        for b in stem.iter_mut() {
            *b = rng.gen();
        }
        let mut k = [0u8; 32];
        k[..31].copy_from_slice(&stem);
        k[31] = rng.gen();
        set.insert(k);
    }
    set.into_iter().collect()
}

fn random_value(rng: &mut impl Rng) -> Vec<u8> {
    let len: usize = 8 + (rng.gen::<u8>() as usize % 24);
    let mut bytes = vec![0u8; len];
    rng.fill(bytes.as_mut_slice());
    bytes
}

// --- Benches ---
fn bench_insert(c: &mut Criterion) {
    let (n, _) = bench_sizes();

    // Fixed RNG for reproducibility
    let mut rng = StdRng::seed_from_u64(0xBEEFA11C_F00DCAFE);
    let kzg = KzgVc::setup(&mut rng).expect("KZG setup");
    let keys = gen_unique_keys(&mut rng, n);
    let values: Vec<Vec<u8>> = (0..n).map(|_| random_value(&mut rng)).collect();

    c.bench_function(&format!("insert_random_n={}", n), |b| {
        b.iter_batched(
            || (VerkleTree::<KzgVc>::new(kzg.clone()), keys.clone(), values.clone()),
            |(mut tree, ks, vs)| {
                for (k, v) in ks.into_iter().zip(vs.into_iter()) {
                    tree.insert(k, Value(v));
                }
                black_box(tree);
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_commit(c: &mut Criterion) {
    let (n, _) = bench_sizes();

    let mut rng = StdRng::seed_from_u64(0xFEEDFACE_D15EA5ED);
    let kzg = KzgVc::setup(&mut rng).expect("KZG setup");
    let keys = gen_unique_keys(&mut rng, n);
    let values: Vec<Vec<u8>> = (0..n).map(|_| random_value(&mut rng)).collect();

    c.bench_function(&format!("commit_after_insert_n={}", n), |b| {
        b.iter_batched(
            || {
                let mut tree = VerkleTree::<KzgVc>::new(kzg.clone());
                for (k, v) in keys.iter().copied().zip(values.iter().cloned()) {
                    tree.insert(k, Value(v));
                }
                tree
            },
            |mut tree| {
                let root = tree.commit();
                black_box(root);
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_verify(c: &mut Criterion) {
    let (n, m) = bench_sizes();

    let mut rng = StdRng::seed_from_u64(0x0123_4567_89AB_CDEF);
    let kzg = KzgVc::setup(&mut rng).expect("KZG setup");
    let keys = gen_unique_keys(&mut rng, n);
    let values: Vec<Vec<u8>> = (0..n).map(|_| random_value(&mut rng)).collect();

    c.bench_function(&format!("verify_m={}__from_n={}", m, n), |b| {
        b.iter_batched(
            || {
                // Build tree and precompute proofs
                let mut tree = VerkleTree::<KzgVc>::new(kzg.clone());
                for (k, v) in keys.iter().copied().zip(values.iter().cloned()) {
                    tree.insert(k, Value(v));
                }
                let root = tree.commit();
                let sample = &keys[..m];
                let proofs: Vec<([u8; 32], _)> = sample
                    .iter()
                    .copied()
                    .map(|k| (k, tree.prove_get(k).expect("proof exists")))
                    .collect();
                (root, proofs)
            },
            |(root, proofs)| {
                for (k, p) in proofs.iter() {
                    let ok = verify_proof(&kzg, &root, p, *k);
                    assert!(ok);
                    black_box(ok);
                }
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!{
    name = verkle_benches;
    config = Criterion::default().sample_size(10);
    targets = bench_insert, bench_commit, bench_verify
}
criterion_main!(verkle_benches);
