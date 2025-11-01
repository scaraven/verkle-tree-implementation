# Verkle Tree (educational implementation)

A minimal Verkle tree in Rust using KZG polynomial commitments (arkworks). Keys are 32 bytes split into a 31-byte stem and 1-byte suffix. The tree has:
- Internal nodes (256-ary) that commit to child digests.
- Extension nodes (one per stem) that hold up to 256 optional values (by suffix), committed via a vector commitment to slot digests.

This implementation binds proofs to the full stem + suffix + value, ensuring path and key binding end-to-end.

## Motivation
This was a project to help me understand this [article](https://dankradfeist.de/ethereum/2021/06/18/verkle-trie-for-eth1.html) from Dankrad Feist.

## Features
- Insert/Get by 32-byte key (stem + suffix).
- Commit the tree to a single KZG commitment.
- Create and verify inclusion proofs for a key/value.
- Deterministic, reproducible tests.

## Quick start
- Build and run tests:
  - `cargo test`

## Minimal example
```rust
use rand::{rngs::StdRng, SeedableRng};
use verkle::{vc::verify_proof, KzgVc, Value, VerkleTree};

fn key_from_bytes(stem: [u8; 31], suffix: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..31].copy_from_slice(&stem);
    k[31] = suffix;
    k
}

fn main() {
    let mut rng = StdRng::seed_from_u64(0xDEADBEEFCAFEBABE);
    let kzg = KzgVc::setup(&mut rng).unwrap();
    let mut tree = VerkleTree::<KzgVc>::new(kzg.clone());

    let stem = [1u8; 31];
    let key = key_from_bytes(stem, 2);
    tree.insert(key, Value(b"hello".to_vec()));

    let root = tree.commit();
    let proof = tree.prove_get(key).unwrap();
    assert!(verify_proof(&kzg, &root, &proof, key));
}
```

## Modules
- `tree`: VerkleTree API (insert, get, commit, prove_get).
- `node`: Node types and splitting logic.
- `vc`: Vector commitment interface, proof format, verification.
- `kzg`: KZG-backed commitment implementation (arkworks).
- `utils`: Hashing/binding helpers and polynomial utilities.

## Notes
- Uses Blake3 for binding to field elements.
- Proof verification checks:
  - Path indices for each internal hop.
  - Commitment chaining (parent→child).
  - Final extension opening binds (stem, suffix, value).
