
# NTRUP Rust

This repository presents an implementation of high-security prime-degree large-Galois-group inert-modulus ideal-lattice-based cryptography on rust programing langudge.
“Prime degree” etc. are defenses against potential attacks; see [official website](https://www.ntru.org/).

This implementation uses: Fields of the form (Z/q)[x]/(xp −x−1), where p is prime, are used in “NTRU Prime”, introduced in this paper, and have all of our recommended defenses.

## Notation and Parameters for NTRU Prime

In the context of NTRU Prime, several parameters and notations
play a crucial role in defining the cryptographic system.

### Parameter Set

A parameter set for NTRU Prime is represented as a triple (p, q, w), 
which forms the foundation of the primary algebraic structures in the system.
Let's break down these parameters:

 * P: This parameter corresponds to the degree of the irreducible polynomial P = xp − x − 1 and is required to be a prime number. Commonly used values for p in the parameter sets are 653, 761, 857, 953, 1013, 1277  .
 * Q: Representing the characteristic of the field R/q = (Z/q)[x]/P, q is also a prime number. The values typically employed for q depend on the specific degree considered in [5] and include 4621, 4591, 5167, 6343, 7177, 7879.
 * W: The weight parameter W is a positive integer that governs the number of non-zero coefficients within specific polynomials.

 * P = 653, Q = 4621, W = 288
 * P = 761, Q = 4591, W = 286
 * P = 857, Q = 5167, W = 322
 * P = 953, Q = 6343, W = 396
 * P = 1013, Q = 7177, W = 448
 * P = 1277, Q = 7879, W = 492

#### Extra parameter Set
 * `R3_BYTES` - Size of encoded R3 poly
 * `RQ_BYTES` - Size of bytes encoded Rq poly
 * `PUBLICKEYS_BYTES` - Size encoded public Key
 * `SECRETKEYS_BYTES` - Size of Secret Key
 * `DIFFICULT` - This parameter is responsible for the complexity of the algorithm for applying statistical analysis to it.

Valid Parameter Set Conditions

To ensure the validity of a parameter set, it must meet the following conditions:

 * `2P ≥ 3W`: This inequality places a constraint on the relationship between p and w, emphasizing the importance of a balanced selection of these parameters.
 * `Q ≥ 16W + 1`: Another crucial condition, this inequality imposes restrictions on q relative to the weight parameter w.

Notational Abbreviations

For brevity and clarity, the following notational abbreviations are used:

R3: Denotes the ring (Z/3)[x]/P, which is a specific variant related to the ring R.
Rq: Represents the field (Z/q)[x]/P, another critical element in the cryptographic system.

## Rust Features

You can select parameters through features, you must select parameters!

 * ntrup653
 * ntrup761
 * ntrup857
 * ntrup953
 * ntrup1013
 * ntrup1277

```
# Cargo.toml

ntrulp = { version = "0.1.7", features = ["ntrup653"] }
ntrulp = { version = "0.1.7", features = ["ntrup761"] }
ntrulp = { version = "0.1.7", features = ["ntrup857"] }
ntrulp = { version = "0.1.7", features = ["ntrup953"] }
ntrulp = { version = "0.1.7", features = ["ntrup1013"] }
ntrulp = { version = "0.1.7", features = ["ntrup1277"] }
```


### install
```bash
cargo add ntrulp
```



### Testing

```bash
git clone https://github.com/zebra-sh/ntrulp.git
cd ntrulp
cargo test --features ntrup1277

```

```bash
git clone https://github.com/zebra-sh/ntrulp.git
cd ntrulp
cargo bench --features ntrup1277
```
## Keys Generation:
```rust
let mut rng = rand::thread_rng();
let mut g: R3;
let f: Rq = Rq::from(short_random(&mut rng).unwrap());
let sk = loop {
    g = R3::from(random_small(&mut rng));

    match PrivKey::compute(&f, &g) {
        Ok(s) => break s,
        Err(_) => continue,
    };
};
let pk = PubKey::compute(&f, &g).unwrap();

let pk = PubKey::compute(&f, &g).unwrap();
let imported_pk = PubKey::from_sk(&sk).unwrap();
let pk_bytes = imported_pk.as_bytes();
let from_bytes = PubKey::import(&pk_bytes).unwrap();

assert_eq!(from_bytes.coeffs, pk.coeffs);
```
## Encrypt/Decrypt bytes example
```rust
use std::sync::Arc;

use ntrulp::key::priv_key::PrivKey;
use ntrulp::key::pub_key::PubKey;
use ntrulp::ntru::cipher::{
    bytes_decrypt, parallel_bytes_decrypt, parallel_bytes_encrypt, 
};
use ntrulp::ntru::errors::NTRUErrors;
use ntrulp::random::{random_small, short_random};


fn gen_keys<'a>() -> Result<(Arc<PrivKey>, Arc<PubKey>), NTRUErrors<'a>> {
    let mut rng = rand::thread_rng();
    let mut g: R3;
    let f: Rq = Rq::from(short_random(&mut rng).unwrap());
    let sk = loop {
        g = R3::from(random_small(&mut rng));

        match PrivKey::compute(&f, &g) {
            Ok(s) => break s,
            Err(_) => continue,
        };
    };
    let pk = PubKey::compute(&f, &g).unwrap();

    Ok((Arc::new(sk), Arc::new(pk)))
}

let mut rng = rand::thread_rng();
let mut bytes = [0u8; 1024];
rng.fill_bytes(&mut bytes);
let bytes = Arc::new(bytes.to_vec());

let (sk, pk) = gen_keys().unwrap();

let num_threads = 4;
let encrypted1 = Arc::new(parallel_bytes_encrypt(&mut rng, &bytes, &pk, num_threads).unwrap());
let decrypted0 = parallel_bytes_decrypt(&encrypted1, &sk, num_threads).unwrap();
let decrypted1 = bytes_decrypt(&encrypted1, &sk).unwrap();

assert_eq!(decrypted0, decrypted1);
```

## TODO
 - add Falcon algorithm for sign,verify signature

## Warnings

#### Implementation 
This implementation has not undergone any security auditing and while care has been taken no guarantees can be made for either correctness or the constant time running of the underlying functions. **Please use at your own risk.**
