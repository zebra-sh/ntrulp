use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};
use ntrulp::key::priv_key::PrivKey;
use ntrulp::key::pub_key::PubKey;
use ntrulp::ntru::cipher::{
    bytes_decrypt, bytes_encrypt, parallel_bytes_decrypt, parallel_bytes_encrypt, r3_encrypt,
    rq_decrypt,
};
use ntrulp::poly::r3::R3;
use ntrulp::poly::rq::Rq;
use ntrulp::random::{random_small, short_random};
use rand::RngCore;

fn encoder_benchmark(cb: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let r: R3 = Rq::from(short_random(&mut rng).unwrap()).r3_from_rq();
    let f: Rq = Rq::from(short_random(&mut rng).unwrap());
    let g: R3 = R3::from(random_small(&mut rng));
    let sk = PrivKey::compute(&f, &g).unwrap();
    let pk = PubKey::compute(&f, &g).unwrap();
    let enc = r3_encrypt(&r, &pk);

    cb.bench_function("r3_encrypt", |b| {
        b.iter(|| {
            r3_encrypt(&r, &pk);
        });
    });
    cb.bench_function("rq_decrypt", |b| {
        b.iter(|| {
            rq_decrypt(&enc, &sk);
        });
    });

    let mut rng1 = rand::thread_rng();

    let mut ciphertext = [0u8; 1024];
    rng.fill_bytes(&mut ciphertext);
    let cipher = bytes_encrypt(&mut rng1, &ciphertext, &pk);

    cb.bench_function("bytes_encrypt", |b| {
        b.iter(|| {
            bytes_encrypt(&mut rng1, &ciphertext, &pk);
        });
    });
    cb.bench_function("bytes_decrypt", |b| {
        b.iter(|| {
            bytes_decrypt(&cipher, &sk).unwrap();
        });
    });

    extern crate num_cpus;

    let num_threads = num_cpus::get();
    let mut rng2 = rand::thread_rng();

    let sk = Arc::new(sk);
    let pk = Arc::new(pk);

    let mut ciphertext = [0u8; 1024];
    rng.fill_bytes(&mut ciphertext);
    let ciphertext = Arc::new(ciphertext.to_vec());
    let cipher =
        Arc::new(parallel_bytes_encrypt(&mut rng2, &ciphertext, &pk, num_threads).unwrap());

    cb.bench_function("parallel_bytes_encrypt", |b| {
        b.iter(|| {
            parallel_bytes_encrypt(&mut rng2, &ciphertext, &pk, num_threads).unwrap();
        });
    });
    cb.bench_function("parallel_bytes_decrypt", |b| {
        b.iter(|| {
            parallel_bytes_decrypt(&cipher, &sk, num_threads).unwrap();
        });
    });
}

criterion_group!(benches, encoder_benchmark);
criterion_main!(benches);
